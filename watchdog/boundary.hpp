#pragma once
// Pinned private Darwin identity/termination support. Signals are not exit proof.
#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <libproc.h>
#include <bsm/libbsm.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pwd.h>
#include <poll.h>
#include <spawn.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach_time.h>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>
#include <algorithm>
#include <atomic>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <deque>
#include <dlfcn.h>
#include <mach-o/loader.h>
extern "C" int csops_audittoken(pid_t, unsigned int, void*, size_t, audit_token_t*);
namespace arbol_boundary {
struct Unique { uint8_t uuid[16]; uint64_t start, parent; int32_t version, originalParentVersion; uint64_t reserve[2]; };
static_assert(sizeof(Unique) == 56);
struct Info { proc_bsdinfo bsd; Unique unique; };
struct Identity { int pid = 0; uint64_t start = 0; int32_t version = 0; uint32_t uid = 0, group = 0; };
inline double clockMs() { mach_timebase_info_data_t s{}; if (mach_timebase_info(&s) != KERN_SUCCESS || !s.denom) _exit(4); return (double)mach_continuous_time() * s.numer / s.denom / 1000000.0; }
inline bool same(const Identity& a, const Identity& b) { return a.pid == b.pid && a.start == b.start && a.version == b.version && a.uid == b.uid; }
// This is the live-list view only. ESRCH may precede descriptor teardown,
// NOTE_EXIT and zombie reaping. It is NEVER complete original-exit evidence.
inline int observe(int pid, Identity& id, Info* detail = nullptr) {
  Info info{}; errno = 0; int n = proc_pidinfo(pid, 18, 0, &info, sizeof(info));
  if (!n && errno == ESRCH) return 0;
  if (n != sizeof(info) || pid < 1 || info.bsd.pbi_pid != (uint32_t)pid || !info.unique.start || info.unique.version <= 0) return -1;
  id = {pid, info.unique.start, info.unique.version, info.bsd.pbi_uid, info.bsd.pbi_pgid}; if (detail) *detail = info; return 1;
}
inline int current(const Identity& original) { if (!original.pid) return 0; Identity now; int n = observe(original.pid, now); return n <= 0 ? n : same(original, now) ? 1 : now.start != original.start ? 0 : -1; }
using OriginalKey=std::pair<int,uint64_t>;
inline OriginalKey key(const Identity& id) { return {id.pid,id.start}; }
// One truthful module lifetime precedes every detached native operation. The
// anchor has internal linkage in this actual Mach-O, not an inferred filename.
static void nativeImageAnchor() {}
inline bool retainNativeImage() {
  struct Pin { std::once_flag once; void* handle=nullptr; bool valid=false; };
  static Pin* pin=new Pin; // process lifetime; never a per-helper loader reference
  Pin* state=pin;
  std::call_once(pin->once,[state] {
    Dl_info image{},again{};
    if(!dladdr((const void*)&nativeImageAnchor,&image)||!image.dli_fname||!image.dli_fbase) return;
    if(((const mach_header*)image.dli_fbase)->filetype!=MH_EXECUTE) {
      state->handle=dlopen(image.dli_fname,RTLD_NOW|RTLD_NOLOAD|RTLD_NODELETE);
      if(!state->handle) return;
    }
    state->valid=dladdr((const void*)&nativeImageAnchor,&again)&&again.dli_fbase==image.dli_fbase;
  });
  return pin->valid;
}
// These are kernel observations, never a flush receipt or an exit timeout.
// A nonzero-arg query can sleep behind a zombie/reap controller. Only these
// four detached read-only workers perform it; the actual protocol/command
// thread never waits and retains its unchanged original deadline.
enum class KernelState : int { transient=-3,pending=-1,uncertain=-2,live=0,exiting=1,absent=2 };
struct KernelAnswer {
  std::atomic<KernelState> state{KernelState::pending}; double completed=0;
  int returned=0,error=0;
  Info observed{};
};
class KernelQueries {
  struct Job { Identity original; bool exactGroup; std::shared_ptr<KernelAnswer> answer; };
  std::mutex mutex_; std::condition_variable available_; std::deque<Job> queue_;
  size_t running_=0; bool ready_=false,failed_=false;
  void run() {
    for(;;) {
      Job job;
      {
        std::unique_lock<std::mutex> held(mutex_);
        available_.wait(held,[&] { return failed_||(ready_&&!queue_.empty()); });
        if(failed_) return;
        job=std::move(queue_.front()); queue_.pop_front(); ++running_;
      }
      Info info{}; errno=0;
      int n=proc_pidinfo(job.original.pid,18,1,&info,sizeof(info)); int failure=errno;
      KernelState result=KernelState::uncertain;
      if(!n&&failure==ESRCH) result=KernelState::absent;
      else if(n<=0&&(failure==EINTR||failure==EAGAIN||failure==EBUSY)) result=KernelState::transient;
      else if(n==sizeof(info)&&info.bsd.pbi_pid==(uint32_t)job.original.pid&&info.unique.start&&info.unique.version>0) {
        Identity actual{job.original.pid,info.unique.start,info.unique.version,info.bsd.pbi_uid,info.bsd.pbi_pgid};
        if(actual.start!=job.original.start) result=KernelState::absent;
        else if(same(actual,job.original)&&(!job.exactGroup||actual.group==job.original.group))
          result=(info.bsd.pbi_flags&PROC_FLAG_INEXIT)?KernelState::exiting:KernelState::live;
      }
      job.answer->observed=info; job.answer->returned=n; job.answer->error=failure; job.answer->completed=clockMs();
      job.answer->state.store(result,std::memory_order_release);
      { std::lock_guard<std::mutex> held(mutex_); --running_; }
    }
  }
  KernelQueries() {
    if(!retainNativeImage()) { failed_=true; return; }
    try {
      for(unsigned i=0;i<4;++i) std::thread([this] { run(); }).detach();
      { std::lock_guard<std::mutex> held(mutex_); ready_=true; } available_.notify_all();
    } catch(...) {
      { std::lock_guard<std::mutex> held(mutex_); failed_=true; } available_.notify_all();
    }
  }
public:
  static KernelQueries* get() {
    // Deliberately no static destructor racing detached blocked kernel reads.
    // This bounded process-local pool is not a custody holder or command port.
    static KernelQueries* pool=[] { try { return new KernelQueries; } catch(...) { return (KernelQueries*)nullptr; } }();
    return pool;
  }
  std::shared_ptr<KernelAnswer> submit(const Identity& original,bool exactGroup,bool priority=false) {
    if(original.pid<=1||!original.start||original.version<=0||original.uid!=geteuid()) return {};
    std::lock_guard<std::mutex> held(mutex_);
    if(!ready_||failed_||queue_.size()+running_>=4096) return {};
    try {
      auto answer=std::make_shared<KernelAnswer>(); Job job{original,exactGroup,answer};
      if(priority) queue_.push_front(std::move(job)); else queue_.push_back(std::move(job));
      available_.notify_one(); return answer;
    } catch(...) { return {}; }
  }
};
struct KernelAbsence {
  Identity original{},replacement{}; uint64_t observedUs=0; unsigned kind=0;
};
class OriginalExit {
  std::shared_ptr<KernelAnswer> answer_; KernelAbsence proof_{};
public:
  bool absent(const Identity& original) {
    if(original.pid<=1||!original.start||original.version<=0) return false;
    Identity now; int live=observe(original.pid,now);
    if(live==1) {
      if(now.start==original.start) return false;
      proof_={original,now,(uint64_t)(clockMs()*1000),2}; return true;
    }
    if(live<0) return false;
    if(answer_) {
      KernelState result=answer_->state.load(std::memory_order_acquire);
      if(result==KernelState::absent) {
        const auto& info=answer_->observed; Identity replacement{}; unsigned kind=1;
        if(answer_->returned==sizeof(Info)&&info.unique.start!=original.start) {
          replacement={original.pid,info.unique.start,info.unique.version,info.bsd.pbi_uid,info.bsd.pbi_pgid}; kind=2;
        }
        proof_={original,replacement,(uint64_t)(answer_->completed*1000),kind}; return true;
      }
      if((result==KernelState::live||result==KernelState::exiting||result==KernelState::transient)&&clockMs()>=answer_->completed+10) answer_.reset();
    }
    if(!answer_) { auto* pool=KernelQueries::get(); if(pool) answer_=pool->submit(original,false); }
    return false;
  }
  const KernelAbsence& proof() const { return proof_; }
};
inline bool canonical(const std::string& path) { char resolved[PATH_MAX]; return !path.empty() && path[0] == '/' && realpath(path.c_str(), resolved) && path == resolved; }
inline bool executable(const Identity& id, std::string& path) {
  audit_token_t token{}; token.val[5] = (uint32_t)id.pid; token.val[7] = (uint32_t)id.version; char bytes[PROC_PIDPATHINFO_MAXSIZE]{};
  if (proc_pidpath_audittoken(&token, bytes, sizeof(bytes)) <= 0 || bytes[0] != '/' || current(id) != 1) return false; path = bytes; return canonical(path);
}
inline CFStringRef appRequirement() {
  return CFSTR("anchor apple generic and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists and identifier \"com.sylvan-stack.arbol\"");
}
inline bool liveApplicationCode(NSDictionary* attributes) {
  SecCodeRef code=nullptr; SecRequirementRef requirement=nullptr;
  bool valid=SecRequirementCreateWithString(appRequirement(),kSecCSDefaultFlags,&requirement)==errSecSuccess&&
    SecCodeCopyGuestWithAttributes(nullptr,(__bridge CFDictionaryRef)attributes,kSecCSDefaultFlags,&code)==errSecSuccess&&
    SecCodeCheckValidity(code,kSecCSDefaultFlags,requirement)==errSecSuccess;
  if(code) CFRelease(code); if(requirement) CFRelease(requirement);
  return valid;
}
inline bool signature(const std::string& path, bool jit, bool application=false) {
  CFStringRef s = CFStringCreateWithCString(nullptr, path.c_str(), kCFStringEncodingUTF8);
  CFURLRef url = s ? CFURLCreateWithFileSystemPath(nullptr, s, kCFURLPOSIXPathStyle, false) : nullptr;
  SecStaticCodeRef code = nullptr; SecRequirementRef req = nullptr; CFDictionaryRef info = nullptr;
  bool valid = url && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
    SecRequirementCreateWithString(application ? appRequirement() :
      CFSTR("anchor apple generic and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"), kSecCSDefaultFlags, &req) == errSecSuccess &&
    SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures, req) == errSecSuccess && SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess;
  if (valid) {
    CFTypeRef f = CFDictionaryGetValue(info, kSecCodeInfoFlags), team = CFDictionaryGetValue(info, kSecCodeInfoTeamIdentifier), timestamp = CFDictionaryGetValue(info, kSecCodeInfoTimestamp); uint32_t flags = 0;
    valid = f && CFGetTypeID(f) == CFNumberGetTypeID() && CFNumberGetValue((CFNumberRef)f, kCFNumberSInt32Type, &flags) && (flags & kSecCodeSignatureRuntime) && team && CFEqual(team, CFSTR("7V372XL59S")) && timestamp && CFGetTypeID(timestamp) == CFDateGetTypeID();
    auto ent = (CFDictionaryRef)CFDictionaryGetValue(info, kSecCodeInfoEntitlementsDict);
    if (ent) {
      if (CFGetTypeID(ent) != CFDictionaryGetTypeID() || CFDictionaryGetCount(ent) > 1) valid = false;
      else if (CFDictionaryGetCount(ent)) valid = valid && jit && CFDictionaryContainsKey(ent, CFSTR("com.apple.security.cs.allow-jit")) && CFEqual(CFDictionaryGetValue(ent, CFSTR("com.apple.security.cs.allow-jit")), kCFBooleanTrue);
    }
  }
  if (info) CFRelease(info); if (req) CFRelease(req); if (code) CFRelease(code); if (url) CFRelease(url); if (s) CFRelease(s); return valid;
}
inline bool sameExecutableFile(const struct stat& original, const struct stat& value) {
  return S_ISREG(value.st_mode) && value.st_dev == original.st_dev && value.st_ino == original.st_ino &&
    value.st_gen == original.st_gen && value.st_mode == original.st_mode && value.st_flags == original.st_flags &&
    value.st_uid == original.st_uid && value.st_gid == original.st_gid && value.st_nlink == 1 && original.st_nlink == 1 &&
    value.st_size == original.st_size && value.st_mtimespec.tv_sec == original.st_mtimespec.tv_sec &&
    value.st_mtimespec.tv_nsec == original.st_mtimespec.tv_nsec && value.st_ctimespec.tv_sec == original.st_ctimespec.tv_sec &&
    value.st_ctimespec.tv_nsec == original.st_ctimespec.tv_nsec;
}
// Writable App storage requires a retained file and the live kernel signing
// status of the originally authenticated exec, independently for each monitor.
class AppSupervisorImage final {
  int fd_ = -1;
  struct stat file_{};
  std::string path_;

  bool fileCurrent() const {
    struct stat held{}, named{};
    return !fstat(fd_, &held) && !lstat(path_.c_str(), &named) &&
      sameExecutableFile(file_, held) && sameExecutableFile(file_, named);
  }
public:
  const Identity process;
  AppSupervisorImage(const Identity& identity, const std::string& path) : path_(path), process(identity) {}
  AppSupervisorImage(const AppSupervisorImage&) = delete;
  AppSupervisorImage& operator=(const AppSupervisorImage&) = delete;
  ~AppSupervisorImage() { if (fd_ >= 0) close(fd_); }

  bool currentImage(const std::string& path) const {
    if(path != path_ || current(process) != 1 || !fileCurrent()) return false;
    audit_token_t token{};
    token.val[5] = (uint32_t)process.pid;
    token.val[7] = (uint32_t)process.version;
    uint32_t status = 0;
    constexpr unsigned signingStatus = 0; // Darwin CS_OPS_STATUS
    return !csops_audittoken(process.pid, signingStatus, &status, sizeof(status), &token) &&
      (status & kSecCodeStatusValid) && (status & kSecCodeSignatureRuntime) &&
      current(process) == 1 && fileCurrent();
  }
  bool authenticate() {
    if(fd_ >= 0 || current(process) != 1) return false;
    fd_ = open(path_.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if(fd_ < 0 || fstat(fd_, &file_) || !fileCurrent()) return false;
    @autoreleasepool {
      auto* attributes=@{(__bridge NSString*)kSecGuestAttributePid:@(process.pid)};
      return liveApplicationCode(attributes) && signature(path_,false,true) && currentImage(path_);
    }
  }
};
// Constructed for the signed main's bound watchdogs only. Writable storage
// keeps live publisher verification. A lost retained proof cannot be renewed.
class ReadOnlyMonitorImage final {
  int fd_ = -1;
  bool accepted_ = false;
  std::string path_;
  struct stat file_{};
  struct statfs mount_{};

  bool sameFile(const struct stat& value) const {
    return sameExecutableFile(file_, value);
  }
  bool sameMount(const struct statfs& value) const {
    constexpr auto requiredFlags = MNT_RDONLY | MNT_LOCAL;
    return (value.f_flags & requiredFlags) == requiredFlags && (mount_.f_flags & requiredFlags) == requiredFlags &&
      !std::memcmp(&value.f_fsid, &mount_.f_fsid, sizeof(value.f_fsid)) &&
      !std::strcmp(value.f_fstypename, mount_.f_fstypename) &&
      !std::strcmp(value.f_mntonname, mount_.f_mntonname) && !std::strcmp(value.f_mntfromname, mount_.f_mntfromname);
  }
  bool current() const {
    struct stat held{}, named{};
    struct statfs heldMount{}, namedMount{};
    char openedPath[PATH_MAX]{};
    return !fstat(fd_, &held) && !lstat(path_.c_str(), &named) && sameFile(held) && sameFile(named) &&
      !fstatfs(fd_, &heldMount) && sameMount(heldMount) && !statfs(path_.c_str(), &namedMount) && sameMount(namedMount) &&
      !fcntl(fd_, F_GETPATH, openedPath) && path_ == openedPath;
  }
public:
  ReadOnlyMonitorImage() = default;
  ReadOnlyMonitorImage(const ReadOnlyMonitorImage&) = delete;
  ReadOnlyMonitorImage& operator=(const ReadOnlyMonitorImage&) = delete;
  ~ReadOnlyMonitorImage() { if (fd_ >= 0) close(fd_); }

  bool capture(const std::string& path) {
    if (fd_ >= 0 || !canonical(path) || statfs(path.c_str(), &mount_)) return false;
    if (!sameMount(mount_)) return true;
    path_ = path;
    fd_ = open(path_.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd_ < 0 || fstat(fd_, &file_) || !current() || !signature(path_, false) || !current()) return false;
    accepted_ = true;
    return true;
  }
  const ReadOnlyMonitorImage* retained() const { return accepted_ ? this : nullptr; }
  bool verifies(const std::string& path) const { return accepted_ && path == path_ && current(); }
};
inline bool signalExact(const Identity& id, int sig) {
  int n = current(id); if (!n) return true; if (n != 1 || id.uid != geteuid()) return false;
  audit_token_t token{}; token.val[5] = (uint32_t)id.pid; token.val[7] = (uint32_t)id.version;
  int result = proc_signal_with_audittoken(&token, sig); return !result || (result == ESRCH && current(id) == 0);
}
struct Lock { int fd = -1; std::string path; uint64_t device = 0, inode = 0; uint32_t uid = 0, mode = 0600; int heldMode = 0; };
inline bool privateAncestors(const std::string& path) {
  size_t at = path.rfind('/'); bool privateParent = false;
  while (at > 0 && at != std::string::npos) {
    std::string parent = path.substr(0, at); struct stat st{};
    if (lstat(parent.c_str(), &st) || !S_ISDIR(st.st_mode) || (st.st_mode & 0022)) return false;
    if (st.st_uid == geteuid() && (st.st_mode & 0777) == 0700) privateParent = true; at = parent.rfind('/');
  } return privateParent;
}
inline bool lockIdentity(const Lock& lock) {
  struct stat d{}, p{}; char path[PATH_MAX]{};
  return lock.fd >= 0 && (lock.heldMode == LOCK_EX || lock.heldMode == LOCK_SH) && canonical(lock.path) && privateAncestors(lock.path) &&
    !fstat(lock.fd, &d) && !lstat(lock.path.c_str(), &p) && !fcntl(lock.fd, F_GETPATH, path) && lock.path == path &&
    S_ISREG(d.st_mode) && S_ISREG(p.st_mode) && d.st_nlink == 1 && p.st_nlink == 1 && d.st_uid == lock.uid && lock.uid == geteuid() &&
    (d.st_mode & 07777) == lock.mode && lock.mode == 0600 && (uint64_t)d.st_dev == lock.device && d.st_ino == lock.inode && d.st_dev == p.st_dev && d.st_ino == p.st_ino;
}
inline std::string appHome() {
  passwd account{},*resolved=nullptr; char buffer[16384];
  if(getuid()!=geteuid()||getpwuid_r(geteuid(),&account,buffer,sizeof(buffer),&resolved)||resolved!=&account||
     account.pw_uid!=geteuid()||!account.pw_dir||!canonical(account.pw_dir)) return {};
  return account.pw_dir;
}
inline const std::string& supervisorExecutable() {
  static const std::string path=[] {
    auto home=appHome();
    return home.empty()?std::string{}:home+"/Applications/Seqoya Lab/Seqoya Lab.app/Contents/MacOS/Seqoya Lab";
  }();
  return path;
}
// The shared gate serializes startup with App departure. The kernel reports
// the live listener's identity. The socket carries no command or credentials.
inline Lock appAdmission(Identity& app) {
  const auto home=appHome(); if(home.empty()) return {};
  const auto directory=home+"/.arbol/app", endpoint=directory+"/browser-supervisor-v1.sock";
  std::string gate=directory+"/browser-start.lock"; struct stat held{}, node{};
  int fd=open(gate.c_str(),O_RDWR|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
  if(fd<0) return {};
  auto refuse=[&] { close(fd); return Lock{}; };
  if(fstat(fd,&held)||flock(fd,LOCK_SH|LOCK_NB)) return refuse();
  Lock lock{fd,gate,(uint64_t)held.st_dev,held.st_ino,held.st_uid,0600,LOCK_SH};
  sockaddr_un address{};
  if(!lockIdentity(lock)||endpoint.size()>=sizeof(address.sun_path)||!canonical(endpoint)||
     lstat(endpoint.c_str(),&node)||!S_ISSOCK(node.st_mode)||node.st_uid!=geteuid()||(node.st_mode&07777)!=0600) return refuse();
  address.sun_family=AF_UNIX; std::memcpy(address.sun_path,endpoint.c_str(),endpoint.size()+1);
  address.sun_len=SUN_LEN(&address);
  int socketFd=socket(AF_UNIX,SOCK_STREAM,0);
  if(socketFd<0) return refuse();
  audit_token_t token{}; socklen_t size=sizeof(token);
  bool valid=!fcntl(socketFd,F_SETFD,FD_CLOEXEC)&&!fcntl(socketFd,F_SETFL,O_NONBLOCK)&&
    !connect(socketFd,(sockaddr*)&address,address.sun_len)&&!
    getsockopt(socketFd,SOL_LOCAL,LOCAL_PEERTOKEN,&token,&size)&&size==sizeof(token);
  // A live acknowledgement also proves that the App recorded the Browser
  // admission before possibly taking the exclusive startup gate for quit.
  unsigned char acknowledgement=0; pollfd ready{socketFd,POLLIN,0};
  if(valid) valid=poll(&ready,1,250)==1&&(ready.revents&POLLIN)&&
    recv(socketFd,&acknowledgement,1,0)==1&&acknowledgement==1;
  close(socketFd);
  if(!valid||audit_token_to_euid(token)!=geteuid()||observe(audit_token_to_pid(token),app)!=1||
     app.version!=audit_token_to_pidversion(token)) return refuse();
  std::string executablePath;
  @autoreleasepool {
    auto* attributes=@{(__bridge NSString*)kSecGuestAttributeAudit:[NSData dataWithBytes:&token length:sizeof(token)]};
    if(!executable(app,executablePath)||executablePath!=supervisorExecutable()||!privateAncestors(executablePath)||
       !liveApplicationCode(attributes)||!signature(executablePath,false,true)||current(app)!=1||!lockIdentity(lock)) return refuse();
  }
  return lock;
}
// Every child mapping first duplicates its actual source ABOVE all reserved
// targets. Ordered dup2 actions must never overwrite a later source descriptor.
class SpawnCopies {
  std::vector<int> copies_;
public:
  SpawnCopies()=default; SpawnCopies(const SpawnCopies&)=delete;
  ~SpawnCopies() { (void)closeCopies(); }
  bool closeCopies() { bool ok=true; for(int fd:copies_) if(close(fd)) ok=false; copies_.clear(); return ok; }
  bool map(posix_spawn_file_actions_t& actions,int source,int target) {
    if(source<0||target<0||target>14) return false;
    int copy=fcntl(source,F_DUPFD_CLOEXEC,64); if(copy<0) return false;
    copies_.push_back(copy); return !posix_spawn_file_actions_adddup2(&actions,copy,target);
  }
};
struct FamilyObservation {
  Identity original{}; uint64_t parentStart=0,capturedUs=0;
  int32_t parentVersion=0; uint32_t session=0,image=0;
};
// Private diagnostic provenance only. Zero preserves the original caller-line
// convention; the two reporting headers have distinct closed tags.
enum class FatalSource : unsigned { existingCaller=0, boundaryHeader=1, exitHeader=2 };
class FamilyCapture {
public:
  virtual ~FamilyCapture()=default;
  virtual bool capture(const FamilyObservation& original)=0;
  virtual void refuse(unsigned callerLine=__builtin_LINE(), FatalSource source=FatalSource::boundaryHeader)=0;
  virtual bool snapshot(std::vector<FamilyObservation>& values)=0;
  virtual bool retire(const KernelAbsence& proof)=0;
  virtual bool complete()=0;
  virtual bool seal()=0;
};
struct ChildExecReadback {
  std::function<double()> liveCutoff;
  double expires=0;
  bool active() const { const double limit=liveCutoff(); return clockMs()<limit; }
};
struct Context {
  Identity main, primary, custody, app; bool authenticated=false, cleanupOnly=false, primaryOutside=false,familyUncertain=false; std::string bundle, digest; int session = 0; Lock owner, build;
  std::map<OriginalKey,Identity> seen;
  std::map<OriginalKey,OriginalExit> exits;
  double lastFullCensus=0; bool fullCensusValid=false,originalGroupRetired=false,groupPending=false;
  std::map<int,std::shared_ptr<KernelAnswer>> groupGaps;
  FamilyCapture* family=nullptr; // actual native capability owns its lifetime
  mutable std::shared_ptr<const AppSupervisorImage> appMonitorImages[2];
  void uncertainFamily(unsigned callerLine=__builtin_LINE()) {
    familyUncertain=true;
    if(family) family->refuse(callerLine,FatalSource::boundaryHeader);
  }
  bool originalGone(const Identity& id) {
    if(!id.pid) return true;
    if(exits.size()>=4096&&!exits.count(key(id))) { uncertainFamily(); return false; }
    auto& observation=exits[key(id)];
    if(!observation.absent(id)) return false;
    return !family||same(id,main)||same(id,primary)||same(id,custody)||family->retire(observation.proof());
  }
  bool monitorBirthsCurrent() {
    // Observe the actual originals independently of UID/group census filters.
    // An exec/version or UID change in the SAME birth is uncertainty, never
    // numeric-PID recycling or a newly eligible Chromium helper.
    for(const auto& original:{primary,custody}) {
      if(!original.pid) continue;
      Identity actual; int state=observe(original.pid,actual);
      if(state<0||(state==1&&actual.start==original.start&&!same(actual,original))) {
        uncertainFamily(); return false;
      }
    }
    return true;
  }
  bool engineMonitorNumberEligible(const Identity& id) {
    for(const auto& original:{primary,custody}) {
      if(!original.pid||id.pid!=original.pid) continue;
      if(id.start==original.start) {
        if(!same(id,original)) uncertainFamily();
        return false; // the exact original monitor is never an engine target
      }
      // Live-list replacement alone is insufficient. Only the independently
      // retained full-kernel original-exit observation authorizes this reuse.
      if(!originalGone(original)) return false;
    }
    return true;
  }
  std::string engine() const { return bundle + "/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron"; }
  bool ownerRunning() const {
    if(!app.pid) return true;
    Identity observed; Info details{};
    return observe(app.pid,observed,&details)==1&&same(app,observed)&&
      details.bsd.pbi_status!=SZOMB&&!(details.bsd.pbi_flags&PROC_FLAG_INEXIT);
  }
  std::string helper() const { return app.pid?supervisorExecutable():bundle + "/Contents/Resources/browser/native/watchdog"; }
  bool helperSignature(const Identity& process, const std::string& path) const {
    if(!app.pid) return signature(path,false);
    for(const auto& image:appMonitorImages) {
      if(image && image->process.pid == process.pid)
        return same(image->process,process) && image->currentImage(path);
    }
    for(auto& image:appMonitorImages) {
      if(image) continue;
      auto original=std::make_shared<AppSupervisorImage>(process,path);
      if(!original->authenticate()) return false;
      image=std::move(original);
      return true;
    }
    return false;
  }
  unsigned engineRole(const std::string& path) const {
    unsigned role=0;
    for(const char* suffix:{""," (Renderer)"," (GPU)"," (Plugin)"}) {
      ++role; std::string name=std::string("Electron Helper")+suffix;
      if(path==bundle+"/Contents/Resources/browser/runtime/Electron.app/Contents/Frameworks/"+name+".app/Contents/MacOS/"+name) return role;
    }
    return 0;
  }
  bool enginePath(const std::string& path) const { return engineRole(path)!=0; }
  bool foundation() const {
    return main.pid>1&&main.group==(uint32_t)main.pid&&main.uid==geteuid()&&canonical(bundle)&&bundle.size()>4&&bundle.substr(bundle.size()-4)==".app"&&
      owner.heldMode==LOCK_EX&&build.heldMode==LOCK_SH&&lockIdentity(owner)&&lockIdentity(build)&&(owner.device!=build.device||owner.inode!=build.inode);
  }
  bool initial() {
    Identity id; std::string path;
    if(getpid()==main.pid) {
      std::string expected="1:"+std::to_string(main.pid)+":"+std::to_string(main.start)+":"+std::to_string(main.group)+":"+std::to_string(session)+":"+std::to_string(main.uid);
      const char* record=getenv("ARBOL_BROWSER_BOOTSTRAP"); if(!record || expected!=record) return false;
    }
    bool valid=foundation()&&observe(main.pid,id)==1&&same(main,id)&&id.group==main.group&&getsid(main.pid)==session&&executable(id,path)&&path==engine()&&signature(path,true);
    if(valid) { authenticated=true; seen.emplace(key(main),main); } // later death never erases custody
    return valid&&!cleanupOnly;
  }
  // Captured before any setpgid: the still-inherited membership reserves the
  // original group even when its leader/producer has already died. This grants
  // cleanup only; readiness additionally requires the live original engine.
  bool authenticateBirth(const Identity& self,const Info& birth,int birthSession,const Identity& producer,bool primaryMode) {
    if(!foundation()||self.uid!=main.uid||self.group!=main.group||birthSession!=session||getsid(0)!=session||getpgrp()!=(int)main.group||
      birth.unique.originalParentVersion!=producer.version||producer.uid!=main.uid||producer.group!=main.group) return false;
    if(primaryMode) { if(!same(producer,main)) return false; primary=self; }
    else primary=producer,custody=self;
    std::string path; Identity actual;
    if(observe(self.pid,actual)!=1||!same(self,actual)||actual.group!=main.group||!executable(self,path)||path!=helper()||!helperSignature(self,path)) return false;
    Info producerInfo{}; Identity producerNow; int parentState=observe(producer.pid,producerNow,&producerInfo);
    if(parentState<0||(parentState==1&&producerNow.start==producer.start&&!same(producer,producerNow))) return false;
    // A kernel zombie may already have no task/image. Its exact identity plus
    // stable original-parent version grants cleanup, never live readiness.
    if(parentState==1&&same(producer,producerNow)&&producerInfo.bsd.pbi_status!=SZOMB) {
      if(birth.unique.parent!=producer.start||!executable(producer,path)||path!=(primaryMode?engine():helper())||
         !(primaryMode?signature(path,true):helperSignature(producer,path))) return false;
    }
    authenticated=true; cleanupOnly=true; seen.emplace(key(main),main); return true;
  }
  bool monitor(const Identity& id, bool anchor, const ReadOnlyMonitorImage* retained = nullptr) const {
    Identity now; std::string path;
    return id.pid > 1 && observe(id.pid, now) == 1 && same(id, now) && now.uid == main.uid && now.group == (anchor ? main.group : (uint32_t)id.pid) &&
      getsid(id.pid) == session && executable(now, path) && path == helper() &&
      (retained && !app.pid ? retained->verifies(path) && current(id) == 1 : helperSignature(id,path));
  }
  bool primaryMonitor(const ReadOnlyMonitorImage* retained = nullptr) {
    Identity now;
    if(observe(primary.pid,now)!=1||!same(primary,now)) return false;
    if(now.group==main.group) return !primaryOutside&&monitor(primary,true,retained);
    // The closed signed primary can leave only after C. Peer liveness is
    // checked separately; a dead anchor must not block post-quiescence retirement.
    if(now.group!=(uint32_t)primary.pid||!monitor(primary,false,retained)) return false;
    primaryOutside=true; return true;
  }
  bool discoverPrimary() {
    if(primary.pid) return current(primary)>=0;
    std::vector<pid_t> pids(16385); int bytes=proc_listpids(PROC_ALL_PIDS,0,pids.data(),(int)(pids.size()*sizeof(pid_t)));
    if(bytes<0||bytes%sizeof(pid_t)||(size_t)bytes>=pids.size()*sizeof(pid_t)) return false;
    Identity found; unsigned count=0;
    for(int i=0;i<bytes/(int)sizeof(pid_t);++i) {
      if(pids[i]<=0) continue; Identity id; Info info{}; std::string path;
      int state=observe(pids[i],id,&info); if(!state) continue; if(state<0) return false;
      if(id.uid!=main.uid||info.unique.parent!=main.start||info.unique.originalParentVersion!=main.version) continue;
      if(executable(id,path)&&path==helper()) {
        if(getsid(id.pid)!=session||(id.group!=main.group&&id.group!=(uint32_t)id.pid)||!helperSignature(id,path)) return false;
        found=id; ++count;
      }
    }
    if(count>1) return false; if(count==1) primary=found; return true;
  }
  bool discoverCustody() {
    if(!authenticated||!discoverPrimary()) return false;
    if(custody.pid) return current(custody)>=0;
    if(!primary.pid) return true;
    std::vector<pid_t> pids(4097); int bytes=proc_listpids(PROC_PGRP_ONLY,main.group,pids.data(),(int)(pids.size()*sizeof(pid_t)));
    if(bytes<0 || bytes%sizeof(pid_t) || (size_t)bytes>=pids.size()*sizeof(pid_t)) return false;
    Identity found; unsigned count=0;
    for(int i=0;i<bytes/(int)sizeof(pid_t);++i) {
      if(pids[i]<=0) continue; Identity id; Info info{}; std::string path;
      int state=observe(pids[i],id,&info); if(!state) continue; if(state<0) return false;
      if(same(id,primary)) { if(primaryOutside||!monitor(primary,true)) return false; continue; }
      if(executable(id,path) && path==helper()) {
        int producerState=current(primary);
        if(producerState<0||info.unique.originalParentVersion!=primary.version||(producerState==1&&info.unique.parent!=primary.start)||!monitor(id,true)) return false;
        found=id; ++count;
      }
    }
    if(count>1) return false; if(count==1) custody=found; return true;
  }
  bool liveDirectChild(const Identity& child,const Info& detail) const {
    Identity leader; Info leaderDetail{};
    return child.uid==main.uid&&child.group==main.group&&detail.bsd.pbi_ppid==(uint32_t)main.pid&&
      detail.unique.parent==main.start&&detail.unique.originalParentVersion==main.version&&
      !(detail.bsd.pbi_flags&PROC_FLAG_INEXIT)&&getsid(child.pid)==session&&
      observe(main.pid,leader,&leaderDetail)==1&&same(leader,main)&&leader.group==main.group&&
      !(leaderDetail.bsd.pbi_flags&PROC_FLAG_INEXIT)&&getsid(main.pid)==session;
  }
  double observeDirectChildExec(Identity& child,ChildExecReadback& readback,double sampledAt,
    std::string& completedImage,unsigned& failureLine) const {
    auto refuse=[&failureLine](unsigned callerLine=__builtin_LINE()) {
      failureLine=callerLine;
      return 0.0;
    };
    const Identity forked=child;
    if(!readback.expires) readback.expires=sampledAt+12;
    int32_t transitionVersion=0;
    bool sawExec=false;
    for(;;) {
      const double limit=std::min(readback.expires,readback.liveCutoff());
      if(clockMs()>=limit) {
        if(limit==readback.expires) return refuse(); // Original readback window.
        return refuse(); // Current live watchdog cutoff.
      }
      Identity observed; Info detail{};
      if(observe(forked.pid,observed,&detail)!=1) return refuse();
      if(observed.start!=forked.start) return refuse();
      if(!liveDirectChild(observed,detail)) return refuse();
      if(transitionVersion&&observed.version!=transitionVersion) return refuse();
      const bool executed=(detail.bsd.pbi_flags&PROC_FLAG_EXEC)!=0;
      const bool versionChanged=observed.version!=forked.version;
      if(sawExec&&!executed) return refuse();
      sawExec=executed;
      if(executed) {
        std::string image;
        if(!versionChanged) {
          // The initial combined kernel sample may already contain this
          // version. Require its actual executed helper, with the same path
          // verified again before and after the original publisher check.
          if(!executable(observed,image)&&!image.empty()) return refuse();
          if(image.empty()||image==engine()) {
            usleep(500);
            continue;
          }
          if(!enginePath(image)) return refuse();
        }
        const double confirmedLimit=std::min(limit,readback.liveCutoff());
        const double at=clockMs();
        if(at>=confirmedLimit) {
          if(confirmedLimit==readback.expires) return refuse();
          return refuse();
        }
        child=observed;
        completedImage=std::move(image);
        return at;
      }
      // Darwin can expose the new PID version before the EXEC flag. Retain
      // that one version for this birth inside the same readback window.
      if(versionChanged) transitionVersion=observed.version;
      usleep(500);
    }
  }
  bool census(std::vector<Identity>& targets,bool forceFull=false,ChildExecReadback* readback=nullptr,unsigned* failureLine=nullptr) {
    // The live caller can record this pass's first invalid observation. It
    // has no effect on family custody or the accepted census result.
    auto reject=[failureLine](unsigned callerLine=__builtin_LINE()) {
      if(failureLine&&!*failureLine) *failureLine=callerLine;
      return false;
    };
    targets.clear();
    if(!authenticated) return reject();
    if(!foundation()) return reject();
    if(!monitorBirthsCurrent()) return reject();
    bool valid=!familyUncertain;
    if(!valid) reject();
    if(family) {
      std::vector<FamilyObservation> shared;
      if(!family->snapshot(shared)) return reject();
      for(const auto& value:shared) {
        auto old=seen.find(key(value.original));
        if(old!=seen.end()&&!same(old->second,value.original)) { uncertainFamily(); return reject(); }
        seen.emplace(key(value.original),value.original);
      }
    }
    // Exact original-parent keys, never parent-version-only ancestry. This
    // active index is rebuilt once per pass, not searched per UID process.
    std::set<std::pair<uint64_t,int32_t>> parents;
    parents.emplace(main.start,main.version);
    for(const auto& entry:seen) parents.emplace(entry.second.start,entry.second.version);
    Identity leader; int leaderState=observe(main.pid,leader);
    if(leaderState<0) return reject();
    if(!originalGroupRetired&&leaderState==1&&leader.start!=main.start&&leader.group==main.group) {
      // Darwin cannot allocate the old leader PID while that original process
      // group exists. A new same-number group is not ours. First reconcile ALL
      // retained originals (including other holders and durable shared union).
      bool retainedSelf=getpid()==primary.pid&&primaryMonitor()&&primaryOutside;
      bool gone=originalGone(main)&&(retainedSelf||originalGone(primary))&&originalGone(custody);
      for(const auto& entry:seen) if(!originalGone(entry.second)) gone=false;
      if(!gone||(family&&!family->complete())) return reject();
      originalGroupRetired=true;
    }
    groupPending=false; std::set<int> currentGaps;
    std::vector<int> incompleteUIDReads;
    auto inspect=[&](int pid,bool groupMember,bool deferIncomplete=false) {
      if(pid<=0) return;
      const double sampledAt=readback?clockMs():0;
      Identity id; Info info{}; int state=observe(pid,id,&info);
      if(!state) {
        if(groupMember) {
          Identity known{};
          if(pid==main.pid) known=main;
          else if(pid==primary.pid) known=primary;
          else if(pid==custody.pid) known=custody;
          for(const auto& entry:seen) if(entry.second.pid==pid) known=entry.second;
          if(!known.pid) { uncertainFamily(); valid=reject(); }
          else {
            // Numeric equality does not prove this group-list occupant is the
            // old original. Keep it unresolved until the actual group no
            // longer lists it; inspect a full kernel identity in the meantime.
            groupPending=true; currentGaps.insert(pid);
            auto& answer=groupGaps[pid];
            if(!answer) { auto* pool=KernelQueries::get(); if(pool) answer=pool->submit(known,false); }
            if(answer) {
              KernelState result=answer->state.load(std::memory_order_acquire);
              if(result!=KernelState::pending) {
                const auto& full=answer->observed;
                if(answer->returned==sizeof(Info)&&full.bsd.pbi_pid==(uint32_t)pid&&full.unique.start&&full.unique.version>0) {
                  Identity actual{pid,full.unique.start,full.unique.version,full.bsd.pbi_uid,full.bsd.pbi_pgid};
                  if((actual.start!=known.start&&actual.group==main.group)||
                     (actual.start==known.start&&!same(actual,known))) { uncertainFamily(); valid=reject(); }
                } else if(result==KernelState::uncertain) { uncertainFamily(); valid=reject(); }
                if(clockMs()>=answer->completed+10) answer.reset();
              }
            }
          }
        }
        return; // known originals remain in the full kernel reconciliation
      }
      if(state<0) {
        // The system-wide list can race a process exiting. Keep the pass
        // incomplete until a fresh kernel read gives a real answer.
        if(deferIncomplete&&!groupMember) { incompleteUIDReads.push_back(pid); return; }
        if(groupMember) valid=reject(); // Original process-group scan.
        else valid=reject(); // Full scan of the owner's UID.
        return;
      }
      bool direct=info.unique.parent==main.start&&info.unique.originalParentVersion==main.version;
      bool descendant=parents.count({info.unique.parent,info.unique.originalParentVersion});
      auto old=seen.find(key(id)); bool captured=old!=seen.end();
      // Numeric equality with a former main/monitor is no identity evidence.
      // Unrelated reuse outside the original group never enrolls or poisons it.
      if((originalGroupRetired||id.group!=main.group)&&!descendant&&!captured&&
         !same(id,main)&&!same(id,primary)&&!same(id,custody)) return;
      if(same(id,primary)) { if(!primaryMonitor()) valid=reject(); return; }
      if(same(id,custody)) { if(!monitor(custody,true)) valid=reject(); return; }
      if(!engineMonitorNumberEligible(id)) { valid=reject(); return; }
      if(id.uid!=main.uid) { uncertainFamily(); valid=reject(); return; }
      bool original=captured&&same(old->second,id);
      std::string path; bool image=executable(id,path);
      double execObservedAt=0;
      // Darwin can briefly report the main's inherited image before the
      // original child executes. Capture only its verified post-exec identity.
      if(readback&&!forceFull&&valid&&!originalGroupRetired&&!captured&&id.pid!=main.pid&&direct&&
         !(info.bsd.pbi_flags&PROC_FLAG_EXEC)&&(path.empty()||path==engine())&&readback->active()&&liveDirectChild(id,info)) {
        unsigned execFailureLine=0;
        std::string completedImage;
        execObservedAt=observeDirectChildExec(id,*readback,sampledAt,completedImage,execFailureLine);
        if(!execObservedAt) { uncertainFamily(execFailureLine); valid=reject(); return; }
        if(!engineMonitorNumberEligible(id)) { uncertainFamily(); valid=reject(); return; }
        path.clear(); image=executable(id,path);
        if(!completedImage.empty()&&(!image||path!=completedImage)) { uncertainFamily(); valid=reject(); return; }
      }
      if(!image&&original) {
        Identity after; Info latest{}; int again=observe(pid,after,&latest);
        // Preserve the accepted ABR-46 race tree. Neither live-list ESRCH nor
        // unique-start reuse alone is complete original-kernel disappearance.
        if(!again||(again==1&&after.start!=id.start&&after.group!=main.group)) return;
        // A genuinely observed exiting original can lack a task/image; retain
        // its immutable capture until its separate full kernel query completes.
        if(again==1&&same(after,id)&&after.group==main.group&&(latest.bsd.pbi_flags&PROC_FLAG_INEXIT)) return;
        uncertainFamily(); valid=reject(); return;
      }
      bool eligible=same(id,main)?image&&path==engine():(direct||original)&&image&&enginePath(path);
      if(!eligible) { uncertainFamily(); valid=reject(); return; }
      if(id.group!=main.group||getsid(id.pid)!=session||(!same(id,main)&&!direct&&!original)) {
        // A helper may disappear after successful image lookup too. Keep only
        // the same narrow proven natural-disappearance/reuse explanation.
        Identity after; int again=observe(pid,after);
        if(original&&(!again||(again==1&&after.start!=id.start&&after.group!=main.group))) return;
        uncertainFamily(); valid=reject(); return;
      }
      if(!captured) {
        if(seen.size()>=4096||!signature(path,true)) { uncertainFamily(); valid=reject(); return; }
        if(execObservedAt) {
          Identity confirmed; Info detail{}; std::string currentPath;
          if(!executable(id,currentPath)||currentPath!=path||observe(id.pid,confirmed,&detail)!=1||
             !same(confirmed,id)||!(detail.bsd.pbi_flags&PROC_FLAG_EXEC)||!liveDirectChild(confirmed,detail)||
             execObservedAt>=readback->expires) {
            uncertainFamily(); valid=reject(); return;
          }
          if(!readback->active()) { uncertainFamily(); valid=reject(); return; }
        }
        if(family&&!same(id,main)) {
          FamilyObservation observation{id,info.unique.parent,(uint64_t)(clockMs()*1000),info.unique.originalParentVersion,(uint32_t)session,engineRole(path)};
          if(!family->capture(observation)) { uncertainFamily(); valid=reject(); return; }
        }
        seen.emplace(key(id),id);
        parents.emplace(id.start,id.version);
      } else if(!original) { uncertainFamily(); valid=reject(); }
    };
    constexpr size_t cap=16385; std::vector<pid_t> pids(cap);
    double began=clockMs();
    // Fixed <=50ms schedule while live; group checks below run every cycle.
    // This clock only controls read cadence and never renews a native deadline.
    if(forceFull||!lastFullCensus||began>=lastFullCensus+40) {
      lastFullCensus=began; fullCensusValid=false;
      int bytes=proc_listpids(PROC_UID_ONLY,main.uid,pids.data(),(int)(cap*sizeof(pid_t)));
      if(bytes<0||bytes%sizeof(pid_t)||(size_t)bytes>=cap*sizeof(pid_t)) return reject();
      for(int i=0;i<bytes/(int)sizeof(pid_t);++i) inspect(pids[i],false,true);
      for(int pid:incompleteUIDReads) inspect(pid,false);
      fullCensusValid=valid;
    }
    if(!originalGroupRetired) {
      int bytes=proc_listpids(PROC_PGRP_ONLY,main.group,pids.data(),(int)(cap*sizeof(pid_t)));
      if(bytes<0||bytes%sizeof(pid_t)||(size_t)bytes>=cap*sizeof(pid_t)) return reject();
      for(int i=0;i<bytes/(int)sizeof(pid_t);++i) inspect(pids[i],true);
    }
    for(auto it=groupGaps.begin();it!=groupGaps.end();) {
      if(!currentGaps.count(it->first)) it=groupGaps.erase(it); else ++it;
    }
    for(auto it=seen.begin();it!=seen.end();) {
      if(!originalGone(it->second)) { targets.push_back(it->second); ++it; }
      else if(!same(it->second,main)) { exits.erase(it->first); it=seen.erase(it); }
      else ++it;
    }
    if(!originalGone(main)&&std::none_of(targets.begin(),targets.end(),[&](const Identity& id){return same(id,main);})) targets.push_back(main);
    if(!valid||!fullCensusValid) return reject();
    return true;
  }
  bool engineGone(bool executingMain = false,ChildExecReadback* readback=nullptr) {
    std::vector<Identity> targets;
    auto empty=[&] { return std::none_of(targets.begin(),targets.end(),[&](const Identity& id){return !executingMain||!same(id,main);}); };
    if(!census(targets,false,readback)||groupPending||familyUncertain||!empty()) return false;
    // Final eligibility always performs a newly completed full UID pass after
    // the candidate quiescence, plus current actual group and durable union.
    if(!census(targets,true)||groupPending||familyUncertain||!empty()||(family&&!family->complete())) return false;
    return executingMain?(getpid()==main.pid&&current(main)==1):originalGone(main);
  }
  bool signalEngine(const Identity& original) {
    Identity actual; std::string path;
    // Observe/latch monitor uncertainty independently of the census filters.
    // Only a target which could alias that original monitor loses signaling
    // authority; unrelated family uncertainty cannot shield a positively
    // captured original engine/main from its existing exact fallback.
    (void)monitorBirthsCurrent();
    if(!engineMonitorNumberEligible(original)||
       observe(original.pid,actual)!=1||!same(original,actual)||actual.uid!=main.uid||
       actual.group!=main.group||getsid(actual.pid)!=session||!executable(actual,path)||
       (same(actual,main)?path!=engine():!enginePath(path))||!signature(path,true)) return false;
    (void)monitorBirthsCurrent();
    if(!engineMonitorNumberEligible(actual)) return false;
    return signalExact(original,SIGKILL);
  }
  void enforce(bool executingMain = false) {
    if(!authenticated) return;
    std::vector<Identity> targets;
    if (!census(targets)) { targets.clear(); for (const auto& entry : seen) targets.push_back(entry.second); }
    for (const auto& id : targets) if ((!executingMain || !same(id,main)) && !same(id,primary) && !same(id,custody)) (void)signalEngine(id);
    if (!executingMain) (void)signalEngine(main);
  }
  bool retireMonitorPeer(const Identity& peer, bool executingMain = false) {
    if (!engineGone(executingMain) || (!same(peer,primary) && !same(peer,custody))) return false;
    if(originalGone(peer)) return true;
    int n = current(peer); if (!n) return false; if (n < 0 || !(same(peer,custody)?monitor(peer,true):primaryMonitor())) return false;
    (void)signalExact(peer,SIGKILL); return originalGone(peer);
  }
};
inline NSDictionary* capsuleIdentity(const Identity& id,int session=0) {
  NSMutableDictionary* value=[@{@"pid":@(id.pid),@"startId":[NSString stringWithUTF8String:std::to_string(id.start).c_str()],@"pidVersion":@(id.version),@"uid":@(id.uid),@"group":@(id.group)} mutableCopy];
  if(session) value[@"session"]=@(session); return value;
}
inline NSDictionary* capsuleLock(const Lock& lock) {
  return @{@"path":[NSString stringWithUTF8String:lock.path.c_str()],@"device":[NSString stringWithUTF8String:std::to_string(lock.device).c_str()],@"inode":[NSString stringWithUTF8String:std::to_string(lock.inode).c_str()],@"uid":@(lock.uid),@"mode":@(lock.mode),@"heldMode":@(lock.heldMode)};
}
inline std::string capsuleBytes(const Context& c,bool primary) {
  @autoreleasepool { @try {
    NSMutableDictionary* value=[@{@"format":c.app.pid?@3:@2,@"mode":primary?@"primary":@"custody",@"producerRole":primary?@"main":@"primary",@"producer":capsuleIdentity(primary?c.main:c.primary),
      @"candidateSnapshotDigest":[NSString stringWithUTF8String:c.digest.c_str()],@"bundle":[NSString stringWithUTF8String:c.bundle.c_str()],@"main":capsuleIdentity(c.main,c.session),@"locks":@{@"owner":capsuleLock(c.owner),@"build":capsuleLock(c.build)}} mutableCopy];
    if(c.app.pid) value[@"app"]=capsuleIdentity(c.app);
    NSData* data=[NSJSONSerialization dataWithJSONObject:value options:0 error:nil];
    if(!data||!data.length||data.length>16384) return {}; return std::string((const char*)data.bytes,data.length);
  } @catch(NSException*) { return {}; } }
}
// Complete immutable read-only anonymous input before spawn. No writable alias
// or asynchronous producer message survives this transaction.
inline int capsuleDescriptor(const std::string& bytes) {
  if(bytes.empty()||bytes.size()>16384) return -1;
  char name[]="/private/tmp/arbol-watchdog-start-XXXXXX"; int writer=mkstemp(name),reader=-1,result=-1;
  if(writer<0) return -1;
  bool ok=!fcntl(writer,F_SETFD,FD_CLOEXEC)&&!fchmod(writer,0600); size_t at=0;
  while(ok&&at<bytes.size()) { ssize_t n=write(writer,bytes.data()+at,bytes.size()-at); if(n>0) at+=(size_t)n; else if(n<0&&errno==EINTR) continue; else ok=false; }
  struct stat a{},b{},path{};
  if(ok) reader=open(name,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
  ok=ok&&reader>=0&&!fstat(writer,&a)&&!fstat(reader,&b)&&!lstat(name,&path)&&S_ISREG(a.st_mode)&&S_ISREG(b.st_mode)&&
    a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&path.st_dev==a.st_dev&&path.st_ino==a.st_ino&&a.st_uid==geteuid()&&(a.st_mode&07777)==0600&&a.st_nlink==1&&b.st_size==(off_t)bytes.size();
  if(ok) ok=!unlink(name)&&!fstat(reader,&b)&&b.st_nlink==0;
  else (void)unlink(name);
  if(close(writer)) ok=false; // every writable description is closed before export
  if(ok) result=fcntl(reader,F_DUPFD_CLOEXEC,10);
  if(reader>=0) close(reader); return result;
}
inline void reap(const Identity& id) { if (id.pid > 1) (void)waitpid(id.pid,nullptr,WNOHANG); }
}

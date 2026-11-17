#pragma once
// Pinned private Darwin identity/termination support. Signals are not exit proof.
#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <libproc.h>
#include <bsm/libbsm.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <spawn.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach_time.h>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
#include <atomic>
#include <memory>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <deque>
#include <dlfcn.h>
#include <mach-o/loader.h>
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
inline bool signature(const std::string& path, bool jit) {
  CFStringRef s = CFStringCreateWithCString(nullptr, path.c_str(), kCFStringEncodingUTF8);
  CFURLRef url = s ? CFURLCreateWithFileSystemPath(nullptr, s, kCFURLPOSIXPathStyle, false) : nullptr;
  SecStaticCodeRef code = nullptr; SecRequirementRef req = nullptr; CFDictionaryRef info = nullptr;
  bool valid = url && SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code) == errSecSuccess &&
    SecRequirementCreateWithString(CFSTR("anchor apple generic and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"), kSecCSDefaultFlags, &req) == errSecSuccess &&
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
class FamilyCapture {
public:
  virtual ~FamilyCapture()=default;
  virtual bool capture(const FamilyObservation& original)=0;
  virtual void refuse()=0;
  virtual bool snapshot(std::vector<FamilyObservation>& values)=0;
  virtual bool retire(const KernelAbsence& proof)=0;
  virtual bool complete()=0;
  virtual bool seal()=0;
};
struct Context {
  Identity main, primary, custody; bool authenticated=false, cleanupOnly=false, primaryOutside=false,familyUncertain=false; std::string bundle, digest; int session = 0; Lock owner, build;
  std::map<OriginalKey,Identity> seen;
  std::map<OriginalKey,OriginalExit> exits;
  FamilyCapture* family=nullptr; // actual native capability owns its lifetime
  void uncertainFamily() { familyUncertain=true; if(family) family->refuse(); }
  bool originalGone(const Identity& id) {
    if(!id.pid) return true;
    if(exits.size()>=4096&&!exits.count(key(id))) { uncertainFamily(); return false; }
    auto& observation=exits[key(id)];
    if(!observation.absent(id)) return false;
    return !family||same(id,main)||same(id,primary)||same(id,custody)||family->retire(observation.proof());
  }
  std::string engine() const { return bundle + "/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron"; }
  std::string helper() const { return bundle + "/Contents/Resources/browser/native/watchdog"; }
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
    if(observe(self.pid,actual)!=1||!same(self,actual)||actual.group!=main.group||!executable(self,path)||path!=helper()||!signature(path,false)) return false;
    Info producerInfo{}; Identity producerNow; int parentState=observe(producer.pid,producerNow,&producerInfo);
    if(parentState<0||(parentState==1&&producerNow.start==producer.start&&!same(producer,producerNow))) return false;
    // A kernel zombie may already have no task/image. Its exact identity plus
    // stable original-parent version grants cleanup, never live readiness.
    if(parentState==1&&same(producer,producerNow)&&producerInfo.bsd.pbi_status!=SZOMB) {
      if(birth.unique.parent!=producer.start||!executable(producer,path)||path!=(primaryMode?engine():helper())||!signature(path,primaryMode)) return false;
    }
    authenticated=true; cleanupOnly=true; seen.emplace(key(main),main); return true;
  }
  bool monitor(const Identity& id, bool anchor) const {
    Identity now; std::string path;
    return id.pid > 1 && observe(id.pid, now) == 1 && same(id, now) && now.uid == main.uid && now.group == (anchor ? main.group : (uint32_t)id.pid) &&
      getsid(id.pid) == session && executable(now, path) && path == helper() && signature(path, false);
  }
  bool primaryMonitor() {
    Identity now;
    if(observe(primary.pid,now)!=1||!same(primary,now)) return false;
    if(now.group==main.group) return !primaryOutside&&monitor(primary,true);
    // The closed signed primary can leave only after C. Peer liveness is
    // checked separately; a dead anchor must not block post-quiescence retirement.
    if(now.group!=(uint32_t)primary.pid||!monitor(primary,false)) return false;
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
        if(getsid(id.pid)!=session||(id.group!=main.group&&id.group!=(uint32_t)id.pid)||!signature(path,false)) return false;
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
  bool census(std::vector<Identity>& targets) {
    targets.clear();
    if(!authenticated||!foundation()) return false;
    // Chromium 156.0.8078.100 ChildProcessLauncherHelper constructs default
    // LaunchOptions; the macOS launcher does not request a new group/session.
    // Eligible children are direct original-browser children, including GPU,
    // renderer and utility images. No Node utility/crash reporter/third-party
    // executable is authorized. Unknown images/descendants never widen this set.
    constexpr size_t cap=16385; std::vector<pid_t> pids(cap);
    int bytes=proc_listpids(PROC_UID_ONLY,main.uid,pids.data(),(int)(cap*sizeof(pid_t)));
    if(bytes<0||bytes%sizeof(pid_t)||(size_t)bytes>=cap*sizeof(pid_t)) return false;
    bool valid=!familyUncertain;
    if(family) {
      std::vector<FamilyObservation> shared;
      if(!family->snapshot(shared)) return false;
      for(const auto& value:shared) {
        auto old=seen.find(key(value.original));
        if(old!=seen.end()&&!same(old->second,value.original)) { uncertainFamily(); return false; }
        seen.emplace(key(value.original),value.original);
      }
    }
    for(int i=0;i<bytes/(int)sizeof(pid_t);++i) {
      int pid=pids[i]; if(pid<=0) continue;
      Identity id; Info info{}; int state=observe(pid,id,&info);
      // Reconcile every known original separately, including a live-list gap.
      if(!state) continue;
      if(state<0) { valid=false; continue; }
      bool direct=info.unique.parent==main.start&&info.unique.originalParentVersion==main.version;
      bool descendant=direct;
      for(const auto& entry:seen)
        if(info.unique.parent==entry.second.start&&info.unique.originalParentVersion==entry.second.version) descendant=true;
      bool captured=seen.count(key(id));
      if(id.group!=main.group&&!descendant&&!captured&&pid!=main.pid&&pid!=primary.pid&&pid!=custody.pid) continue;
      if(same(id,primary)) { if(!primaryMonitor()) valid=false; continue; }
      if(same(id,custody)) { if(!monitor(custody,true)) valid=false; continue; }
      if(id.uid!=main.uid) { valid=false; continue; }
      std::string path; bool image=executable(id,path);
      bool original=captured&&same(seen.at(key(id)),id);
      bool eligible=same(id,main)?image&&path==engine():(direct||original)&&image&&enginePath(path);
      if(!eligible) {
        // A known original may be in irreversible exit without an image. Keep
        // its original provenance and require complete kernel absence below.
        if(!captured||!(info.bsd.pbi_flags&PROC_FLAG_INEXIT)||!same(seen.at(key(id)),id)) { uncertainFamily(); valid=false; }
      } else {
        if(!captured) {
          if(seen.size()>=4096||!signature(path,true)) { valid=false; continue; }
          if(family&&!same(id,main)) {
            FamilyObservation observation{id,info.unique.parent,(uint64_t)(clockMs()*1000),info.unique.originalParentVersion,(uint32_t)getsid(id.pid),engineRole(path)};
            if(!family->capture(observation)) { uncertainFamily(); valid=false; continue; }
          }
          seen.emplace(key(id),id); // first authoritative capture is retained before local use
        } else if(!same(seen.at(key(id)),id)) { uncertainFamily(); valid=false; }
      }
      if(id.group!=main.group||(!(info.bsd.pbi_flags&PROC_FLAG_INEXIT)&&getsid(id.pid)!=session)||
         (!same(id,main)&&!direct&&!original)) {
        // Retain authenticated originals for exact cleanup, but escape/drift
        // permanently refuses readiness/ordinary finalization.
        uncertainFamily(); valid=false;
      }
    }
    // A second kernel group list includes allproc AND zombproc on the pinned
    // kernel path. A listed live-view ESRCH is not silently skipped; wait until
    // it is gone from the actual group list, or retain/refuse at the old cutoff.
    bytes=proc_listpids(PROC_PGRP_ONLY,main.group,pids.data(),(int)(cap*sizeof(pid_t)));
    if(bytes<0||bytes%sizeof(pid_t)||(size_t)bytes>=cap*sizeof(pid_t)) return false;
    for(int i=0;i<bytes/(int)sizeof(pid_t);++i) {
      if(pids[i]<=0) continue;
      Identity id; int state=observe(pids[i],id);
      if(!state) {
        // A captured original in the kernel exit gap remains pending, not a
        // fabricated identity failure. The immutable history below includes
        // it until the separate exiting/zombie-aware query proves absence.
        bool known=pids[i]==main.pid||pids[i]==primary.pid||pids[i]==custody.pid;
        for(const auto& entry:seen) if(entry.second.pid==pids[i]) known=true;
        if(!known) { uncertainFamily(); valid=false; }
        continue;
      }
      if(state<0) { valid=false; continue; }
      if(same(id,primary)||same(id,custody)) continue;
      if(!seen.count(key(id))||!same(seen.at(key(id)),id)) valid=false;
    }
    // Every captured original survives orphaning, group escape and PID reuse.
    // A pending/uncertain zombie-aware query keeps it in the target set.
    for(auto it=seen.begin();it!=seen.end();) {
      if(!originalGone(it->second)) { targets.push_back(it->second); ++it; }
      else if(!same(it->second,main)) { exits.erase(it->first); it=seen.erase(it); }
      else ++it;
    }
    if(!originalGone(main)&&std::none_of(targets.begin(),targets.end(),[&](const Identity& id){return same(id,main);}))
      targets.push_back(main);
    return valid;
  }
  bool engineGone(bool executingMain = false) {
    std::vector<Identity> targets; if(!census(targets)||familyUncertain||(family&&!family->complete())) return false;
    return std::none_of(targets.begin(),targets.end(),[&](const Identity& id){return !executingMain||!same(id,main);})&&
      (executingMain?(getpid()==main.pid&&current(main)==1):originalGone(main));
  }
  bool signalEngine(const Identity& original) {
    Identity actual; std::string path;
    if(observe(original.pid,actual)!=1||!same(original,actual)||actual.uid!=main.uid||
       actual.group!=main.group||getsid(actual.pid)!=session||!executable(actual,path)||
       (same(actual,main)?path!=engine():!enginePath(path))||!signature(path,true)) return false;
    return signalExact(original,SIGKILL);
  }
  void enforce(bool executingMain = false) {
    if(!authenticated) return;
    std::vector<Identity> targets;
    if (!census(targets)) { targets.clear(); for (const auto& entry : seen) targets.push_back(entry.second); }
    for (const auto& id : targets) if ((!executingMain || !same(id,main)) && id.pid != primary.pid && id.pid != custody.pid) (void)signalEngine(id);
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
    NSDictionary* value=@{@"format":@2,@"mode":primary?@"primary":@"custody",@"producerRole":primary?@"main":@"primary",@"producer":capsuleIdentity(primary?c.main:c.primary),
      @"candidateSnapshotDigest":[NSString stringWithUTF8String:c.digest.c_str()],@"bundle":[NSString stringWithUTF8String:c.bundle.c_str()],@"main":capsuleIdentity(c.main,c.session),@"locks":@{@"owner":capsuleLock(c.owner),@"build":capsuleLock(c.build)}};
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

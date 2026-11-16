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
namespace arbol_boundary {
struct Unique { uint8_t uuid[16]; uint64_t start, parent; int32_t version, originalParentVersion; uint64_t reserve[2]; };
static_assert(sizeof(Unique) == 56);
struct Info { proc_bsdinfo bsd; Unique unique; };
struct Identity { int pid = 0; uint64_t start = 0; int32_t version = 0; uint32_t uid = 0, group = 0; };
inline double clockMs() { mach_timebase_info_data_t s{}; if (mach_timebase_info(&s) != KERN_SUCCESS || !s.denom) _exit(4); return (double)mach_continuous_time() * s.numer / s.denom / 1000000.0; }
inline bool same(const Identity& a, const Identity& b) { return a.pid == b.pid && a.start == b.start && a.version == b.version && a.uid == b.uid; }
// ESRCH alone proves absence. A changed exec version is uncertainty, not death.
inline int observe(int pid, Identity& id, Info* detail = nullptr) {
  Info info{}; errno = 0; int n = proc_pidinfo(pid, 18, 0, &info, sizeof(info));
  if (!n && errno == ESRCH) return 0;
  if (n != sizeof(info) || pid < 1 || info.bsd.pbi_pid != (uint32_t)pid || !info.unique.start || info.unique.version <= 0) return -1;
  id = {pid, info.unique.start, info.unique.version, info.bsd.pbi_uid, info.bsd.pbi_pgid}; if (detail) *detail = info; return 1;
}
inline int current(const Identity& original) { if (!original.pid) return 0; Identity now; int n = observe(original.pid, now); return n <= 0 ? n : same(original, now) ? 1 : now.start != original.start ? 0 : -1; }
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
struct Context {
  Identity main, primary, custody; bool authenticated=false, cleanupOnly=false, primaryOutside=false; std::string bundle, digest; int session = 0; Lock owner, build; std::map<int, Identity> seen;
  std::string engine() const { return bundle + "/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron"; }
  std::string helper() const { return bundle + "/Contents/Resources/browser/native/watchdog"; }
  bool enginePath(const std::string& path) const {
    for (const char* suffix : {"", " (Renderer)", " (GPU)", " (Plugin)"}) { std::string name = std::string("Electron Helper") + suffix;
      if (path == bundle + "/Contents/Resources/browser/runtime/Electron.app/Contents/Frameworks/" + name + ".app/Contents/MacOS/" + name) return true; } return false;
  }
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
    if(valid) authenticated=true; // later death never erases previously proven custody
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
    authenticated=true; cleanupOnly=true; return true;
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
    if(!authenticated) return false;
    targets.clear(); Identity actual; int alive = observe(main.pid, actual); if (alive < 0) return false;
    if (alive == 1 && actual.start != main.start && actual.group == main.group) {
      // A reused leader PID cannot have been allocated while the old group existed.
      for (const auto& entry : seen) if (current(entry.second) != 0) return false; return true;
    }
    constexpr size_t cap = 4097; std::vector<pid_t> pids(cap);
    int bytes = proc_listpids(PROC_PGRP_ONLY, main.group, pids.data(), (int)(cap * sizeof(pid_t)));
    if (bytes < 0 || bytes % sizeof(pid_t) || (size_t)bytes >= cap*sizeof(pid_t)) return false;
    for (int i = 0; i < bytes/(int)sizeof(pid_t); ++i) {
      int pid = pids[i]; if (pid <= 0) continue; Identity id; Info info{}; int state = observe(pid, id, &info); if (!state) continue;
      if (state < 0 || id.uid != main.uid || id.group != main.group) return false;
      if (pid==primary.pid&&same(id,primary)) { if(!primaryMonitor()) return false; continue; }
      if (pid==custody.pid&&same(id,custody)) { if(!monitor(custody,true)) return false; continue; }
      std::string path;
      if (pid == main.pid) { if (!same(id, main) || !executable(id,path) || path != engine()) return false; }
      else {
        if (!executable(id,path)) {
          auto known=seen.find(pid); Identity now;
          if (known==seen.end() || !same(known->second,id)) return false;
          int state=observe(pid,now);
          // Keep the verified original for final reconciliation. Only proven
          // absence or unique-start reuse outside our group explains this race.
          if (!state || (state==1 && now.start!=id.start && now.group!=main.group)) continue;
          return false;
        }
        if (!enginePath(path) || (info.unique.parent != main.start && info.unique.originalParentVersion != main.version)) return false;
      }
      auto known=seen.find(pid);
      if ((known==seen.end() || !same(known->second,id)) && !signature(path,true)) return false; seen[pid] = id; targets.push_back(id);
    }
    int mainState = current(main); if (mainState < 0) return false;
    if (mainState == 1 && std::none_of(targets.begin(),targets.end(),[&](const Identity& id){return same(id,main);})) return false;
    for (const auto& entry : seen) { int state = current(entry.second); if (state < 0 || (state == 1 && std::none_of(targets.begin(),targets.end(),[&](const Identity& id){return same(id,entry.second);}))) return false; }
    return true;
  }
  bool engineGone(bool executingMain = false) {
    std::vector<Identity> targets; if (!census(targets)) return false;
    return std::none_of(targets.begin(),targets.end(),[&](const Identity& id){return !executingMain || !same(id,main);}) &&
      (executingMain ? (getpid() == main.pid && current(main) == 1) : current(main) == 0);
  }
  void enforce(bool executingMain = false) {
    if(!authenticated) return;
    std::vector<Identity> targets;
    if (!census(targets)) { targets.clear(); for (const auto& entry : seen) targets.push_back(entry.second); }
    for (const auto& id : targets) if ((!executingMain || !same(id,main)) && id.pid != primary.pid && id.pid != custody.pid) (void)signalExact(id,SIGKILL);
    if (!executingMain) (void)signalExact(main,SIGKILL);
  }
  bool retireMonitorPeer(const Identity& peer, bool executingMain = false) {
    if (!engineGone(executingMain) || (!same(peer,primary) && !same(peer,custody))) return false;
    int n = current(peer); if (!n) return true; if (n < 0 || !(same(peer,custody)?monitor(peer,true):primaryMonitor())) return false;
    (void)signalExact(peer,SIGKILL); return current(peer) == 0;
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

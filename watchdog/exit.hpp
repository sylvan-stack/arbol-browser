#pragma once
// Retained native post-exit proof. Enrollment/status never asserts storage flush.
#include "boundary.hpp"
#include <sys/event.h>
#include "../src/runtime/attempt.hpp"
#include <sys/mman.h>
#include <sys/sysctl.h>
#include <atomic>
#include <new>
#include <thread>
#include <memory>
namespace arbol_exit {
using arbol_boundary::Identity;
class ExitWatch {
  int queue_=-1; Identity original_{}; bool attempted_=false, enrolled_=false, uncertain_=false, seen_=false;
  int status_=-1; double observed_=0;
public:
  ExitWatch()=default;
  ExitWatch(const ExitWatch&)=delete; ExitWatch& operator=(const ExitWatch&)=delete;
  ~ExitWatch() { if(queue_>=0) close(queue_); }
  bool enroll(const Identity& original) {
    if(attempted_) return false; attempted_=true;
    // SDK macosx27.0 sys/event.h: NOTE_EXITSTATUS is available to a
    // child watcher OR a process allowed to signal the exact target. Enrollment
    // is made by each genuine signed monitor while the original is still live.
    if(original.pid<=1 || original.uid!=geteuid() || arbol_boundary::current(original)!=1) return false;
    queue_=kqueue(); if(queue_<0 || fcntl(queue_,F_SETFD,FD_CLOEXEC)) { uncertain_=true; return false; }
    struct kevent change{},receipt{}; timespec zero{};
    EV_SET(&change,(uintptr_t)original.pid,EVFILT_PROC,EV_ADD|EV_ENABLE|EV_CLEAR|EV_RECEIPT,
      NOTE_EXIT|NOTE_EXITSTATUS|NOTE_EXEC,0,this);
    int count=kevent(queue_,&change,1,&receipt,1,&zero);
    constexpr uint16_t receiptFlags=EV_ADD|EV_ENABLE|EV_CLEAR|EV_RECEIPT|EV_ERROR;
    if(count!=1 || receipt.ident!=(uintptr_t)original.pid || receipt.filter!=EVFILT_PROC ||
       !(receipt.flags&EV_ERROR) || (receipt.flags&~receiptFlags) || receipt.fflags!=(NOTE_EXIT|NOTE_EXITSTATUS|NOTE_EXEC) ||
       receipt.data!=0 || receipt.udata!=this ||
       arbol_boundary::current(original)!=1) { uncertain_=true; return false; }
    original_=original; enrolled_=true; return true;
  }
  bool enrolledAlive(const Identity& main) const {
    return enrolled_ && !uncertain_ && !seen_ && arbol_boundary::same(main,original_) && arbol_boundary::current(original_)==1;
  }
  bool poll() {
    if(!enrolled_ || uncertain_) return false;
    struct kevent events[2]{}; timespec zero{};
    int count=kevent(queue_,nullptr,0,events,2,&zero);
    if(count<0 || count>1 || (seen_ && count)) { uncertain_=true; return false; }
    if(!count) return true;
    const auto& event=events[0];
    constexpr uint16_t permitted=EV_ADD|EV_ENABLE|EV_CLEAR|EV_ONESHOT|EV_EOF;
    if(event.ident!=(uintptr_t)original_.pid || event.filter!=EVFILT_PROC || event.udata!=this ||
       (event.flags&~permitted) || !(event.flags&EV_EOF) || !(event.flags&EV_ONESHOT) ||
       // A separate or coalesced NOTE_EXEC is irreversible identity drift,
       // including exec+exit between polls. Never adopt its later zero status.
       event.fflags!=(NOTE_EXIT|NOTE_EXITSTATUS) || event.data<0 || event.data>INT_MAX) {
      uncertain_=true; return false;
    }
    seen_=true; status_=(int)event.data; observed_=arbol_boundary::clockMs(); return true;
  }
  // Only a timely actually observed ordinary zero wait status is eligible for
  // the later independent family/flush/peer/final-holder proof. Nothing here
  // resets a deadline, liveness loss, force latch or native admission authority.
  bool ordinaryBefore(double deadline) const {
    return enrolled_ && !uncertain_ && seen_ && observed_<deadline && WIFEXITED(status_) && WEXITSTATUS(status_)==0;
  }
  bool observed() const { return enrolled_ && !uncertain_ && seen_; }
  double observedAt() const { return observed_; }
  int status() const { return status_; }
  const Identity& original() const { return original_; }
};

/** An exiting-list query can wait on another zombie/reap controller. It never
 * runs on a monitor's protocol thread and supplies no completion/flush proof.
 * The exact enrolled NOTE_EXIT and original fixed deadline remain mandatory. */
class KernelExitProbe {
public:
  enum Result { pending=-1,uncertain=-2,live=0,exiting=1,absent=2 };
private:
  struct Answer { std::atomic<int> result{pending}; };
  std::shared_ptr<Answer> answer_;
public:
  bool start(const Identity& original) {
    if(answer_) return false;
    answer_=std::make_shared<Answer>(); auto answer=answer_;
    try { std::thread([answer,original] {
      arbol_boundary::Info info{}; errno=0;
      // The pinned private combined identity layout is already used by the
      // Native boundary. Nonzero arg additionally includes exiting/zombie
      // lookup; SDK PROC_FLAG_INEXIT is exit-in-progress, never a flush receipt.
      int n=proc_pidinfo(original.pid,18,1,&info,sizeof(info)); int result=uncertain;
      if(!n&&errno==ESRCH) result=absent;
      else if(n==sizeof(info)&&info.bsd.pbi_pid==(uint32_t)original.pid&&info.unique.start) {
        Identity actual{original.pid,info.unique.start,info.unique.version,info.bsd.pbi_uid,info.bsd.pbi_pgid};
        if(actual.start!=original.start) result=absent;
        else if(arbol_boundary::same(actual,original)&&actual.group==original.group)
          result=(info.bsd.pbi_flags&PROC_FLAG_INEXIT)?exiting:live;
      }
      answer->result.store(result,std::memory_order_release);
    }).detach(); } catch(...) { answer_->result.store(uncertain,std::memory_order_release); return false; }
    return true;
  }
  Result result() const { return answer_?(Result)answer_->result.load(std::memory_order_acquire):pending; }
  bool started() const { return (bool)answer_; }
};

enum FatalReason : uint64_t { protocolLoss=1,forced=2,identityLoss=4,watchLoss=8,storageLoss=16,admissionLoss=32,peerLoss=64 };
struct IdentitySlot {
  std::atomic<uint32_t> state{0}; Identity value{};
  bool bind(const Identity& id,double deadline) {
    uint32_t empty=0;
    if(state.compare_exchange_strong(empty,1,std::memory_order_acq_rel)) { value=id; state.store(2,std::memory_order_release); return true; }
    while(state.load(std::memory_order_acquire)==1 && arbol_boundary::clockMs()<deadline) usleep(100);
    return state.load(std::memory_order_acquire)==2 && arbol_boundary::same(value,id);
  }
  // Immutable role identity excludes group: primary legitimately leaves the
  // original group only after C. Context independently validates group/session
  // and physical signed executable at each birth/C/G/J/retirement boundary.
  bool is(const Identity& id) const { return state.load(std::memory_order_acquire)==2 && arbol_boundary::same(value,id); }
};
struct MarkerBinding {
  uint64_t device=0,inode=0,size=0,dataEpoch=0; uint32_t uid=0;
  char digest[65]{},reader[257]{};
};
// This mapping's writable descriptions never cross a JS API. Only the native
// fixed spawn actions and authenticated enrolled native roles receive them.
// All status publications are one-way. No setter can clear a fatal history.
struct SharedState {
  char magic[8]={'A','B','R','2','9','S','1','\0'},capabilityDigest[65]{};
  uint64_t bytes=sizeof(SharedState); std::atomic<uint64_t> fatal{0};
  std::atomic<uint64_t> fatalCutoffUs{0};
  IdentitySlot main,primary,custody;
  std::atomic<uint32_t> enrolled{0},transfer{0},mutation{0},markerBound{0},admitted{0};
  std::atomic<uint32_t> cookieAcknowledged{0},domRequested{0},quitRequested{0},retiredPages{0};
  std::atomic<uint32_t> primaryConsent{0},custodyConsent{0};
  std::atomic<uint32_t> ordinaryPostExitEligible{0};
  // Verified native mutation preparation publishes this before permission to
  // write. A later independent holder can authenticate an uncertain resulting
  // dirty marker; it never predicts or grants its replacement inode.
  char expectedMarkerDigest[65]{};
  MarkerBinding marker{};
  void poison(uint64_t reason) { fatal.fetch_or(reason,std::memory_order_acq_rel); }
  void declareFatal() {
    uint64_t cutoff=(uint64_t)((arbol_boundary::clockMs()+1000)*1000),old=fatalCutoffUs.load(std::memory_order_acquire);
    while((!old||cutoff<old)&&!fatalCutoffUs.compare_exchange_weak(old,cutoff,std::memory_order_acq_rel)) {}
    // Publish the bound before the admission loss. This preserves F's existing
    // one-second forwarding/receipt window; a genuine hard loss remains sooner.
    poison(admissionLoss);
  }
};
static_assert(std::atomic<uint64_t>::is_always_lock_free && std::atomic<uint32_t>::is_always_lock_free);
inline bool anonymousFile(int fd,bool writable,size_t size) {
  struct stat st{}; int flags=fcntl(fd,F_GETFL);
  return fd>=3 && flags>=0 && (flags&O_ACCMODE)==(writable?O_RDWR:O_RDONLY) && !fstat(fd,&st) && S_ISREG(st.st_mode) &&
    st.st_uid==geteuid() && (st.st_mode&07777)==0600 && st.st_nlink==0 && st.st_size==(off_t)size;
}
inline bool anonymousBytes(int fd,std::string& raw,double deadline) {
  struct stat st{}; if(fstat(fd,&st) || st.st_size<1 || st.st_size>(off_t)arbol_attempt::limit || !anonymousFile(fd,false,(size_t)st.st_size)) return false;
  raw.resize((size_t)st.st_size+1); size_t offset=0;
  while(offset<raw.size()) {
    if(arbol_boundary::clockMs()>=deadline) return false;
    ssize_t n=pread(fd,raw.data()+offset,raw.size()-offset,offset);
    if(n>0) offset+=(size_t)n; else if(n<0&&errno==EINTR) continue; else if(!n) break; else return false;
  }
  struct stat after{};
  if(offset!=(size_t)st.st_size || fstat(fd,&after) || after.st_dev!=st.st_dev || after.st_ino!=st.st_ino ||
     after.st_size!=st.st_size || after.st_nlink || after.st_mtimespec.tv_sec!=st.st_mtimespec.tv_sec ||
     after.st_mtimespec.tv_nsec!=st.st_mtimespec.tv_nsec || after.st_ctimespec.tv_sec!=st.st_ctimespec.tv_sec || after.st_ctimespec.tv_nsec!=st.st_ctimespec.tv_nsec) return false;
  raw.resize(offset); return true;
}
inline NSDictionary* fileIdentity(const struct stat& st) {
  return @{@"device":[NSString stringWithUTF8String:std::to_string(st.st_dev).c_str()],
    @"inode":[NSString stringWithUTF8String:std::to_string(st.st_ino).c_str()],@"uid":@(st.st_uid),@"mode":@(st.st_mode&07777)};
}
inline NSString* bootSession() {
  char uuid[64]{}; size_t size=sizeof(uuid);
  if(sysctlbyname("kern.bootsessionuuid",uuid,&size,nullptr,0)||size<36||size>sizeof(uuid)||uuid[sizeof(uuid)-1]) return nil;
  NSString* value=[[NSString stringWithUTF8String:uuid] lowercaseString];
  return arbol_attempt::pattern(value,@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")?value:nil;
}
inline bool privateDirectoryAt(int parent,const char* name,struct stat& out,bool exclusive=false) {
  bool created=!mkdirat(parent,name,0700);
  if(!created&&(errno!=EEXIST||exclusive)) return false;
  int fd=openat(parent,name,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
  struct stat named{};
  bool valid=!fstat(fd,&out)&&!fstatat(parent,name,&named,AT_SYMLINK_NOFOLLOW)&&S_ISDIR(out.st_mode)&&out.st_uid==geteuid()&&
    (out.st_mode&07777)==0700&&out.st_dev==named.st_dev&&out.st_ino==named.st_ino;
  if(valid&&created) valid=!fsync(fd)&&!fsync(parent);
  if(close(fd)) valid=false; return valid;
}
class HostCapability {
  int capsule_=-1,stateFd_=-1; SharedState* state_=nullptr;
  NSDictionary* value_=nil; std::string raw_; bool attempted_=false,valid_=false;
public:
  HostCapability()=default; HostCapability(const HostCapability&)=delete; HostCapability& operator=(const HostCapability&)=delete;
  // Native custody keeps this object for process lifetime. A helper's OS exit
  // closes its own descriptions; no JS finalizer, unlock or disarm exists.
  int capsule() const { return capsule_; } int stateDescriptor() const { return stateFd_; }
  SharedState* shared() const { return state_; } NSDictionary* value() const { return value_; }
  const std::string& raw() const { return raw_; }
  bool present() const { return valid_ && state_ && value_; }
  bool prepare(arbol_boundary::Context& c,const std::string& input,double deadline) {
    if(attempted_) return false; attempted_=true;
    if(getpid()!=c.main.pid || !c.initial()) return false;
    NSDictionary* proposed=arbol_attempt::json(input);
    if(!arbol_attempt::keys(proposed,@[@"requestPath",@"runtime",@"prior"]) || !arbol_attempt::path(proposed[@"requestPath"])) return false;
    std::string request=[proposed[@"requestPath"] UTF8String]; arbol_attempt::Claim claim; std::string attemptRaw; NSDictionary* attempt=nil;
    if(!claim.acquire(request,deadline) || !claim.read(attemptRaw,attempt) || !arbol_attempt::launchRequest(claim,request,attempt) ||
       ![attempt[@"phase"] isEqual:@"claimed"] || ![attempt[@"stage"] isEqual:@"untransferred"] ||
       [attempt[@"expires"] doubleValue]<=arbol_boundary::clockMs() || !arbol_attempt::currentProcess(attempt[@"engine"],true) ||
       ![attempt[@"candidateDigest"] isEqual:[NSString stringWithUTF8String:c.digest.c_str()]] ||
       ![attempt[@"buildGuard"] isEqual:[NSString stringWithUTF8String:c.build.path.c_str()]] ||
       c.owner.path!=std::string([attempt[@"profile"] UTF8String])+"/owner.lock" ||
       !arbol_attempt::runtime(proposed[@"runtime"],attempt) || proposed[@"runtime"]==NSNull.null ||
       ![proposed[@"runtime"][@"phase"] isEqual:@"starting"] ||
       [proposed[@"runtime"][@"pid"] intValue]!=c.main.pid || ![proposed[@"runtime"][@"processStartId"] isEqual:attempt[@"engine"][@"startId"]]) return false;
    deadline=std::min(deadline,[attempt[@"expires"] doubleValue]);
    std::string runtimeRaw; bool absent;
    if(!arbol_attempt::readAt(claim.at.directory,"runtime.json",runtimeRaw,absent) || absent ||
       ![arbol_attempt::json(runtimeRaw) isEqual:proposed[@"runtime"]]) return false;
    NSMutableDictionary* boundAttempt=[attempt mutableCopy]; boundAttempt[@"runtime"]=proposed[@"runtime"];
    std::string boundRaw=arbol_attempt::bytes(boundAttempt);
    if(!arbol_attempt::transition(attempt,boundAttempt,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(claim.at,attemptRaw,false,boundRaw)) return false;
    attempt=boundAttempt;
    NSString* profile=attempt[@"profile"]; std::string profilePath=profile.fileSystemRepresentation;
    if(!arbol_boundary::canonical(profilePath) || !arbol_boundary::privateAncestors(profilePath+"/profile.json")) return false;
    int directory=open(profilePath.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); struct stat root{},named{},record{};
    if(directory<0) return false;
    bool valid=!fstat(directory,&root)&&!lstat(profilePath.c_str(),&named)&&S_ISDIR(root.st_mode)&&root.st_uid==geteuid()&&
      (root.st_mode&07777)==0700&&root.st_dev==named.st_dev&&root.st_ino==named.st_ino;
    std::string profileRaw; struct stat data{},userData{},exits{},hashDirectory{},receiptDirectory{};
    valid=valid&&arbol_attempt::readAt(directory,"profile.json",profileRaw,absent)&&!absent&&
      !fstatat(directory,"profile.json",&record,AT_SYMLINK_NOFOLLOW);
    NSDictionary* profileRecord=arbol_attempt::json(profileRaw);
    valid=valid&&arbol_attempt::keys(profileRecord,@[@"format",@"id",@"instance",@"creationRequest",@"createdAt"])&&
      [profileRecord[@"format"] isEqual:@1]&&[profileRecord[@"id"] isEqual:profile.lastPathComponent]&&
      [profileRecord[@"instance"] isEqual:attempt[@"profileInstance"]]&&
      !fstatat(directory,"data",&data,AT_SYMLINK_NOFOLLOW)&&!fstatat(directory,"userData",&userData,AT_SYMLINK_NOFOLLOW);
    for(const struct stat* st : {&data,&userData}) valid=valid&&S_ISDIR(st->st_mode)&&st->st_uid==geteuid()&&
      (st->st_mode&07777)==0700&&st->st_dev==root.st_dev;
    if(close(directory)) valid=false; if(!valid) return false;
    // Pre-compatibility evidence is outside the profile/engine root. A refused
    // incompatible/unmanaged profile receives no metadata directory mutation.
    NSString* state=profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
    if(!arbol_boundary::canonical(state.fileSystemRepresentation)) return false;
    int stateFd=open(state.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat stateStat{}; valid=stateFd>=0&&!fstat(stateFd,&stateStat)&&S_ISDIR(stateStat.st_mode)&&
      stateStat.st_uid==geteuid()&&(stateStat.st_mode&07777)==0700&&stateStat.st_dev==root.st_dev;
    valid=valid&&privateDirectoryAt(stateFd,"exit-evidence",exits)&&exits.st_dev==root.st_dev;
    int exitsFd=valid?openat(stateFd,"exit-evidence",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC):-1;
    valid=valid&&exitsFd>=0&&privateDirectoryAt(exitsFd,[attempt[@"profilePathHash"] UTF8String],hashDirectory)&&hashDirectory.st_dev==root.st_dev;
    int hashFd=valid?openat(exitsFd,[attempt[@"profilePathHash"] UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC):-1;
    valid=valid&&hashFd>=0&&privateDirectoryAt(hashFd,[attempt[@"request"] UTF8String],receiptDirectory,true)&&receiptDirectory.st_dev==root.st_dev;
    if(hashFd>=0&&close(hashFd)) valid=false; if(exitsFd>=0&&close(exitsFd)) valid=false; if(stateFd>=0&&close(stateFd)) valid=false;
    if(!valid) return false;
    NSDictionary* prior=proposed[@"prior"];
    // This is an immutable expectation, never a PreviousExit proof or marker
    // read. Real held-guard readers and post-enrollment marker binding verify it.
    bool priorOK=(arbol_attempt::keys(prior,@[@"kind"])&&[prior[@"kind"] isEqual:@"absent"]) ||
      (arbol_attempt::keys(prior,@[@"kind",@"path",@"digest"])&&[@[@"activated",@"terminal"] containsObject:prior[@"kind"]]&&
       arbol_attempt::path(prior[@"path"])&&arbol_attempt::pattern(prior[@"digest"],@"^[0-9a-f]{64}$"));
    if(!priorOK) return false;
    NSString* boot=bootSession(); if(!boot) return false;
    value_=@{@"format":@1,@"kind":@"host-finalization",@"bootSession":boot,@"bundle":[NSString stringWithUTF8String:c.bundle.c_str()],
      @"main":arbol_boundary::capsuleIdentity(c.main,c.session),@"locks":@{@"owner":arbol_boundary::capsuleLock(c.owner),@"build":arbol_boundary::capsuleLock(c.build)},
      @"attempt":attempt,@"attemptPath":[NSString stringWithUTF8String:(claim.at.path+"/claim.json").c_str()],
      @"profileDirectory":fileIdentity(root),@"profileRecord":fileIdentity(record),@"profileRecordDigest":arbol_attempt::digest(profileRaw),
      @"directories":@{@"data":fileIdentity(data),@"userData":fileIdentity(userData)},
      @"receiptDirectory":@{@"path":[[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:attempt[@"profilePathHash"]] stringByAppendingPathComponent:attempt[@"request"]],@"identity":fileIdentity(receiptDirectory)},
      @"runtime":proposed[@"runtime"],@"markerPath":[profile stringByAppendingPathComponent:@"engine.json"],@"prior":prior};
    raw_=arbol_attempt::bytes(value_); capsule_=arbol_boundary::capsuleDescriptor(raw_); if(capsule_<0) return false;
    char temporary[]="/private/tmp/arbol-browser-state-XXXXXX"; int writer=mkstemp(temporary);
    if(writer<0) return false;
    bool ok=!fcntl(writer,F_SETFD,FD_CLOEXEC)&&!fchmod(writer,0600)&&!ftruncate(writer,sizeof(SharedState))&&!unlink(temporary);
    if(!ok) { (void)unlink(temporary); close(writer); return false; }
    stateFd_=fcntl(writer,F_DUPFD_CLOEXEC,10); if(close(writer)||stateFd_<0||!anonymousFile(stateFd_,true,sizeof(SharedState))) return false;
    void* mapping=mmap(nullptr,sizeof(SharedState),PROT_READ|PROT_WRITE,MAP_SHARED,stateFd_,0); if(mapping==MAP_FAILED) return false;
    state_=new(mapping) SharedState; memcpy(state_->capabilityDigest,[arbol_attempt::digest(raw_) UTF8String],65);
    if(!state_->main.bind(c.main,deadline)) return false; state_->enrolled.fetch_or(1,std::memory_order_release);
    valid_=arbol_boundary::clockMs()<deadline && metadata() && arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build);
    return valid_;
  }
  bool load(arbol_boundary::Context& c,bool primary,double deadline) {
    if(attempted_) return false; attempted_=true;
    if(!anonymousBytes(8,raw_,deadline)||!anonymousFile(9,true,sizeof(SharedState))) return false;
    value_=arbol_attempt::json(raw_); NSDictionary* main=value_[@"main"],*locks=value_[@"locks"],*attempt=value_[@"attempt"];
    if(!arbol_attempt::keys(value_,@[@"format",@"kind",@"bootSession",@"bundle",@"main",@"locks",@"attempt",@"attemptPath",@"profileDirectory",@"profileRecord",@"profileRecordDigest",@"directories",@"receiptDirectory",@"runtime",@"markerPath",@"prior"]) ||
       ![value_[@"format"] isEqual:@1]||![value_[@"kind"] isEqual:@"host-finalization"]||
       ![value_[@"bootSession"] isEqual:bootSession()]||
       ![value_[@"bundle"] isEqual:[NSString stringWithUTF8String:c.bundle.c_str()]]||
       ![main isEqual:arbol_boundary::capsuleIdentity(c.main,c.session)]||
       ![locks isEqual:@{@"owner":arbol_boundary::capsuleLock(c.owner),@"build":arbol_boundary::capsuleLock(c.build)}]||
       !arbol_attempt::record(attempt)||![attempt[@"candidateDigest"] isEqual:[NSString stringWithUTF8String:c.digest.c_str()]]||
       ![value_[@"markerPath"] isEqual:[attempt[@"profile"] stringByAppendingPathComponent:@"engine.json"]]||
       !arbol_attempt::runtime(value_[@"runtime"],attempt)) return false;
    capsule_=fcntl(8,F_DUPFD_CLOEXEC,10); stateFd_=fcntl(9,F_DUPFD_CLOEXEC,10);
    if(capsule_<0||stateFd_<0||close(8)||close(9)) return false;
    void* mapping=mmap(nullptr,sizeof(SharedState),PROT_READ|PROT_WRITE,MAP_SHARED,stateFd_,0); if(mapping==MAP_FAILED) return false;
    state_=static_cast<SharedState*>(mapping);
    if(memcmp(state_->magic,"ABR29S1",8)||state_->bytes!=sizeof(SharedState)||
       memcmp(state_->capabilityDigest,[arbol_attempt::digest(raw_) UTF8String],65)||!state_->main.is(c.main)) return false;
    const Identity& self=primary?c.primary:c.custody;
    valid_=metadata() && arbol_boundary::clockMs()<deadline && arbol_boundary::current(self)==1 && c.monitor(self,true) &&
      (primary?state_->primary:state_->custody).bind(self,deadline);
    return valid_;
  }
  bool enrolled(arbol_boundary::Context& c,bool primary,const ExitWatch& watch) {
    if(!present()||!watch.enrolledAlive(c.main)||!state_->main.is(c.main)||
       !(primary?state_->primary:state_->custody).is(primary?c.primary:c.custody)) return false;
    state_->enrolled.fetch_or(primary?2:4,std::memory_order_acq_rel); return true;
  }
  std::string requestPath() const {
    NSString* path=value_[@"attemptPath"];
    return std::string([[path.stringByDeletingLastPathComponent stringByAppendingPathComponent:
      [@"launch-" stringByAppendingFormat:@"%@.json",value_[@"attempt"][@"request"]]] UTF8String]);
  }
  bool currentAttempt(arbol_boundary::Context& c,arbol_attempt::Claim& claim,std::string& raw,NSDictionary* __strong& attempt,double deadline) const {
    if(!present()||!claim.acquire(requestPath(),deadline)||!claim.read(raw,attempt)||
       !arbol_attempt::immutable(value_[@"attempt"],attempt)||
       ![attempt[@"engine"] isEqual:value_[@"attempt"][@"engine"]]||
       ![attempt[@"bootstrap"] isEqual:value_[@"attempt"][@"bootstrap"]]||
       !arbol_attempt::sameRuntimeBinding(value_[@"runtime"],attempt[@"runtime"])||
       !arbol_boundary::lockIdentity(c.owner)||!arbol_boundary::lockIdentity(c.build)) return false;
    return true;
  }
  bool controls(arbol_boundary::Context& c,double deadline) const {
    arbol_attempt::Claim claim; std::string raw; NSDictionary* attempt=nil;
    if(!currentAttempt(c,claim,raw,attempt,deadline)) return false;
    return ([attempt[@"phase"] isEqual:@"claimed"] && [attempt[@"expires"] doubleValue]>arbol_boundary::clockMs()) ||
      [attempt[@"phase"] isEqual:@"ready"] || [attempt[@"phase"] isEqual:@"closing"];
  }
  bool metadata() const {
    if(!value_) return false;
    NSString* profile=value_[@"attempt"][@"profile"];
    if(!arbol_attempt::path(profile)||!arbol_boundary::canonical(profile.fileSystemRepresentation)||
       !arbol_boundary::privateAncestors(std::string(profile.fileSystemRepresentation)+"/profile.json")) return false;
    int fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
    struct stat root{},record{},child{}; std::string raw; bool absent;
    bool valid=!fstat(fd,&root)&&[fileIdentity(root) isEqual:value_[@"profileDirectory"]]&&
      arbol_attempt::readAt(fd,"profile.json",raw,absent)&&!absent&&
      !fstatat(fd,"profile.json",&record,AT_SYMLINK_NOFOLLOW)&&[fileIdentity(record) isEqual:value_[@"profileRecord"]]&&
      [arbol_attempt::digest(raw) isEqual:value_[@"profileRecordDigest"]];
    for(NSString* name in @[@"data",@"userData"]) valid=valid&&!fstatat(fd,name.UTF8String,&child,AT_SYMLINK_NOFOLLOW)&&
      S_ISDIR(child.st_mode)&&child.st_dev==root.st_dev&&[fileIdentity(child) isEqual:value_[@"directories"][name]];
    NSString* receiptPath=value_[@"receiptDirectory"][@"path"];
    NSString* state=profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
    valid=valid&&[receiptPath isEqual:[[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:value_[@"attempt"][@"profilePathHash"]] stringByAppendingPathComponent:value_[@"attempt"][@"request"]]]&&
      arbol_boundary::canonical(receiptPath.fileSystemRepresentation)&&!lstat(receiptPath.fileSystemRepresentation,&child)&&S_ISDIR(child.st_mode)&&
      arbol_boundary::privateAncestors(std::string(receiptPath.fileSystemRepresentation)+"/activation.json")&&
      child.st_dev==root.st_dev&&[fileIdentity(child) isEqual:value_[@"receiptDirectory"][@"identity"]];
    if(close(fd)) valid=false; return valid;
  }
  bool held(arbol_boundary::Context& c) const {
    return present()&&state_->enrolled.load(std::memory_order_acquire)==7&&
      state_->main.is(c.main)&&state_->primary.is(c.primary)&&state_->custody.is(c.custody)&&
      arbol_boundary::current(c.main)==1&&arbol_boundary::current(c.primary)==1&&arbol_boundary::current(c.custody)==1&&
      getpgid(c.main.pid)==(int)c.main.group&&getsid(c.main.pid)==c.session&&c.primaryMonitor()&&c.monitor(c.custody,true)&&
      arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build)&&metadata();
  }
  bool ready(arbol_boundary::Context& c) const { return held(c)&&state_->fatal.load(std::memory_order_acquire)==0; }
};
} // namespace arbol_exit

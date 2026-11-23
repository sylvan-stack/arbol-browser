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
#include <dirent.h>
#include <os/log.h>
namespace arbol_exit {
using arbol_boundary::Identity;
// Purpose-specific private exit evidence only. Launch/cancel/capsule/marker
// formats retain their independent16KiB bounds in arbol_attempt. A journal
// contains the whole bounded capability PLUS ordinary/storage evidence.
constexpr size_t exitReceiptLimit=262144;
inline std::string encodeExitReceiptValue(NSDictionary* value) {
  @try {
    if(![value isKindOfClass:NSDictionary.class]||![NSJSONSerialization isValidJSONObject:value]) return {};
    NSError* error=nil;
    NSData* data=[NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:&error];
    if(error||!data||!data.length||data.length>=exitReceiptLimit||![[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]) return {};
    return std::string((const char*)data.bytes,data.length)+"\n";
  } @catch(NSException*) { return {}; }
}
inline NSDictionary* parseExitReceipt(const std::string& raw) {
  @try {
    if(raw.empty()||raw.size()>exitReceiptLimit||raw.find('\0')!=std::string::npos) return nil;
    NSData* data=[NSData dataWithBytes:raw.data() length:raw.size()];
    if(![[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]) return nil;
    NSError* error=nil; id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
    // Canonical complete writer bytes exclude partial prefixes, duplicate-key
    // substitutions, trailing material or lossy/non-stable round trips.
    return !error&&[value isKindOfClass:NSDictionary.class]&&encodeExitReceiptValue(value)==raw?value:nil;
  } @catch(NSException*) { return nil; }
}
inline std::string exitReceiptBytes(NSDictionary* value) {
  std::string raw=encodeExitReceiptValue(value); if(raw.empty()) return {};
  NSDictionary* complete=parseExitReceipt(raw);
  return complete&&[complete isEqual:value]?raw:std::string{};
}
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
    // Darwin can keep the registration's EV_RECEIPT on the terminal event.
    constexpr uint16_t permitted=EV_ADD|EV_ENABLE|EV_CLEAR|EV_RECEIPT|EV_ONESHOT|EV_EOF;
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
  bool attempted_=false; Identity original_{}; std::shared_ptr<arbol_boundary::KernelAnswer> answer_;
public:
  bool start(const Identity& original) {
    if(attempted_) return false; attempted_=true; original_=original;
    auto* pool=arbol_boundary::KernelQueries::get();
    if(pool) answer_=pool->submit(original,true,true);
    return (bool)answer_;
  }
  Result result() {
    if(!answer_) return attempted_?uncertain:pending;
    auto state=answer_->state.load(std::memory_order_acquire);
    if(state!=arbol_boundary::KernelState::transient) return (Result)(int)state;
    if(arbol_boundary::clockMs()>=answer_->completed+10) {
      auto* pool=arbol_boundary::KernelQueries::get();
      auto retry=pool?pool->submit(original_,true,true):nullptr;
      if(retry) answer_=retry;
    }
    return pending; // original identity, watch, fatal history and cutoff unchanged
  }
  bool started() const { return attempted_; }
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
// Reusable active slots use atomic scalar fields plus a monotonically tagged
// publication. A reader never races non-atomic payload reuse or mistakes ABA
// for one complete identity. Phase 1 is actual incomplete identity publication,
// not a generic read-only census in progress.
struct FamilySlot {
  std::atomic<uint64_t> publication{0},start{0},parentStart{0},capturedUs{0};
  std::atomic<uint64_t> captureAck{0},resolver{0},absenceAck{0};
  std::atomic<uint32_t> pid{0},version{0},uid{0},group{0},parentVersion{0},session{0},image{0};
  bool read(arbol_boundary::FamilyObservation& out,uint64_t& serial) const {
    uint64_t before=publication.load(std::memory_order_acquire);
    if((before&3)!=2) return false;
    out.original={(int)pid.load(),start.load(),(int32_t)version.load(),uid.load(),group.load()};
    out.parentStart=parentStart.load(); out.parentVersion=(int32_t)parentVersion.load();
    out.capturedUs=capturedUs.load(); out.session=session.load(); out.image=image.load();
    serial=before>>2; return publication.load(std::memory_order_acquire)==before;
  }
  bool publish(const arbol_boundary::FamilyObservation& value,uint64_t serial) {
    uint64_t empty=publication.load(std::memory_order_acquire);
    if((empty&3)||!serial||serial>(UINT64_MAX>>2)||
       !publication.compare_exchange_strong(empty,(serial<<2)|1,std::memory_order_acq_rel)) return false;
    captureAck.store(0); resolver.store(0); absenceAck.store(0);
    pid.store(value.original.pid); start.store(value.original.start); version.store(value.original.version);
    uid.store(value.original.uid); group.store(value.original.group); parentStart.store(value.parentStart);
    parentVersion.store(value.parentVersion); capturedUs.store(value.capturedUs); session.store(value.session); image.store(value.image);
    publication.store((serial<<2)|2,std::memory_order_release); return true;
  }
};
struct LedgerStamp {
  uint64_t device=0,inode=0,size=0; uint32_t uid=0,mode=0;
  int64_t modified=0,changed=0; uint64_t modifiedNs=0,changedNs=0;
  static LedgerStamp from(const struct stat& st) {
    return {(uint64_t)st.st_dev,st.st_ino,(uint64_t)st.st_size,st.st_uid,(uint32_t)(st.st_mode&07777),
      st.st_mtimespec.tv_sec,st.st_ctimespec.tv_sec,(uint64_t)st.st_mtimespec.tv_nsec,(uint64_t)st.st_ctimespec.tv_nsec};
  }
  bool is(const struct stat& st) const {
    return S_ISREG(st.st_mode)&&st.st_nlink==1&&device==(uint64_t)st.st_dev&&inode==st.st_ino&&size==(uint64_t)st.st_size&&
      uid==st.st_uid&&mode==(uint32_t)(st.st_mode&07777)&&modified==st.st_mtimespec.tv_sec&&changed==st.st_ctimespec.tv_sec&&
      modifiedNs==(uint64_t)st.st_mtimespec.tv_nsec&&changedNs==(uint64_t)st.st_ctimespec.tv_nsec;
  }
};
struct LedgerFront {
  LedgerStamp file{}; uint64_t count=0,tailOffset=0,tailLength=0; std::string chain;
};
struct FamilyFrontier {
  std::atomic<uint64_t> publication{0},device{0},inode{0},size{0},uid{0},mode{0},modified{0},changed{0},modifiedNs{0},changedNs{0};
  std::atomic<uint64_t> count{0},tailOffset{0},tailLength{0},hash[4]{};
  bool read(LedgerFront& out) const {
    uint64_t first=publication.load(std::memory_order_acquire); if(!first||(first&1)) return false;
    out.file={device.load(),inode.load(),size.load(),(uint32_t)uid.load(),(uint32_t)mode.load(),
      (int64_t)modified.load(),(int64_t)changed.load(),modifiedNs.load(),changedNs.load()};
    out.count=count.load(); out.tailOffset=tailOffset.load(); out.tailLength=tailLength.load(); out.chain.clear();
    char word[17]; for(unsigned i=0;i<4;++i) { snprintf(word,sizeof(word),"%016llx",(unsigned long long)hash[i].load()); out.chain+=word; }
    return publication.load(std::memory_order_acquire)==first;
  }
  bool publish(const LedgerFront& value) {
    if(value.chain.size()!=64) return false;
    uint64_t old=publication.load(std::memory_order_acquire); if((old&1)||old>UINT64_MAX-2) return false;
    publication.store(old+1,std::memory_order_release);
    device.store(value.file.device); inode.store(value.file.inode); size.store(value.file.size); uid.store(value.file.uid); mode.store(value.file.mode);
    modified.store(value.file.modified); changed.store(value.file.changed); modifiedNs.store(value.file.modifiedNs); changedNs.store(value.file.changedNs);
    count.store(value.count); tailOffset.store(value.tailOffset); tailLength.store(value.tailLength);
    for(unsigned i=0;i<4;++i) hash[i].store(strtoull(value.chain.substr(i*16,16).c_str(),nullptr,16));
    publication.store(old+2,std::memory_order_release); return true;
  }
};
struct FamilyRoleState {
  std::atomic<uint64_t> nextCapture{0};
  FamilyFrontier frontier;
  std::atomic<uint32_t> appendInFlight{0},failed{0},sealed{0};
  FamilySlot active[4096]; // simultaneous unresolved originals, not lifetime count
};
struct FamilyState { std::atomic<uint32_t> uncertain{0}; std::atomic<uint64_t> activity{0}; FamilyRoleState roles[3]; };
struct LedgerHeader {
  char magic[8]={'A','B','R','2','9','F','1','\0'}; uint32_t format=1,role=0;
  char capabilityDigest[65]{},nonce[65]{}; uint8_t reserved[6]{};
};
static_assert(sizeof(LedgerHeader)==152);
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
  // Installed only by the genuine13.4 Close/local-event budget consumer.
  std::atomic<uint64_t> closeReceivedUs{0},closeGraceUs{0},closeOverallUs{0};
  IdentitySlot main,primary,custody;
  FamilyState family;
  std::atomic<uint32_t> enrolled{0},transfer{0},mutation{0},markerBound{0},admitted{0};
  std::atomic<uint32_t> cookieAcknowledged{0},domRequested{0},quitRequested{0},retiredPages{0};
  std::atomic<uint32_t> primaryConsent{0},custodyConsent{0};
  std::atomic<uint64_t> primaryConsentUs{0},custodyConsentUs{0};
  // Actual main-native publishers (13.5) advance this once through retired
  // pages, same website DOM request, cookie callback, intended guarded quit.
  // A void JS return or intent cannot set post-exit eligibility.
  std::atomic<uint32_t> shutdownOrder{0};
  std::atomic<uint64_t> shutdownTimes[4]{{0},{0},{0},{0}};
  std::atomic<uint32_t> ordinaryPostExitEligible{0};
  // 0=no clean mutation, 1=in-flight mutation/publication, 2=acknowledged commit,
  // 3=refused unresolved mutation, 4=refused before any clean mutation.
  // Commit versus every fatal/expiry refusal has ONE irreversible CAS winner.
  std::atomic<uint32_t> activation{0};
  // Verified native mutation preparation publishes this before permission to
  // write. A later independent holder can authenticate an uncertain resulting
  // dirty marker; it never predicts or grants its replacement inode.
  char expectedMarkerDigest[65]{};
  MarkerBinding marker{};
  void poison(uint64_t reason,unsigned callerLine=__builtin_LINE(),
    arbol_boundary::FatalSource source=arbol_boundary::FatalSource::existingCaller) {
    uint32_t value=activation.load(std::memory_order_acquire);
    while((value==0||value==1)&&!activation.compare_exchange_weak(value,value==0?4:3,std::memory_order_acq_rel)) {}
    // A post-commit reason remains recorded, but cannot retroactively erase
    // the genuine acknowledged cut which won before this fatal publication.
    uint64_t previous=fatal.fetch_or(reason,std::memory_order_acq_rel);
    if(previous==0) {
      int savedErrno=errno;
      try {
        @try {
          os_log_error(OS_LOG_DEFAULT,"arbol-browser-first-fatal reason=%{public}llu line=%{public}u source=%{public}u",
            (unsigned long long)reason,callerLine,static_cast<unsigned>(source));
        } @catch(NSException*) {}
      } catch(...) {}
      errno=savedErrno;
    }
  }
  static void minimum(std::atomic<uint64_t>& field,uint64_t value) {
    uint64_t old=field.load(std::memory_order_acquire);
    while((!old||value<old)&&!field.compare_exchange_weak(old,value,std::memory_order_acq_rel)) {}
  }
  void installClose(uint64_t received,uint64_t grace,uint64_t overall) {
    // All offsets are fixed. Independent MIN publications can only shorten an
    // already admitted budget. Grace is published last for first admission.
    minimum(closeReceivedUs,received); minimum(closeOverallUs,overall); minimum(closeGraceUs,grace);
  }
  void declareFatal(unsigned callerLine=__builtin_LINE()) {
    uint64_t cutoff=(uint64_t)((arbol_boundary::clockMs()+1000)*1000),old=fatalCutoffUs.load(std::memory_order_acquire);
    while((!old||cutoff<old)&&!fatalCutoffUs.compare_exchange_weak(old,cutoff,std::memory_order_acq_rel)) {}
    // Publish the bound before the admission loss. This preserves F's existing
    // one-second forwarding/receipt window; a genuine hard loss remains sooner.
    poison(admissionLoss,callerLine);
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
class RetainedFamily final:public arbol_boundary::FamilyCapture {
  struct Job { unsigned origin,index; uint64_t serial; arbol_boundary::FamilyObservation value; arbol_boundary::KernelAbsence proof; bool absence; };
  SharedState* state_; unsigned role_; Identity main_; int session_;
  int readers_[3],writer_; NSDictionary* capability_; std::string capabilityDigest_;
  std::mutex mutex_; std::condition_variable available_; std::deque<Job> queue_; bool worker_=false,failed_=false;
  bool compatible(const arbol_boundary::FamilyObservation& value) const {
    return value.original.pid>1&&value.original.start&&value.original.version>0&&value.original.uid==main_.uid&&
      value.original.group==main_.group&&value.parentStart==main_.start&&value.parentVersion==main_.version&&
      value.session==(uint32_t)session_&&value.image>=1&&value.image<=4;
  }
  bool self() const {
    const auto& slot=role_==0?state_->main:role_==1?state_->primary:state_->custody;
    Identity now; if(slot.state.load(std::memory_order_acquire)!=2||arbol_boundary::observe(getpid(),now)!=1||!slot.is(now)||getsid(0)!=session_) return false;
    return now.group==main_.group||(role_==1&&now.group==(uint32_t)getpid());
  }
  bool physical(unsigned role,const LedgerFront& front) const {
    if(role>2||readers_[role]<0) return false;
    struct stat fd{},named{}; char path[PATH_MAX]{};
    NSString* expected=capability_[@"family"][role][@"path"];
    return expected&&arbol_boundary::canonical(expected.fileSystemRepresentation)&&!fstat(readers_[role],&fd)&&
      !lstat(expected.fileSystemRepresentation,&named)&&front.file.is(fd)&&front.file.is(named)&&
      !fcntl(readers_[role],F_GETPATH,path)&&std::string(path)==expected.fileSystemRepresentation;
  }
  NSDictionary* identity(const arbol_boundary::FamilyObservation& value) const {
    NSMutableDictionary* out=[arbol_boundary::capsuleIdentity(value.original) mutableCopy];
    out[@"parentStartId"]=[NSString stringWithUTF8String:std::to_string(value.parentStart).c_str()];
    out[@"parentPidVersion"]=@(value.parentVersion); out[@"session"]=@(value.session); out[@"image"]=@(value.image); out[@"capturedUs"]=@(value.capturedUs); return out;
  }
  bool append(std::vector<Job>& jobs,unsigned& firstRefusalLine) {
    // Owned by this one worker operation. Recording a failed site performs no
    // syscall and cannot replace the original false result or errno.
    auto refused=[&](unsigned callerLine=__builtin_LINE()) {
      if(!firstRefusalLine) firstRefusalLine=callerLine;
      return false;
    };
    @autoreleasepool { @try {
      if(!self()) return refused();
      LedgerFront before; if(!state_->family.roles[role_].frontier.read(before)||!physical(role_,before)) return refused();
      struct stat writing{}; if(fstat(writer_,&writing)||!before.file.is(writing)||(fcntl(writer_,F_GETFL)&O_ACCMODE)!=O_WRONLY) return refused();
      LedgerFront next=before; std::string bytes; std::vector<Job> committed;
      for(const auto& job:jobs) {
        if(next.count==UINT64_MAX||!compatible(job.value)) return refused();
        auto& slot=state_->family.roles[job.origin].active[job.index];
        arbol_boundary::FamilyObservation current; uint64_t serial;
        uint64_t publication=slot.publication.load(std::memory_order_acquire);
        // Reuse is allowed only after the old generation's durable absence.
        // An old queued observation may therefore be harmlessly superseded;
        // never charge or acknowledge the replacement original.
        if((publication>>2)>job.serial||((publication>>2)==job.serial&&!(publication&3))) continue;
        if(!slot.read(current,serial)||serial!=job.serial||!arbol_boundary::same(current.original,job.value.original)) return refused();
        if(job.absence&&slot.resolver.load(std::memory_order_acquire)!=((job.serial<<2)|(role_+1))) return refused();
        NSMutableDictionary* record=[@{@"format":@1,@"kind":job.absence?@"absence":@"capture",@"writerRole":@(role_),@"sequence":@(++next.count),
          @"originRole":@(job.origin),@"capture":@(job.serial),@"original":identity(job.value),@"previous":[NSString stringWithUTF8String:next.chain.c_str()]} mutableCopy];
        if(job.absence) {
          if(!arbol_boundary::same(job.proof.original,job.value.original)||!job.proof.observedUs||(job.proof.kind!=1&&job.proof.kind!=2)) return refused();
          record[@"proof"]=@{@"kind":job.proof.kind==1?@"complete-kernel-absence":@"unique-start-reuse",@"observedUs":@(job.proof.observedUs),
            @"replacement":job.proof.kind==2?arbol_boundary::capsuleIdentity(job.proof.replacement):(id)NSNull.null};
        }
        std::string core=arbol_attempt::bytes(record); if(core.empty()) return refused();
        next.chain=[arbol_attempt::digest(core) UTF8String]; record[@"digest"]=[NSString stringWithUTF8String:next.chain.c_str()];
        std::string raw=arbol_attempt::bytes(record); if(raw.empty()||bytes.size()+raw.size()>1048576) return refused();
        next.tailOffset=before.file.size+bytes.size(); next.tailLength=raw.size(); bytes+=raw; committed.push_back(job);
      }
      if(committed.empty()) return true;
      // No unexpected edit or append may be hidden behind our next increment.
      if(!physical(role_,before)) return refused();
      size_t at=0;
      while(at<bytes.size()) {
        ssize_t n=pwrite(writer_,bytes.data()+at,bytes.size()-at,before.file.size+at);
        if(n>0) at+=n;
        else if(n<0&&errno==EINTR) continue;
        else return refused();
      }
      if(fsync(writer_)||fcntl(writer_,F_FULLFSYNC)||fstat(writer_,&writing)||writing.st_size!=(off_t)(before.file.size+bytes.size())||
         writing.st_dev!=(dev_t)before.file.device||writing.st_ino!=before.file.inode||!arbol_attempt::privateFile(writing)) return refused();
      next.file=LedgerStamp::from(writing); if(!physical(role_,next)||!state_->family.roles[role_].frontier.publish(next)) return refused();
      for(const auto& job:committed) {
        auto& slot=state_->family.roles[job.origin].active[job.index];
        auto& acknowledgement=job.absence?slot.absenceAck:slot.captureAck;
        uint64_t value=acknowledgement.load(std::memory_order_acquire);
        while(value<job.serial&&slot.publication.load(std::memory_order_acquire)==((job.serial<<2)|2)) {
          if(acknowledgement.compare_exchange_weak(value,job.serial,std::memory_order_acq_rel)) break;
        }
      }
      state_->family.activity.fetch_add(1,std::memory_order_acq_rel);
      return true;
    } @catch(NSException*) { return refused(); } }
  }
  void fail(unsigned callerLine=__builtin_LINE()) {
    state_->family.roles[role_].failed.store(1,std::memory_order_release);
    refuse(callerLine,arbol_boundary::FatalSource::exitHeader);
  }
  void run() {
    for(;;) {
      std::vector<Job> jobs;
      {
        std::unique_lock<std::mutex> held(mutex_); available_.wait(held,[&] { return failed_||!queue_.empty(); });
        if(failed_) return;
        while(!queue_.empty()&&jobs.size()<64) { jobs.push_back(std::move(queue_.front())); queue_.pop_front(); }
      }
      unsigned firstRefusalLine=0;
      bool ok=false;
      try { ok=append(jobs,firstRefusalLine); }
      catch(...) { if(!firstRefusalLine) firstRefusalLine=__builtin_LINE(); }
      if(!ok) {
        { std::lock_guard<std::mutex> held(mutex_); failed_=true; }
        fail(firstRefusalLine);
        return;
      }
      { std::lock_guard<std::mutex> held(mutex_); if(queue_.empty()) state_->family.roles[role_].appendInFlight.store(0,std::memory_order_release); }
    }
  }
  bool enqueue(Job job) {
    std::lock_guard<std::mutex> held(mutex_);
    if(failed_||state_->family.roles[role_].sealed.load(std::memory_order_acquire)||queue_.size()>=16384) { fail(); return false; }
    state_->family.roles[role_].appendInFlight.store(1,std::memory_order_release);
    try {
      queue_.push_back(std::move(job));
      if(!worker_) {
        if(!arbol_boundary::retainNativeImage()) { failed_=true; fail(); return false; }
        std::thread([this] { run(); }).detach(); worker_=true;
      }
      available_.notify_one(); return true;
    } catch(...) { failed_=true; fail(); return false; }
  }
public:
  RetainedFamily(SharedState* state,unsigned role,const Identity& main,int session,const int* readers,int writer,NSDictionary* capability,const std::string& digest):
    state_(state),role_(role),main_(main),session_(session),writer_(writer),capability_(capability),capabilityDigest_(digest) {
    for(unsigned i=0;i<3;++i) readers_[i]=readers[i];
  }
  void refuse(unsigned callerLine=__builtin_LINE(),
    arbol_boundary::FatalSource source=arbol_boundary::FatalSource::exitHeader) override {
    state_->family.uncertain.store(1,std::memory_order_release);
    state_->poison(identityLoss,callerLine,source);
  }
  bool capture(const arbol_boundary::FamilyObservation& value) override {
    if(role_>2||!compatible(value)||!self()) { refuse(); return false; }
    auto& role=state_->family.roles[role_];
    for(auto& slot:role.active) {
      arbol_boundary::FamilyObservation old; uint64_t serial;
      if(slot.read(old,serial)&&arbol_boundary::same(old.original,value.original))
        return old.original.group==value.original.group&&old.parentStart==value.parentStart&&old.parentVersion==value.parentVersion&&old.session==value.session&&old.image==value.image;
    }
    for(unsigned i=0;i<4096;++i) if(!(role.active[i].publication.load(std::memory_order_acquire)&3)) {
      uint64_t serial=role.nextCapture.fetch_add(1,std::memory_order_acq_rel)+1;
      state_->family.activity.fetch_add(1,std::memory_order_acq_rel);
      if(role.active[i].publish(value,serial)) return enqueue({role_,i,serial,value,{},false});
    }
    refuse(); return false;
  }
  bool snapshot(std::vector<arbol_boundary::FamilyObservation>& values) override {
    values.clear(); if(state_->family.uncertain.load(std::memory_order_acquire)) return false;
    for(unsigned r=0;r<3;++r) {
      if(state_->family.roles[r].failed.load(std::memory_order_acquire)) return false;
      for(auto& slot:state_->family.roles[r].active) {
        arbol_boundary::FamilyObservation value; uint64_t serial;
        if(slot.read(value,serial)) {
          if(!compatible(value)) { refuse(); return false; }
          // A completed durable absence increment is immutable history. It can
          // leave the active union without replaying that lifetime stream.
          if(slot.absenceAck.load(std::memory_order_acquire)==serial) {
            uint64_t expected=(serial<<2)|2;
            if(slot.publication.compare_exchange_strong(expected,serial<<2,std::memory_order_acq_rel)) state_->family.activity.fetch_add(1,std::memory_order_acq_rel);
          } else values.push_back(value);
        }
      }
    }
    return true;
  }
  bool retire(const arbol_boundary::KernelAbsence& proof) override {
    if(!proof.kind||!proof.observedUs) return false;
    bool done=true;
    for(unsigned r=0;r<3;++r) for(unsigned i=0;i<4096;++i) {
      auto& slot=state_->family.roles[r].active[i]; arbol_boundary::FamilyObservation value; uint64_t serial;
      if(!slot.read(value,serial)||!arbol_boundary::same(value.original,proof.original)) continue;
      uint64_t publication=(serial<<2)|2;
      if(slot.absenceAck.load(std::memory_order_acquire)==serial) continue;
      done=false;
      if(slot.captureAck.load(std::memory_order_acquire)!=serial) continue;
      uint64_t current=slot.resolver.load(std::memory_order_acquire);
      if(current&&(current>>2)<serial) {
        // A delayed old claimant can race legitimate acknowledged reuse. Only
        // its exact stale tag is cleared; a current replacement claim is safe.
        if(slot.publication.load(std::memory_order_acquire)==publication)
          slot.resolver.compare_exchange_strong(current,0,std::memory_order_acq_rel);
        continue;
      }
      if(current&&(current>>2)>serial) continue; // our snapshot is superseded
      uint64_t empty=0,claim=(serial<<2)|(role_+1);
      if(slot.publication.load(std::memory_order_acquire)!=publication) continue;
      if(slot.resolver.compare_exchange_strong(empty,claim,std::memory_order_acq_rel)) {
        if(slot.publication.load(std::memory_order_acquire)!=publication) {
          slot.resolver.compare_exchange_strong(claim,0,std::memory_order_acq_rel); continue;
        }
        if(!enqueue({r,i,serial,value,proof,true})) return false;
      }
    }
    return done;
  }
  bool complete() override {
    uint64_t activity=state_->family.activity.load(std::memory_order_acquire);
    if(state_->family.uncertain.load(std::memory_order_acquire)) return false;
    for(unsigned r=0;r<3;++r) {
      const auto& role=state_->family.roles[r]; LedgerFront frontier;
      if(role.failed.load(std::memory_order_acquire)||role.appendInFlight.load(std::memory_order_acquire)||!role.frontier.read(frontier)||!physical(r,frontier)) return false;
      for(const auto& slot:role.active) {
        uint64_t publication=slot.publication.load(std::memory_order_acquire);
        if((publication&3)==1||((publication&3)==2&&slot.absenceAck.load(std::memory_order_acquire)!=(publication>>2))||
           slot.publication.load(std::memory_order_acquire)!=publication) return false;
      }
    }
    return state_->family.activity.load(std::memory_order_acquire)==activity;
  }
  bool seal() override {
    if(!complete()) return false;
    std::lock_guard<std::mutex> held(mutex_);
    if(!queue_.empty()||state_->family.roles[role_].appendInFlight.load(std::memory_order_acquire)) return false;
    state_->family.roles[role_].sealed.store(1,std::memory_order_release); return true;
  }
  NSDictionary* frontierTuple() const {
    NSMutableArray* values=[NSMutableArray new];
    for(unsigned r=0;r<3;++r) {
      LedgerFront f; if(!state_->family.roles[r].frontier.read(f)||!physical(r,f)) return nil;
      [values addObject:@{@"role":@(r),@"path":capability_[@"family"][r][@"path"],@"device":@(f.file.device),@"inode":@(f.file.inode),
        @"uid":@(f.file.uid),@"mode":@(f.file.mode),@"size":@(f.file.size),@"modified":@(f.file.modified),@"modifiedNs":@(f.file.modifiedNs),
        @"changed":@(f.file.changed),@"changedNs":@(f.file.changedNs),@"count":@(f.count),@"tailOffset":@(f.tailOffset),@"tailLength":@(f.tailLength),
        @"chain":[NSString stringWithUTF8String:f.chain.c_str()],@"nonce":capability_[@"family"][r][@"nonce"]}];
    }
    return @{@"format":@1,@"capabilityDigest":[NSString stringWithUTF8String:capabilityDigest_.c_str()],@"streams":values};
  }
};
// One post-exit pass over opaque emitted files, never a backend transaction
// acknowledgement. The private profile ancestor makes owner-owned 0644/0755
// children private without rewriting Chromium modes. No symlink, hardlinked
// regular file, foreign device/owner or group/other write access is admitted.
inline bool engineRootStorageName(const std::string& name) {
  return name!="profile.json"&&name!="engine.json"&&name!="owner.lock"&&name!="logs"&&name!="data"&&name!="userData";
}
inline bool engineRootStorageType(const std::string& name,const struct stat& st) {
  if(name=="Local State") return S_ISREG(st.st_mode);
  if(name=="GraphiteDawnCache"||name=="GPUPersistentCache") return S_ISDIR(st.st_mode);
  return true;
}
inline bool sameStorageNode(const struct stat& a,const struct stat& b) {
  return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_mode==b.st_mode&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid&&
    a.st_nlink==b.st_nlink&&a.st_size==b.st_size&&a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&
    a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec&&a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec&&a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec;
}
inline bool storageNames(int fd,double deadline,std::vector<std::string>& names) {
  int copy=fcntl(fd,F_DUPFD_CLOEXEC,64); DIR* stream=copy>=0?fdopendir(copy):nullptr;
  if(!stream) { if(copy>=0) close(copy); return false; }
  bool ok=true; errno=0;
  while(auto* entry=readdir(stream)) {
    if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,"..")) continue;
    if(arbol_boundary::clockMs()>=deadline||names.size()>=131072) { ok=false; break; }
    names.emplace_back(entry->d_name);
  }
  if(errno) ok=false;
  if(closedir(stream)) ok=false;
  std::sort(names.begin(),names.end());
  return ok&&std::adjacent_find(names.begin(),names.end())==names.end()&&arbol_boundary::clockMs()<deadline;
}
struct StorageResult {
  std::atomic<int> state{0}; // pending, 1=actual completed success, -1=refused
  double started=0,completed=0; uint64_t files=0,directories=0; std::string digest;
};
class StorageScan {
  NSDictionary* capability_; double deadline_; dev_t device_; uint64_t visited_=0,files_=0,directories_=0;
  bool within() const { return arbol_boundary::clockMs()<deadline_; }
  bool safe(const struct stat& st) const {
    return st.st_dev==device_&&st.st_uid==geteuid()&&!(st.st_mode&0022)&&
      ((S_ISREG(st.st_mode)&&st.st_nlink==1)||(S_ISDIR(st.st_mode)&&st.st_nlink>0));
  }
  static std::string metadata(const struct stat& st) {
    std::string value;
    for(auto v:{(uint64_t)st.st_dev,st.st_ino,(uint64_t)st.st_mode,(uint64_t)st.st_uid,(uint64_t)st.st_gid,
      (uint64_t)st.st_nlink,(uint64_t)st.st_size,(uint64_t)st.st_mtimespec.tv_sec,(uint64_t)st.st_mtimespec.tv_nsec,
      (uint64_t)st.st_ctimespec.tv_sec,(uint64_t)st.st_ctimespec.tv_nsec}) value+=std::to_string(v)+":";
    return value;
  }
  bool node(int parent,const std::string& name,unsigned depth,bool synchronize,std::string& digest) {
    if(!within()||depth>128||++visited_>131072||name.empty()||name=="."||name==".."||name.find('/')!=std::string::npos) return false;
    struct stat named{},first{},last{},after{};
    if(fstatat(parent,name.c_str(),&named,AT_SYMLINK_NOFOLLOW)||!safe(named)) return false;
    int fd=openat(parent,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC|(S_ISDIR(named.st_mode)?O_DIRECTORY:0));
    if(fd<0) return false;
    bool ok=!fstat(fd,&first)&&safe(first)&&sameStorageNode(first,named)&&within(); std::string summary=metadata(first);
    if(ok&&S_ISDIR(first.st_mode)) {
      ++directories_; std::vector<std::string> names;
      ok=storageNames(fd,deadline_,names);
      for(const auto& child:names) {
        if(!ok) break; std::string content;
        ok=node(fd,child,depth+1,synchronize,content);
        // No file contents or names enter the durable receipt. Only an opaque
        // digest of stable filesystem metadata and private names is retained.
        if(ok) summary+=std::string([arbol_attempt::digest(child) UTF8String])+":"+content+":";
      }
      if(ok&&synchronize) ok=within()&&!fsync(fd)&&within(); // actual directory acknowledgement
    } else if(ok) {
      ++files_;
      if(synchronize) ok=within()&&!fsync(fd)&&within()&&!fcntl(fd,F_FULLFSYNC)&&within();
    }
    ok=ok&&!fstat(fd,&last)&&!fstatat(parent,name.c_str(),&after,AT_SYMLINK_NOFOLLOW)&&
      safe(last)&&sameStorageNode(first,last)&&sameStorageNode(last,after)&&within();
    if(close(fd)) ok=false;
    if(ok) digest=[arbol_attempt::digest(summary) UTF8String]; return ok;
  }
  bool pass(bool synchronize,std::string& digest) {
    NSString* profile=capability_[@"attempt"][@"profile"];
    if(!within()||!arbol_boundary::canonical(profile.fileSystemRepresentation)) return false;
    int root=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(root<0) return false;
    struct stat held{},named{},after{},endName{};
    bool ok=!fstat(root,&held)&&!lstat(profile.fileSystemRepresentation,&named)&&safe(held)&&S_ISDIR(held.st_mode)&&
      (held.st_mode&07777)==0700&&sameStorageNode(held,named)&&[fileIdentity(held) isEqual:capability_[@"profileDirectory"]];
    std::string result;
    for(NSString* name in @[@"data",@"userData"]) {
      struct stat child{}; std::string digest;
      ok=ok&&!fstatat(root,name.UTF8String,&child,AT_SYMLINK_NOFOLLOW)&&S_ISDIR(child.st_mode)&&
        [fileIdentity(child) isEqual:capability_[@"directories"][name]]&&node(root,name.UTF8String,0,synchronize,digest);
      if(ok) result+=digest;
    }
    std::vector<std::string> names;
    ok=ok&&storageNames(root,deadline_,names);
    for(const auto& name:names) {
      if(!ok||!within()) { ok=false; break; }
      if(!engineRootStorageName(name)) continue;
      struct stat child{},current{};
      std::string digest;
      ok=!name.empty()&&name.find('/')==std::string::npos&&!fstatat(root,name.c_str(),&child,AT_SYMLINK_NOFOLLOW)&&
        engineRootStorageType(name,child)&&node(root,name,0,synchronize,digest)&&
        !fstatat(root,name.c_str(),&current,AT_SYMLINK_NOFOLLOW)&&sameStorageNode(child,current);
      if(ok) result+=std::string([arbol_attempt::digest(name) UTF8String])+":"+digest+":";
    }
    if(ok&&synchronize) ok=within()&&!fsync(root)&&within();
    ok=ok&&!fstat(root,&after)&&!lstat(profile.fileSystemRepresentation,&endName)&&
      sameStorageNode(held,after)&&sameStorageNode(after,endName)&&within();
    if(close(root)) ok=false; if(ok) digest=[arbol_attempt::digest(result) UTF8String]; return ok;
  }
public:
  StorageScan(NSDictionary* capability,double deadline,dev_t device):capability_(capability),deadline_(deadline),device_(device) {}
  bool run(StorageResult& out) {
    std::string before,after;
    if(!pass(true,before)) return false;
    uint64_t files=files_,directories=directories_; visited_=files_=directories_=0;
    // Reopen only to independently compare the complete stable metadata tree;
    // this second pass neither interprets nor rewrites any storage content.
    if(!pass(false,after)||before!=after||files!=files_||directories!=directories_) return false;
    out.files=files; out.directories=directories; out.digest=after; return within();
  }
};
// Strict private receipt I/O. Each published tuple comes from the same
// retained actual description and its final no-follow named-path check.
struct NativeFile {
  int fd=-1; NativeFile()=default; NativeFile(const NativeFile&)=delete;
  ~NativeFile() { if(fd>=0) close(fd); }
  bool finish() { if(fd<0) return true; int original=fd; fd=-1; return !close(original); }
};
inline bool readNativeFile(int directory,const std::string& name,std::string& raw,struct stat& identity,size_t limit) {
  NativeFile file; file.fd=openat(directory,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC); if(file.fd<0) return false;
  struct stat first{},named{},last{},after{}; raw.clear();
  bool ok=!fstat(file.fd,&first)&&!fstatat(directory,name.c_str(),&named,AT_SYMLINK_NOFOLLOW)&&
    arbol_attempt::privateFile(first)&&arbol_attempt::sameFile(first,named)&&first.st_size>0&&(uint64_t)first.st_size<=limit;
  char bytes[4096];
  while(ok&&raw.size()<=(size_t)first.st_size) {
    ssize_t n=read(file.fd,bytes,std::min(sizeof(bytes),(size_t)first.st_size+1-raw.size()));
    if(n>0) raw.append(bytes,n); else if(!n) break; else if(errno!=EINTR) ok=false;
  }
  ok=ok&&raw.size()==(size_t)first.st_size&&!fstat(file.fd,&last)&&!fstatat(directory,name.c_str(),&after,AT_SYMLINK_NOFOLLOW)&&
    arbol_attempt::sameFile(first,last)&&arbol_attempt::sameFile(last,after);
  if(!file.finish()) ok=false; if(ok) identity=last; return ok;
}
inline bool writeNativeFile(int directory,const std::string& temporary,const std::string& raw,double deadline,NativeFile& file) {
  if(raw.empty()||raw.size()>exitReceiptLimit||arbol_boundary::clockMs()>=deadline) return false;
  file.fd=openat(directory,temporary.c_str(),O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
  if(file.fd<0||fchmod(file.fd,0600)) return false;
  size_t at=0;
  while(at<raw.size()) {
    if(arbol_boundary::clockMs()>=deadline) return false;
    ssize_t n=write(file.fd,raw.data()+at,raw.size()-at);
    if(n>0) at+=n; else if(n<0&&errno==EINTR) continue; else return false;
  }
  return !fsync(file.fd)&&arbol_boundary::clockMs()<deadline&&!fcntl(file.fd,F_FULLFSYNC)&&arbol_boundary::clockMs()<deadline;
}
inline bool publishedNativeFile(int directory,const std::string& name,const std::string& raw,NativeFile& file,struct stat& identity,double deadline) {
  struct stat held{},named{},last{},after{};
  if(arbol_boundary::clockMs()>=deadline||fstat(file.fd,&held)||fstatat(directory,name.c_str(),&named,AT_SYMLINK_NOFOLLOW)||
     !arbol_attempt::privateFile(held)||!arbol_attempt::sameFile(held,named)||held.st_size!=(off_t)raw.size()) return false;
  std::string actual(raw.size()+1,'\0'); size_t at=0;
  while(at<actual.size()) {
    if(arbol_boundary::clockMs()>=deadline) return false;
    ssize_t n=pread(file.fd,actual.data()+at,actual.size()-at,at);
    if(n>0) at+=n; else if(n<0&&errno==EINTR) continue; else if(!n) break; else return false;
  }
  actual.resize(at);
  if(actual!=raw||fsync(directory)||arbol_boundary::clockMs()>=deadline||fcntl(file.fd,F_FULLFSYNC)||
     fstat(file.fd,&last)||fstatat(directory,name.c_str(),&after,AT_SYMLINK_NOFOLLOW)||
     !arbol_attempt::sameFile(held,last)||!arbol_attempt::sameFile(last,after)||arbol_boundary::clockMs()>=deadline) return false;
  identity=last; return true;
}
inline bool publishNativeReceipt(int directory,const std::string& name,const std::string& raw,double deadline,struct stat& identity) {
  std::string temporary=".receipt-"+std::string(NSUUID.UUID.UUIDString.UTF8String); NativeFile file;
  if(!writeNativeFile(directory,temporary,raw,deadline,file)) return false;
  // RENAME_EXCL never overwrites a prior immutable receipt or another attempt.
  if(renameatx_np(directory,temporary.c_str(),directory,name.c_str(),RENAME_EXCL)) return false;
  return publishedNativeFile(directory,name,raw,file,identity,deadline)&&file.finish();
}
inline bool terminalEngineMarker(NSDictionary* value) {
  uint64_t epoch;
  return arbol_attempt::keys(value,@[@"format",@"profileInstance",@"engine",@"dataEpoch",@"lastWriterBuild",@"lastWriterChromium",@"lastWriterElectron",@"requiredReader",@"cleanExit"])&&
    [value[@"format"] isEqual:@(arbol_attempt::profileFormat)]&&[value[@"engine"] isEqual:@"chromium"]&&
    arbol_attempt::pattern(value[@"profileInstance"],@"^prf_[A-Za-z0-9_-]{22}$")&&arbol_attempt::uintNumber(value[@"dataEpoch"],epoch)&&epoch>0&&
    arbol_attempt::pattern(value[@"lastWriterBuild"],@"^[1-9a-f][0-9a-f]{0,15}$")&&
    [value[@"lastWriterChromium"] isKindOfClass:NSString.class]&&[value[@"lastWriterChromium"] length]>0&&
    [value[@"lastWriterElectron"] isKindOfClass:NSString.class]&&[value[@"lastWriterElectron"] length]>0&&
    [value[@"requiredReader"] isKindOfClass:NSString.class]&&[value[@"requiredReader"] length]>0&&[value[@"requiredReader"] length]<=256&&
    value[@"cleanExit"]&&CFGetTypeID((__bridge CFTypeRef)value[@"cleanExit"])==CFBooleanGetTypeID();
}
struct ActivationResult {
  std::atomic<int> state{0}; double acknowledged=0;
  std::string path,digest;
};
class HostCapability {
  int capsule_=-1,stateFd_=-1; SharedState* state_=nullptr;
  int reads_[3]{-1,-1,-1},writes_[3]{-1,-1,-1}; unsigned role_=0;
  RetainedFamily* family_=nullptr;
  NSDictionary* value_=nil; std::string raw_; bool attempted_=false,valid_=false;
  NSDictionary* ordinaryProof_=nil; double ordinaryDeadline_=0;
  NSDictionary* quiescenceProof_=nil;
  bool terminalAttempted_=false,terminalUnresolved_=false,terminalCommitted_=false; double terminalDeadline_=0;
  std::shared_ptr<StorageResult> storageJob_; NSDictionary* storageProof_=nil; bool storageAttempted_=false;
  std::shared_ptr<ActivationResult> activationJob_; std::thread* activationThread_=nullptr; bool activationAttempted_=false;
  std::thread* storageThread_=nullptr; // one native process-lifetime handle, never a joinable temporary destructor
  bool ledgerDescriptor(int fd,unsigned index,bool writable,bool header=true) const {
    NSArray* streams=value_[@"family"];
    if(![streams isKindOfClass:NSArray.class]||streams.count!=3||index>2||fd<0) return false;
    NSDictionary* stream=streams[index]; uint64_t role;
    if(!arbol_attempt::keys(stream,@[@"role",@"path",@"identity",@"nonce"])||!arbol_attempt::uintNumber(stream[@"role"],role)||role!=index||
       !arbol_attempt::path(stream[@"path"])||!arbol_attempt::pattern(stream[@"nonce"],@"^[0-9a-f]{64}$")) return false;
    NSString* expected=[value_[@"receiptDirectory"][@"path"] stringByAppendingPathComponent:
      [@[@"family-main.log",@"family-primary.log",@"family-custody.log"] objectAtIndex:index]];
    std::string path=expected.fileSystemRepresentation; char actual[PATH_MAX]{}; struct stat held{},named{};
    int flags=fcntl(fd,F_GETFL);
    if(![stream[@"path"] isEqual:expected]||!arbol_boundary::canonical(path)||flags<0||
       (flags&O_ACCMODE)!=(writable?O_WRONLY:O_RDONLY)||fstat(fd,&held)||lstat(path.c_str(),&named)||
       !arbol_attempt::privateFile(held)||!arbol_attempt::privateFile(named)||held.st_dev!=named.st_dev||held.st_ino!=named.st_ino||
       ![fileIdentity(held) isEqual:stream[@"identity"]]||fcntl(fd,F_GETPATH,actual)||path!=actual) return false;
    if(!header) return true;
    LedgerHeader bytes{},expectedHeader{}; expectedHeader.role=index;
    memcpy(expectedHeader.capabilityDigest,[arbol_attempt::digest(raw_) UTF8String],65);
    memcpy(expectedHeader.nonce,[stream[@"nonce"] UTF8String],65);
    // Writer validation uses its already verified read-only sibling; no role
    // reopens a writer by pathname or acquires another writer's description.
    int reader=writable?reads_[index]:fd;
    return reader>=0&&held.st_size>=(off_t)sizeof(bytes)&&pread(reader,&bytes,sizeof(bytes),0)==sizeof(bytes)&&
      !memcmp(&bytes,&expectedHeader,sizeof(bytes));
  }
  bool createLedgers(NSString* directory,dev_t device,NSArray* __strong& streams) {
    int parent=open(directory.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(parent<0) return false;
    NSMutableArray* values=[NSMutableArray new]; bool ok=true;
    for(unsigned i=0;i<3&&ok;++i) {
      NSString* name=@[@"family-main.log",@"family-primary.log",@"family-custody.log"][i];
      int writer=openat(parent,name.UTF8String,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
      if(writer<0) { ok=false; break; }
      int reader=openat(parent,name.UTF8String,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
      struct stat w{},r{},named{};
      ok=reader>=0&&!fchmod(writer,0600)&&!fstat(writer,&w)&&!fstat(reader,&r)&&!fstatat(parent,name.UTF8String,&named,AT_SYMLINK_NOFOLLOW)&&
        arbol_attempt::privateFile(w)&&w.st_dev==device&&w.st_size==0&&w.st_dev==r.st_dev&&w.st_ino==r.st_ino&&w.st_dev==named.st_dev&&w.st_ino==named.st_ino;
      if(ok) { writes_[i]=fcntl(writer,F_DUPFD_CLOEXEC,64); reads_[i]=fcntl(reader,F_DUPFD_CLOEXEC,64); ok=writes_[i]>=64&&reads_[i]>=64; }
      if(close(writer)) ok=false; if(reader>=0&&close(reader)) ok=false;
      if(ok) [values addObject:@{@"role":@(i),@"path":[directory stringByAppendingPathComponent:name],@"identity":fileIdentity(w),
        @"nonce":arbol_attempt::digest(NSUUID.UUID.UUIDString.UTF8String)}];
    }
    if(ok) ok=!fsync(parent); if(close(parent)) ok=false;
    streams=values; return ok&&values.count==3;
  }
  bool initializeLedgers() {
    for(unsigned i=0;i<3;++i) {
      LedgerHeader header{}; header.role=i;
      memcpy(header.capabilityDigest,[arbol_attempt::digest(raw_) UTF8String],65);
      memcpy(header.nonce,[value_[@"family"][i][@"nonce"] UTF8String],65);
      size_t at=0; const char* bytes=(const char*)&header;
      while(at<sizeof(header)) { ssize_t n=pwrite(writes_[i],bytes+at,sizeof(header)-at,at); if(n>0) at+=n; else if(n<0&&errno==EINTR) continue; else return false; }
      if(fsync(writes_[i])||fcntl(writes_[i],F_FULLFSYNC)||!ledgerDescriptor(reads_[i],i,false)||!ledgerDescriptor(writes_[i],i,true)) return false;
    }
    return true;
  }
  bool loadLedgers(bool primary) {
    role_=primary?1:2;
    for(unsigned i=0;i<3;++i) {
      reads_[i]=fcntl(10+i,F_DUPFD_CLOEXEC,64);
      if(reads_[i]<64||!ledgerDescriptor(reads_[i],i,false)) return false;
    }
    writes_[role_]=fcntl(13,F_DUPFD_CLOEXEC,64);
    if(writes_[role_]<64||!ledgerDescriptor(writes_[role_],role_,true)) return false;
    if(primary) { writes_[2]=fcntl(14,F_DUPFD_CLOEXEC,64); if(writes_[2]<64||!ledgerDescriptor(writes_[2],2,true)) return false; }
    for(int fd=10;fd<=13+(primary?1:0);++fd) if(close(fd)) return false;
    return true;
  }
  bool attachFamily(arbol_boundary::Context& c) {
    if(family_||role_>2) return false;
    family_=new RetainedFamily(state_,role_,c.main,c.session,reads_,writes_[role_],value_,[arbol_attempt::digest(raw_) UTF8String]); c.family=family_; return true;
  }
public:
  HostCapability()=default; HostCapability(const HostCapability&)=delete; HostCapability& operator=(const HostCapability&)=delete;
  // Native custody keeps this object for process lifetime. A helper's OS exit
  // closes its own descriptions; no JS finalizer, unlock or disarm exists.
  int capsule() const { return capsule_; } int stateDescriptor() const { return stateFd_; }
  SharedState* shared() const { return state_; } NSDictionary* value() const { return value_; }
  const std::string& raw() const { return raw_; }
  bool present() const { return valid_ && state_ && value_; }
  bool spawnBindings(posix_spawn_file_actions_t& actions,arbol_boundary::SpawnCopies& copies,unsigned childRole) {
    if(!present()||!((role_==0&&childRole==1)||(role_==1&&childRole==2))) return false;
    if(!copies.map(actions,capsule_,8)||!copies.map(actions,stateFd_,9)) return false;
    for(unsigned i=0;i<3;++i) if(!ledgerDescriptor(reads_[i],i,false)||!copies.map(actions,reads_[i],10+i)) return false;
    if(!ledgerDescriptor(writes_[childRole],childRole,true)||!copies.map(actions,writes_[childRole],13)) return false;
    return childRole!=1||(ledgerDescriptor(writes_[2],2,true)&&copies.map(actions,writes_[2],14));
  }
  bool spawned(unsigned childRole) {
    // Close only actual producer aliases after successful actual spawn. The
    // child's own checked descriptors are already retained by the kernel.
    bool ok=true;
    for(unsigned i=childRole;i<3;++i) if(i!=role_&&writes_[i]>=0) {
      if(close(writes_[i])) ok=false; else writes_[i]=-1;
    }
    if(!ok) { state_->family.uncertain.store(1,std::memory_order_release); state_->poison(identityLoss); }
    return ok;
  }
  RetainedFamily* family() const { return family_; }
  bool exclusiveWriter() const {
    for(unsigned i=0;i<3;++i) if(i!=role_&&writes_[i]>=0) return false;
    return ledgerDescriptor(writes_[role_],role_,true);
  }

  bool prepare(arbol_boundary::Context& c,const std::string& input,double deadline) {
    if(attempted_) return false; attempted_=true;
    if(getpid()!=c.main.pid || !c.initial()) return false;
    NSDictionary* proposed=arbol_attempt::json(input);
    if(!arbol_attempt::keys(proposed,@[@"requestPath",@"runtime",@"prior"]) || !arbol_attempt::path(proposed[@"requestPath"])) return false;
    std::string request=[proposed[@"requestPath"] UTF8String]; arbol_attempt::Claim claim; std::string attemptRaw; NSDictionary* attempt=nil;
    arbol_attempt::PackagedLayout layout;
    if(!claim.acquire(request,deadline) || !claim.read(attemptRaw,attempt) || !arbol_attempt::launchRequest(claim,request,attempt) ||
       !arbol_attempt::claimedLayout(attempt,layout)||layout.bundle!=c.bundle||layout.guard!=c.build.path||
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
      [profileRecord[@"format"] isEqual:@(arbol_attempt::profileFormat)]&&[profileRecord[@"id"] isEqual:profile.lastPathComponent]&&
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
    NSString* receiptPath=[[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:attempt[@"profilePathHash"]] stringByAppendingPathComponent:attempt[@"request"]];
    NSArray* streams=nil; if(!createLedgers(receiptPath,root.st_dev,streams)) return false;

    value_=@{@"format":@1,@"kind":@"host-finalization",@"bootSession":boot,@"bundle":[NSString stringWithUTF8String:c.bundle.c_str()],
      @"main":arbol_boundary::capsuleIdentity(c.main,c.session),@"locks":@{@"owner":arbol_boundary::capsuleLock(c.owner),@"build":arbol_boundary::capsuleLock(c.build)},
      @"attempt":attempt,@"attemptPath":[NSString stringWithUTF8String:(claim.at.path+"/claim.json").c_str()],
      @"profileDirectory":fileIdentity(root),@"profileRecord":fileIdentity(record),@"profileRecordDigest":arbol_attempt::digest(profileRaw),
      @"directories":@{@"data":fileIdentity(data),@"userData":fileIdentity(userData)},
      @"receiptDirectory":@{@"path":[[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:attempt[@"profilePathHash"]] stringByAppendingPathComponent:attempt[@"request"]],@"identity":fileIdentity(receiptDirectory)},
      @"family":streams,@"runtime":proposed[@"runtime"],@"markerPath":[profile stringByAppendingPathComponent:@"engine.json"],@"prior":prior};
    raw_=arbol_attempt::bytes(value_); if(!initializeLedgers()) return false; capsule_=arbol_boundary::capsuleDescriptor(raw_); if(capsule_<0) return false;
    char temporary[]="/private/tmp/arbol-browser-state-XXXXXX"; int writer=mkstemp(temporary);
    if(writer<0) return false;
    bool ok=!fcntl(writer,F_SETFD,FD_CLOEXEC)&&!fchmod(writer,0600)&&!ftruncate(writer,sizeof(SharedState))&&!unlink(temporary);
    if(!ok) { (void)unlink(temporary); close(writer); return false; }
    stateFd_=fcntl(writer,F_DUPFD_CLOEXEC,10); if(close(writer)||stateFd_<0||!anonymousFile(stateFd_,true,sizeof(SharedState))) return false;
    void* mapping=mmap(nullptr,sizeof(SharedState),PROT_READ|PROT_WRITE,MAP_SHARED,stateFd_,0); if(mapping==MAP_FAILED) return false;
    state_=new(mapping) SharedState; memcpy(state_->capabilityDigest,[arbol_attempt::digest(raw_) UTF8String],65);
    if(!state_->main.bind(c.main,deadline)) return false; state_->enrolled.fetch_or(1,std::memory_order_release);
    for(unsigned i=0;i<3;++i) {
      struct stat st{}; LedgerHeader header{};
      if(fstat(reads_[i],&st)||pread(reads_[i],&header,sizeof(header),0)!=sizeof(header)) return false;
      LedgerFront front{LedgerStamp::from(st),0,0,0,[arbol_attempt::digest(std::string((const char*)&header,sizeof(header))) UTF8String]};
      if(!state_->family.roles[i].frontier.publish(front)) return false;
    }
    if(!attachFamily(c)) return false;
    valid_=arbol_boundary::clockMs()<deadline && metadata() && arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build);
    return valid_;
  }
  bool load(arbol_boundary::Context& c,bool primary,double deadline) {
    if(attempted_) return false; attempted_=true;
    if(!anonymousBytes(8,raw_,deadline)||!anonymousFile(9,true,sizeof(SharedState))) return false;
    value_=arbol_attempt::json(raw_); NSDictionary* main=value_[@"main"],*locks=value_[@"locks"],*attempt=value_[@"attempt"];
    arbol_attempt::PackagedLayout layout;
    if(!arbol_attempt::keys(value_,@[@"format",@"kind",@"bootSession",@"bundle",@"main",@"locks",@"attempt",@"attemptPath",@"profileDirectory",@"profileRecord",@"profileRecordDigest",@"directories",@"receiptDirectory",@"family",@"runtime",@"markerPath",@"prior"]) ||
       ![value_[@"format"] isEqual:@1]||![value_[@"kind"] isEqual:@"host-finalization"]||
       ![value_[@"bootSession"] isEqual:bootSession()]||
       ![value_[@"bundle"] isEqual:[NSString stringWithUTF8String:c.bundle.c_str()]]||
       ![main isEqual:arbol_boundary::capsuleIdentity(c.main,c.session)]||
       ![locks isEqual:@{@"owner":arbol_boundary::capsuleLock(c.owner),@"build":arbol_boundary::capsuleLock(c.build)}]||
       !arbol_attempt::record(attempt)||!arbol_attempt::claimedLayout(attempt,layout)||layout.bundle!=c.bundle||layout.guard!=c.build.path||
       ![attempt[@"candidateDigest"] isEqual:[NSString stringWithUTF8String:c.digest.c_str()]]||
       ![value_[@"markerPath"] isEqual:[attempt[@"profile"] stringByAppendingPathComponent:@"engine.json"]]||
       !arbol_attempt::runtime(value_[@"runtime"],attempt)) return false;
    capsule_=fcntl(8,F_DUPFD_CLOEXEC,10); stateFd_=fcntl(9,F_DUPFD_CLOEXEC,10);
    if(capsule_<0||stateFd_<0||close(8)||close(9)) return false;
    void* mapping=mmap(nullptr,sizeof(SharedState),PROT_READ|PROT_WRITE,MAP_SHARED,stateFd_,0); if(mapping==MAP_FAILED) return false;
    state_=static_cast<SharedState*>(mapping);
    if(memcmp(state_->magic,"ABR29S1",8)||state_->bytes!=sizeof(SharedState)||
       memcmp(state_->capabilityDigest,[arbol_attempt::digest(raw_) UTF8String],65)||!state_->main.is(c.main)) return false;
    if(!loadLedgers(primary)||!attachFamily(c)) return false;
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
  // Same actual descriptor supplies both bytes and the physical dirty marker
  // identity. No reopened inode can be paired with previously closed bytes.
  NSDictionary* boundMarker(arbol_boundary::Context& c) const {
    if(!present()||state_->markerBound.load(std::memory_order_acquire)!=1||!metadata()||
       !arbol_boundary::lockIdentity(c.owner)||!arbol_boundary::lockIdentity(c.build)) return nil;
    NSString* path=value_[@"attempt"][@"profile"];
    int root=open(path.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(root<0) return nil;
    struct stat parent{},namedParent{},first{},named{},last{},after{}; std::string raw;
    bool ok=!fstat(root,&parent)&&!lstat(path.fileSystemRepresentation,&namedParent)&&S_ISDIR(parent.st_mode)&&
      [fileIdentity(parent) isEqual:value_[@"profileDirectory"]]&&parent.st_dev==namedParent.st_dev&&parent.st_ino==namedParent.st_ino;
    int fd=ok?openat(root,"engine.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC):-1;
    ok=ok&&fd>=0&&!fstat(fd,&first)&&!fstatat(root,"engine.json",&named,AT_SYMLINK_NOFOLLOW)&&
      arbol_attempt::privateFile(first)&&arbol_attempt::sameFile(first,named)&&first.st_size>0&&first.st_size<16384;
    char bytes[4096];
    while(ok&&raw.size()<=(size_t)first.st_size) {
      ssize_t n=read(fd,bytes,std::min(sizeof(bytes),(size_t)first.st_size+1-raw.size()));
      if(n>0) raw.append(bytes,n); else if(!n) break; else if(errno!=EINTR) ok=false;
    }
    ok=ok&&raw.size()==(size_t)first.st_size&&!fstat(fd,&last)&&!fstatat(root,"engine.json",&after,AT_SYMLINK_NOFOLLOW)&&
      arbol_attempt::sameFile(first,last)&&arbol_attempt::sameFile(last,after);
    if(fd>=0&&close(fd)) ok=false;
    struct stat end{},endName{};
    ok=ok&&!fstat(root,&end)&&!lstat(path.fileSystemRepresentation,&endName)&&
      [fileIdentity(end) isEqual:value_[@"profileDirectory"]]&&end.st_dev==endName.st_dev&&end.st_ino==endName.st_ino;
    if(close(root)) ok=false;
    const auto& bound=state_->marker;
    NSDictionary* marker=arbol_attempt::json(raw); NSString* hash=arbol_attempt::digest(raw);
    ok=ok&&marker&&last.st_dev==(dev_t)bound.device&&last.st_ino==bound.inode&&last.st_uid==bound.uid&&last.st_size==(off_t)bound.size&&
      [hash isEqual:[NSString stringWithUTF8String:bound.digest]]&&[marker[@"cleanExit"] isEqual:@NO]&&
      [marker[@"dataEpoch"] unsignedLongLongValue]==bound.dataEpoch&&
      [marker[@"requiredReader"] isEqual:[NSString stringWithUTF8String:bound.reader]]&&
      arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build)&&metadata();
    return ok?@{@"identity":fileIdentity(last),@"digest":hash,@"value":marker}:nil;
  }
  bool bindOrdinaryQuiescence(arbol_boundary::Context& c,const ExitWatch& watch,double mainLimit) {
    if(quiescenceProof_||!present()||!watch.ordinaryBefore(mainLimit)||!arbol_boundary::same(watch.original(),c.main)||
       state_->fatal.load(std::memory_order_acquire)||!c.engineGone()||!family_||!family_->complete()) return false;
    NSDictionary* frontier=family_->frontierTuple(); double now=arbol_boundary::clockMs();
    if(!frontier||now>=mainLimit||state_->fatal.load(std::memory_order_acquire)) return false;
    quiescenceProof_=@{@"mainExitStatus":@(watch.status()),@"mainObservedUs":@((uint64_t)(watch.observedAt()*1000)),
      @"quiescentUs":@((uint64_t)(now*1000)),@"liveLimitUs":@((uint64_t)(mainLimit*1000)),@"family":frontier};
    return true;
  }
  bool hasOrdinaryQuiescence() const { return quiescenceProof_!=nil; }
  bool ordinaryCurrent(arbol_boundary::Context& c,double deadline) const {
    return present()&&role_==1&&getpid()==c.primary.pid&&arbol_boundary::clockMs()<deadline&&
      state_->fatal.load(std::memory_order_acquire)==0&&state_->enrolled.load(std::memory_order_acquire)==7&&
      state_->main.is(c.main)&&state_->primary.is(c.primary)&&state_->custody.is(c.custody)&&
      state_->admitted.load(std::memory_order_acquire)==1&&state_->markerBound.load(std::memory_order_acquire)==1&&
      c.primaryMonitor()&&c.primaryOutside&&arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build)&&
      c.engineGone()&&c.originalGone(c.custody)&&family_&&family_->complete()&&metadata()&&
      state_->fatal.load(std::memory_order_acquire)==0&&arbol_boundary::clockMs()<deadline;
  }
  bool collectOrdinary(arbol_boundary::Context& c,const ExitWatch& mainWatch,const ExitWatch& peerWatch,
    double mainLimit,double roundStart,double roundLimit) {
    if(ordinaryProof_) return false;
    // H/ACK proves timely original engine quiescence. Its frozen proof does
    // not renew or truncate the separate one-second T/K round. Durability is
    // bounded by the genuine already admitted overall Close/local-event budget.
    double deadline=(double)state_->closeOverallUs.load(std::memory_order_acquire)/1000;
    uint64_t grace=state_->closeGraceUs.load(std::memory_order_acquire);
    if(!quiescenceProof_||!grace||![quiescenceProof_[@"liveLimitUs"] isEqual:@((uint64_t)(mainLimit*1000))]||
       [quiescenceProof_[@"quiescentUs"] unsignedLongLongValue]>=grace||arbol_boundary::clockMs()>=roundLimit||
       !ordinaryCurrent(c,deadline)||!arbol_boundary::same(mainWatch.original(),c.main)||
       !arbol_boundary::same(peerWatch.original(),c.custody)||!mainWatch.ordinaryBefore(mainLimit)||!peerWatch.ordinaryBefore(roundLimit)||
       state_->primaryConsent.load(std::memory_order_acquire)!=1||state_->custodyConsent.load(std::memory_order_acquire)!=1||
       state_->shutdownOrder.load(std::memory_order_acquire)!=4||state_->retiredPages.load(std::memory_order_acquire)!=1||
       state_->domRequested.load(std::memory_order_acquire)!=1||state_->cookieAcknowledged.load(std::memory_order_acquire)!=1||
       state_->quitRequested.load(std::memory_order_acquire)!=1) return false;
    uint64_t times[4]; for(unsigned i=0;i<4;++i) times[i]=state_->shutdownTimes[i].load(std::memory_order_acquire);
    for(unsigned i=0;i<4;++i) if(!times[i]||(i&&times[i]<times[i-1])) return false;
    uint64_t primaryConsent=state_->primaryConsentUs.load(std::memory_order_acquire),custodyConsent=state_->custodyConsentUs.load(std::memory_order_acquire);
    if(times[3]>=(uint64_t)(mainWatch.observedAt()*1000)||primaryConsent<(uint64_t)(roundStart*1000)||
       custodyConsent<(uint64_t)(roundStart*1000)||primaryConsent>=(uint64_t)(roundLimit*1000)||
       custodyConsent>=(uint64_t)(peerWatch.observedAt()*1000)) return false;
    arbol_attempt::Claim claim; std::string currentRaw; NSDictionary* current=nil;
    if(!currentAttempt(c,claim,currentRaw,current,deadline)||![current[@"phase"] isEqual:@"closing"]||
       ![current[@"stage"] isEqual:@"admitted"]) return false;
    NSDictionary* marker=boundMarker(c),*frontier=family_->frontierTuple();
    if(!marker||!frontier||![frontier isEqual:quiescenceProof_[@"family"]]||!ordinaryCurrent(c,deadline)) return false;
    Identity self; if(arbol_boundary::observe(getpid(),self)!=1||!arbol_boundary::same(self,c.primary)) return false;
    ordinaryProof_=@{@"format":@1,@"kind":@"ordinary-post-exit",@"capabilityDigest":arbol_attempt::digest(raw_),
      @"bootSession":value_[@"bootSession"],@"attempt":current,@"runtime":value_[@"runtime"],
      @"profileDirectory":value_[@"profileDirectory"],@"profileRecordDigest":value_[@"profileRecordDigest"],
      @"main":value_[@"main"],@"primary":arbol_boundary::capsuleIdentity(c.primary),@"custody":arbol_boundary::capsuleIdentity(c.custody),
      @"lastHolder":arbol_boundary::capsuleIdentity(self,c.session),@"marker":marker,@"family":frontier,@"quiescence":quiescenceProof_,
      @"shutdown":@{@"pagesRetiredUs":@(times[0]),@"domRequestUs":@(times[1]),@"cookieCallbackUs":@(times[2]),@"quitIntentUs":@(times[3])},
      @"mainExit":@{@"status":@(mainWatch.status()),@"observedUs":@((uint64_t)(mainWatch.observedAt()*1000)),@"limitUs":@((uint64_t)(mainLimit*1000))},
      @"peerExit":@{@"status":@(peerWatch.status()),@"observedUs":@((uint64_t)(peerWatch.observedAt()*1000)),@"limitUs":@((uint64_t)(roundLimit*1000))},
      @"consent":@{@"roundUs":@((uint64_t)(roundStart*1000)),@"primaryUs":@(primaryConsent),@"custodyUs":@(custodyConsent)},
      @"deadlineUs":@((uint64_t)(deadline*1000)),@"collectedUs":@((uint64_t)(arbol_boundary::clockMs()*1000)),
      @"storageScope":@"pinned Chromium ordinary shutdown; emitted storage requires independent native durable synchronization"};
    ordinaryDeadline_=deadline; state_->ordinaryPostExitEligible.store(1,std::memory_order_release); return true;
  }
  NSDictionary* ordinaryProof() const { return ordinaryProof_; }
  double ordinaryDeadline() const { return ordinaryDeadline_; }
  bool storagePending() const { return storageJob_&&storageJob_->state.load(std::memory_order_acquire)==0; }
  bool startStorage(arbol_boundary::Context& c) {
    if(storageAttempted_) return false; storageAttempted_=true;
    if(!ordinaryProof_||!ordinaryCurrent(c,ordinaryDeadline_)||!family_->seal()||!arbol_boundary::retainNativeImage()||
       ![boundMarker(c) isEqual:ordinaryProof_[@"marker"]]||![family_->frontierTuple() isEqual:ordinaryProof_[@"family"]]) return false;
    arbol_boundary::Lock owner=c.owner,build=c.build;
    owner.fd=fcntl(c.owner.fd,F_DUPFD_CLOEXEC,64); build.fd=fcntl(c.build.fd,F_DUPFD_CLOEXEC,64);
    if(!arbol_boundary::lockIdentity(owner)||!arbol_boundary::lockIdentity(build)) {
      if(owner.fd>=0) close(owner.fd); if(build.fd>=0) close(build.fd); return false;
    }
    try {
      storageJob_=std::make_shared<StorageResult>(); auto result=storageJob_;
      NSDictionary* capability=value_; double deadline=ordinaryDeadline_; dev_t device=(dev_t)state_->marker.device;
      storageThread_=new std::thread([result,capability,deadline,device,owner,build] {
        @autoreleasepool { @try {
          result->started=arbol_boundary::clockMs(); bool ok=false;
          try {
            StorageScan scan(capability,deadline,device);
            ok=arbol_boundary::lockIdentity(owner)&&arbol_boundary::lockIdentity(build)&&scan.run(*result)&&
              arbol_boundary::lockIdentity(owner)&&arbol_boundary::lockIdentity(build);
          } catch(...) { ok=false; }
          if(close(owner.fd)) ok=false; if(close(build.fd)) ok=false;
          result->completed=arbol_boundary::clockMs();
          result->state.store(ok&&result->completed<deadline?1:-1,std::memory_order_release);
        } @catch(NSException*) {
          close(owner.fd); close(build.fd); result->completed=arbol_boundary::clockMs(); result->state.store(-1,std::memory_order_release);
        } }
      });
      // Even an exceptional detach failure leaves the actual running thread
      // and its one retained handle alive. Never terminate via a joinable
      // temporary destructor, close worker-owned guards or block on join.
      try { storageThread_->detach(); } catch(...) {}
      return true;
    } catch(...) {
      close(owner.fd); close(build.fd); if(storageJob_) storageJob_->state.store(-1,std::memory_order_release); return false;
    }
  }
  int pollStorage(arbol_boundary::Context& c) {
    if(!storageJob_||!present()||!ordinaryProof_||arbol_boundary::clockMs()>=ordinaryDeadline_||
       state_->fatal.load(std::memory_order_acquire)||!arbol_boundary::lockIdentity(c.owner)||!arbol_boundary::lockIdentity(c.build)) {
      if(state_) state_->poison(storageLoss); return -1;
    }
    int result=storageJob_->state.load(std::memory_order_acquire); if(!result) return 0;
    if(result<0||storageJob_->completed>=ordinaryDeadline_||!metadata()||
       ![boundMarker(c) isEqual:ordinaryProof_[@"marker"]]||![family_->frontierTuple() isEqual:ordinaryProof_[@"family"]]||
       !ordinaryCurrent(c,ordinaryDeadline_)) { state_->poison(storageLoss); return -1; }
    std::string ordinaryRaw=exitReceiptBytes(ordinaryProof_);
    if(ordinaryRaw.empty()) { state_->poison(storageLoss); return -1; }
    if(!storageProof_) storageProof_=@{@"format":@1,@"kind":@"native-emitted-storage-sync",@"ordinaryProofDigest":arbol_attempt::digest(ordinaryRaw),
      @"device":@((uint64_t)state_->marker.device),@"directories":value_[@"directories"],@"files":@(storageJob_->files),@"directoryCount":@(storageJob_->directories),
      @"metadataDigest":[NSString stringWithUTF8String:storageJob_->digest.c_str()],@"startedUs":@((uint64_t)(storageJob_->started*1000)),
      @"completedUs":@((uint64_t)(storageJob_->completed*1000)),@"deadlineUs":@((uint64_t)(ordinaryDeadline_*1000)),
      @"fileOperation":@"fsync+F_FULLFSYNC",@"directoryOperation":@"fsync",@"scope":@"opaque emitted data/userData; no stronger backend transaction claim"};
    if(exitReceiptBytes(storageProof_).empty()) { state_->poison(storageLoss); return -1; }
    return 1;
  }
  NSDictionary* storageProof() const { return storageProof_; }
  bool performActivation(arbol_boundary::Context& c,ActivationResult& result) {
    const double deadline=ordinaryDeadline_;
    arbol_attempt::Claim claim; std::string currentRaw; NSDictionary* current=nil;
    if(!storageProof_||!ordinaryCurrent(c,deadline)||!currentAttempt(c,claim,currentRaw,current,deadline)||
       ![current[@"phase"] isEqual:@"closing"]||![current[@"stage"] isEqual:@"admitted"]||
       ![boundMarker(c) isEqual:ordinaryProof_[@"marker"]]||![family_->frontierTuple() isEqual:ordinaryProof_[@"family"]]) return false;
    NSString* receiptPath=value_[@"receiptDirectory"][@"path"],*profile=value_[@"attempt"][@"profile"];
    NativeFile receipts,root;
    receipts.fd=open(receiptPath.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    root.fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat receiptRoot{},profileRoot{};
    if(receipts.fd<0||root.fd<0||fstat(receipts.fd,&receiptRoot)||fstat(root.fd,&profileRoot)||
       ![fileIdentity(receiptRoot) isEqual:value_[@"receiptDirectory"][@"identity"]]||
       ![fileIdentity(profileRoot) isEqual:value_[@"profileDirectory"]]||receiptRoot.st_dev!=profileRoot.st_dev||!metadata()) return false;
    Identity last; if(arbol_boundary::observe(getpid(),last)!=1||!arbol_boundary::same(last,c.primary)) return false;
    NSDictionary* journal=@{@"format":@1,@"kind":@"post-exit-journal",@"capability":value_,@"capabilityDigest":arbol_attempt::digest(raw_),
      @"ordinary":ordinaryProof_,@"storage":storageProof_,@"lastHolder":arbol_boundary::capsuleIdentity(last,c.session)};
    std::string journalRaw=exitReceiptBytes(journal); struct stat journalIdentity{};
    if(journalRaw.empty()) return false;
    if(!publishNativeReceipt(receipts.fd,"proof.json",journalRaw,deadline,journalIdentity)||
       !ordinaryCurrent(c,deadline)||![boundMarker(c) isEqual:ordinaryProof_[@"marker"]]) return false;
    // The journal and emitted-storage acknowledgements precede ANY clean-bit
    // mutation. Preserve the normative closed marker schema exactly.
    NSMutableDictionary* clean=[ordinaryProof_[@"marker"][@"value"] mutableCopy]; clean[@"cleanExit"]=@YES;
    std::string cleanRaw=arbol_attempt::bytes(clean),temporary=".engine-"+std::string(NSUUID.UUID.UUIDString.UTF8String);
    NativeFile cleanFile; struct stat cleanIdentity{};
    uint32_t untouched=0;
    if(!state_->activation.compare_exchange_strong(untouched,1,std::memory_order_acq_rel)) return false;
    if(!writeNativeFile(root.fd,temporary,cleanRaw,deadline,cleanFile)||!ordinaryCurrent(c,deadline)||
       ![boundMarker(c) isEqual:ordinaryProof_[@"marker"]]||!arbol_attempt::unchanged(claim.at)||
       renameat(root.fd,temporary.c_str(),root.fd,"engine.json")||
       !publishedNativeFile(root.fd,"engine.json",cleanRaw,cleanFile,cleanIdentity,deadline)||!cleanFile.finish()) return false;
    NSDictionary* cleanMarker=@{@"identity":fileIdentity(cleanIdentity),@"digest":arbol_attempt::digest(cleanRaw),@"value":clean};
    std::string actualClean,actualJournal; struct stat checkedClean{},checkedJournal{};
    if(!ordinaryCurrent(c,deadline)||!readNativeFile(root.fd,"engine.json",actualClean,checkedClean,arbol_attempt::limit)||actualClean!=cleanRaw||
       !arbol_attempt::sameFile(cleanIdentity,checkedClean)||!readNativeFile(receipts.fd,"proof.json",actualJournal,checkedJournal,exitReceiptLimit)||
       actualJournal!=journalRaw||!arbol_attempt::sameFile(journalIdentity,checkedJournal)||
       ![family_->frontierTuple() isEqual:ordinaryProof_[@"family"]]) return false;
    NSDictionary* activation=@{@"format":@1,@"kind":@"activated-exit",@"bootSession":value_[@"bootSession"],
      @"profileInstance":current[@"profileInstance"],@"profilePathHash":current[@"profilePathHash"],@"request":current[@"request"],
      @"build":current[@"build"],@"sourceDigest":current[@"sourceDigest"],@"productDigest":current[@"productDigest"],@"candidateDigest":current[@"candidateDigest"],
      @"profileDirectory":value_[@"profileDirectory"],@"capabilityDigest":arbol_attempt::digest(raw_),@"marker":cleanMarker,
      @"journal":@{@"path":[receiptPath stringByAppendingPathComponent:@"proof.json"],@"identity":fileIdentity(journalIdentity),@"digest":arbol_attempt::digest(journalRaw)},
      @"main":value_[@"main"],@"primary":arbol_boundary::capsuleIdentity(c.primary),@"custody":arbol_boundary::capsuleIdentity(c.custody),
      @"lastHolder":arbol_boundary::capsuleIdentity(last,c.session),@"deadlineUs":@((uint64_t)(deadline*1000))};
    std::string activationRaw=exitReceiptBytes(activation); struct stat activationIdentity{};
    if(activationRaw.empty()) return false;
    if(!ordinaryCurrent(c,deadline)||!publishNativeReceipt(receipts.fd,"activation.json",activationRaw,deadline,activationIdentity)||
       !ordinaryCurrent(c,deadline)||!arbol_attempt::unchanged(claim.at)) return false;
    // This existing native terminal reference is written ONLY after actual
    // activation file+parent synchronization acknowledgement inside the
    // original cutoff. Independent readers require it, the complete matching
    // activation/journal/marker and later actual last-holder absence. A lone
    // clean bit or an interrupted/late unacknowledged activation grants nothing.
    NSString* activationPath=[receiptPath stringByAppendingPathComponent:@"activation.json"];
    NSMutableDictionary* closed=[current mutableCopy]; closed[@"phase"]=@"closed";
    closed[@"terminal"]=@{@"path":activationPath,@"digest":arbol_attempt::digest(activationRaw)};
    std::string closedRaw=arbol_attempt::bytes(closed);
    if(!arbol_attempt::transition(current,closed,arbol_attempt::Role::terminal)||
       !arbol_attempt::replace(claim.at,currentRaw,false,closedRaw)) return false;
    NativeFile finalClaim; finalClaim.fd=openat(claim.at.directory,"claim.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    std::string checkedClaim; struct stat claimIdentity{},heldClaim{},afterClaim{};
    if(finalClaim.fd<0||fstat(finalClaim.fd,&heldClaim)||!arbol_attempt::privateFile(heldClaim)||
       fsync(finalClaim.fd)||fcntl(finalClaim.fd,F_FULLFSYNC)||fsync(claim.at.directory)||
       !readNativeFile(claim.at.directory,"claim.json",checkedClaim,claimIdentity,arbol_attempt::limit)||checkedClaim!=closedRaw||
       fstat(finalClaim.fd,&afterClaim)||!arbol_attempt::sameFile(heldClaim,afterClaim)||!arbol_attempt::sameFile(afterClaim,claimIdentity)||
       !arbol_attempt::unchanged(claim.at)||!ordinaryCurrent(c,deadline)||!finalClaim.finish()||!root.finish()||!receipts.finish()) return false;
    result.path=activationPath.fileSystemRepresentation; result.digest=[arbol_attempt::digest(activationRaw) UTF8String];
    result.acknowledged=arbol_boundary::clockMs();
    if(result.acknowledged>=deadline||state_->fatal.load(std::memory_order_acquire)) { state_->poison(storageLoss); return false; }
    uint32_t inFlight=1;
    return state_->activation.compare_exchange_strong(inFlight,2,std::memory_order_acq_rel);
  }
  bool activationUnresolved() const {
    if(!present()) return false; uint32_t value=state_->activation.load(std::memory_order_acquire); return value==1||value==3;
  }
  bool activationCommitted() const { return present()&&state_->activation.load(std::memory_order_acquire)==2; }
  bool activationPending() const { return activationJob_&&activationJob_->state.load(std::memory_order_acquire)==0; }
  bool startActivation(arbol_boundary::Context& c) {
    if(activationAttempted_) return false; activationAttempted_=true;
    if(!storageProof_||!ordinaryCurrent(c,ordinaryDeadline_)||storagePending()||!arbol_boundary::retainNativeImage()) return false;
    arbol_boundary::Context retained=c;
    retained.owner.fd=fcntl(c.owner.fd,F_DUPFD_CLOEXEC,64); retained.build.fd=fcntl(c.build.fd,F_DUPFD_CLOEXEC,64);
    if(!arbol_boundary::lockIdentity(retained.owner)||!arbol_boundary::lockIdentity(retained.build)) {
      if(retained.owner.fd>=0) close(retained.owner.fd); if(retained.build.fd>=0) close(retained.build.fd); return false;
    }
    try {
      activationJob_=std::make_shared<ActivationResult>(); auto result=activationJob_;
      activationThread_=new std::thread([this,result,retained]() mutable {
        bool ok=false;
        @autoreleasepool { @try { try { ok=performActivation(retained,*result); } catch(...) { ok=false; } } @catch(NSException*) { ok=false; } }
        // No proof, mutation or I/O remains after successful publication. Native
        // original descriptions remain held in the live main protocol thread.
        close(retained.owner.fd); close(retained.build.fd);
        if(activationCommitted()) ok=true; // no later delivery/cleanup exception erases a won commit
        if(!ok) state_->poison(storageLoss);
        result->state.store(ok?1:-1,std::memory_order_release);
      });
      try { activationThread_->detach(); } catch(...) {} // retain one truthful process-lifetime handle
      return true;
    } catch(...) {
      close(retained.owner.fd); close(retained.build.fd); if(activationJob_) activationJob_->state.store(-1,std::memory_order_release); return false;
    }
  }
  int pollActivation(arbol_boundary::Context& c) {
    if(!activationJob_) return -1;
    int result=activationJob_->state.load(std::memory_order_acquire);
    if(activationCommitted()) {
      // The exact native commit already won. Join the actual retained worker's
      // completion, even when the CLI's delivery window has since expired.
      if(!result) return 0;
      return result==1&&activationJob_->acknowledged<ordinaryDeadline_&&arbol_boundary::current(c.primary)==1&&
        arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build)?1:-1;
    }
    if(result<0||arbol_boundary::clockMs()>=ordinaryDeadline_||state_->fatal.load(std::memory_order_acquire)) {
      state_->poison(storageLoss); // CAS refusal prevents a later worker commit
      if(activationCommitted()) return 0; // commit won the same actual arbitration
      return -1;
    }
    return 0;
  }
  bool originalMonitor(arbol_boundary::Context& c) const {
    if(!present()||getpid()==c.main.pid||state_->enrolled.load(std::memory_order_acquire)!=7||
       !state_->main.is(c.main)||!state_->primary.is(c.primary)||!state_->custody.is(c.custody)||
       !arbol_boundary::lockIdentity(c.owner)||!arbol_boundary::lockIdentity(c.build)||!metadata()) return false;
    if(role_==1&&getpid()==c.primary.pid) return c.primaryMonitor();
    return role_==2&&getpid()==c.custody.pid&&c.monitor(c.custody,true);
  }
  bool canHandoff(arbol_boundary::Context& c,double roundLimit) {
    return originalMonitor(c)&&role_==2&&arbol_boundary::clockMs()<roundLimit&&!activationUnresolved()&&!terminalUnresolved_&&
      state_->custodyConsent.load(std::memory_order_acquire)==1&&state_->custodyConsentUs.load(std::memory_order_acquire)&&
      c.primaryMonitor()&&arbol_boundary::current(c.primary)==1&&c.engineGone()&&family_&&family_->complete()&&family_->seal();
  }
  bool canExitCommitted(arbol_boundary::Context& c) {
    return activationCommitted()&&activationJob_&&activationJob_->state.load(std::memory_order_acquire)==1&&
      activationJob_->acknowledged<ordinaryDeadline_&&!activationPending()&&!storagePending()&&role_==1&&
      originalMonitor(c)&&c.engineGone()&&c.originalGone(c.custody)&&family_&&family_->complete();
  }
  // Dirty termination certifies no flush and never changes engine.json. It
  // binds either the actual accepted dirty inode, the exact planned dirty
  // digest after an interrupted mutation, or the unchanged authenticated prior.
  id terminalMarker(arbol_boundary::Context& c) const {
    if(!present()||!metadata()||!arbol_boundary::lockIdentity(c.owner)||!arbol_boundary::lockIdentity(c.build)) return nil;
    if(state_->markerBound.load(std::memory_order_acquire)==1) return boundMarker(c);
    NSString* profile=value_[@"attempt"][@"profile"]; NativeFile root;
    root.fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(root.fd<0) return nil;
    struct stat directory{},named{},markerIdentity{}; std::string raw;
    if(fstat(root.fd,&directory)||![fileIdentity(directory) isEqual:value_[@"profileDirectory"]]) return nil;
    errno=0; bool absent=fstatat(root.fd,"engine.json",&named,AT_SYMLINK_NOFOLLOW)<0;
    if(absent&&errno!=ENOENT) return nil;
    id marker=NSNull.null;
    if(!absent) {
      if(!readNativeFile(root.fd,"engine.json",raw,markerIdentity,arbol_attempt::limit)) return nil;
      NSDictionary* actual=arbol_attempt::json(raw);
      if(!terminalEngineMarker(actual)||![actual[@"profileInstance"] isEqual:value_[@"attempt"][@"profileInstance"]]) return nil;
      marker=@{@"identity":fileIdentity(markerIdentity),@"digest":arbol_attempt::digest(raw),@"value":actual};
      if(state_->mutation.load(std::memory_order_acquire)==1&&state_->expectedMarkerDigest[0]&&
         [marker[@"digest"] isEqual:[NSString stringWithUTF8String:state_->expectedMarkerDigest]]&&[actual[@"cleanExit"] isEqual:@NO]) {
        if(!root.finish()||!metadata()) return nil; return marker;
      }
    }
    NSDictionary* prior=value_[@"prior"];
    bool matches=[prior[@"kind"] isEqual:@"absent"]&&absent;
    if([@[@"activated",@"terminal"] containsObject:prior[@"kind"]]) {
      NSString* path=prior[@"path"],*state=profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
      NSString* prefix=[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:value_[@"attempt"][@"profilePathHash"]];
      if(![path hasPrefix:[prefix stringByAppendingString:@"/"]]||![@[@"activation.json",@"terminal.json"] containsObject:path.lastPathComponent]||
         !arbol_boundary::canonical(path.fileSystemRepresentation)) return nil;
      NativeFile parent; parent.fd=open(path.stringByDeletingLastPathComponent.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      std::string previous; struct stat identity{};
      if(parent.fd<0||!readNativeFile(parent.fd,path.lastPathComponent.UTF8String,previous,identity,exitReceiptLimit)||
         ![arbol_attempt::digest(previous) isEqual:prior[@"digest"]]) return nil;
      NSDictionary* receipt=parseExitReceipt(previous);
      matches=receipt&&[receipt[@"profileInstance"] isEqual:value_[@"attempt"][@"profileInstance"]]&&
        [receipt[@"profilePathHash"] isEqual:value_[@"attempt"][@"profilePathHash"]]&&[receipt[@"profileDirectory"] isEqual:value_[@"profileDirectory"]]&&
        [receipt[@"marker"] isEqual:marker];
      if(!parent.finish()) return nil;
    }
    if(absent) { errno=0; if(fstatat(root.fd,"engine.json",&named,AT_SYMLINK_NOFOLLOW)>=0||errno!=ENOENT) return nil; }
    if(!root.finish()||!metadata()||!arbol_boundary::lockIdentity(c.owner)||!arbol_boundary::lockIdentity(c.build)) return nil;
    return matches?marker:nil;
  }
  bool dirtyMonitorCurrent(arbol_boundary::Context& c,double deadline) {
    if(!originalMonitor(c)||activationCommitted()||activationUnresolved()||storagePending()||activationPending()||
       state_->fatal.load(std::memory_order_acquire)==0||arbol_boundary::clockMs()>=deadline||!c.engineGone()||!family_||!family_->complete()) return false;
    const auto& peer=role_==1?c.custody:c.primary;
    return c.originalGone(peer)&&arbol_boundary::clockMs()<deadline;
  }
  bool originalMain(arbol_boundary::Context& c) const {
    arbol_boundary::Identity actual; std::string image;
    return present()&&role_==0&&getpid()==c.main.pid&&c.authenticated&&c.foundation()&&exclusiveWriter()&&
      state_->enrolled.load(std::memory_order_acquire)==7&&state_->main.is(c.main)&&
      c.primary.pid>1&&c.custody.pid>1&&state_->primary.is(c.primary)&&state_->custody.is(c.custody)&&
      arbol_boundary::observe(getpid(),actual)==1&&arbol_boundary::same(actual,c.main)&&actual.group==c.main.group&&
      getsid(0)==c.session&&arbol_boundary::executable(actual,image)&&image==c.engine()&&arbol_boundary::signature(image,true)&&metadata();
  }
  bool dirtyMainCurrent(arbol_boundary::Context& c,double deadline) {
    return originalMain(c)&&!activationCommitted()&&!activationUnresolved()&&!storagePending()&&!activationPending()&&
      state_->fatal.load(std::memory_order_acquire)!=0&&arbol_boundary::clockMs()<deadline&&
      c.engineGone(true)&&c.originalGone(c.primary)&&c.originalGone(c.custody)&&family_&&family_->complete()&&
      arbol_boundary::clockMs()<deadline;
  }
  bool publishDirtyTerminal(arbol_boundary::Context& c,bool mainLast) {
    auto original=[&] { return mainLast?originalMain(c):originalMonitor(c); };
    auto gone=[&] { return mainLast?(c.engineGone(true)&&c.originalGone(c.primary)&&c.originalGone(c.custody)):
      (c.engineGone()&&c.originalGone(role_==1?c.custody:c.primary)); };
    auto currentTerminal=[&] { return mainLast?dirtyMainCurrent(c,terminalDeadline_):dirtyMonitorCurrent(c,terminalDeadline_); };
    if(terminalCommitted_) return original()&&gone();
    if(terminalAttempted_||!original()||activationCommitted()||activationUnresolved()||storagePending()||activationPending()) return false;
    state_->poison(forced); // irreversible dirty attribution precedes its final proof
    // No engine or caller deadline is renewed. This separate one-shot bounded
    // METADATA phase starts only after genuine whole-engine/peer quiescence.
    // Late dirty evidence can serve a later independent reader, never turn an
    // expired Close into success; its original cutoffs remain recorded below.
    if(!gone()||!family_||!family_->complete()) return false;
    terminalAttempted_=true;
    terminalDeadline_=arbol_boundary::clockMs()+1000;
    if(!currentTerminal()||!family_->seal()) return false;
    terminalUnresolved_=true;
    @try { try {
      arbol_attempt::Claim claim; std::string raw; NSDictionary* current=nil;
      if(!currentAttempt(c,claim,raw,current,terminalDeadline_)) return false;
      id marker=terminalMarker(c); NSDictionary* frontier=family_->frontierTuple(); Identity self;
      if(!marker||!frontier||arbol_boundary::observe(getpid(),self)!=1||
         !arbol_boundary::same(self,mainLast?c.main:(role_==1?c.primary:c.custody))||!currentTerminal()) return false;
      NSDictionary* receipt=@{@"format":@1,@"kind":@"terminal-exit",@"disposition":@"dirty",@"bootSession":value_[@"bootSession"],
        @"profileInstance":current[@"profileInstance"],@"profilePathHash":current[@"profilePathHash"],@"profileDirectory":value_[@"profileDirectory"],
        @"profileRecordDigest":value_[@"profileRecordDigest"],@"request":current[@"request"],@"build":current[@"build"],
        @"sourceDigest":current[@"sourceDigest"],@"productDigest":current[@"productDigest"],@"candidateDigest":current[@"candidateDigest"],
        @"capability":value_,@"capabilityDigest":arbol_attempt::digest(raw_),@"attempt":current,@"runtime":value_[@"runtime"],
        @"main":value_[@"main"],@"primary":arbol_boundary::capsuleIdentity(c.primary),@"custody":arbol_boundary::capsuleIdentity(c.custody),
        @"lastHolder":arbol_boundary::capsuleIdentity(self,c.session),@"lastRole":mainLast?@"main":(role_==1?@"primary":@"custody"),@"marker":marker,@"family":frontier,
        @"nativeState":@{@"fatal":@(state_->fatal.load(std::memory_order_acquire)),@"fatalCutoffUs":@(state_->fatalCutoffUs.load(std::memory_order_acquire)),
          @"enrolled":@(state_->enrolled.load(std::memory_order_acquire)),@"transfer":@(state_->transfer.load(std::memory_order_acquire)),
          @"mutation":@(state_->mutation.load(std::memory_order_acquire)),@"markerBound":@(state_->markerBound.load(std::memory_order_acquire)),
          @"sealedSession":@(state_->admitted.load(std::memory_order_acquire)),@"activation":@(state_->activation.load(std::memory_order_acquire))},
        @"originalClose":@{@"receivedUs":@(state_->closeReceivedUs.load(std::memory_order_acquire)),
          @"graceUs":@(state_->closeGraceUs.load(std::memory_order_acquire)),@"overallUs":@(state_->closeOverallUs.load(std::memory_order_acquire))},
        @"observedUs":@((uint64_t)(arbol_boundary::clockMs()*1000)),@"metadataDeadlineUs":@((uint64_t)(terminalDeadline_*1000))};
      std::string bytes=exitReceiptBytes(receipt); if(bytes.empty()) return false;
      NSString* path=value_[@"receiptDirectory"][@"path"]; NativeFile directory;
      directory.fd=open(path.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); struct stat identity{},published{};
      if(directory.fd<0||fstat(directory.fd,&identity)||![fileIdentity(identity) isEqual:value_[@"receiptDirectory"][@"identity"]]||
         !publishNativeReceipt(directory.fd,"terminal.json",bytes,terminalDeadline_,published)||!currentTerminal()||
         ![terminalMarker(c) isEqual:marker]||![family_->frontierTuple() isEqual:frontier]) return false;
      NSMutableDictionary* closed=[current mutableCopy]; closed[@"phase"]=@"closed";
      closed[@"terminal"]=@{@"path":[path stringByAppendingPathComponent:@"terminal.json"],@"digest":arbol_attempt::digest(bytes)};
      std::string next=arbol_attempt::bytes(closed);
      if(!arbol_attempt::transition(current,closed,arbol_attempt::Role::terminal)||!arbol_attempt::replace(claim.at,raw,false,next)) return false;
      NativeFile proof; proof.fd=openat(claim.at.directory,"claim.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
      std::string checked; struct stat before{},after{},named{};
      if(proof.fd<0||fstat(proof.fd,&before)||fsync(proof.fd)||fcntl(proof.fd,F_FULLFSYNC)||fsync(claim.at.directory)||
         !readNativeFile(claim.at.directory,"claim.json",checked,named,arbol_attempt::limit)||checked!=next||fstat(proof.fd,&after)||
         !arbol_attempt::sameFile(before,after)||!arbol_attempt::sameFile(after,named)||!arbol_attempt::unchanged(claim.at)||
         !currentTerminal()||![terminalMarker(c) isEqual:marker]||!proof.finish()||!directory.finish()) return false;
      terminalCommitted_=true; terminalUnresolved_=false; return true;
    } catch(...) { return false; } } @catch(NSException*) { return false; }
  }
  bool publishDirtyMonitor(arbol_boundary::Context& c) { return publishDirtyTerminal(c,false); }
  bool publishDirtyMain(arbol_boundary::Context& c) { return publishDirtyTerminal(c,true); }
  bool terminalUnresolved() const { return terminalUnresolved_; }
  bool held(arbol_boundary::Context& c,const arbol_boundary::ReadOnlyMonitorImage* retained=nullptr) const {
    return present()&&exclusiveWriter()&&state_->enrolled.load(std::memory_order_acquire)==7&&
      state_->main.is(c.main)&&state_->primary.is(c.primary)&&state_->custody.is(c.custody)&&
      arbol_boundary::current(c.main)==1&&arbol_boundary::current(c.primary)==1&&arbol_boundary::current(c.custody)==1&&
      getpgid(c.main.pid)==(int)c.main.group&&getsid(c.main.pid)==c.session&&c.primaryMonitor(retained)&&c.monitor(c.custody,true,retained)&&
      arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build)&&metadata();
  }
  bool ready(arbol_boundary::Context& c) const { return held(c)&&state_->fatal.load(std::memory_order_acquire)==0; }
};
// A distinct pre-profile-use terminal producer. This never substitutes for
// HostCapability enrollment, full-family dirty closure or a storage flush.
// All setters are native-only, one-way and precede possible actual permission.
class NoUseOriginal {
  bool attempted_=false,valid_=false,uncertain_=false,publicationAttempted_=false,committed_=false;
  bool execIntent_=false,execFailedReturned_=false,ownerAttempted_=false,noClaimConfirmed_=false;
  uint32_t permissions_=0; int execError_=0; double metadataDeadline_=0;
  std::string requestPath_,bundle_,initialRaw_,baselineRaw_,closedRaw_;
  NSDictionary* baseline_=nil,*actor_=nil; NSString* stage_=nil;
  arbol_boundary::Lock build_,owner_;
  bool self() const {
    if(!valid_||uncertain_||permissions_||!arbol_boundary::lockIdentity(build_)||
       (ownerAttempted_&&!arbol_boundary::lockIdentity(owner_))||!arbol_attempt::currentProcess(actor_,true)) return false;
    std::string image=[actor_[@"executable"] UTF8String];
    bool outer=[stage_ isEqual:@"outer"];
    if(image!=bundle_+(outer?"/Contents/MacOS/arbol-browser-native":"/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron")||
       [actor_[@"group"] intValue]!=getpid()||!arbol_boundary::signature(image,!outer)) return false;
    return !outer||!execIntent_||(execFailedReturned_&&execError_!=0);
  }
  bool emptyCensus() {
    if(!self()) return false;
    std::vector<pid_t> pids(16385); unsigned present=0;
    int bytes=proc_listpids(PROC_PGRP_ONLY,getpgrp(),pids.data(),(int)(pids.size()*sizeof(pid_t)));
    if(bytes<0||bytes%sizeof(pid_t)||(size_t)bytes>=pids.size()*sizeof(pid_t)) return false;
    for(int i=0;i<bytes/(int)sizeof(pid_t);++i) {
      if(pids[i]<=0) continue;
      if(pids[i]!=getpid()) { uncertain_=true; return false; }
      if(!arbol_attempt::currentProcess(actor_,true)) return false; ++present;
    }
    if(present!=1) return false;
    bytes=proc_listpids(PROC_UID_ONLY,geteuid(),pids.data(),(int)(pids.size()*sizeof(pid_t)));
    if(bytes<0||bytes%sizeof(pid_t)||(size_t)bytes>=pids.size()*sizeof(pid_t)) return false;
    uint64_t start=strtoull([actor_[@"startId"] UTF8String],nullptr,10); int version=[actor_[@"pidVersion"] intValue];
    for(int i=0;i<bytes/(int)sizeof(pid_t);++i) {
      if(pids[i]<=0||pids[i]==getpid()) continue; arbol_boundary::Identity actual; arbol_boundary::Info detail{};
      int state=arbol_boundary::observe(pids[i],actual,&detail); if(!state) continue; if(state<0) return false;
      // No supported descendant ever had a native spawn permission. Even a
      // same-publisher child is not silently adopted into a no-use witness.
      if(detail.unique.parent==start&&detail.unique.originalParentVersion==version) { uncertain_=true; return false; }
    }
    return self();
  }
  bool current(NSDictionary* value) const {
    if(!arbol_attempt::record(value)||!arbol_attempt::immutable(baseline_,value)||
       ![value[@"bootstrap"] isEqual:baseline_[@"bootstrap"]]||![value[@"engine"] isEqual:baseline_[@"engine"]]||
       ![value[@"stage"] isEqual:@"untransferred"]||value[@"terminal"]!=NSNull.null||
       ![@[@"claimed",@"cancelled"] containsObject:value[@"phase"]]||
       !arbol_attempt::sameRuntimeBinding(baseline_[@"runtime"],value[@"runtime"])) return false;
    return value[@"runtime"]==NSNull.null||([value[@"runtime"][@"phase"] isEqual:@"starting"]&&
      [value[@"runtime"][@"pid"] isEqual:actor_[@"pid"]]&&[value[@"runtime"][@"processStartId"] isEqual:actor_[@"startId"]]);
  }
  bool priorData(int history,NSDictionary* __strong& prior,std::string& headRaw,bool& absent) const {
    if(!arbol_attempt::readAt(history,"previous-claim.json",headRaw,absent)) return false;
    if(absent) { prior=(id)NSNull.null; return true; }
    NSDictionary* head=arbol_attempt::json(headRaw);
    if(!arbol_attempt::record(head)||![head[@"phase"] isEqual:@"closed"]||
       ![head[@"profile"] isEqual:baseline_[@"profile"]]||![head[@"profileInstance"] isEqual:baseline_[@"profileInstance"]]||head[@"terminal"]==NSNull.null) return false;
    NSString* name=[head[@"terminal"][@"path"] lastPathComponent];
    if([@[@"activation.json",@"terminal.json"] containsObject:name]) { prior=head; return true; }
    if(![name isEqual:@"unused.json"]) return false;
    NSString* path=head[@"terminal"][@"path"];
    NSString* expected=[[[[baseline_[@"profile"] stringByDeletingLastPathComponent].stringByDeletingLastPathComponent
      stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:baseline_[@"profilePathHash"]] stringByAppendingPathComponent:head[@"request"]];
    if(![path.stringByDeletingLastPathComponent isEqual:expected]||!arbol_boundary::canonical(path.fileSystemRepresentation)) return false;
    NativeFile directory; directory.fd=open(expected.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    std::string raw; struct stat identity{};
    if(directory.fd<0||!readNativeFile(directory.fd,"unused.json",raw,identity,exitReceiptLimit)||
       ![arbol_attempt::digest(raw) isEqual:head[@"terminal"][@"digest"]]) return false;
    NSDictionary* previous=parseExitReceipt(raw); prior=previous[@"priorDataClaim"];
    if(![previous[@"kind"] isEqual:@"unused-host-terminal"]||!arbol_attempt::record(previous[@"attempt"])||
       !arbol_attempt::immutable(previous[@"attempt"],head)||!prior||!directory.finish()) return false;
    if(prior==(id)NSNull.null) return true;
    return arbol_attempt::record(prior)&&[prior[@"phase"] isEqual:@"closed"]&&
      [prior[@"profile"] isEqual:baseline_[@"profile"]]&&[prior[@"profileInstance"] isEqual:baseline_[@"profileInstance"]]&&
      [@[@"activation.json",@"terminal.json"] containsObject:[prior[@"terminal"][@"path"] lastPathComponent]];
  }
public:
  NoUseOriginal()=default; NoUseOriginal(const NoUseOriginal&)=delete;
  ~NoUseOriginal() { if(attempted_) finish(); }
  // Called on the actual native transition path before its write attempt. A
  // partly failed write is reconciled under the same genuine Claim; it cannot
  // become a bare post-claim return. Failure to capture retains the real FD.
  void capture(const std::string& request,const std::string& bundle,const arbol_boundary::Lock& build,
    NSDictionary* baseline,NSString* stage,const std::string& initial={}) {
    if(attempted_) { uncertain_=true; return; } attempted_=true;
    build_=build; build_.fd=fcntl(build.fd,F_DUPFD_CLOEXEC,64);
    requestPath_=request; bundle_=bundle; baselineRaw_=arbol_attempt::bytes(baseline); baseline_=arbol_attempt::json(baselineRaw_); initialRaw_=initial;
    actor_=arbol_attempt::processRecord(getpid()); stage_=stage;
    arbol_attempt::PackagedLayout layout;
    if(!arbol_attempt::record(baseline_)||!arbol_attempt::claimedLayout(baseline_,layout)||layout.bundle!=bundle||layout.guard!=build.path||
       ![baseline_[@"stage"] isEqual:@"untransferred"]||
       ![baseline_[@"phase"] isEqual:@"claimed"]||!actor_||![@[@"outer",@"post-exec",@"adopted"] containsObject:stage_]||
       ![baseline_[@"buildGuard"] isEqual:[NSString stringWithUTF8String:build.path.c_str()]]) return;
    NSDictionary* parent=baseline_[@"bootstrap"];
    if(!arbol_attempt::process(parent)) return;
    if([stage_ isEqual:@"outer"]) { if(![actor_ isEqual:parent]||baseline_[@"engine"]!=NSNull.null||baseline_[@"runtime"]!=NSNull.null) return; }
    else {
      for(NSString* field in @[@"pid",@"uid",@"startId",@"group",@"session",@"parentStartId",@"parentPidVersion"])
        if(![actor_[field] isEqual:parent[field]]) return;
      if([actor_[@"pidVersion"] isEqual:parent[@"pidVersion"]]) return;
      if([stage_ isEqual:@"post-exec"]&&(baseline_[@"engine"]!=NSNull.null||baseline_[@"runtime"]!=NSNull.null)) return;
      if([stage_ isEqual:@"adopted"]&&![baseline_[@"engine"] isEqual:actor_]) return;
    }
    valid_=true; if(!self()) valid_=false;
  }
  bool confirmUnclaimed(const arbol_attempt::Claim& claim,const std::string& expected) {
    // Only the actual failed outer transition calls this BEFORE releasing its
    // still-held short Claim. This one-way native fact survives later genuine
    // cancellation/replacement, and authorizes no access to that newer record.
    if(initialRaw_.empty()||expected!=initialRaw_||execIntent_||permissions_||!self()||
       claim.fd<0||claim.at.lock!=claim.fd||!arbol_attempt::unchanged(claim.at)) return false;
    std::string actual; bool absent;
    if(!arbol_attempt::readAt(claim.at.directory,"claim.json",actual,absent)||absent||actual!=expected) return false;
    NSDictionary* pending=arbol_attempt::json(actual);
    if(!arbol_attempt::record(pending)||!arbol_attempt::immutable(pending,baseline_)||![pending[@"phase"] isEqual:@"pending"]||
       pending[@"bootstrap"]!=NSNull.null||pending[@"engine"]!=NSNull.null||pending[@"runtime"]!=NSNull.null||pending[@"terminal"]!=NSNull.null||
       !emptyCensus()||!arbol_attempt::unchanged(claim.at)) return false;
    noClaimConfirmed_=true; return true;
  }
  void bindOwner(const arbol_boundary::Lock& owner) {
    if(ownerAttempted_) { if(![arbol_boundary::capsuleLock(owner_) isEqual:arbol_boundary::capsuleLock(owner)]) uncertain_=true; return; }
    ownerAttempted_=true; owner_=owner; owner_.fd=fcntl(owner.fd,F_DUPFD_CLOEXEC,64);
    if(owner.path!=std::string([baseline_[@"profile"] UTF8String])+"/owner.lock"||owner.heldMode!=LOCK_EX||!arbol_boundary::lockIdentity(owner_)) uncertain_=true;
  }
  void spawnIntent() { permissions_|=1; }
  void markerPermission() { permissions_|=2; }
  void sessionPermission() { permissions_|=4; }
  void beforeExec() { execIntent_=true; }
  void returnedExecFailure(int failure) { if(execIntent_&&failure) { execError_=failure; execFailedReturned_=true; } else uncertain_=true; }
  bool attempted() const { return attempted_; }
  bool committed() const { return committed_; }
  bool mayFinalize() const { return attempted_&&valid_&&!permissions_&&!uncertain_; }
  bool matches(const std::string& bundle,const std::string& digest,const arbol_boundary::Lock& build) const {
    return attempted_&&valid_&&bundle==bundle_&&[baseline_[@"candidateDigest"] isEqual:[NSString stringWithUTF8String:digest.c_str()]]&&
      [arbol_boundary::capsuleLock(build_) isEqual:arbol_boundary::capsuleLock(build)];
  }
  bool acceptAdopted(const arbol_attempt::Claim& claim,const std::string& raw,bool terminalOnly=false) {
    // Actual engine adoption is not a profile-use permission. Capture only its
    // genuine guarded successful bytes, including a returned ambiguous write
    // whose actual current record is now exactly that native result.
    if(![stage_ isEqual:@"post-exec"]||!self()||permissions_||claim.fd<0||!arbol_attempt::unchanged(claim.at)) return false;
    std::string actual; bool absent;
    if(!arbol_attempt::readAt(claim.at.directory,"claim.json",actual,absent)||absent||actual!=raw) return false;
    NSDictionary* next=arbol_attempt::json(raw);
    if(!arbol_attempt::record(next)||!arbol_attempt::immutable(baseline_,next)||
       (!([next[@"phase"] isEqual:@"claimed"]||(terminalOnly&&[next[@"phase"] isEqual:@"cancelled"])))||
       ![next[@"stage"] isEqual:@"untransferred"]||![next[@"bootstrap"] isEqual:baseline_[@"bootstrap"]]||
       ![next[@"engine"] isEqual:actor_]||next[@"runtime"]!=NSNull.null||next[@"terminal"]!=NSNull.null) return false;
    NSMutableDictionary* adopted=[next mutableCopy]; adopted[@"phase"]=@"claimed";
    baselineRaw_=arbol_attempt::bytes(adopted); baseline_=arbol_attempt::json(baselineRaw_); stage_=@"adopted";
    return self()&&arbol_attempt::unchanged(claim.at);
  }
  [[noreturn]] void terminate() noexcept {
    finish();
    for(;;) {
      @autoreleasepool { @try { try {
        if(committed_&&self()) {
          arbol_boundary::Identity original{[actor_[@"pid"] intValue],strtoull([actor_[@"startId"] UTF8String],nullptr,10),
            [actor_[@"pidVersion"] intValue],[actor_[@"uid"] unsignedIntValue],[actor_[@"group"] unsignedIntValue]};
          (void)arbol_boundary::signalExact(original,SIGKILL);
        }
      } catch(...) {} } @catch(NSException*) {} }
      usleep(10000);
    }
  }
  bool publish() {
    if(!attempted_||!self()||!emptyCensus()) return false;
    if(noClaimConfirmed_) return true; // no touching any later attempt
    arbol_attempt::Claim claim; std::string raw; NSDictionary* value=nil;
    double lockDeadline=arbol_boundary::clockMs()+1000;
    if(!claim.acquire(requestPath_,lockDeadline)||!claim.read(raw,value)) return false;
    if(committed_) return raw==closedRaw_&&self()&&emptyCensus();
    if([stage_ isEqual:@"post-exec"]&&value[@"engine"]!=NSNull.null) {
      // A caught adoption failure may follow an actually installed engine
      // record. Reconcile only this exact original under the real Claim, and
      // use it solely for terminal proof, never resume active adoption.
      if(!acceptAdopted(claim,raw,true)) return false;
    }
    // An actual outer write which did NOT claim can exit without certifying
    // someone else's profile. This is not the claimed no-use proof route.
    if(!initialRaw_.empty()&&raw==initialRaw_&&[value[@"phase"] isEqual:@"pending"]&&
       value[@"bootstrap"]==NSNull.null&&value[@"engine"]==NSNull.null&&value[@"runtime"]==NSNull.null) return self()&&emptyCensus();
    if(!current(value)||publicationAttempted_) return false;
    publicationAttempted_=true; metadataDeadline_=arbol_boundary::clockMs()+1000;
    NSString* profile=value[@"profile"],*state=profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
    if(!arbol_boundary::canonical(state.fileSystemRepresentation)||!arbol_boundary::privateAncestors(std::string(state.fileSystemRepresentation)+"/exit-evidence")) return false;
    NativeFile stateRoot,exits,history,directory;
    stateRoot.fd=open(state.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat stateIdentity{},exitsIdentity{},historyIdentity{},directoryIdentity{};
    if(stateRoot.fd<0||fstat(stateRoot.fd,&stateIdentity)||!S_ISDIR(stateIdentity.st_mode)||stateIdentity.st_uid!=geteuid()||
       (stateIdentity.st_mode&07777)!=0700||!privateDirectoryAt(stateRoot.fd,"exit-evidence",exitsIdentity)||exitsIdentity.st_dev!=stateIdentity.st_dev) return false;
    exits.fd=openat(stateRoot.fd,"exit-evidence",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(exits.fd<0||!privateDirectoryAt(exits.fd,[value[@"profilePathHash"] UTF8String],historyIdentity)||historyIdentity.st_dev!=stateIdentity.st_dev) return false;
    history.fd=openat(exits.fd,[value[@"profilePathHash"] UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(history.fd<0||!privateDirectoryAt(history.fd,[value[@"request"] UTF8String],directoryIdentity)||directoryIdentity.st_dev!=stateIdentity.st_dev) return false;
    directory.fd=openat(history.fd,[value[@"request"] UTF8String],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    NSDictionary* prior=nil; std::string headRaw; bool headAbsent;
    if(directory.fd<0||!priorData(history.fd,prior,headRaw,headAbsent)||!self()||!emptyCensus()||arbol_boundary::clockMs()>=metadataDeadline_) return false;
    NSString* boot=bootSession(); if(!boot) return false;
    NSDictionary* receipt=@{@"format":@1,@"kind":@"unused-host-terminal",@"bootSession":boot,@"actorStage":stage_,@"actor":actor_,
      @"attempt":value,@"baseline":baseline_,@"baselineDigest":arbol_attempt::digest(baselineRaw_),@"bundle":[NSString stringWithUTF8String:bundle_.c_str()],
      @"locks":@{@"build":arbol_boundary::capsuleLock(build_),@"owner":ownerAttempted_?(id)arbol_boundary::capsuleLock(owner_):(id)NSNull.null},
      @"priorDataClaim":prior,@"marker":@{@"kind":@"unobserved"},
      @"nativeFacts":@{@"spawnIntent":@NO,@"markerPermission":@NO,@"sessionPermission":@NO,@"execIntent":@(execIntent_),
        @"execReturnedFailure":@(execFailedReturned_),@"execError":@(execError_),@"ownerAcquired":@(ownerAttempted_),@"fullEnrollmentClaimed":@NO},
      @"census":@{@"kind":@"native-no-spawn-with-fresh-empty-supported-descendants",@"group":actor_[@"group"],@"session":actor_[@"session"]},
      @"observedUs":@((uint64_t)(arbol_boundary::clockMs()*1000)),@"metadataDeadlineUs":@((uint64_t)(metadataDeadline_*1000)),
      @"originalAdmissionExpiryUs":@((uint64_t)([value[@"expires"] doubleValue]*1000))};
    std::string bytes=exitReceiptBytes(receipt); struct stat published{};
    if(bytes.empty()||!publishNativeReceipt(directory.fd,"unused.json",bytes,metadataDeadline_,published)||!self()||!emptyCensus()) return false;
    NSDictionary* checkedPrior=nil; std::string checkedHead; bool checkedAbsent;
    if(!priorData(history.fd,checkedPrior,checkedHead,checkedAbsent)||checkedHead!=headRaw||checkedAbsent!=headAbsent||![checkedPrior isEqual:prior]) return false;
    NSString* receiptPath=[[[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:value[@"profilePathHash"]]
      stringByAppendingPathComponent:value[@"request"]] stringByAppendingPathComponent:@"unused.json"];
    NSMutableDictionary* closed=[value mutableCopy]; closed[@"phase"]=@"closed";
    closed[@"terminal"]=@{@"path":receiptPath,@"digest":arbol_attempt::digest(bytes)}; closedRaw_=arbol_attempt::bytes(closed);
    if(arbol_boundary::clockMs()>=metadataDeadline_||!arbol_attempt::transition(value,closed,arbol_attempt::Role::terminal)||
       !arbol_attempt::replace(claim.at,raw,false,closedRaw_)) return false;
    NativeFile proof; proof.fd=openat(claim.at.directory,"claim.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    struct stat held{},named{},after{}; std::string checked;
    if(proof.fd<0||fstat(proof.fd,&held)||fsync(proof.fd)||fcntl(proof.fd,F_FULLFSYNC)||fsync(claim.at.directory)||
       !readNativeFile(claim.at.directory,"claim.json",checked,named,arbol_attempt::limit)||checked!=closedRaw_||fstat(proof.fd,&after)||
       !arbol_attempt::sameFile(held,after)||!arbol_attempt::sameFile(after,named)||!arbol_attempt::unchanged(claim.at)||
       !self()||!emptyCensus()||arbol_boundary::clockMs()>=metadataDeadline_||
       !proof.finish()||!directory.finish()||!history.finish()||!exits.finish()||!stateRoot.finish()) return false;
    committed_=true; return true;
  }
  void finish() noexcept {
    if(!attempted_) return;
    for(;;) {
      bool done=false;
      @autoreleasepool { @try { try { done=publish(); } catch(...) {} } @catch(NSException*) {} }
      if(done) return;
      // No caller deadline is renewed and no profile data is opened. Actual
      // ambiguous transfer/publication retains the existing original OFDs.
      usleep(10000);
    }
  }
};

} // namespace arbol_exit

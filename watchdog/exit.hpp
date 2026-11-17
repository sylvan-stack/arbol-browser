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
    pid.store(value.original.pid); start.store(value.original.start); version.store(value.original.version);
    uid.store(value.original.uid); group.store(value.original.group); parentStart.store(value.parentStart);
    parentVersion.store(value.parentVersion); capturedUs.store(value.capturedUs); session.store(value.session); image.store(value.image);
    publication.store((serial<<2)|2,std::memory_order_release); return true;
  }
};
struct FamilyRoleState {
  std::atomic<uint64_t> nextCapture{0};
  std::atomic<uint32_t> appendInFlight{0},failed{0},sealed{0};
  FamilySlot active[4096]; // simultaneous unresolved originals, not lifetime count
};
struct FamilyState { std::atomic<uint32_t> uncertain{0}; FamilyRoleState roles[3]; };
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
  IdentitySlot main,primary,custody;
  FamilyState family;
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
class RetainedFamily final:public arbol_boundary::FamilyCapture {
  SharedState* state_; unsigned role_; Identity main_; int session_;
public:
  RetainedFamily(SharedState* state,unsigned role,const Identity& main,int session):state_(state),role_(role),main_(main),session_(session) {}
  void refuse() override { state_->family.uncertain.store(1,std::memory_order_release); state_->poison(identityLoss); }
  bool capture(const arbol_boundary::FamilyObservation& value) override {
    if(role_>2||value.original.pid<=1||!value.original.start||value.original.version<=0||value.original.uid!=main_.uid||
       value.original.group!=main_.group||value.parentStart!=main_.start||value.parentVersion!=main_.version||
       value.session!=(uint32_t)session_||value.image<1||value.image>4) { refuse(); return false; }
    auto& role=state_->family.roles[role_];
    for(auto& slot:role.active) {
      arbol_boundary::FamilyObservation old; uint64_t serial;
      if(slot.read(old,serial)&&arbol_boundary::same(old.original,value.original))
        return old.original.group==value.original.group&&old.parentStart==value.parentStart&&old.parentVersion==value.parentVersion&&
          old.session==value.session&&old.image==value.image;
    }
    for(auto& slot:role.active) if(!(slot.publication.load(std::memory_order_acquire)&3)) {
      uint64_t serial=role.nextCapture.fetch_add(1,std::memory_order_acq_rel)+1;
      if(slot.publish(value,serial)) return true;
    }
    refuse(); return false;
  }
};
class HostCapability {
  int capsule_=-1,stateFd_=-1; SharedState* state_=nullptr;
  int reads_[3]{-1,-1,-1},writes_[3]{-1,-1,-1}; unsigned role_=0;
  RetainedFamily* family_=nullptr;
  NSDictionary* value_=nil; std::string raw_; bool attempted_=false,valid_=false;
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
      if(fsync(writes_[i])||!ledgerDescriptor(reads_[i],i,false)||!ledgerDescriptor(writes_[i],i,true)) return false;
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
    family_=new RetainedFamily(state_,role_,c.main,c.session); c.family=family_; return true;
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
    if(!attachFamily(c)) return false;
    valid_=arbol_boundary::clockMs()<deadline && metadata() && arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build);
    return valid_;
  }
  bool load(arbol_boundary::Context& c,bool primary,double deadline) {
    if(attempted_) return false; attempted_=true;
    if(!anonymousBytes(8,raw_,deadline)||!anonymousFile(9,true,sizeof(SharedState))) return false;
    value_=arbol_attempt::json(raw_); NSDictionary* main=value_[@"main"],*locks=value_[@"locks"],*attempt=value_[@"attempt"];
    if(!arbol_attempt::keys(value_,@[@"format",@"kind",@"bootSession",@"bundle",@"main",@"locks",@"attempt",@"attemptPath",@"profileDirectory",@"profileRecord",@"profileRecordDigest",@"directories",@"receiptDirectory",@"family",@"runtime",@"markerPath",@"prior"]) ||
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
  bool held(arbol_boundary::Context& c) const {
    return present()&&exclusiveWriter()&&state_->enrolled.load(std::memory_order_acquire)==7&&
      state_->main.is(c.main)&&state_->primary.is(c.primary)&&state_->custody.is(c.custody)&&
      arbol_boundary::current(c.main)==1&&arbol_boundary::current(c.primary)==1&&arbol_boundary::current(c.custody)==1&&
      getpgid(c.main.pid)==(int)c.main.group&&getsid(c.main.pid)==c.session&&c.primaryMonitor()&&c.monitor(c.custody,true)&&
      arbol_boundary::lockIdentity(c.owner)&&arbol_boundary::lockIdentity(c.build)&&metadata();
  }
  bool ready(arbol_boundary::Context& c) const { return held(c)&&state_->fatal.load(std::memory_order_acquire)==0; }
};
} // namespace arbol_exit

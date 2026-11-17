// Private signed watchdog executable. Never loads Electron or an input addon.
#import <Foundation/Foundation.h>
#include "boundary.hpp"
#include "exit.hpp"
#include <poll.h>
#include <spawn.h>
#include <deque>
#include <limits>
#include <cmath>
using namespace arbol_boundary;
static bool keys(NSDictionary* value, NSArray* expected) {
  return [value isKindOfClass:[NSDictionary class]] && [[NSSet setWithArray:value.allKeys] isEqual:[NSSet setWithArray:expected]];
}
static bool unsignedText(id value,uint64_t& out) {
  if(![value isKindOfClass:[NSString class]]) return false;
  std::string text=[value UTF8String]; if(text.empty() || text.size()>20 || (text.size()>1 && text[0]=='0')) return false;
  out=0; for(char ch:text) { if(ch<'0'||ch>'9'||out>(UINT64_MAX-(ch-'0'))/10) return false; out=out*10+(ch-'0'); } return out>0;
}
static bool number(id value,uint32_t& out) {
  if(![value isKindOfClass:[NSNumber class]] || CFGetTypeID((__bridge CFTypeRef)value)==CFBooleanGetTypeID()) return false;
  double n=[value doubleValue]; if(!std::isfinite(n)||n<0||n>UINT32_MAX||n!=(uint32_t)n) return false; out=(uint32_t)n; return true;
}
static bool identityRecord(NSDictionary* value,Identity& id,int* session=nullptr) {
  if(!keys(value,session?@[@"pid",@"startId",@"pidVersion",@"uid",@"group",@"session"]:@[@"pid",@"startId",@"pidVersion",@"uid",@"group"])) return false;
  uint32_t pid,version,sid=0;
  if(!number(value[@"pid"],pid)||pid<2||pid>INT_MAX||!unsignedText(value[@"startId"],id.start)||!number(value[@"pidVersion"],version)||version<1||version>INT_MAX||!number(value[@"uid"],id.uid)||!number(value[@"group"],id.group)) return false;
  if(session && (!number(value[@"session"],sid)||sid<1||sid>INT_MAX)) return false;
  id.pid=(int)pid; id.version=(int32_t)version; if(session) *session=(int)sid; return true;
}
static bool lockRecord(NSDictionary* value,int fd,Lock& lock) {
  uint32_t mode;
  if(!keys(value,@[@"path",@"device",@"inode",@"uid",@"mode",@"heldMode"])||![value[@"path"] isKindOfClass:[NSString class]]||!unsignedText(value[@"device"],lock.device)||!unsignedText(value[@"inode"],lock.inode)||!number(value[@"uid"],lock.uid)||!number(value[@"mode"],lock.mode)||!number(value[@"heldMode"],mode)) return false;
  lock.fd=fd; lock.path=[value[@"path"] UTF8String]; lock.heldMode=(int)mode; return lockIdentity(lock);
}
static void nonblocking(int fd) { int f=fcntl(fd,F_GETFL); if(f<0||fcntl(fd,F_SETFL,f|O_NONBLOCK)<0||fcntl(fd,F_SETFD,FD_CLOEXEC)<0) throw 4; }
static std::string startup(double deadline) {
  struct stat metadata{}; int flags=fcntl(5,F_GETFL);
  if(flags<0||(flags&O_ACCMODE)!=O_RDONLY||fstat(5,&metadata)||!S_ISREG(metadata.st_mode)||metadata.st_uid!=geteuid()||(metadata.st_mode&07777)!=0600||metadata.st_nlink!=0||metadata.st_size<1||metadata.st_size>16384) throw 4;
  nonblocking(5); std::string raw; char bytes[4096];
  for(;;) {
    if(clockMs()>=deadline) throw 4;
    ssize_t n=read(5,bytes,sizeof(bytes));
    if(n>0) { raw.append(bytes,(size_t)n); if(raw.size()>16384) throw 4; }
    else if(n==0) { close(5); return raw; }
    else if(errno!=EINTR && errno!=EAGAIN && errno!=EWOULDBLOCK) throw 4;
    else { pollfd p{5,POLLIN,0}; (void)poll(&p,1,5); }
  }
}
static Context record(const std::string& raw,bool primary,Identity& producer) {
  NSData* bytes=[NSData dataWithBytes:raw.data() length:raw.size()];
  NSDictionary* value=[NSJSONSerialization JSONObjectWithData:bytes options:0 error:nil]; Context c;
  if(!keys(value,@[@"format",@"mode",@"producerRole",@"producer",@"candidateSnapshotDigest",@"bundle",@"main",@"locks"])||![value[@"format"] isEqual:@2]||![value[@"mode"] isEqual:primary?@"primary":@"custody"]||![value[@"producerRole"] isEqual:primary?@"main":@"primary"]||![value[@"bundle"] isKindOfClass:[NSString class]]||![value[@"candidateSnapshotDigest"] isKindOfClass:[NSString class]]||[value[@"candidateSnapshotDigest"] length]!=64||!keys(value[@"locks"],@[@"owner",@"build"])||!identityRecord(value[@"main"],c.main,&c.session)||!identityRecord(value[@"producer"],producer)||!lockRecord(value[@"locks"][@"owner"],3,c.owner)||!lockRecord(value[@"locks"][@"build"],4,c.build)) throw 4;
  std::string digest=[value[@"candidateSnapshotDigest"] UTF8String]; for(char ch:digest) if(!((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f'))) throw 4;
  c.bundle=[value[@"bundle"] UTF8String]; c.digest=digest; if(!primary) c.primary=producer; return c;
}
// Refusal never advertises R or gives up the only retained descriptions. An
// already identified family can be enforced; unknown input cannot select PIDs.
static void poison(arbol_exit::HostCapability* cap,uint64_t reason) {
  if(cap&&cap->present()) cap->shared()->poison(reason);
}
[[noreturn]] static void retainedRefusal(Context* c,arbol_exit::HostCapability* cap=nullptr) {
  poison(cap,arbol_exit::protocolLoss|arbol_exit::forced);
  struct stat a{},b{}; if(!c&&(fstat(3,&a)||fstat(4,&b)||!S_ISREG(a.st_mode)||!S_ISREG(b.st_mode))) _exit(4);
  for(;;) { if(c) { (void)c->discoverCustody(); c->enforce(); reap(c->custody); if(c->engineGone()) { const Identity& peer=getpid()==c->primary.pid?c->custody:c->primary; if(current(peer)==0) _exit(4); (void)c->retireMonitorPeer(peer); } } usleep(10000); }
}
struct Channel {
  int input,output; std::string incoming,outgoing; bool failed=false,ended=false,brokenWrite=false,truncated=false;
  Channel(int in,int out):input(in),output(out) { nonblocking(input); nonblocking(output); }
  void send(const std::string& line) { if(line.size()>128||outgoing.size()+line.size()>4096) {failed=true;return;} outgoing+=line; }
  void flush(double expires=0) {
    while(!outgoing.empty()&&!failed) { if(expires&&clockMs()>=expires) { failed=true; return; } ssize_t n=write(output,outgoing.data(),outgoing.size());
      if(n>0) outgoing.erase(0,(size_t)n); else if(n<0&&errno==EINTR) continue;
      else if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK)) break; else { brokenWrite=n<0&&errno==EPIPE; failed=true; } }
  }
  std::vector<std::string> readLines() {
    std::vector<std::string> lines; char bytes[512];
    for(int batch=0;batch<8&&!failed;++batch) {
      ssize_t n=read(input,bytes,sizeof(bytes));
      if(n>0) { for(ssize_t i=0;i<n;++i) { unsigned char ch=bytes[i];
        if(ch=='\n') { lines.push_back(incoming); incoming.clear(); if(lines.size()>32) failed=true; }
        else if(ch<32||ch>126||incoming.size()>=127) failed=true; else incoming+=(char)ch; } }
      else if(n==0) { failed=ended=true; truncated=!incoming.empty(); } else if(errno==EINTR) continue; else if(errno!=EAGAIN&&errno!=EWOULDBLOCK) failed=true; else break;
    } return lines;
  }
};
struct Frame { char kind=0; uint64_t sequence=0; };
static bool frame(const std::string& line,Frame& result,const std::string& allowed) {
  if(line.size()<3||line.size()>127||line[1]!=' '||allowed.find(line[0])==std::string::npos) return false;
  std::string digits=line.substr(2); if(digits.empty()||(digits.size()>1&&digits[0]=='0')||digits.size()>20) return false;
  uint64_t value=0; for(char ch:digits) { if(ch<'0'||ch>'9'||value>(UINT64_MAX-(ch-'0'))/10) return false; value=value*10+(ch-'0'); }
  result={line[0],value}; return true;
}
struct Deadline {
  double expires; bool fatal=false,received=false,elapsed=false,sealed=false,hardLoss=false; uint64_t sequence=0;
  explicit Deadline(double start):expires(start+2500) {}
  bool expired(double now) { if((!sealed||fatal)&&now>=expires) fatal=elapsed=hardLoss=true; return elapsed; }
  bool accept(const Frame& value,double now) {
    if(expired(now)) return false;
    if(received&&value.sequence<=sequence) return false;
    received=true; sequence=value.sequence;
    if(value.kind=='F') { fatal=true; expires=std::min(expires,now+1000); }
    else if(!fatal) expires=now+2500;
    return true;
  }
  void seal() { sealed=elapsed=true; } // closes renewal only, never a completion proof
  void lost(double now) { fatal=elapsed=sealed=hardLoss=true; expires=std::min(expires,now); }
};
[[noreturn]] static void retirePair(Context& c,Channel& pair,bool primary,arbol_exit::HostCapability* cap=nullptr,
  arbol_exit::ExitWatch* mainWatch=nullptr,double mainLimit=0,std::vector<std::string> first={}) {
  // No R/H/A/F renewal survives this independently observed quiescence. A/K
  // history is not current T/K consent, and peer EOF is not peer exit proof.
  const Identity peer=primary?c.custody:c.primary; const uint64_t token=1; const double requested=clockMs(),expires=requested+1000;
  arbol_exit::ExitWatch peerWatch; bool watched=cap&&peerWatch.enroll(peer),gotK=false,gotP=false,gotT=false,tCommitted=false;
  if(cap&&!watched) poison(cap,arbol_exit::peerLoss);
  pair.outgoing.clear(); pair.send(std::string(primary?"T ":"P ")+std::to_string(token)+"\n");
  for(;;) {
    if(watched&&!peerWatch.poll()) poison(cap,arbol_exit::watchLoss);
    auto lines=pair.readLines(); if(!first.empty()) { lines.insert(lines.begin(),first.begin(),first.end()); first.clear(); }
    if(pair.failed&&(!pair.ended||pair.truncated)) poison(cap,arbol_exit::protocolLoss);
    // Inspect the complete received batch before any K/exit branch so an
    // already-received F or malformed suffix cannot disappear behind it.
    unsigned tCount=0,kCount=0,pCount=0;
    for(const auto& line:lines) {
      Frame f;
      if(frame(line,f,"HFA")) { if(f.kind=='F') poison(cap,arbol_exit::admissionLoss); }
      else if(!frame(line,f,"TKP")||f.sequence!=token) poison(cap,arbol_exit::protocolLoss);
      else if((f.kind=='T'&&(primary||++tCount>1))||(f.kind=='K'&&(!primary||++kCount>1))||
              (f.kind=='P'&&(!primary||++pCount>1))) poison(cap,arbol_exit::protocolLoss);
    }
    for(const auto& line:lines) {
      Frame f;
      if(frame(line,f,"HFA")) { if(f.kind=='F') poison(cap,arbol_exit::admissionLoss); continue; }
      if(!frame(line,f,"TKP")||f.sequence!=token) { poison(cap,arbol_exit::protocolLoss); continue; }
      if(primary&&f.kind=='P') {
        // Our one T is already issued for this round. The simultaneous P
        // neither duplicates T nor resets the original absolute cutoff.
        if(gotP) poison(cap,arbol_exit::protocolLoss); gotP=true;
      } else if(primary&&f.kind=='K') {
        if(!tCommitted||gotK) { poison(cap,arbol_exit::protocolLoss); continue; }
        gotK=true; if(cap) cap->shared()->primaryConsent.store(1,std::memory_order_release);
      } else if(!primary&&f.kind=='T') {
        if(gotT) { poison(cap,arbol_exit::protocolLoss); continue; } gotT=true;
        pair.outgoing.clear(); pair.send("K "+std::to_string(token)+"\n");
        while(!pair.outgoing.empty()&&!pair.failed&&clockMs()<expires) { pair.flush(expires); usleep(1000); }
        // The actual original consent is published while this native process
        // is still live, only after the matching K committed to its real pipe.
        if(pair.outgoing.empty()&&!pair.failed&&c.engineGone()&&current(c.custody)==1) {
          if(cap) cap->shared()->custodyConsent.store(1,std::memory_order_release);
          _exit(0);
        }
        poison(cap,arbol_exit::peerLoss|arbol_exit::forced);
      } else poison(cap,arbol_exit::protocolLoss);
    }
    reap(peer);
    if(!c.engineGone()||!lockIdentity(c.owner)||!lockIdentity(c.build)) {
      poison(cap,arbol_exit::identityLoss|arbol_exit::forced); c.enforce(); usleep(10000); continue;
    }
    int state=current(peer);
    if(state<0) poison(cap,arbol_exit::identityLoss);
    if(!state) {
      if(!cap) _exit(0); // Native-only legacy has no finalization authority
      if(watched&&!peerWatch.observed()&&clockMs()<expires) { usleep(1000); continue; }
      bool consent=primary&&gotK&&cap->shared()->primaryConsent.load(std::memory_order_acquire)==1&&
        cap->shared()->custodyConsent.load(std::memory_order_acquire)==1;
      bool ordinary=consent&&watched&&peerWatch.ordinaryBefore(expires)&&mainWatch&&mainWatch->ordinaryBefore(mainLimit)&&
        cap->shared()->fatal.load(std::memory_order_acquire)==0;
      if(ordinary) cap->shared()->ordinaryPostExitEligible.store(1,std::memory_order_release);
      else poison(cap,arbol_exit::peerLoss);
      // No clean marker or flush receipt here. The later native independent
      // finalizer/dirty witness owns this last-holder exit boundary.
      _exit(ordinary?0:4);
    }
    pair.flush(expires);
    if(primary&&pair.outgoing.empty()&&!pair.failed) tCommitted=true;
    if(pair.failed&&(!pair.ended||pair.truncated||!gotK)) poison(cap,arbol_exit::peerLoss);
    if(clockMs()>=expires) {
      poison(cap,arbol_exit::peerLoss|arbol_exit::forced);
      (void)c.retireMonitorPeer(peer); reap(peer);
      if(c.engineGone()&&current(peer)==0) _exit(cap?4:0);
    }
    usleep(5000);
  }
}
[[noreturn]] static void protocolLoop(Context& c,Channel& pair,bool primary,double start,arbol_exit::ExitWatch& watch,arbol_exit::HostCapability* cap) {
  Channel host(primary?0:6,primary?1:7); Deadline deadline(start);
  struct Pending { uint64_t sequence; double sent; }; std::deque<Pending> pending;
  if(primary) host.send("R 1 "+std::to_string(c.main.pid)+"\n");
  double blockedWrite=0,responseExpires=0,terminalExpires=0; bool terminal=false,terminalHostDrained=false;
  std::vector<std::string> pendingRetirement;
  arbol_exit::KernelExitProbe probe;
  auto liveLimit=[&] {
    double limit=deadline.expires;
    if(primary&&!pending.empty()) limit=std::min(limit,pending.front().sent+1000);
    if(responseExpires) limit=std::min(limit,responseExpires);
    if(blockedWrite) limit=std::min(limit,blockedWrite+1000);
    return limit;
  };
  auto sealTerminal=[&] {
    if(!terminal) { terminalExpires=liveLimit(); terminal=true; }
    deadline.seal(); // never renew H/A or manufacture a receipt
  };
  auto observedExit=[&] {
    if(!cap||!watch.observed()) return;
    if(!terminal) terminalExpires=liveLimit();
    if(!watch.ordinaryBefore(terminalExpires)) { deadline.lost(clockMs()); poison(cap,arbol_exit::watchLoss); }
    sealTerminal();
    if(primary&&!terminalHostDrained) {
      terminalHostDrained=true;
      // Kernel exit can race already buffered bytes. Drain only to classify
      // actual F/malformed/partial history; never issue A or renew H here.
      for(const auto& line:host.readLines()) {
        Frame f;
        if(!frame(line,f,"HF")) { deadline.lost(clockMs()); poison(cap,arbol_exit::protocolLoss); }
        else if(f.kind=='F') { cap->shared()->declareFatal(); deadline.fatal=true; deadline.expires=std::min(deadline.expires,clockMs()+1000); }
      }
      if(host.truncated||!host.incoming.empty()||(host.failed&&!host.ended&&!host.brokenWrite)) {
        deadline.lost(clockMs()); poison(cap,arbol_exit::protocolLoss);
      }
    }
  };
  auto kernelTerminal=[&] {
    if(terminal) return true;
    if(!cap) return false;
    Identity actual; Info detail{}; int state=observe(c.main.pid,actual,&detail);
    if(state<0 || (state==1&&(!same(actual,c.main)||actual.group!=c.main.group||!(detail.bsd.pbi_flags&PROC_FLAG_INEXIT)))) {
      deadline.lost(clockMs()); poison(cap,arbol_exit::protocolLoss); return false;
    }
    // The genuine native-retained endpoints close only on original kernel FD
    // teardown. A live original is always fatal. No-live lookup/EOF supplies
    // only bounded terminal arbitration, never completion or clean evidence.
    if(state==0&&!watch.observed()&&!probe.start(c.main)) { deadline.lost(clockMs()); return false; }
    sealTerminal(); return true;
  };
  auto hostLoss=[&] {
    if(!primary||!host.failed) return;
    if(!cap||host.truncated||(!host.ended&&!host.brokenWrite)) { deadline.lost(clockMs()); return; }
    (void)kernelTerminal();
  };
  auto holdRetirement=[&](const std::vector<std::string>& lines,char expected) {
    if(!cap||!pendingRetirement.empty()) { deadline.lost(clockMs()); return; }
    size_t count=0;
    for(const auto& line:lines) {
      Frame f;
      if(frame(line,f,"HFA")) {
        if(f.kind=='F') { cap->shared()->declareFatal(); deadline.fatal=true; deadline.expires=std::min(deadline.expires,clockMs()+1000); }
        continue;
      }
      if(!frame(line,f,std::string(1,expected))||f.sequence!=1||++count!=1) { deadline.lost(clockMs()); return; }
    }
    if(count!=1||!kernelTerminal()) { deadline.lost(clockMs()); return; }
    // Exactly one expected peer prompt may precede our own observation. This
    // reserves no consent, emits no acknowledgement and never renews a bound.
    pendingRetirement=lines;
  };
  auto maybeRetire=[&](const std::vector<std::string>& first=std::vector<std::string>{}) {
    if(!watch.poll()) { deadline.lost(clockMs()); poison(cap,arbol_exit::watchLoss); }
    observedExit();
    if(probe.started()) {
      auto result=probe.result();
      if(result==arbol_exit::KernelExitProbe::uncertain||result==arbol_exit::KernelExitProbe::live) {
        deadline.lost(clockMs()); poison(cap,arbol_exit::identityLoss);
      } else if(result==arbol_exit::KernelExitProbe::pending&&!deadline.hardLoss) return;
    }
    // This handoff is itself a cleanup boundary; never leave attribution until
    // the loop tail when a complete census may make this call nonreturning.
    if(deadline.hardLoss) poison(cap,arbol_exit::protocolLoss|arbol_exit::forced);
    else if(deadline.fatal&&cap) cap->shared()->declareFatal();
    if(c.engineGone()&&(!cap||watch.observed()||deadline.hardLoss)) {
      // The census itself may have been delayed. Its first complete result
      // cannot be backdated from a late poll into the frozen live window.
      if(cap&&terminal&&clockMs()>=terminalExpires) { deadline.lost(clockMs()); poison(cap,arbol_exit::identityLoss); }
      retirePair(c,pair,primary,cap,&watch,terminalExpires?terminalExpires:liveLimit(),first);
    }
  };
  for(;;) {
    double now=clockMs();
    if(!watch.poll()) { deadline.lost(now); poison(cap,arbol_exit::watchLoss); }
    if(cap) {
      if(!cap->present()) deadline.lost(now);
      else {
        uint64_t reasons=cap->shared()->fatal.load(std::memory_order_acquire),cutoff=cap->shared()->fatalCutoffUs.load(std::memory_order_acquire);
        if(reasons&~arbol_exit::admissionLoss) deadline.lost(now);
        else if(reasons) {
          if(!cutoff) deadline.lost(now);
          else { deadline.fatal=true; deadline.expires=std::min(deadline.expires,(double)cutoff/1000); }
        }
      }
    }
    observedExit();
    if(!terminal) {
      if(primary&&!pending.empty()&&now-pending.front().sent>=1000) deadline.lost(now);
      (void)deadline.expired(now);
    } else if(probe.started()) {
      auto result=probe.result();
      if(result==arbol_exit::KernelExitProbe::live||result==arbol_exit::KernelExitProbe::uncertain) {
        deadline.lost(now); poison(cap,arbol_exit::identityLoss);
      } else if(result==arbol_exit::KernelExitProbe::pending&&now>=terminalExpires) deadline.lost(now);
    }
    if(terminal&&!watch.observed()&&now>=terminalExpires) deadline.lost(now);
    if(terminal&&now>=terminalExpires&&!c.engineGone()) { deadline.lost(now); poison(cap,arbol_exit::identityLoss); }
    if(deadline.fatal) (void)deadline.expired(now);
    maybeRetire(pendingRetirement);
    Channel& input=primary?host:pair;
    if(!deadline.elapsed) {
      auto lines=input.readLines(); hostLoss();
      for(const std::string& line:lines) {
        now=clockMs(); Frame value;
        if(!frame(line,value,"HF")) {
          Frame retirement;
          if(!primary&&cap&&frame(line,retirement,"T")) { holdRetirement(lines,'T'); maybeRetire(pendingRetirement); break; }
          deadline.lost(now); break;
        }
        if(value.kind=='F'&&cap) {
          cap->shared()->declareFatal(); deadline.fatal=true;
          deadline.expires=std::min(deadline.expires,now+1000);
        }
        // An F already in this batch is never discarded on terminal seal.
        if(deadline.elapsed) continue;
        if(primary&&!pending.empty()&&now-pending.front().sent>=1000) { deadline.lost(now); break; }
        if(!deadline.accept(value,now)) { deadline.lost(now); break; }
        if(primary) { if(pending.size()>=16) { deadline.lost(now); break; } pending.push_back({value.sequence,now}); pair.send(line+"\n"); }
        else pair.send("A "+std::to_string(value.sequence)+"\n");
      }
    }
    if(primary&&!deadline.expired(clockMs())) {
      auto pairLines=pair.readLines();
      for(const std::string& line:pairLines) {
        now=clockMs(); Frame value;
        if(cap&&frame(line,value,"P")) { holdRetirement(pairLines,'P'); maybeRetire(pendingRetirement); break; }
        if(deadline.expired(now)||!frame(line,value,"A")||pending.empty()||pending.front().sequence!=value.sequence||now-pending.front().sent>=1000) { deadline.lost(now); break; }
        double issuedDeadline=pending.front().sent+1000;
        responseExpires=responseExpires?std::min(responseExpires,issuedDeadline):issuedDeadline;
        pending.pop_front(); host.send(line+"\n");
      }
    }
    now=clockMs();
    if(!terminal&&primary&&((!pending.empty()&&now-pending.front().sent>=1000)||(responseExpires&&now>=responseExpires))) deadline.lost(now);
    if(!deadline.expired(now)) {
      pair.flush(deadline.expires);
      now=clockMs(); if(responseExpires&&now>=responseExpires) deadline.lost(now);
      if(primary&&!deadline.expired(now)) host.flush(responseExpires?std::min(deadline.expires,responseExpires):deadline.expires);
    }
    hostLoss();
    if(host.outgoing.empty()) responseExpires=0;
    now=clockMs();
    bool outputPending=!pair.outgoing.empty()||(primary&&!host.outgoing.empty());
    if(!terminal&&outputPending) { if(!blockedWrite) blockedWrite=now; else if(now-blockedWrite>=1000) deadline.lost(now); }
    else if(!terminal) blockedWrite=0;
    std::vector<Identity> observed;
    Identity peerNow; const Identity& peer=primary?c.custody:c.primary;
    if(pair.failed||observe(peer.pid,peerNow)!=1||!same(peer,peerNow)||peerNow.group!=(primary?c.main.group:(uint32_t)c.primary.pid)||
       !c.census(observed)||!lockIdentity(c.owner)||!lockIdentity(c.build)) deadline.lost(clockMs());
    if(deadline.hardLoss) { poison(cap,arbol_exit::protocolLoss|arbol_exit::forced); c.enforce(); }
    reap(c.custody); maybeRetire(pendingRetirement); usleep(5000);
  }
}

static void pipeDescriptors(int (&out)[2]) {
  int raw[2]; if(pipe(raw)) throw 4;
  out[0]=fcntl(raw[0],F_DUPFD_CLOEXEC,10); out[1]=fcntl(raw[1],F_DUPFD_CLOEXEC,10); close(raw[0]); close(raw[1]);
  if(out[0]<0||out[1]<0) throw 4;
}
static Channel launchCustody(Context& c,double deadline,arbol_exit::HostCapability* cap) {
  int init= capsuleDescriptor(capsuleBytes(c,false)),forward[2],reply[2]; if(init<0) throw 4; pipeDescriptors(forward); pipeDescriptors(reply);
  int owner=fcntl(3,F_DUPFD_CLOEXEC,10),build=fcntl(4,F_DUPFD_CLOEXEC,10);
  posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
  if(owner<0||build<0||posix_spawn_file_actions_init(&actions)||posix_spawnattr_init(&attr)) throw 4;
  bool ok=!posix_spawn_file_actions_adddup2(&actions,owner,3)&&!posix_spawn_file_actions_adddup2(&actions,build,4)&&
    !posix_spawn_file_actions_adddup2(&actions,init,5)&&!posix_spawn_file_actions_adddup2(&actions,forward[0],6)&&!posix_spawn_file_actions_adddup2(&actions,reply[1],7)&&
    !posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0)&&!posix_spawn_file_actions_addopen(&actions,1,"/dev/null",O_WRONLY,0)&&!posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)&&
    !posix_spawnattr_setpgroup(&attr,c.main.group)&&!posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_CLOEXEC_DEFAULT);
  if(ok&&cap) ok=cap->present()&&!posix_spawn_file_actions_adddup2(&actions,cap->capsule(),8)&&
    !posix_spawn_file_actions_adddup2(&actions,cap->stateDescriptor(),9);
  std::string helper=c.helper(); char* args[]={helper.data(),(char*)"--custody",cap?(char*)"--host-finalization":nullptr,nullptr}; char* env[]={(char*)"PATH=/usr/bin:/bin",nullptr}; pid_t pid=0;
  int result=ok?posix_spawn(&pid,helper.c_str(),&actions,&attr,args,env):EINVAL;
  posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr);
  close(owner); close(build); close(init); close(forward[0]); close(reply[1]);
  if(result) throw 4;
  // Capture the actual child even if its validation fails: failed-attempt
  // retirement must not forget a child which already owns duplicate locks.
  if(observe(pid,c.custody)!=1||!c.monitor(c.custody,true)) throw 4;
  if(cap&&!cap->shared()->custody.bind(c.custody,deadline)) throw 4;
  Channel pair(reply[0],forward[1]);
  std::string expected="C 1 "+std::to_string(c.custody.pid)+" "+std::to_string(c.custody.start);
  for(;;) { if(clockMs()>=deadline||pair.failed||current(c.custody)!=1) throw 4;
    auto lines=pair.readLines(); if(lines.size()==1&&lines[0]==expected&&c.monitor(c.custody,true)&&c.monitor(c.primary,true)&&c.initial()) return pair;
    if(!lines.empty()) throw 4; usleep(1000); }
}
static bool liveStart(Context& c,double deadline,arbol_exit::HostCapability* cap) {
  return clockMs()<deadline&&c.initial()&&lockIdentity(c.owner)&&lockIdentity(c.build)&&
    (!cap||(cap->present()&&cap->metadata()&&!cap->shared()->fatal.load(std::memory_order_acquire)));
}
static int runPrimary(Context& c,double deadline,arbol_exit::ExitWatch& watch,arbol_exit::HostCapability* cap) {
  // authenticateBirth deliberately granted cleanup only. Live original-main
  // proof is needed before any child handover or external readiness.
  c.cleanupOnly=false;
  if(!liveStart(c,deadline,cap)||!c.monitor(c.primary,true)||!watch.enrolledAlive(c.main)) { c.cleanupOnly=true; throw 4; }
  Channel pair=launchCustody(c,deadline,cap); // primary still anchors the old group
  if(!liveStart(c,deadline,cap)||!c.monitor(c.primary,true)||!c.monitor(c.custody,true)) { c.cleanupOnly=true; throw 4; }
  // C acknowledged actual descriptors/provenance in this continuously held
  // group. It now has a real second anchor; only this transition leaves it.
  if(setpgid(0,0)||getpgrp()!=getpid()||!c.monitor(c.primary,false)||!c.monitor(c.custody,true)) throw 4;
  c.primaryOutside=true; pair.send("G 1\n");
  for(;;) {
    if(!liveStart(c,deadline,cap)||pair.failed||!c.primaryMonitor()||!c.monitor(c.custody,true)) throw 4;
    pair.flush(); auto lines=pair.readLines();
    if(lines.size()==1&&lines[0]=="J 1"&&pair.outgoing.empty()) break;
    if(!lines.empty()) throw 4; usleep(1000);
  }
  if(!liveStart(c,deadline,cap)||!c.primaryMonitor()||!c.monitor(c.custody,true)||(cap&&!cap->ready(c))) throw 4;
  if(!watch.enrolledAlive(c.main)) throw 4;
  protocolLoop(c,pair,true,deadline-1000,watch,cap);
}
static int runCustody(Context& c,double deadline,arbol_exit::ExitWatch& watch,arbol_exit::HostCapability* cap) {
  c.cleanupOnly=false;
  if(!liveStart(c,deadline,cap)||!c.monitor(c.primary,true)||!c.monitor(c.custody,true)||!watch.enrolledAlive(c.main)) { c.cleanupOnly=true; throw 4; }
  Channel pair(6,7); pair.send("C 1 "+std::to_string(c.custody.pid)+" "+std::to_string(c.custody.start)+"\n");
  while(!pair.outgoing.empty()) { if(!liveStart(c,deadline,cap)||pair.failed||!c.primaryMonitor()) throw 4; pair.flush(); usleep(1000); }
  // A producer death before G is cleanup-only, whether or not C was consumed.
  // Our actual inherited membership/OFDs do not depend on a parent's callback.
  for(;;) {
    if(!liveStart(c,deadline,cap)||pair.failed||current(c.primary)!=1||!c.monitor(c.custody,true)) throw 4;
    auto lines=pair.readLines();
    if(lines.size()==1&&lines[0]=="G 1"&&c.monitor(c.primary,false)) { c.primaryOutside=true; break; }
    if(!lines.empty()) throw 4; usleep(1000);
  }
  if(!liveStart(c,deadline,cap)||!c.primaryMonitor()||(cap&&!cap->ready(c))) throw 4;
  pair.send("J 1\n");
  while(!pair.outgoing.empty()) { if(!liveStart(c,deadline,cap)||pair.failed||!c.primaryMonitor()) throw 4; pair.flush(); usleep(1000); }
  if(!watch.enrolledAlive(c.main)) throw 4;
  protocolLoop(c,pair,false,deadline-1000,watch,cap);
}

int main(int argc,const char* argv[]) {
  signal(SIGPIPE,SIG_IGN); double deadline=clockMs()+1000; Context c; bool parsed=false; arbol_exit::ExitWatch watch; arbol_exit::HostCapability hostCap;
  Identity birth; Info birthInfo{}; int birthSession=getsid(0); bool birthValid=observe(getpid(),birth,&birthInfo)==1;
  @autoreleasepool {
    @try { try {
      if(argc!=2&&argc!=3) throw 4;
      bool host=argc==3; if(host&&strcmp(argv[2],"--host-finalization")) throw 4;
      bool primary=!strcmp(argv[1],"--watchdog"),custody=!strcmp(argv[1],"--custody");
      if((!primary&&!custody)||!birthValid) throw 4;
      Identity producer; std::string raw=startup(deadline); c=record(raw,primary,producer); parsed=true;
      if(!c.authenticateBirth(birth,birthInfo,birthSession,producer,primary)) throw 4;
      if(host&&!hostCap.load(c,primary,deadline)) throw 4;
      if(!watch.enroll(c.main)) throw 4;
      if(host&&!hostCap.enrolled(c,primary,watch)) throw 4;
      return primary?runPrimary(c,deadline,watch,host?&hostCap:nullptr):runCustody(c,deadline,watch,host?&hostCap:nullptr);
    } catch(...) { c.cleanupOnly=true; retainedRefusal(parsed?&c:nullptr,hostCap.present()?&hostCap:nullptr); } } @catch(NSException*) { c.cleanupOnly=true; retainedRefusal(parsed?&c:nullptr,hostCap.present()?&hostCap:nullptr); }
  }
}

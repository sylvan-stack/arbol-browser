// Private signed watchdog executable. Never loads Electron or an input addon.
#import <Foundation/Foundation.h>
#include "boundary.hpp"
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
[[noreturn]] static void retainedRefusal(Context* c) {
  struct stat a{},b{}; if(!c&&(fstat(3,&a)||fstat(4,&b)||!S_ISREG(a.st_mode)||!S_ISREG(b.st_mode))) _exit(4);
  for(;;) { if(c) { (void)c->discoverCustody(); c->enforce(); reap(c->custody); if(c->engineGone()) { const Identity& peer=getpid()==c->primary.pid?c->custody:c->primary; if(current(peer)==0) _exit(4); (void)c->retireMonitorPeer(peer); } } usleep(10000); }
}
struct Channel {
  int input,output; std::string incoming,outgoing; bool failed=false;
  Channel(int in,int out):input(in),output(out) { nonblocking(input); nonblocking(output); }
  void send(const std::string& line) { if(line.size()>128||outgoing.size()+line.size()>4096) {failed=true;return;} outgoing+=line; }
  void flush(double expires=0) {
    while(!outgoing.empty()&&!failed) { if(expires&&clockMs()>=expires) { failed=true; return; } ssize_t n=write(output,outgoing.data(),outgoing.size());
      if(n>0) outgoing.erase(0,(size_t)n); else if(n<0&&errno==EINTR) continue;
      else if(n<0&&(errno==EAGAIN||errno==EWOULDBLOCK)) break; else failed=true; }
  }
  std::vector<std::string> readLines() {
    std::vector<std::string> lines; char bytes[512];
    for(int batch=0;batch<8&&!failed;++batch) {
      ssize_t n=read(input,bytes,sizeof(bytes));
      if(n>0) { for(ssize_t i=0;i<n;++i) { unsigned char ch=bytes[i];
        if(ch=='\n') { lines.push_back(incoming); incoming.clear(); if(lines.size()>32) failed=true; }
        else if(ch<32||ch>126||incoming.size()>=127) failed=true; else incoming+=(char)ch; } }
      else if(n==0) failed=true; else if(errno==EINTR) continue; else if(errno!=EAGAIN&&errno!=EWOULDBLOCK) failed=true; else break;
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
  double expires; bool fatal=false,received=false,elapsed=false; uint64_t sequence=0;
  explicit Deadline(double start):expires(start+2500) {}
  bool expired(double now) { if(now>=expires) fatal=elapsed=true; return elapsed; }
  bool accept(const Frame& value,double now) {
    if(expired(now)) return false;
    if(received&&value.sequence<=sequence) return false;
    received=true; sequence=value.sequence;
    if(value.kind=='F') { fatal=true; expires=std::min(expires,now+1000); }
    else if(!fatal) expires=now+2500;
    return true;
  }
  void lost(double now) { fatal=elapsed=true; expires=std::min(expires,now); }
};
[[noreturn]] static void retirePair(Context& c,Channel& pair,bool primary) {
  // External R/H/A/F authority is already dead. T/K/P cannot be reached before
  // this independent original-main/engine disappearance proof.
  const Identity peer=primary?c.custody:c.primary; uint64_t token=1; double requested=clockMs();
  pair.send(std::string(primary?"T ":"P ")+std::to_string(token)+"\n");
  for(;;) {
    reap(peer);
    if(!c.engineGone()||!lockIdentity(c.owner)||!lockIdentity(c.build)) { usleep(10000); continue; }
    int state=current(peer); if(!state) _exit(0);
    for(const auto& line:pair.readLines()) {
      Frame f; if(frame(line,f,"A")) continue; // pending pre-quiescence receipt, never authority
      if(!frame(line,f,"TKP")) continue;
      if(primary&&f.kind=='P') { token=f.sequence; requested=clockMs(); pair.outgoing.clear(); pair.send("T "+std::to_string(token)+"\n"); }
      else if(!primary&&f.kind=='T') {
        token=f.sequence; requested=clockMs(); pair.outgoing.clear(); pair.send("K "+std::to_string(token)+"\n");
        // Keep actual descriptions until the last send is complete. An old A
        // or bare live PID cannot substitute for the fresh current T.
        while(!pair.outgoing.empty()&&!pair.failed&&clockMs()-requested<1000) { pair.flush(); usleep(1000); }
        if(pair.outgoing.empty()&&!pair.failed&&c.engineGone()) _exit(0);
      }
      // K acknowledges consent only; primary still waits/reaps actual death.
    }
    pair.flush();
    if(clockMs()-requested>=1000) {
      (void)c.retireMonitorPeer(peer); reap(peer);
      if(c.engineGone()&&current(peer)==0) _exit(0);
    }
    usleep(5000);
  }
}
[[noreturn]] static void protocolLoop(Context& c,Channel& pair,bool primary,double start) {
  Channel host(primary?0:6,primary?1:7); Deadline deadline(start);
  struct Pending { uint64_t sequence; double sent; }; std::deque<Pending> pending;
  if(primary) host.send("R 1 "+std::to_string(c.main.pid)+"\n");
  double blockedWrite=0,responseExpires=0;
  for(;;) {
    double now=clockMs();
    // Latch before touching traffic. Late H or a queued A cannot revive an
    // already expired window, even when this executor itself was delayed.
    if(primary&&!pending.empty()&&now-pending.front().sent>=1000) deadline.lost(now);
    (void)deadline.expired(now);
    Channel& input=primary?host:pair;
    if(!deadline.elapsed) for(const std::string& line:input.readLines()) {
      now=clockMs(); Frame value;
      if(primary&&!pending.empty()&&now-pending.front().sent>=1000) { deadline.lost(now); break; }
      if(!frame(line,value,"HF")||!deadline.accept(value,now)) { deadline.lost(now); break; }
      if(primary) { if(pending.size()>=16) { deadline.lost(now); break; } pending.push_back({value.sequence,now}); pair.send(line+"\n"); }
      else pair.send("A "+std::to_string(value.sequence)+"\n");
    }
    if(primary&&!deadline.expired(clockMs())) {
      for(const std::string& line:pair.readLines()) {
        now=clockMs(); Frame value;
        if(deadline.expired(now)||!frame(line,value,"A")||pending.empty()||pending.front().sequence!=value.sequence||now-pending.front().sent>=1000) { deadline.lost(now); break; }
        double issuedDeadline=pending.front().sent+1000;
        responseExpires=responseExpires?std::min(responseExpires,issuedDeadline):issuedDeadline;
        pending.pop_front(); host.send(line+"\n");
      }
    }
    now=clockMs();
    if(primary&&((!pending.empty()&&now-pending.front().sent>=1000)||(responseExpires&&now>=responseExpires))) deadline.lost(now);
    if(!deadline.expired(now)) {
      pair.flush(deadline.expires);
      now=clockMs(); if(responseExpires&&now>=responseExpires) deadline.lost(now);
      if(primary&&!deadline.expired(now)) host.flush(responseExpires?std::min(deadline.expires,responseExpires):deadline.expires);
    }
    if(host.outgoing.empty()) responseExpires=0;
    now=clockMs();
    bool outputPending=!pair.outgoing.empty()||(primary&&!host.outgoing.empty());
    if(outputPending) { if(!blockedWrite) blockedWrite=now; else if(now-blockedWrite>=1000) deadline.lost(now); } else blockedWrite=0;
    std::vector<Identity> observed;
    Identity peerNow; const Identity& peer=primary?c.custody:c.primary;
    if(pair.failed||(primary&&host.failed)||observe(peer.pid,peerNow)!=1||!same(peer,peerNow)||peerNow.group!=(primary?c.main.group:(uint32_t)c.primary.pid)||!c.census(observed)||!lockIdentity(c.owner)||!lockIdentity(c.build)) deadline.lost(clockMs());
    if(deadline.expired(clockMs())) c.enforce();
    reap(c.custody);
    if(c.engineGone()) retirePair(c,pair,primary);
    usleep(5000);
  }
}

static void pipeDescriptors(int (&out)[2]) {
  int raw[2]; if(pipe(raw)) throw 4;
  out[0]=fcntl(raw[0],F_DUPFD_CLOEXEC,10); out[1]=fcntl(raw[1],F_DUPFD_CLOEXEC,10); close(raw[0]); close(raw[1]);
  if(out[0]<0||out[1]<0) throw 4;
}
static Channel launchCustody(Context& c,double deadline) {
  int init= capsuleDescriptor(capsuleBytes(c,false)),forward[2],reply[2]; if(init<0) throw 4; pipeDescriptors(forward); pipeDescriptors(reply);
  int owner=fcntl(3,F_DUPFD_CLOEXEC,10),build=fcntl(4,F_DUPFD_CLOEXEC,10);
  posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
  if(owner<0||build<0||posix_spawn_file_actions_init(&actions)||posix_spawnattr_init(&attr)) throw 4;
  bool ok=!posix_spawn_file_actions_adddup2(&actions,owner,3)&&!posix_spawn_file_actions_adddup2(&actions,build,4)&&
    !posix_spawn_file_actions_adddup2(&actions,init,5)&&!posix_spawn_file_actions_adddup2(&actions,forward[0],6)&&!posix_spawn_file_actions_adddup2(&actions,reply[1],7)&&
    !posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0)&&!posix_spawn_file_actions_addopen(&actions,1,"/dev/null",O_WRONLY,0)&&!posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)&&
    !posix_spawnattr_setpgroup(&attr,c.main.group)&&!posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_CLOEXEC_DEFAULT);
  std::string helper=c.helper(); char* args[]={helper.data(),(char*)"--custody",nullptr}; char* env[]={(char*)"PATH=/usr/bin:/bin",nullptr}; pid_t pid=0;
  int result=ok?posix_spawn(&pid,helper.c_str(),&actions,&attr,args,env):EINVAL;
  posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr);
  close(owner); close(build); close(init); close(forward[0]); close(reply[1]);
  if(result) throw 4;
  // Capture the actual child even if its validation fails: failed-attempt
  // retirement must not forget a child which already owns duplicate locks.
  if(observe(pid,c.custody)!=1||!c.monitor(c.custody,true)) throw 4;
  Channel pair(reply[0],forward[1]);
  std::string expected="C 1 "+std::to_string(c.custody.pid)+" "+std::to_string(c.custody.start);
  for(;;) { if(clockMs()>=deadline||pair.failed||current(c.custody)!=1) throw 4;
    auto lines=pair.readLines(); if(lines.size()==1&&lines[0]==expected&&c.monitor(c.custody,true)&&c.monitor(c.primary,true)&&c.initial()) return pair;
    if(!lines.empty()) throw 4; usleep(1000); }
}
static bool liveStart(Context& c,double deadline) {
  return clockMs()<deadline&&c.initial()&&lockIdentity(c.owner)&&lockIdentity(c.build);
}
static int runPrimary(Context& c,double deadline) {
  // authenticateBirth deliberately granted cleanup only. Live original-main
  // proof is needed before any child handover or external readiness.
  c.cleanupOnly=false;
  if(!liveStart(c,deadline)||!c.monitor(c.primary,true)) { c.cleanupOnly=true; throw 4; }
  Channel pair=launchCustody(c,deadline); // primary still anchors the old group
  if(!liveStart(c,deadline)||!c.monitor(c.primary,true)||!c.monitor(c.custody,true)) { c.cleanupOnly=true; throw 4; }
  // C acknowledged actual descriptors/provenance in this continuously held
  // group. It now has a real second anchor; only this transition leaves it.
  if(setpgid(0,0)||getpgrp()!=getpid()||!c.monitor(c.primary,false)||!c.monitor(c.custody,true)) throw 4;
  c.primaryOutside=true; pair.send("G 1\n");
  for(;;) {
    if(!liveStart(c,deadline)||pair.failed||!c.primaryMonitor()||!c.monitor(c.custody,true)) throw 4;
    pair.flush(); auto lines=pair.readLines();
    if(lines.size()==1&&lines[0]=="J 1"&&pair.outgoing.empty()) break;
    if(!lines.empty()) throw 4; usleep(1000);
  }
  if(!liveStart(c,deadline)||!c.primaryMonitor()||!c.monitor(c.custody,true)) throw 4;
  protocolLoop(c,pair,true,deadline-1000);
}
static int runCustody(Context& c,double deadline) {
  c.cleanupOnly=false;
  if(!liveStart(c,deadline)||!c.monitor(c.primary,true)||!c.monitor(c.custody,true)) { c.cleanupOnly=true; throw 4; }
  Channel pair(6,7); pair.send("C 1 "+std::to_string(c.custody.pid)+" "+std::to_string(c.custody.start)+"\n");
  while(!pair.outgoing.empty()) { if(!liveStart(c,deadline)||pair.failed||!c.primaryMonitor()) throw 4; pair.flush(); usleep(1000); }
  // A producer death before G is cleanup-only, whether or not C was consumed.
  // Our actual inherited membership/OFDs do not depend on a parent's callback.
  for(;;) {
    if(!liveStart(c,deadline)||pair.failed||current(c.primary)!=1||!c.monitor(c.custody,true)) throw 4;
    auto lines=pair.readLines();
    if(lines.size()==1&&lines[0]=="G 1"&&c.monitor(c.primary,false)) { c.primaryOutside=true; break; }
    if(!lines.empty()) throw 4; usleep(1000);
  }
  if(!liveStart(c,deadline)||!c.primaryMonitor()) throw 4;
  pair.send("J 1\n");
  while(!pair.outgoing.empty()) { if(!liveStart(c,deadline)||pair.failed||!c.primaryMonitor()) throw 4; pair.flush(); usleep(1000); }
  protocolLoop(c,pair,false,deadline-1000);
}

int main(int argc,const char* argv[]) {
  signal(SIGPIPE,SIG_IGN); double deadline=clockMs()+1000; Context c; bool parsed=false;
  Identity birth; Info birthInfo{}; int birthSession=getsid(0); bool birthValid=observe(getpid(),birth,&birthInfo)==1;
  @autoreleasepool {
    @try { try {
      if(argc!=2) throw 4;
      bool primary=!strcmp(argv[1],"--watchdog"),custody=!strcmp(argv[1],"--custody");
      if((!primary&&!custody)||!birthValid) throw 4;
      Identity producer; std::string raw=startup(deadline); c=record(raw,primary,producer); parsed=true;
      if(!c.authenticateBirth(birth,birthInfo,birthSession,producer,primary)) throw 4;
      return primary?runPrimary(c,deadline):runCustody(c,deadline);
    } catch(...) { c.cleanupOnly=true; retainedRefusal(parsed?&c:nullptr); } } @catch(NSException*) { c.cleanupOnly=true; retainedRefusal(parsed?&c:nullptr); }
  }
}

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
static Context record(const std::string& raw) {
  NSData* bytes=[NSData dataWithBytes:raw.data() length:raw.size()];
  NSDictionary* value=[NSJSONSerialization JSONObjectWithData:bytes options:0 error:nil]; Context c;
  if(!keys(value,@[@"format",@"candidateSnapshotDigest",@"bundle",@"main",@"primary",@"locks"])||![value[@"format"] isEqual:@1]||![value[@"bundle"] isKindOfClass:[NSString class]]||![value[@"candidateSnapshotDigest"] isKindOfClass:[NSString class]]||[value[@"candidateSnapshotDigest"] length]!=64||!keys(value[@"locks"],@[@"owner",@"build"])||!identityRecord(value[@"main"],c.main,&c.session)||!identityRecord(value[@"primary"],c.primary)||!lockRecord(value[@"locks"][@"owner"],3,c.owner)||!lockRecord(value[@"locks"][@"build"],4,c.build)) throw 4;
  std::string digest=[value[@"candidateSnapshotDigest"] UTF8String]; for(char ch:digest) if(!((ch>='0'&&ch<='9')||(ch>='a'&&ch<='f'))) throw 4;
  c.bundle=[value[@"bundle"] UTF8String]; return c;
}
// Refusal never advertises R or gives up the only retained descriptions. An
// already identified family can be enforced; unknown input cannot select PIDs.
[[noreturn]] static void retainedRefusal(Context* c) {
  for(;;) { if(c) { (void)c->discoverCustody(); c->enforce(); reap(c->custody); if(c->engineGone()) { const Identity& peer=getpid()==c->primary.pid?c->custody:c->primary; if(current(peer)==0) _exit(4); (void)c->retireMonitorPeer(peer); } } usleep(10000); }
}
struct Channel {
  int input,output; std::string incoming,outgoing; bool failed=false;
  Channel(int in,int out):input(in),output(out) { nonblocking(input); nonblocking(output); }
  void send(const std::string& line) { if(line.size()>128||outgoing.size()+line.size()>4096) {failed=true;return;} outgoing+=line; }
  void flush() {
    while(!outgoing.empty()&&!failed) { ssize_t n=write(output,outgoing.data(),outgoing.size());
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
  double expires; bool fatal=false,received=false; uint64_t sequence=0;
  explicit Deadline(double start):expires(start+2500) {}
  bool accept(const Frame& value,double now) {
    if(received&&value.sequence<=sequence) return false;
    received=true; sequence=value.sequence;
    if(value.kind=='F') { fatal=true; expires=std::min(expires,now+1000); }
    else if(!fatal) expires=now+2500;
    return true;
  }
  void lost(double now) { fatal=true; expires=std::min(expires,now); }
};
[[noreturn]] static void protocolLoop(Context& c,Channel& pair,bool primary,double start) {
  Channel host(primary?0:6,primary?1:7); Deadline deadline(start);
  struct Pending { uint64_t sequence; double sent; }; std::deque<Pending> pending;
  if(primary) host.send("R 1 "+std::to_string(c.main.pid)+"\n");
  double blockedWrite=0;
  for(;;) {
    double now=clockMs();
    Channel& input=primary?host:pair;
    for(const std::string& line:input.readLines()) {
      Frame value;
      if(!frame(line,value,"HF")||!deadline.accept(value,now)) { deadline.lost(now); break; }
      if(primary) { if(pending.size()>=16) { deadline.lost(now); break; } pending.push_back({value.sequence,now}); pair.send(line+"\n"); }
      else pair.send("A "+std::to_string(value.sequence)+"\n");
    }
    if(primary) {
      for(const std::string& line:pair.readLines()) {
        Frame value;
        if(!frame(line,value,"A")||pending.empty()||pending.front().sequence!=value.sequence) { deadline.lost(now); break; }
        pending.pop_front(); host.send(line+"\n");
      }
      if(!pending.empty()&&now-pending.front().sent>=1000) deadline.lost(now);
    }
    pair.flush(); if(primary) host.flush();
    bool outputPending=!pair.outgoing.empty()||(primary&&!host.outgoing.empty());
    if(outputPending) { if(!blockedWrite) blockedWrite=now; else if(now-blockedWrite>=1000) deadline.lost(now); } else blockedWrite=0;
    if(pair.failed||(primary&&host.failed)||current(primary?c.custody:c.primary)!=1||!lockIdentity(c.owner)||!lockIdentity(c.build)) deadline.lost(now);
    if(now>=deadline.expires) c.enforce();
    reap(c.custody);
    if(c.engineGone()) retainedRefusal(&c); // post-quiescence phase follows
    usleep(5000);
  }
}
static void pipeDescriptors(int (&out)[2]) {
  int raw[2]; if(pipe(raw)) throw 4;
  out[0]=fcntl(raw[0],F_DUPFD_CLOEXEC,10); out[1]=fcntl(raw[1],F_DUPFD_CLOEXEC,10); close(raw[0]); close(raw[1]);
  if(out[0]<0||out[1]<0) throw 4;
}
static Channel launchCustody(Context& c,const std::string& raw,double deadline) {
  int init[2],forward[2],reply[2]; pipeDescriptors(init); pipeDescriptors(forward); pipeDescriptors(reply);
  int owner=fcntl(3,F_DUPFD_CLOEXEC,10),build=fcntl(4,F_DUPFD_CLOEXEC,10);
  posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
  if(owner<0||build<0||posix_spawn_file_actions_init(&actions)||posix_spawnattr_init(&attr)) throw 4;
  bool ok=!posix_spawn_file_actions_adddup2(&actions,owner,3)&&!posix_spawn_file_actions_adddup2(&actions,build,4)&&
    !posix_spawn_file_actions_adddup2(&actions,init[0],5)&&!posix_spawn_file_actions_adddup2(&actions,forward[0],6)&&!posix_spawn_file_actions_adddup2(&actions,reply[1],7)&&
    !posix_spawn_file_actions_addopen(&actions,0,"/dev/null",O_RDONLY,0)&&!posix_spawn_file_actions_addopen(&actions,1,"/dev/null",O_WRONLY,0)&&!posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)&&
    !posix_spawnattr_setpgroup(&attr,c.main.group)&&!posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_CLOEXEC_DEFAULT);
  std::string helper=c.helper(); char* args[]={helper.data(),(char*)"--custody",nullptr}; char* env[]={(char*)"PATH=/usr/bin:/bin",nullptr}; pid_t pid=0;
  int result=ok?posix_spawn(&pid,helper.c_str(),&actions,&attr,args,env):EINVAL;
  posix_spawn_file_actions_destroy(&actions); posix_spawnattr_destroy(&attr);
  close(owner); close(build); close(init[0]); close(forward[0]); close(reply[1]);
  if(result) throw 4;
  // Capture the actual child even if its validation fails: failed-attempt
  // retirement must not forget a child which already owns duplicate locks.
  if(observe(pid,c.custody)!=1||!c.monitor(c.custody,true)) throw 4;
  nonblocking(init[1]); size_t offset=0;
  while(offset<raw.size()) { if(clockMs()>=deadline) throw 4; ssize_t n=write(init[1],raw.data()+offset,raw.size()-offset);
    if(n>0) offset+=(size_t)n; else if(n<0&&(errno==EINTR||errno==EAGAIN||errno==EWOULDBLOCK)) usleep(1000); else throw 4; }
  close(init[1]); Channel pair(reply[0],forward[1]);
  std::string expected="C 1 "+std::to_string(c.custody.pid)+" "+std::to_string(c.custody.start);
  for(;;) { if(clockMs()>=deadline||pair.failed||current(c.custody)!=1) throw 4;
    auto lines=pair.readLines(); if(lines.size()==1&&lines[0]==expected&&c.monitor(c.custody,true)&&c.initial()) return pair;
    if(!lines.empty()) throw 4; usleep(1000); }
}
static int runPrimary(Context& c,const std::string& raw,double deadline) {
  Identity self; Info detail{};
  if(getppid()!=c.main.pid||observe(getpid(),self,&detail)!=1||!same(self,c.primary)||detail.unique.parent!=c.main.start||!c.initial()||!c.monitor(self,false)) throw 4;
  Channel pair=launchCustody(c,raw,deadline);
  if(clockMs()>=deadline) throw 4; protocolLoop(c,pair,true,deadline-1000);
}
static int runCustody(Context& c,double deadline) {
  Info detail{};
  if(getppid()!=c.primary.pid||observe(getpid(),c.custody,&detail)!=1||detail.unique.parent!=c.primary.start||!c.initial()||!c.monitor(c.primary,false)||!c.monitor(c.custody,true)||clockMs()>=deadline) throw 4;
  Channel pair(6,7); pair.send("C 1 "+std::to_string(c.custody.pid)+" "+std::to_string(c.custody.start)+"\n");
  while(!pair.outgoing.empty()) { if(clockMs()>=deadline||pair.failed) throw 4; pair.flush(); usleep(1000); }
  protocolLoop(c,pair,false,deadline-1000);
}

int main(int argc,const char* argv[]) {
  signal(SIGPIPE,SIG_IGN); double deadline=clockMs()+1000; Context c; bool parsed=false;
  @autoreleasepool {
    @try { try {
      if(argc!=2) throw 4;
      bool primary=!strcmp(argv[1],"--watchdog"),custody=!strcmp(argv[1],"--custody");
      if((!primary&&!custody)||(primary&&(setpgid(0,0)||getpgrp()!=getpid()))) throw 4;
      std::string raw=startup(deadline); c=record(raw); parsed=true;
      return primary?runPrimary(c,raw,deadline):runCustody(c,deadline);
    } catch(...) { retainedRefusal(parsed?&c:nullptr); } } @catch(NSException*) { retainedRefusal(parsed?&c:nullptr); }
  }
}

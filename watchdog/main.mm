// Private signed watchdog executable. Never loads Electron or an input addon.
#import <Foundation/Foundation.h>
#include "boundary.hpp"
#include <poll.h>
#include <spawn.h>
#include <deque>
#include <limits>
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
  for(;;) { if(c) { (void)c->discoverCustody(); c->enforce(); reap(c->custody); if(c->engineGone() && current(c->custody)==0) _exit(4); } usleep(10000); }
}
static int runPrimary(Context& c,const std::string&,double) {
  Identity self; Info detail{};
  if(getppid()!=c.main.pid||observe(getpid(),self,&detail)!=1||!same(self,c.primary)||detail.unique.parent!=c.main.start||!c.initial()||!c.monitor(self,false)) throw 4;
  // Pair startup/protocol is installed by the following atomic leaves. Until
  // then this executable provides no ready acknowledgement or admission.
  retainedRefusal(&c);
}
int main(int argc,const char* argv[]) {
  signal(SIGPIPE,SIG_IGN); double deadline=clockMs()+1000; Context c; bool parsed=false;
  @autoreleasepool {
    @try { try {
      if(argc!=2||strcmp(argv[1],"--watchdog")||setpgid(0,0)||getpgrp()!=getpid()) throw 4;
      std::string raw=startup(deadline); c=record(raw); parsed=true;
      return runPrimary(c,raw,deadline);
    } catch(...) { retainedRefusal(parsed?&c:nullptr); } } @catch(NSException*) { retainedRefusal(parsed?&c:nullptr); }
  }
}

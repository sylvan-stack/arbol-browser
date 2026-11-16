// Testing-only out-of-group observer, independent of platform.node.
// No production census/signaling helper is included or used as its own oracle.
#import <Foundation/Foundation.h>
#include <libproc.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <time.h>
struct ObserverUnique { uint8_t uuid[16]; uint64_t start,parent; int32_t version,parentVersion; uint64_t reserved[2]; };
struct ObserverInfo { proc_bsdinfo bsd; ObserverUnique unique; };
static_assert(sizeof(ObserverUnique)==56);
static NSDictionary* process(pid_t pid) {
  ObserverInfo first{},last{}; errno=0;
  int n=proc_pidinfo(pid,18,0,&first,sizeof(first));
  if(n==0&&errno==ESRCH) return @{ @"pid":@(pid),@"status":@"gone" };
  if(n!=sizeof(first)||first.bsd.pbi_pid!=(uint32_t)pid||!first.unique.start||first.unique.version<1) return @{ @"pid":@(pid),@"status":@"uncertain" };
  char executable[PROC_PIDPATHINFO_MAXSIZE]{}; int pathSize=proc_pidpath(pid,executable,sizeof(executable));
  if(proc_pidinfo(pid,18,0,&last,sizeof(last))!=sizeof(last)||last.unique.start!=first.unique.start||last.unique.version!=first.unique.version||last.bsd.pbi_pgid!=first.bsd.pbi_pgid||pathSize<=0) return @{ @"pid":@(pid),@"status":@"uncertain" };
  return @{ @"pid":@(pid),@"status":@"alive",@"startId":[NSString stringWithFormat:@"%llu",first.unique.start],@"pidVersion":@(first.unique.version),@"uid":@(first.bsd.pbi_uid),@"group":@(first.bsd.pbi_pgid),@"session":@(getsid(pid)),@"parent":@(first.bsd.pbi_ppid),@"parentStartId":[NSString stringWithFormat:@"%llu",first.unique.parent],@"originalParentVersion":@(first.unique.parentVersion),@"executable":@(executable) };
}
static NSDictionary* group(pid_t value) {
  std::vector<pid_t> pids(4097); int bytes=proc_listpids(PROC_PGRP_ONLY,(uint32_t)value,pids.data(),(int)(pids.size()*sizeof(pid_t)));
  if(bytes<0||bytes%(int)sizeof(pid_t)||bytes>=(int)(pids.size()*sizeof(pid_t))) return nil;
  NSMutableArray* members=[NSMutableArray new];
  for(int i=0;i<bytes/(int)sizeof(pid_t);++i) if(pids[i]>0) {
    NSDictionary* item=process(pids[i]);
    if([item[@"status"] isEqual:@"uncertain"]||([item[@"status"] isEqual:@"alive"]&&[item[@"group"] intValue]!=value)) return nil;
    [members addObject:item];
  }
  return @{ @"group":@(value),@"members":members };
}
static NSString* monotonic() {
  struct timespec value{};if(clock_gettime(CLOCK_MONOTONIC_RAW,&value)) return nil;
  return [NSString stringWithFormat:@"%llu",(unsigned long long)value.tv_sec*1000000000ULL+(unsigned long long)value.tv_nsec];
}
static bool originalMatches(NSDictionary* expected,NSDictionary* current) {
  for(NSString* key in @[@"pid",@"startId",@"pidVersion",@"uid",@"executable"])
    if(![expected[key] isEqual:current[key]]) return false;
  return [current[@"status"] isEqual:@"alive"];
}
static NSDictionary* startupSlots(pid_t pid) {
  NSDictionary* before=process(pid);
  if(![before[@"status"] isEqual:@"alive"]) return @{@"before":before};
  NSMutableArray* slots=[NSMutableArray new];
  for(int fd : {3,4,5}) {
    struct vnode_fdinfo info{};
    errno=0;
    int size=proc_pidfdinfo(pid,fd,PROC_PIDFDVNODEINFO,&info,sizeof(info));
    if(size!=sizeof(info)) { [slots addObject:@{@"fd":@(fd),@"unavailable":@(errno),@"size":@(size)}]; continue; }
    const auto& stat=info.pvi.vi_stat;
    [slots addObject:@{@"fd":@(fd),@"device":[NSString stringWithFormat:@"%llu",(uint64_t)stat.vst_dev],
      @"inode":[NSString stringWithFormat:@"%llu",stat.vst_ino],@"uid":@(stat.vst_uid),@"mode":@(stat.vst_mode&07777),
      @"links":@(stat.vst_nlink),@"flags":@(info.pfi.fi_openflags),@"regular":@(S_ISREG(stat.vst_mode))}];
  }
  NSDictionary* after=process(pid);
  return @{@"before":before,@"after":after,@"identityMatches":@(originalMatches(before,after)),@"slots":slots};
}
static NSArray* originals(NSArray* expected) {
  NSMutableArray* result=[NSMutableArray new];
  for(NSDictionary* original in expected) {
    NSDictionary* current=process([original[@"pid"] intValue]);
    [result addObject:@{@"original":original,@"current":current,@"identityMatches":@(originalMatches(original,current))}];
  }
  return result;
}
static bool lockIdentity(int fd,NSDictionary* expected) {
  NSString* path=expected[@"path"];if(![path isKindOfClass:NSString.class]||!path.isAbsolutePath) return false;
  char canonical[PATH_MAX];struct stat actual{},published{};
  if(!realpath(path.fileSystemRepresentation,canonical)||strcmp(canonical,path.fileSystemRepresentation)||
      fstat(fd,&actual)||lstat(path.fileSystemRepresentation,&published)||!S_ISREG(actual.st_mode)||actual.st_dev!=published.st_dev||actual.st_ino!=published.st_ino||
      actual.st_uid!=geteuid()||actual.st_nlink!=1||(actual.st_mode&07777)!=0600) return false;
  return [expected[@"device"] isEqual:[NSString stringWithFormat:@"%llu",(uint64_t)actual.st_dev]]&&
    [expected[@"inode"] isEqual:[NSString stringWithFormat:@"%llu",actual.st_ino]]&&[expected[@"uid"] unsignedIntValue]==actual.st_uid;
}
static NSDictionary* custody(const char* input) {
  size_t size=strlen(input);if(!size||size>65536) return nil;
  id request=[NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:input length:size] options:0 error:nil];
  if(![request isKindOfClass:NSDictionary.class]||[request count]!=5||![request[@"format"] isEqual:@1]||
      ![request[@"processes"] isKindOfClass:NSArray.class]||[request[@"processes"] count]<1||[request[@"processes"] count]>64||
      ![request[@"locks"] isKindOfClass:NSDictionary.class]||[request[@"locks"] count]!=2||![request[@"group"] isKindOfClass:NSNumber.class]||[request[@"group"] intValue]<2) return nil;
  NSArray* expected=request[@"processes"];NSDictionary* anchor=request[@"anchor"];
  if(anchor!=(id)NSNull.null&&![anchor isKindOfClass:NSDictionary.class]) return nil;
  for(id value in expected) if(![value isKindOfClass:NSDictionary.class]||![value[@"pid"] isKindOfClass:NSNumber.class]||[value[@"pid"] intValue]<2||
      ![value[@"startId"] isKindOfClass:NSString.class]||![value[@"pidVersion"] isKindOfClass:NSNumber.class]||![value[@"executable"] isKindOfClass:NSString.class]) return nil;
  struct Descriptors { int values[2]={-1,-1};~Descriptors(){for(int fd:values)if(fd>=0)close(fd);} } descriptors;
  NSArray* names=@[@"owner",@"build"];
  for(unsigned i=0;i<2;++i) {
    NSDictionary* lock=request[@"locks"][names[i]];
    if(![lock isKindOfClass:NSDictionary.class]||![lock[@"path"] isKindOfClass:NSString.class]) return nil;
    descriptors.values[i]=open([lock[@"path"] fileSystemRepresentation],O_RDWR|O_NOFOLLOW|O_CLOEXEC);
    if(descriptors.values[i]<0||!lockIdentity(descriptors.values[i],lock)) return @{@"unavailable":@"original_lock_identity"};
  }
  NSMutableArray* order=[NSMutableArray new];NSMutableDictionary* locks=[NSMutableDictionary new];
  auto snapshot=[&](NSString* stage) { [order addObject:@{@"stage":stage,@"nanos":monotonic(),@"processes":originals(expected)}]; };
  snapshot(@"opened");
  for(unsigned i=0;i<2;++i) {
    NSString* name=names[i];snapshot([@"before-" stringByAppendingString:name]);
    if(!lockIdentity(descriptors.values[i],request[@"locks"][name])) return @{@"unavailable":@"lock_identity_before_attempt",@"order":order};
    errno=0;NSString* before=monotonic();bool acquired=flock(descriptors.values[i],LOCK_EX|LOCK_NB)==0;int error=acquired?0:errno;NSString* after=monotonic();
    NSDictionary* attempt=@{@"stage":[name stringByAppendingString:@"-attempt"],@"beforeNanos":before,@"afterNanos":after,@"acquired":@(acquired),@"errno":@(error)};
    [order addObject:attempt];locks[name]=attempt;snapshot([@"after-" stringByAppendingString:name]);
    if(!lockIdentity(descriptors.values[i],request[@"locks"][name])) return @{@"unavailable":@"lock_identity_after_attempt",@"order":order};
    if(!acquired&&error!=EWOULDBLOCK&&error!=EAGAIN) return @{@"unavailable":@"lock_attempt_error",@"order":order};
  }
  id anchorBefore=anchor==(id)NSNull.null?(id)NSNull.null:process([anchor[@"pid"] intValue]);
  [order addObject:@{@"stage":@"anchor-before-census",@"nanos":monotonic(),@"anchor":anchorBefore}];
  NSDictionary* census=group([request[@"group"] intValue]);
  [order addObject:@{@"stage":@"census",@"nanos":monotonic(),@"census":census?:@{@"unavailable":@"group_census"}}];
  id anchorAfter=anchor==(id)NSNull.null?(id)NSNull.null:process([anchor[@"pid"] intValue]);
  [order addObject:@{@"stage":@"anchor-after-census",@"nanos":monotonic(),@"anchor":anchorAfter}];
  snapshot(@"before-close");
  for(unsigned i=0;i<2;++i) if(!lockIdentity(descriptors.values[i],request[@"locks"][names[i]])) return @{@"unavailable":@"lock_identity_before_close",@"order":order};
  // Acquired descriptors stay held across every post-observation and close only.
  // No simultaneous census, continuous anchor or complete-family exit is inferred.
  NSString* heldThrough=monotonic();
  return @{@"format":@1,@"expected":request,@"locks":locks,@"heldThroughNanos":heldThrough,@"order":order,
    @"limit":@"ordered observations only; individual kernel reads and census are not atomic; unseen family members remain unavailable"};
}
static bool positive(const char* text,int& value) { char* end=nullptr; errno=0; long n=strtol(text,&end,10); if(errno||!end||*end||n<2||n>INT_MAX) return false; value=(int)n; return true; }
int main(int argc,const char* argv[]) {
  @autoreleasepool {
    if(argc!=3) return 64; id result=nil; int value=0;
    if(!strcmp(argv[1],"process")&&positive(argv[2],value)) result=process(value);
    else if(!strcmp(argv[1],"startup-slots")&&positive(argv[2],value)) result=startupSlots(value);
    else if(!strcmp(argv[1],"group")&&positive(argv[2],value)) {
      result=group(value);if(!result)return 70;
    } else if(!strcmp(argv[1],"custody")) {
      result=custody(argv[2]);if(!result)return 65;
    } else if(!strcmp(argv[1],"contend")) {
      char canonical[PATH_MAX]; struct stat st{};
      if(argv[2][0]!='/'||!realpath(argv[2],canonical)||strcmp(canonical,argv[2])||lstat(argv[2],&st)||!S_ISREG(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&07777)!=0600||st.st_nlink!=1) return 65;
      int fd=open(argv[2],O_RDWR|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return 70;
      bool acquired=flock(fd,LOCK_EX|LOCK_NB)==0; int error=errno;
      if(!acquired&&error!=EWOULDBLOCK&&error!=EAGAIN) { close(fd); return 70; }
      // Close only; LOCK_UN would corrupt shared original-description custody.
      close(fd); result=@{ @"acquired":@(acquired),@"device":[NSString stringWithFormat:@"%llu",(uint64_t)st.st_dev],@"inode":[NSString stringWithFormat:@"%llu",st.st_ino] };
    } else return 64;
    NSData* bytes=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:nil]; if(!bytes) return 70;
    if(fwrite(bytes.bytes,1,bytes.length,stdout)!=bytes.length||fputc('\n',stdout)==EOF) return 70; return 0;
  }
}

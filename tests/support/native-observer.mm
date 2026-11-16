// Testing-only out-of-group observer, independent of platform.node.
// No production census/signaling helper is included or used as its own oracle.
#import <Foundation/Foundation.h>
#include <bsm/libbsm.h>
#include <libproc.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/stat.h>
#include <signal.h>
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
  return @{ @"pid":@(pid),@"status":@"alive",@"startId":[NSString stringWithFormat:@"%llu",first.unique.start],@"pidVersion":@(first.unique.version),@"uid":@(first.bsd.pbi_uid),@"group":@(first.bsd.pbi_pgid),@"session":@(getsid(pid)),@"parent":@(first.bsd.pbi_ppid),@"parentStartId":[NSString stringWithFormat:@"%llu",first.unique.parent],@"originalParentVersion":@(first.unique.parentVersion),@"executable":@(executable),@"stopped":@(last.bsd.pbi_status==SSTOP),@"executed":@((last.bsd.pbi_flags&PROC_FLAG_EXEC)!=0) };
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
      @"links":@(stat.vst_nlink),@"flags":@(info.pfi.fi_openflags),@"regular":@(S_ISREG(stat.vst_mode)),@"bytes":@(stat.vst_size)}];
  }
  NSDictionary* after=process(pid);
  return @{@"before":before,@"after":after,@"identityMatches":@(originalMatches(before,after)),@"slots":slots};
}
static NSDictionary* custody(const char* input);
static int signalOriginal(NSDictionary* identity,int signal) {
  int pid=[identity[@"pid"] intValue];
  ObserverInfo now{};
  if(pid<2||proc_pidinfo(pid,18,0,&now,sizeof(now))!=sizeof(now)||now.bsd.pbi_pid!=(uint32_t)pid||
     !(now.bsd.pbi_flags&PROC_FLAG_EXEC)||now.bsd.pbi_uid!=geteuid()||now.unique.version!=[identity[@"pidVersion"] intValue]||
     now.unique.start!=strtoull([identity[@"startId"] UTF8String],nullptr,10)) return ESRCH;
  audit_token_t token{};
  token.val[5]=(uint32_t)pid;
  token.val[7]=[identity[@"pidVersion"] unsignedIntValue];
  return proc_signal_with_audittoken(&token,signal);
}
static NSDictionary* stoppedProcess(NSDictionary* identity) {
  const int pid=[identity[@"pid"] intValue];
  uint64_t deadline=clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+30000000ULL;
  while(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)<deadline) {
    @autoreleasepool {
      NSDictionary* current=process(pid);
      if(!originalMatches(identity,current)) return nil;
      if([current[@"stopped"] boolValue]) return current;
    }
    usleep(100);
  }
  return nil;
}
static NSDictionary* stoppedBirth(NSDictionary* identity) {
  NSDictionary* stopped=stoppedProcess(identity);
  return stopped?startupSlots([stopped[@"pid"] intValue]):nil;
}
struct ResumeOriginal {
  NSDictionary* target;
  ~ResumeOriginal() { (void)signalOriginal(target,SIGCONT); }
};
static NSDictionary* lockSample(NSDictionary* main,NSDictionary* primary,NSDictionary* anchor,NSDictionary* locks) {
  NSArray* family=[primary[@"pid"] isEqual:anchor[@"pid"]]?@[main,primary]:@[main,primary,anchor];
  NSDictionary* request=@{@"format":@1,@"group":main[@"group"],@"processes":family,@"anchor":anchor,@"locks":locks};
  NSData* encoded=[NSJSONSerialization dataWithJSONObject:request options:0 error:nil];
  NSString* text=encoded?[[NSString alloc] initWithData:encoded encoding:NSUTF8StringEncoding]:nil;
  return text?custody(text.UTF8String):nil;
}
static NSDictionary* waitForStopRetirement(NSDictionary* target) {
  int pid=[target[@"pid"] intValue];
  const uint64_t deadline=clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1100000000ULL;
  while(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)<deadline) {
    @autoreleasepool { if([process(pid)[@"status"] isEqual:@"gone"]) break; }
    usleep(1000);
  }
  return process(pid);
}
static NSDictionary* faultAtBirth(NSString* mode,NSDictionary* main,NSDictionary* primary,NSDictionary* target,NSDictionary* locks) {
  if([target[@"stopped"] boolValue]) return @{@"unavailable":@"target-already-stopped"};
  const int pid=[target[@"pid"] intValue];
  const int stop=signalOriginal(target,SIGSTOP);
  if(stop) return @{@"unavailable":@"stop-refused",@"error":@(stop)};
  ResumeOriginal resume{target};
  NSDictionary* held=stoppedBirth(target);
  NSDictionary* before=held[@"before"], *after=held[@"after"], *capsule=[held[@"slots"] lastObject];
  if(![held[@"identityMatches"] boolValue]||!originalMatches(target,before)||![before[@"stopped"] boolValue]||![after[@"stopped"] boolValue]||
     ![before[@"group"] isEqual:main[@"group"]]||![after[@"group"] isEqual:main[@"group"]]||
     ![capsule[@"regular"] boolValue]||[capsule[@"links"] intValue]!=0||([capsule[@"flags"] unsignedIntValue]&3)!=1)
    return @{@"unavailable":@"startup-slot-closed-before-stop",@"observed":held?:@{}};
  const bool isPrimary=[mode isEqual:@"primary-producer-lost"];
  NSDictionary* primaryBefore=process([primary[@"pid"] intValue]);
  if(!originalMatches(primary,primaryBefore)||![primaryBefore[@"group"] isEqual:main[@"group"]])
    return @{@"unavailable":@"primary-left-original-group",@"observed":held};
  NSDictionary* producer=isPrimary?main:primaryBefore;
  NSString* triggeredAt=monotonic();
  NSDictionary* post, *targetAfter;
  if([mode isEqual:@"custody-withholds-c"]) {
    // FD 5 is still open and the stopped process cannot send C. Let the
    // signed components enforce the deadline while the group remains held.
    post=lockSample(main,primary,target,locks);
    targetAfter=waitForStopRetirement(target);
  } else {
    const int killed=signalOriginal(producer,SIGKILL);
    if(killed) return @{@"unavailable":@"producer-signal-refused",@"error":@(killed),@"observed":held};
    const int parent=[producer[@"pid"] intValue];
    const uint64_t deadline=clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+250000000ULL;
    while(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)<deadline) {
      @autoreleasepool { if([process(parent)[@"status"] isEqual:@"gone"]) break; }
      usleep(100);
    }
    post=lockSample(main,primary,target,locks);
    targetAfter=process(pid);
  }
  return @{@"observed":held,@"primaryBefore":primaryBefore,@"producer":producer,@"triggeredAtNanos":triggeredAt,
    @"sample":post?:@{},@"targetAfter":targetAfter,@"finishedAtNanos":monotonic()};
}
static NSDictionary* startupQueues(NSDictionary* primary,NSDictionary* anchor) {
  NSDictionary* before=process([anchor[@"pid"] intValue]);
  NSDictionary* migrated=process([primary[@"pid"] intValue]);
  if(!originalMatches(anchor,before)||![before[@"group"] isEqual:anchor[@"group"]]||
     !originalMatches(primary,migrated)||![migrated[@"group"] isEqual:migrated[@"pid"]]) return nil;
  struct pipe_fdinfo forward{}, reverse{};
  int pid=[anchor[@"pid"] intValue];
  if(proc_pidfdinfo(pid,6,PROC_PIDFDPIPEINFO,&forward,sizeof(forward))!=sizeof(forward)||
     proc_pidfdinfo(pid,7,PROC_PIDFDPIPEINFO,&reverse,sizeof(reverse))!=sizeof(reverse)) return nil;
  NSDictionary* after=process(pid);
  if(!originalMatches(before,after)||![after[@"group"] isEqual:before[@"group"]]) return nil;
  return @{@"anchorBefore":before,@"anchorAfter":after,@"primary":migrated,
    @"forwardBytes":@(forward.pipeinfo.pipe_stat.vst_size),@"reverseBytes":@(reverse.pipeinfo.pipe_stat.vst_size)};
}
static bool transferPending(NSDictionary* queues,bool pendingG) {
  return queues&&[queues[@"forwardBytes"] intValue]==(pendingG?4:0)&&[queues[@"reverseBytes"] intValue]==(pendingG?0:4);
}
static NSDictionary* faultAtTransfer(NSDictionary* observed,NSDictionary* main,NSDictionary* primary,NSDictionary* anchor,NSDictionary* locks,bool pendingG) {
  NSDictionary* target=observed[pendingG?@"anchorAfter":@"primary"];
  int stop=signalOriginal(target,SIGSTOP);
  if(stop) return @{@"unavailable":@"transfer-stop-refused",@"error":@(stop),@"candidate":observed};
  ResumeOriginal resume{target};
  NSDictionary* held=stoppedBirth(target), *queues=startupQueues(primary,anchor);
  if(![held[@"identityMatches"] boolValue]||![held[@"before"][@"stopped"] boolValue]||![held[@"after"][@"stopped"] boolValue]||
     !transferPending(queues,pendingG)||![queues[pendingG?@"anchorAfter":@"primary"][@"stopped"] boolValue])
    return @{@"unavailable":@"transfer-consumed-before-stop",@"candidate":observed,@"held":held?:@{},@"queues":queues?:@{}};
  NSString* triggeredAt=monotonic();
  NSDictionary* sample=lockSample(main,primary,anchor,locks);
  NSDictionary* targetAfter=waitForStopRetirement(target);
  return @{@"observed":held,@"beforeStop":observed,@"queued":queues,@"triggeredAtNanos":triggeredAt,
    @"sample":sample?:@{},@"targetAfter":targetAfter,@"finishedAtNanos":monotonic()};
}
static NSDictionary* observeBirths(const char* input) {
  const size_t size=strlen(input);
  if(!size||size>16384) return nil;
  NSData* data=[NSData dataWithBytes:input length:size];
  NSDictionary* request=[NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
  if(![request isKindOfClass:NSDictionary.class]||![request[@"main"] isKindOfClass:NSDictionary.class]||
     ![request[@"helper"] isKindOfClass:NSString.class]||[request[@"main"][@"pid"] intValue]<=1) return nil;
  NSDictionary* main=request[@"main"];
  int pid=[main[@"pid"] intValue];
  NSString* helper=request[@"helper"];
  NSString* mode=request[@"mode"];
  if(![mode isKindOfClass:NSString.class]||![@[@"startup-descriptors",@"primary-producer-lost",@"custody-producer-lost",@"custody-withholds-c",
      @"custody-withholds-g",@"primary-withholds-j"] containsObject:mode]||
     ![request[@"locks"] isKindOfClass:NSDictionary.class]) return nil;
  const bool pendingG=[mode isEqual:@"custody-withholds-g"], watchTransfer=pendingG||[mode isEqual:@"primary-withholds-j"];
  if(!originalMatches(main,process(pid))||[main[@"group"] intValue]!=pid||[main[@"uid"] unsignedIntValue]!=geteuid()) return nil;
  if(fputs("{\"stage\":\"watch-ready\"}\n",stdout)==EOF||fflush(stdout)) return nil;
  NSDictionary* primary=nil;
  NSMutableDictionary* first=[NSMutableDictionary new], *capsules=[NSMutableDictionary new];
  const bool control=[mode isEqual:@"startup-descriptors"];
  ResumeOriginal releaseMain{nil};
  NSDictionary* mainBeforeCustody=nil;
  uint64_t deadline=clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1800000000ULL;
  std::vector<pid_t> pids(4097);
  while(clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)<deadline) {
    @autoreleasepool {
      int size=proc_listpids(PROC_PGRP_ONLY,(uint32_t)pid,pids.data(),(int)(pids.size()*sizeof(pid_t)));
      if(size<0||size%(int)sizeof(pid_t)||size>=(int)(pids.size()*sizeof(pid_t))) return nil;
      for(int i=0;i<size/(int)sizeof(pid_t);++i) {
        if(pids[i]<2||pids[i]==pid) continue;
        NSDictionary* candidate=process(pids[i]);
        if(![candidate[@"status"] isEqual:@"alive"]||![candidate[@"executed"] boolValue]||![candidate[@"executable"] isEqual:helper]||
           ![candidate[@"group"] isEqual:main[@"group"]]||![candidate[@"session"] isEqual:main[@"session"]]||
           ![candidate[@"uid"] isEqual:main[@"uid"]]) continue;
        auto isChildOf=[&](NSDictionary* parent) {
          return [candidate[@"parent"] isEqual:parent[@"pid"]]&&[candidate[@"parentStartId"] isEqual:parent[@"startId"]]&&
            [candidate[@"originalParentVersion"] isEqual:parent[@"pidVersion"]];
        };
        NSString* role=nil;
        if(isChildOf(main)) {
          if(primary&&!originalMatches(primary,candidate)) return nil;
          primary=candidate; role=@"primary";
        } else if(primary&&isChildOf(primary)) role=@"custody";
        if(!role||capsules[role]) continue;
        if(!first[role]) first[role]=candidate;
        else if(!originalMatches(first[role],candidate)) return nil;
        const bool fault=[role isEqual:@"primary"]?[mode isEqual:@"primary-producer-lost"]:
          [mode isEqual:@"custody-producer-lost"]||[mode isEqual:@"custody-withholds-c"];
        if(fault) {
          NSDictionary* attempt=faultAtBirth(mode,main,primary,candidate,request[@"locks"]);
          return @{@"main":main,@"first":first,@"capsules":capsules,@"fault":attempt};
        }
        NSDictionary* primaryBefore=[role isEqual:@"custody"]?process([primary[@"pid"] intValue]):nil;
        NSDictionary* observation=startupSlots(pids[i]);
        NSDictionary* primaryAfter=primaryBefore?process([primary[@"pid"] intValue]):nil;
        if(![observation[@"identityMatches"] boolValue]||!originalMatches(candidate,observation[@"before"])||
           ![observation[@"before"][@"group"] isEqual:main[@"group"]]||![observation[@"after"][@"group"] isEqual:main[@"group"]]) continue;
        NSDictionary* capsule=[observation[@"slots"] lastObject];
        if([capsule[@"regular"] boolValue]&&[capsule[@"links"] unsignedIntValue]==0&&[capsule[@"bytes"] longLongValue]>0) {
          NSMutableDictionary* receipt=[@{@"observedAtNanos":monotonic(),@"observation":observation} mutableCopy];
          if(primaryBefore) receipt[@"primaryOverlap"]=@[primaryBefore,primaryAfter];
          capsules[role]=receipt;
          if(control&&[role isEqual:@"primary"]&&!releaseMain.target) {
            // The real primary can continue startup while the original main
            // holds its process group. Resume main as soon as custody exists.
            if([process(pid)[@"stopped"] boolValue]||signalOriginal(main,SIGSTOP)) return nil;
            releaseMain.target=main;
            mainBeforeCustody=stoppedProcess(main);
            if(![mainBeforeCustody[@"group"] isEqual:main[@"group"]]) return nil;
            receipt[@"mainHeldAtNanos"]=monotonic();
          }
          if(control&&[role isEqual:@"custody"]) {
            NSDictionary* mainAfter=process(pid);
            if(!mainBeforeCustody||!originalMatches(mainBeforeCustody,mainAfter)||![mainAfter[@"stopped"] boolValue]||
               ![mainAfter[@"group"] isEqual:main[@"group"]]) return nil;
            receipt[@"mainOverlap"]=@[mainBeforeCustody,mainAfter];
          }
        }
      }
      if(watchTransfer&&first[@"custody"]) {
        NSDictionary* queues=startupQueues(primary,first[@"custody"]);
        if(transferPending(queues,pendingG)&&originalMatches(main,process(pid))) {
          NSDictionary* attempt=faultAtTransfer(queues,main,primary,first[@"custody"],request[@"locks"],pendingG);
          return @{@"main":main,@"first":first,@"capsules":capsules,@"fault":attempt};
        }
      }
    }
    if(!watchTransfer&&capsules.count==2) break;
    usleep(100);
  }
  return @{@"main":main,@"first":first,@"capsules":capsules};
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
    else if(!strcmp(argv[1],"startup-births")) result=observeBirths(argv[2]);
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
    if(!result) return 70;
    NSData* bytes=[NSJSONSerialization dataWithJSONObject:result options:NSJSONWritingSortedKeys error:nil]; if(!bytes) return 70;
    if(fwrite(bytes.bytes,1,bytes.length,stdout)!=bytes.length||fputc('\n',stdout)==EOF) return 70; return 0;
  }
}

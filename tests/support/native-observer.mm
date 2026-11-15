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
static bool positive(const char* text,int& value) { char* end=nullptr; errno=0; long n=strtol(text,&end,10); if(errno||!end||*end||n<2||n>INT_MAX) return false; value=(int)n; return true; }
int main(int argc,const char* argv[]) {
  @autoreleasepool {
    if(argc!=3) return 64; id result=nil; int value=0;
    if(!strcmp(argv[1],"process")&&positive(argv[2],value)) result=process(value);
    else if(!strcmp(argv[1],"group")&&positive(argv[2],value)) {
      std::vector<pid_t> pids(4097); int bytes=proc_listpids(PROC_PGRP_ONLY,(uint32_t)value,pids.data(),(int)(pids.size()*sizeof(pid_t)));
      if(bytes<0||bytes%(int)sizeof(pid_t)||bytes>=(int)(pids.size()*sizeof(pid_t))) return 70;
      NSMutableArray* members=[NSMutableArray new];
      for(int i=0;i<bytes/(int)sizeof(pid_t);++i) if(pids[i]>0) { NSDictionary* item=process(pids[i]); if([item[@"status"] isEqual:@"uncertain"]||([item[@"status"] isEqual:@"alive"]&&[item[@"group"] intValue]!=value)) return 70; [members addObject:item]; }
      result=@{ @"group":@(value),@"members":members };
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

// Testing-only kernel-observation driver. The census algorithm is included
// verbatim from the hash-bound frozen header, never copied or reimplemented.
#import <Foundation/Foundation.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>
#include <libproc.h>
#include <bsm/libbsm.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/proc.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#include <mach/mach_time.h>
#include <cerrno>
#include <climits>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <vector>
#include <algorithm>
static int fixtureInfo(int,int,uint64_t,void*,int);
static int fixtureList(uint32_t,uint32_t,void*,int);
static int fixturePath(audit_token_t*,void*,uint32_t);
#define proc_pidinfo fixtureInfo
#define proc_listpids fixtureList
#define proc_pidpath_audittoken fixturePath
#include ARBOL_CENSUS_HEADER
#undef proc_pidinfo
#undef proc_listpids
#undef proc_pidpath_audittoken
using namespace arbol_boundary;
static constexpr int mainPid=10001, helperPid=10002;
static Identity originalMain{mainPid,101,1,0,mainPid}, originalHelper{helperPid,102,1,0,mainPid};
static std::string bundle, scenario;
static bool fault=false, failedPath=false;
static unsigned helperReads=0;
static NSMutableArray* observations;
static int fixtureInfo(int pid,int flavor,uint64_t arg,void* output,int size) {
  if(flavor!=18||arg||size!=(int)sizeof(Info)||(pid!=mainPid&&pid!=helperPid)) { errno=EINVAL; return -1; }
  Identity id=pid==mainPid?originalMain:originalHelper;
  int state=1;
  if(pid==helperPid&&fault) {
    ++helperReads;
    if(failedPath) {
      if(scenario=="absent"||scenario=="never-verified") state=0;
      else if(scenario=="outside-reuse") { ++id.start; id.group=20001; }
      else if(scenario=="unresolved") state=-1;
      else if(scenario=="same-start-uid") ++id.uid;
      else if(scenario=="same-start-version") ++id.version;
      else if(scenario=="inside-reuse") ++id.start;
      else if(scenario=="final-original-live"&&helperReads==2) state=0;
    }
  }
  [observations addObject:@{@"call":@"pidinfo",@"pid":@(pid),@"state":@(state),@"start":@(id.start),@"version":@(id.version),@"uid":@(id.uid),@"group":@(id.group)}];
  if(state!=1) { errno=state==0?ESRCH:EACCES; return 0; }
  Info info{};info.bsd.pbi_pid=pid;info.bsd.pbi_uid=id.uid;info.bsd.pbi_pgid=id.group;
  info.unique.start=id.start;info.unique.version=id.version;
  info.unique.parent=originalMain.start;info.unique.originalParentVersion=originalMain.version;
  memcpy(output,&info,sizeof(info));return sizeof(info);
}
static int fixtureList(uint32_t type,uint32_t group,void* output,int size) {
  if(type!=PROC_PGRP_ONLY||group!=mainPid||size<8) { errno=EINVAL; return -1; }
  const int count=!fault&&scenario=="never-verified"?1:2;
  int pids[]={mainPid,helperPid};memcpy(output,pids,count*sizeof(int));
  [observations addObject:@{@"call":@"listpids",@"count":@(count)}];return count*sizeof(int);
}
static int fixturePath(audit_token_t* token,void* output,uint32_t size) {
  int pid=token->val[5];
  if(fault&&pid==helperPid) { failedPath=true; [observations addObject:@{@"call":@"executable",@"pid":@(pid),@"failed":@YES}]; errno=ESRCH; return 0; }
  std::string path=bundle+"/Contents/Resources/browser/runtime/Electron.app/Contents/"+(pid==mainPid?std::string("MacOS/Electron"):std::string("Frameworks/Electron Helper (Renderer).app/Contents/MacOS/Electron Helper (Renderer)"));
  if(path.size()+1>size) return 0;memcpy(output,path.c_str(),path.size()+1);return (int)path.size();
}
int main(int argc,char** argv) { @autoreleasepool {
  if(argc!=3) return 2;bundle=argv[1];scenario=argv[2];
  originalMain.uid=originalHelper.uid=geteuid();observations=[NSMutableArray new];
  Context context;context.authenticated=true;context.bundle=bundle;context.main=originalMain;
  std::vector<Identity> targets;bool admitted=context.census(targets);
  bool verified=context.seen.count(helperPid)&&same(context.seen.at(helperPid),originalHelper);
  NSArray* admission=[observations copy];[observations removeAllObjects];fault=true;
  bool accepted=admitted&&context.census(targets);
  NSMutableArray* selected=[NSMutableArray new];for(const auto& id:targets) [selected addObject:capsuleIdentity(id)];
  NSMutableArray* seen=[NSMutableArray new];for(const auto& entry:context.seen) [seen addObject:capsuleIdentity(entry.second)];
  NSDictionary* report=@{@"scenario":@(scenario.c_str()),@"admitted":@(admitted),@"helperVerified":@(verified),@"accepted":@(accepted),
    @"originalHelper":capsuleIdentity(originalHelper),@"targets":selected,@"seen":seen,@"admissionObservations":admission,@"faultObservations":observations,
    @"scope":@"controlled kernel observations; actual shared census, canonical paths and signature validation; no product seam"};
  NSData* data=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingSortedKeys error:nil];
  if(!data) return 3;fwrite(data.bytes,1,data.length,stdout);putchar('\n');return 0;
} }

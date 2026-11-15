// Testing-only external launcher. No production boundary code is linked.
// The packaged native platform revalidates this actual pre-exec kernel identity.
#import <Foundation/Foundation.h>
#include <libproc.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <string>
struct LaunchUnique { uint8_t uuid[16]; uint64_t start,parent; int32_t version,parentVersion; uint64_t reserved[2]; };
struct LaunchInfo { proc_bsdinfo bsd; LaunchUnique unique; };
static_assert(sizeof(LaunchUnique)==56);
static bool canonical(const char* path) { char result[PATH_MAX]; return path[0]=='/'&&realpath(path,result)&&!strcmp(path,result); }
int main(int argc,const char* argv[]) {
  @autoreleasepool {
    if(argc!=5||!canonical(argv[1])||!canonical(argv[2])||!canonical(argv[3])||!canonical(argv[4])) return 64;
    struct stat request{},home{};
    if(lstat(argv[3],&home)||!S_ISDIR(home.st_mode)||(home.st_mode&07777)!=0700||home.st_uid!=geteuid()||
       lstat(argv[4],&request)||!S_ISREG(request.st_mode)||(request.st_mode&07777)!=0600||request.st_uid!=geteuid()||request.st_nlink!=1||request.st_size<1||request.st_size>16384) return 65;
    if(setpgid(0,0)||getpgrp()!=getpid()) return 66;
    LaunchInfo info{};
    if(proc_pidinfo(getpid(),18,0,&info,sizeof(info))!=sizeof(info)||!info.unique.start||info.bsd.pbi_pgid!=(uint32_t)getpid()||getsid(0)<=0) return 67;
    std::string engine=std::string(argv[1])+"/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron";
    if(!canonical(engine.c_str())) return 68;
    std::string homeEnv="HOME="+std::string(argv[3]),requestEnv="ARBOL_BROWSER_QUALIFICATION_REQUEST="+std::string(argv[4]);
    std::string original="ARBOL_BROWSER_BOOTSTRAP=1:"+std::to_string(getpid())+":"+std::to_string(info.unique.start)+":"+std::to_string(getpgrp())+":"+std::to_string(getsid(0))+":"+std::to_string(geteuid());
    char* args[]={engine.data(),const_cast<char*>(argv[2]),nullptr};
    char* environment[]={homeEnv.data(),requestEnv.data(),original.data(),(char*)"PATH=/usr/bin:/bin",(char*)"TMPDIR=/private/tmp",(char*)"LANG=en_US.UTF-8",nullptr};
    // This external fixture supplies no production bootstrap or host-start proof.
    execve(engine.c_str(),args,environment); return 69;
  }
}

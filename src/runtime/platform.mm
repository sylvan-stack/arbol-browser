// Private process support only (BRW-0.14, BRW-1.7, BRW-3.11), not native input ABI.
#import <Foundation/Foundation.h>
#include <node_api.h>
#include "../../watchdog/boundary.hpp"
#include "attempt.hpp"
#include "../../watchdog/exit.hpp"
#include <spawn.h>
#include <set>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libproc.h>
#include <bsm/libbsm.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <cmath>
#include <dirent.h>
#include <cstdint>
#include <string>
#include <vector>

// Darwin kernel ABI, absent from the public SDK. Refuse unavailable/changed sizes.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info_private.h
struct UniqueInfo {
  uint8_t uuid[16]; uint64_t uniqueid, parentUniqueid;
  int32_t pidVersion, originalParentVersion; uint64_t reserved2, reserved3;
};
static_assert(sizeof(UniqueInfo) == 56);
struct ProcessInfo { proc_bsdinfo bsd; UniqueInfo unique; };
static constexpr int kBsdWithUniqueId = 18;
struct HeldLock { int fd; std::string path; dev_t dev; ino_t ino; int mode; bool retained = false; };
static std::set<HeldLock*> liveLocks;

static napi_value fail(napi_env env) {
  napi_throw_error(env, "platform_unavailable", "Private OS support unavailable."); return nullptr;
}
static napi_value text(napi_env env, const std::string& value) {
  napi_value out; if (napi_create_string_utf8(env, value.c_str(), value.size(), &out) != napi_ok) return fail(env);
  return out;
}
static napi_value number(napi_env env, uint32_t value) {
  napi_value out; if (napi_create_uint32(env, value, &out) != napi_ok) return fail(env); return out;
}
static bool property(napi_env env, napi_value object, const char* name, napi_value value) {
  return value && napi_set_named_property(env, object, name, value) == napi_ok;
}
static bool integer(napi_env env, napi_value value, int* out) {
  double n; if (napi_get_value_double(env, value, &n) != napi_ok || !std::isfinite(n) || n < 0 || n > INT_MAX || n != (int)n) return false;
  *out = (int)n; return true;
}
static bool string(napi_env env, napi_value value, std::string& out) {
  size_t length = 0, written = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok || !length || length >= PATH_MAX) return false;
  out.resize(length + 1);
  if (napi_get_value_string_utf8(env, value, out.data(), out.size(), &written) != napi_ok || written != length) return false;
  out.resize(length); return out[0] == '/' && out.find('\0') == std::string::npos;
}
static bool argument(napi_env env, napi_callback_info info, napi_value* value) {
  size_t n = 1; return napi_get_cb_info(env, info, &n, value, nullptr, nullptr) == napi_ok && n == 1;
}
static void finalize(napi_env, void* data, void*) {
  auto* lock = static_cast<HeldLock*>(data);
  if (lock->retained) return; // exact fixed-exec original lasts until OS exit
  liveLocks.erase(lock);
  if (lock->fd >= 0) close(lock->fd);
  delete lock;
}
static bool matches(const HeldLock* lock, struct stat* out) {
  struct stat path;
  return lock->fd >= 0 && fstat(lock->fd, out) == 0 && lstat(lock->path.c_str(), &path) == 0 &&
    S_ISREG(out->st_mode) && S_ISREG(path.st_mode) && out->st_uid == geteuid() &&
    (out->st_mode & 07777) == 0600 && out->st_nlink == 1 && path.st_nlink == 1 &&
    out->st_dev == lock->dev && out->st_ino == lock->ino &&
    path.st_dev == out->st_dev && path.st_ino == out->st_ino;
}
static napi_value acquireLock(napi_env env, napi_callback_info info, int mode) {
  napi_value arg; std::string path;
  if (!argument(env, info, &arg) || !string(env, arg, path)) return fail(env);
  int fd = open(path.c_str(), O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
  if (fd < 0) return fail(env);
  struct stat st;
  if (fstat(fd, &st) != 0) { close(fd); return fail(env); }
  auto* lock = new HeldLock{fd, path, st.st_dev, st.st_ino, mode};
  if (!matches(lock, &st)) { finalize(env, lock, nullptr); return fail(env); }
  if (flock(fd, mode | LOCK_NB) != 0) {
    int error = errno; finalize(env, lock, nullptr);
    if (error == EWOULDBLOCK || error == EAGAIN) { napi_value nullValue; napi_get_null(env, &nullValue); return nullValue; }
    return fail(env);
  }
  if (!matches(lock, &st)) { finalize(env, lock, nullptr); return fail(env); }
  napi_value handle;
  if (napi_create_external(env, lock, finalize, nullptr, &handle) != napi_ok) {
    finalize(env, lock, nullptr); return fail(env);
  }
  liveLocks.insert(lock);
  return handle;
}
static napi_value tryLock(napi_env env, napi_callback_info info) { return acquireLock(env, info, LOCK_EX); }
static napi_value trySharedLock(napi_env env, napi_callback_info info) { return acquireLock(env, info, LOCK_SH); }
static HeldLock* held(napi_env env, napi_callback_info info) {
  napi_value arg; void* data = nullptr;
  if (!argument(env, info, &arg) || napi_get_value_external(env, arg, &data) != napi_ok || !data) return nullptr;
  auto* lock = static_cast<HeldLock*>(data);
  return liveLocks.count(lock) ? lock : nullptr;
}
static napi_value assertLock(napi_env env, napi_callback_info info) {
  auto* lock = held(env, info); struct stat st;
  if (!lock || !matches(lock, &st)) return fail(env);
  napi_value object; if (napi_create_object(env, &object) != napi_ok) return fail(env);
  if (!property(env, object, "device", text(env, std::to_string(st.st_dev))) ||
      !property(env, object, "inode", text(env, std::to_string(st.st_ino))) ||
      !property(env, object, "uid", number(env, st.st_uid))) return fail(env);
  return object;
}
static napi_value releaseLock(napi_env env, napi_callback_info info) {
  auto* lock = held(env, info); if (!lock) return fail(env);
  if (lock->retained) return fail(env); // no main-process early Build release
  if (lock->fd >= 0) {
    int fd = lock->fd; lock->fd = -1;
    // close releases flock; never unlink the shared lock inode, or retry close.
    if (close(fd) != 0) return fail(env);
  }
  napi_value out; napi_get_undefined(env, &out); return out;
}
static int processInfo(int pid, ProcessInfo& info) {
  errno = 0;
  int size = proc_pidinfo(pid, kBsdWithUniqueId, 0, &info, sizeof(info));
  if (size == 0 && errno == ESRCH) return 0;
  if (size != sizeof(info) || info.bsd.pbi_pid != (uint32_t)pid || !info.unique.uniqueid) return -1;
  return 1;
}
static napi_value identity(napi_env env, int pid, const ProcessInfo& info) {
  napi_value object; if (napi_create_object(env, &object) != napi_ok) return fail(env);
  if (!property(env, object, "pid", number(env, pid)) ||
      !property(env, object, "uid", number(env, info.bsd.pbi_uid)) ||
      !property(env, object, "startId", text(env, std::to_string(info.unique.uniqueid)))) return fail(env);
  return object;
}
static napi_value processIdentity(napi_env env, napi_callback_info info) {
  napi_value arg; int pid; ProcessInfo data{};
  if (!argument(env, info, &arg) || !integer(env, arg, &pid) || pid <= 0) return fail(env);
  int status = processInfo(pid, data);
  if (status < 0) return fail(env);
  if (!status) { napi_value nullValue; napi_get_null(env, &nullValue); return nullValue; }
  return identity(env, pid, data);
}
static napi_value peerIdentity(napi_env env, napi_callback_info info) {
  napi_value arg; int fd, socketType; uid_t uid; gid_t gid; pid_t pid; audit_token_t token{};
  if (!argument(env, info, &arg) || !integer(env, arg, &fd)) return fail(env);
  socklen_t n = sizeof(socketType);
  sockaddr_un address{}; socklen_t addressSize = sizeof(address);
  if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socketType, &n) != 0 || socketType != SOCK_STREAM ||
      getpeername(fd, (sockaddr*)&address, &addressSize) != 0 || address.sun_family != AF_UNIX ||
      getpeereid(fd, &uid, &gid) != 0 || uid != geteuid()) return fail(env);
  n = sizeof(pid);
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &n) != 0 || n != sizeof(pid) || pid <= 0) return fail(env);
  n = sizeof(token);
  if (getsockopt(fd, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &n) != 0 || n != sizeof(token) ||
      audit_token_to_pid(token) != pid || audit_token_to_euid(token) != uid) return fail(env);
  ProcessInfo data{};
  // The socket audit-token's PID version prevents a recycled peer PID being adopted.
  if (processInfo(pid, data) != 1 || data.bsd.pbi_uid != uid ||
      data.unique.pidVersion != audit_token_to_pidversion(token)) return fail(env);
  return identity(env, pid, data);
}
// Closed bounded kernel enumeration. Return only an observation, never a claim
// that a helper cannot escape the group or that Chromium flushed its storage.
static napi_value groupCensus(napi_env env, napi_callback_info info) {
  napi_value arg; int group;
  if (!argument(env, info, &arg) || !integer(env, arg, &group) || group <= 1) return fail(env);
  constexpr size_t capacity = 4097;
  std::vector<pid_t> pids(capacity);
  int count = proc_listpids(PROC_PGRP_ONLY, group, pids.data(), (int)(pids.size() * sizeof(pid_t)));
  if (count < 0 || count % sizeof(pid_t) || (size_t)count >= pids.size() * sizeof(pid_t)) return fail(env);
  napi_value result; if (napi_create_array(env, &result) != napi_ok) return fail(env);
  uint32_t index = 0;
  for (int i = 0; i < count / (int)sizeof(pid_t); ++i) {
    int pid = pids[i]; if (pid <= 0) continue;
    ProcessInfo before{}, after{};
    if (processInfo(pid, before) != 1 || before.bsd.pbi_uid != geteuid() ||
        before.bsd.pbi_pgid != (uint32_t)group) return fail(env);
    char path[PROC_PIDPATHINFO_MAXSIZE] = {};
    int length = proc_pidpath(pid, path, sizeof(path));
    if (length <= 0 || path[0] != '/' || processInfo(pid, after) != 1 ||
        before.unique.uniqueid != after.unique.uniqueid || after.bsd.pbi_pgid != (uint32_t)group) return fail(env);
    napi_value item = identity(env, pid, after);
    if (!property(env, item, "group", number(env, group)) ||
        !property(env, item, "parentStartId", text(env, std::to_string(after.unique.parentUniqueid))) ||
        !property(env, item, "executable", text(env, path)) ||
        napi_set_element(env, result, index++, item) != napi_ok) return fail(env);
  }
  return result;
}
// Atomic no-replacement publication, never Node rename's replacement semantics.
// The caller holds registry.lock and syncs all staging contents before this call,
// then syncs this parent after return. Ancestor validation remains with the caller.
static napi_value publishDirectory(napi_env env, napi_callback_info info) {
  napi_value args[2]; size_t count = 2; std::string source, destination;
  if (napi_get_cb_info(env, info, &count, args, nullptr, nullptr) != napi_ok || count != 2 ||
      !string(env, args[0], source) || !string(env, args[1], destination)) return fail(env);
  size_t a = source.rfind('/'), b = destination.rfind('/');
  if (a == 0 || b == 0 || source.substr(0, a) != destination.substr(0, b)) return fail(env);
  std::string parent = source.substr(0, a), from = source.substr(a + 1), to = destination.substr(b + 1);
  if (from.empty() || to.empty() || from == "." || from == ".." || to == "." || to == ".." || from == to) return fail(env);
  int fd = open(parent.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
  if (fd < 0) return fail(env);
  struct stat st{}, path{}, staged{}, published{};
  bool valid = fstat(fd, &st) == 0 && lstat(parent.c_str(), &path) == 0 &&
    S_ISDIR(st.st_mode) && S_ISDIR(path.st_mode) && st.st_uid == geteuid() &&
    (st.st_mode & 07777) == 0700 && st.st_dev == path.st_dev && st.st_ino == path.st_ino &&
    fstatat(fd, from.c_str(), &staged, AT_SYMLINK_NOFOLLOW) == 0 && S_ISDIR(staged.st_mode) &&
    staged.st_uid == geteuid() && (staged.st_mode & 07777) == 0700;
  if (!valid || renameatx_np(fd, from.c_str(), fd, to.c_str(), RENAME_EXCL) != 0) {
    close(fd); return fail(env);
  }
  valid = fstatat(fd, to.c_str(), &published, AT_SYMLINK_NOFOLLOW) == 0 &&
    S_ISDIR(published.st_mode) && published.st_dev == staged.st_dev && published.st_ino == staged.st_ino &&
    lstat(parent.c_str(), &path) == 0 && path.st_dev == st.st_dev && path.st_ino == st.st_ino;
  int result = close(fd);
  if (!valid || result != 0) return fail(env);
  napi_value out; napi_get_undefined(env, &out); return out;
}

static bool boundedText(napi_env env, napi_value value, std::string& out, size_t maximum=arbol_attempt::limit) {
  size_t length = 0, written = 0;
  if (napi_get_value_string_utf8(env,value,nullptr,0,&length) != napi_ok || !length || length > maximum) return false;
  out.resize(length+1);
  if (napi_get_value_string_utf8(env,value,out.data(),out.size(),&written) != napi_ok || written != length) return false;
  out.resize(length); return out.find('\0') == std::string::npos;
}
// Command receipt has no caller-selected clock/issuer. A single detached
// native I/O job can block without keeping the CLI event loop alive past its
// original cutoff; actual module/input/socket lifetime remains native-owned.
struct CloseBudgetNative {
  NSDictionary* issuer=nil; NSString* boot=nil; uint64_t received=0,grace=0,overall=0;
  bool used=false; std::atomic<bool> cancelled{false}; std::atomic<int> state{0};
  std::thread* worker=nullptr; std::thread* retirement=nullptr; std::atomic<int> retired{0};
  bool created=false,attributable=false; std::string leaf,filename; NSDictionary* attempt=nil;
  struct stat createdFile{},directory{},lock{};
};
// The worker captures its actual still-open created description immediately
// before close, including a partial failed write. Never infer a replaced inode.
struct CloseCreatedCapture {
  CloseBudgetNative* budget; arbol_exit::NativeFile* file;
  ~CloseCreatedCapture() {
    if(file->fd<0) return;
    struct stat actual{};
    if(fstat(file->fd,&actual)||!arbol_attempt::privateFile(actual)||actual.st_dev!=budget->createdFile.st_dev||actual.st_ino!=budget->createdFile.st_ino)
      budget->attributable=false;
    else { budget->createdFile=actual; budget->attributable=true; }
  }
};
static std::set<CloseBudgetNative*> closeBudgets;
static bool closeBudgetCaptured=false;
static CloseBudgetNative* closeBudgetArgument(napi_env env,napi_value value) {
  void* raw=nullptr; if(napi_get_value_external(env,value,&raw)!=napi_ok) return nullptr;
  auto* budget=static_cast<CloseBudgetNative*>(raw); return closeBudgets.count(budget)?budget:nullptr;
}
static uint64_t continuousUs() {
  double value=arbol_boundary::clockMs()*1000;
  return std::isfinite(value)&&value>0&&value<9007199246740991.0?(uint64_t)value:0;
}
static NSDictionary* kernelPeer(int fd) {
  int type=0; uid_t uid; gid_t gid; pid_t pid; audit_token_t token{};
  socklen_t n=sizeof(type); sockaddr_un address{}; socklen_t length=sizeof(address);
  if(fd<0||getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&n)||n!=sizeof(type)||type!=SOCK_STREAM||
     getpeername(fd,(sockaddr*)&address,&length)||address.sun_family!=AF_UNIX||getpeereid(fd,&uid,&gid)||uid!=geteuid()) return nil;
  n=sizeof(pid); if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&n)||n!=sizeof(pid)||pid<=1) return nil;
  n=sizeof(token);
  if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERTOKEN,&token,&n)||n!=sizeof(token)||audit_token_to_pid(token)!=pid||audit_token_to_euid(token)!=uid) return nil;
  NSDictionary* actual=arbol_attempt::processRecord(pid);
  return actual&&[actual[@"uid"] unsignedIntValue]==uid&&[actual[@"pidVersion"] intValue]==audit_token_to_pidversion(token)&&
    arbol_attempt::currentProcess(actual)?actual:nil;
}
static bool managementSocketPath(int fd,bool remote,NSString* expected) {
  if(!arbol_attempt::path(expected)) return false;
  sockaddr_un address{}; socklen_t length=sizeof(address);
  int result=remote?getpeername(fd,(sockaddr*)&address,&length):getsockname(fd,(sockaddr*)&address,&length);
  size_t offset=offsetof(sockaddr_un,sun_path);
  if(result||address.sun_family!=AF_UNIX||length<=offset||length>sizeof(address)||address.sun_len!=length) return false;
  size_t available=length-offset,n=strnlen(address.sun_path,available); const char* path=expected.fileSystemRepresentation;
  // Pinned libuv supplies zero-padded sockaddr_un. Darwin also supports a
  // length-delimited non-NUL pathname; never read past the returned length.
  if(!path||!n||n>=sizeof(address.sun_path)||strlen(path)!=n||memcmp(address.sun_path,path,n)) return false;
  for(size_t i=n;i<available;++i) if(address.sun_path[i]) return false;
  return true;
}
static bool budgetValue(napi_env env,napi_value value,uint64_t received,uint64_t grace,uint64_t overall,const char* kind=nullptr) {
  for(const auto& entry:std::vector<std::pair<const char*,uint64_t>>{{"received",received},{"grace",grace},{"overall",overall}}) {
    napi_value field; if(napi_create_double(env,(double)entry.second/1000,&field)!=napi_ok||!property(env,value,entry.first,field)) return false;
  }
  return !kind||property(env,value,"kind",text(env,kind));
}
static napi_value captureCloseBudget(napi_env env,napi_callback_info) {
  uint64_t received=continuousUs(); if(closeBudgetCaptured||!received) return fail(env); closeBudgetCaptured=true;
  @autoreleasepool { @try {
    auto* budget=new CloseBudgetNative; budget->received=received; budget->grace=received+5000000; budget->overall=received+8000000;
    budget->issuer=arbol_attempt::processRecord(getpid()); budget->boot=arbol_exit::bootSession();
    if(!budget->issuer||!budget->boot||!arbol_attempt::currentProcess(budget->issuer,true)) { delete budget; return fail(env); }
    closeBudgets.insert(budget); napi_value out,handle;
    if(napi_create_object(env,&out)!=napi_ok||napi_create_external(env,budget,nullptr,nullptr,&handle)!=napi_ok||
       !property(env,out,"handle",handle)||!budgetValue(env,out,budget->received,budget->grace,budget->overall)) return fail(env);
    return out;
  } @catch(NSException*) { return fail(env); } }
}
static bool closeStamp(CloseBudgetNative* budget,const std::string& leaf,const std::string& runtimeRaw,const std::string& requestId,int socket) {
  if(budget->cancelled.load(std::memory_order_acquire)||continuousUs()>=budget->grace||
     ![budget->boot isEqual:arbol_exit::bootSession()]||!arbol_attempt::currentProcess(budget->issuer,true)) return false;
  std::string filename="close-"+requestId+".json";
  arbol_attempt::Claim claim; std::string currentRaw; NSDictionary* current=nil;
  if(!claim.acquire(leaf+"/"+filename,std::min((double)budget->grace/1000,arbol_boundary::clockMs()+250))||!claim.read(currentRaw,current)||
     ![@[@"ready",@"closing"] containsObject:current[@"phase"]]||![current[@"stage"] isEqual:@"admitted"]||
     ![current[@"runtime"] isEqual:arbol_attempt::json(runtimeRaw)]||!arbol_attempt::currentProcess(current[@"engine"])) return false;
  NSDictionary* peer=kernelPeer(socket);
  if(!peer||![peer isEqual:current[@"engine"]]||![current[@"runtime"][@"phase"] isEqual:@"ready"]||
     !managementSocketPath(socket,true,current[@"runtime"][@"managementSocket"])) return false;
  arbol_exit::NativeFile file;
  file.fd=openat(claim.at.directory,filename.c_str(),O_RDWR|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
  struct stat first{},published{};
  if(file.fd<0||fchmod(file.fd,0600)||fstat(file.fd,&first)||!arbol_attempt::privateFile(first)) return false;
  budget->created=true; budget->attributable=true; budget->createdFile=first; budget->leaf=claim.at.path; budget->filename=filename;
  budget->directory=claim.at.identity; budget->lock=claim.at.lockIdentity; budget->attempt=current;
  CloseCreatedCapture capture{budget,&file};
  NSDictionary* value=@{@"format":@1,@"kind":@"management-close-budget",@"bootSession":budget->boot,
    @"requestId":[NSString stringWithUTF8String:requestId.c_str()],@"issuer":budget->issuer,@"attempt":current,
    @"receivedUs":@(budget->received),@"graceUs":@(budget->grace),@"overallUs":@(budget->overall),@"file":arbol_exit::fileIdentity(first)};
  std::string raw=arbol_attempt::bytes(value); if(raw.empty()) return false; size_t at=0;
  while(at<raw.size()) {
    if(budget->cancelled.load(std::memory_order_acquire)||continuousUs()>=budget->grace) return false;
    ssize_t n=write(file.fd,raw.data()+at,raw.size()-at); if(n>0) at+=n; else if(n<0&&errno==EINTR) continue; else return false;
  }
  bool valid=!fsync(file.fd)&&!fcntl(file.fd,F_FULLFSYNC)&&
    arbol_exit::publishedNativeFile(claim.at.directory,filename,raw,file,published,(double)budget->grace/1000)&&
    [arbol_exit::fileIdentity(published) isEqual:value[@"file"]]&&arbol_attempt::unchanged(claim.at)&&
    [kernelPeer(socket) isEqual:peer]&&managementSocketPath(socket,true,current[@"runtime"][@"managementSocket"])&&arbol_attempt::currentProcess(budget->issuer,true)&&
    !budget->cancelled.load(std::memory_order_acquire)&&continuousUs()<budget->grace;
  if(valid) budget->createdFile=published;
  return valid&&file.finish();
}
static napi_value beginCloseStamp(napi_env env,napi_callback_info info) {
  napi_value args[5]; size_t n=5; std::string leaf,runtime,request; int socket;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=5) return fail(env);
  auto* budget=closeBudgetArgument(env,args[0]); if(!budget||budget->used) return fail(env); budget->used=true;
  if(!boundedText(env,args[1],leaf)||!boundedText(env,args[2],runtime)||!boundedText(env,args[3],request)||
     !integer(env,args[4],&socket)||socket<0||!arbol_attempt::pattern([NSString stringWithUTF8String:request.c_str()],@"^req_[A-Za-z0-9_-]{22}$")||
     !arbol_boundary::retainNativeImage()) return fail(env);
  int retained=fcntl(socket,F_DUPFD_CLOEXEC,64); if(retained<0) return fail(env);
  try {
    budget->worker=new std::thread([budget,leaf,runtime,request,retained] {
      bool ok=false; @autoreleasepool { @try { try { ok=closeStamp(budget,leaf,runtime,request,retained); } catch(...) {} } @catch(NSException*) {} }
      if(close(retained)) ok=false;
      budget->state.store(ok?1:-1,std::memory_order_release);
    });
    try { budget->worker->detach(); } catch(...) {} // actual handle/module stay retained
  } catch(...) { close(retained); budget->state.store(-1,std::memory_order_release); return fail(env); }
  napi_value out; napi_get_undefined(env,&out); return out;
}
static napi_value pollCloseStamp(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* budget=closeBudgetArgument(env,arg); if(!budget||!budget->used) return fail(env);
  int state=budget->state.load(std::memory_order_acquire); napi_value out;
  if(napi_create_int32(env,state,&out)!=napi_ok) return fail(env); return out;
}
static napi_value cancelCloseStamp(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* budget=closeBudgetArgument(env,arg); if(!budget) return fail(env);
  budget->cancelled.store(true,std::memory_order_release); napi_value out; napi_get_undefined(env,&out); return out;
}
static bool retireCreatedClose(CloseBudgetNative* budget) {
  if(!budget->created) return true;
  if(!budget->attributable||continuousUs()>=budget->overall) return false;
  arbol_attempt::Claim claim; std::string raw; NSDictionary* current=nil;
  if(!claim.acquire(budget->leaf+"/"+budget->filename,(double)budget->overall/1000)||
     claim.at.identity.st_dev!=budget->directory.st_dev||claim.at.identity.st_ino!=budget->directory.st_ino||
     claim.at.lockIdentity.st_dev!=budget->lock.st_dev||claim.at.lockIdentity.st_ino!=budget->lock.st_ino) return false;
  struct stat named{}; errno=0;
  if(fstatat(claim.at.directory,budget->filename.c_str(),&named,AT_SYMLINK_NOFOLLOW)) return errno==ENOENT&&arbol_attempt::unchanged(claim.at);
  if(!claim.read(raw,current)||!arbol_attempt::immutable(budget->attempt,current)||
     ![budget->attempt[@"engine"] isEqual:current[@"engine"]]||![budget->attempt[@"bootstrap"] isEqual:current[@"bootstrap"]]||
     !arbol_attempt::privateFile(named)||!arbol_attempt::sameFile(budget->createdFile,named)||!arbol_attempt::unchanged(claim.at)) return false;
  return !unlinkat(claim.at.directory,budget->filename.c_str(),0)&&!fsync(claim.at.directory)&&
    arbol_attempt::unchanged(claim.at)&&continuousUs()<budget->overall;
}
static napi_value beginCloseRetirement(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* budget=closeBudgetArgument(env,arg); if(!budget) return fail(env);
  budget->cancelled.store(true,std::memory_order_release);
  if(!budget->retirement) {
    if(!arbol_boundary::retainNativeImage()) return fail(env);
    try {
      budget->retirement=new std::thread([budget] {
        while(budget->worker&&budget->state.load(std::memory_order_acquire)==0&&continuousUs()<budget->overall) usleep(1000);
        bool complete=!budget->worker||budget->state.load(std::memory_order_acquire)!=0,ok=false;
        @autoreleasepool { @try { try { ok=complete&&retireCreatedClose(budget); } catch(...) {} } @catch(NSException*) {} }
        budget->retired.store(ok?1:-1,std::memory_order_release);
      });
      try { budget->retirement->detach(); } catch(...) {}
    } catch(...) { budget->retired.store(-1,std::memory_order_release); return fail(env); }
  }
  napi_value out; napi_get_undefined(env,&out); return out;
}
static napi_value pollCloseRetirement(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* budget=closeBudgetArgument(env,arg); if(!budget) return fail(env);
  napi_value out; if(napi_create_int32(env,budget->retired.load(std::memory_order_acquire),&out)!=napi_ok) return fail(env); return out;
}
static HeldLock* claimLock(napi_env env, napi_value value) {
  void* data = nullptr; struct stat st{};
  if (napi_get_value_external(env,value,&data) != napi_ok) return nullptr;
  auto* lock = static_cast<HeldLock*>(data);
  return liveLocks.count(lock) && lock->mode == LOCK_EX && matches(lock,&st) ? lock : nullptr;
}
static napi_value continuousTime(napi_env env, napi_callback_info) {
  double value = arbol_boundary::clockMs(); napi_value out;
  if (!std::isfinite(value) || value < 0 || value > 9007199254740991.0 || napi_create_double(env,value,&out) != napi_ok) return fail(env);
  return out;
}
static napi_value processProvenance(napi_env env, napi_callback_info info) {
  napi_value arg; int pid; arbol_boundary::Identity id;
  if (!argument(env,info,&arg) || !integer(env,arg,&pid) || pid < 2) return fail(env);
  int state = arbol_boundary::observe(pid,id); if (state < 0) return fail(env);
  if (!state) { napi_value out; napi_get_null(env,&out); return out; }
  @autoreleasepool { @try {
    NSDictionary* record = arbol_attempt::processRecord(pid);
    if (!arbol_attempt::process(record)) return fail(env);
    napi_value out; if (napi_create_object(env,&out) != napi_ok) return fail(env);
    for (NSString* key in @[@"pid",@"uid",@"pidVersion",@"group",@"session",@"parentPidVersion"])
      if (!property(env,out,key.UTF8String,number(env,[record[key] unsignedIntValue]))) return fail(env);
    for (NSString* key in @[@"startId",@"parentStartId",@"executable"])
      if (!property(env,out,key.UTF8String,text(env,[record[key] UTF8String]))) return fail(env);
    return out;
  } @catch (NSException*) { return fail(env); } }
}
static bool attemptAt(const arbol_attempt::Location& at, NSDictionary* value) {
  return arbol_attempt::record(value) && at.path.substr(at.path.rfind('/')+1) == std::string([value[@"profilePathHash"] UTF8String]).substr(0,32);
}
static napi_value readLaunchAttempt(napi_env env, napi_callback_info info) {
  napi_value arg; if (!argument(env,info,&arg)) return fail(env);
  auto* lock = claimLock(env,arg); if (!lock) return fail(env);
  @autoreleasepool { @try {
    arbol_attempt::Location at;
    if (!arbol_attempt::location(lock->path,lock->fd,at)) return fail(env);
    bool absent; std::string raw;
    if (!arbol_attempt::readAt(at.directory,"claim.json",raw,absent) || !arbol_attempt::unchanged(at) ||
        (!absent && !attemptAt(at,arbol_attempt::json(raw)))) return fail(env);
    if (absent) { napi_value out; napi_get_null(env,&out); return out; }
    return text(env,raw);
  } @catch (NSException*) { return fail(env); } }
}
static napi_value writeLaunchAttempt(napi_env env, napi_callback_info info) {
  napi_value args[3]; size_t n = 3; std::string expected,next; napi_valuetype kind;
  if (napi_get_cb_info(env,info,&n,args,nullptr,nullptr) != napi_ok || n != 3 ||
      napi_typeof(env,args[1],&kind) != napi_ok || (kind != napi_null && !boundedText(env,args[1],expected)) ||
      !boundedText(env,args[2],next)) return fail(env);
  auto* lock = claimLock(env,args[0]); if (!lock) return fail(env);
  @autoreleasepool { @try {
    arbol_attempt::Location at;
    if (!arbol_attempt::location(lock->path,lock->fd,at)) return fail(env);
    bool absent; std::string raw;
    if (!arbol_attempt::readAt(at.directory,"claim.json",raw,absent) || absent != (kind == napi_null) ||
        (!absent && raw != expected) || !attemptAt(at,arbol_attempt::json(next)) ||
        !arbol_attempt::transition(absent ? nil : arbol_attempt::json(raw),arbol_attempt::json(next),arbol_attempt::Role::starter) ||
        !arbol_attempt::replace(at,raw,absent,next)) return fail(env);
    struct stat current{}; if (!matches(lock,&current)) return fail(env);
    napi_value out; napi_get_undefined(env,&out); return out;
  } @catch (NSException*) { return fail(env); } }
}

static bool adoptionAttempted=false;
// Genuine process-lifetime native state. No destructor/finalizer runs its
// terminal loop on ordinary Node teardown after actual transfer/session use.
static arbol_exit::NoUseOriginal* adoptedNoUse=nullptr;
static HeldLock* adoptedBuild=nullptr;
static napi_value adoptHostBuild(napi_env env,napi_callback_info info) {
  napi_value args[3]; size_t n=3; std::string requestPath,guard,bundle;
  if(adoptionAttempted) return fail(env); adoptionAttempted=true;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok || n!=3 || !string(env,args[0],requestPath) ||
      !string(env,args[1],guard) || !string(env,args[2],bundle)) return fail(env);
  @autoreleasepool { try { @try {
    std::string root,expected; if(!arbol_attempt::bundleGuard(bundle,root,expected)||expected!=guard) return fail(env);
    const char* inherited=getenv("ARBOL_BROWSER_BUILD_CAPSULE");
    if(!inherited || !*inherited || strspn(inherited,"0123456789")!=strlen(inherited) || strlen(inherited)>9) return fail(env);
    int capsule=atoi(inherited); unsetenv("ARBOL_BROWSER_BUILD_CAPSULE");
    struct stat st{},after{};
    if(capsule<3 || fstat(capsule,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink ||
       (st.st_mode&07777)!=0600 || st.st_size<1 || st.st_size>(off_t)arbol_attempt::limit ||
       (fcntl(capsule,F_GETFL)&O_ACCMODE)!=O_RDONLY || (fcntl(capsule,F_GETFD)&FD_CLOEXEC)) return fail(env);
    std::string raw((size_t)st.st_size+1,'\0'); size_t offset=0;
    while(offset<raw.size()) { ssize_t bytes=pread(capsule,raw.data()+offset,raw.size()-offset,offset);
      if(bytes>0) offset+=(size_t)bytes; else if(bytes<0&&errno==EINTR) continue; else if(!bytes) break; else return fail(env); }
    if(offset!=(size_t)st.st_size || fstat(capsule,&after) || after.st_dev!=st.st_dev || after.st_ino!=st.st_ino ||
       after.st_nlink || after.st_size!=st.st_size || after.st_mtimespec.tv_sec!=st.st_mtimespec.tv_sec ||
       after.st_mtimespec.tv_nsec!=st.st_mtimespec.tv_nsec || after.st_ctimespec.tv_sec!=st.st_ctimespec.tv_sec ||
       after.st_ctimespec.tv_nsec!=st.st_ctimespec.tv_nsec) return fail(env);
    raw.resize(offset); NSDictionary* transport=arbol_attempt::json(raw); uint64_t descriptor;
    if(!arbol_attempt::keys(transport,@[@"format",@"kind",@"requestPath",@"claimDigest",@"bootstrap",@"guard",@"descriptor"]) ||
       ![transport[@"format"] isEqual:@1] || ![transport[@"kind"] isEqual:@"host-build"] ||
       ![transport[@"requestPath"] isEqual:[NSString stringWithUTF8String:requestPath.c_str()]] ||
       !arbol_attempt::uintNumber(transport[@"descriptor"],descriptor) || descriptor<3 || descriptor>INT_MAX || descriptor==(uint64_t)capsule) return fail(env);
    int fd=(int)descriptor; struct stat guardStat{};
    if(fstat(fd,&guardStat) || (fcntl(fd,F_GETFL)&O_ACCMODE)!=O_RDWR || (fcntl(fd,F_GETFD)&FD_CLOEXEC)) return fail(env);
    arbol_boundary::Lock original{fd,guard,(uint64_t)guardStat.st_dev,guardStat.st_ino,guardStat.st_uid,0600,LOCK_SH};
    if(!arbol_boundary::lockIdentity(original) || ![arbol_boundary::capsuleLock(original) isEqual:transport[@"guard"]] ||
       flock(fd,LOCK_SH|LOCK_NB) || !arbol_boundary::lockIdentity(original)) return fail(env);
    arbol_attempt::Claim claim; std::string prior; NSDictionary* attempt=nil;
    if(!claim.acquire(requestPath,arbol_boundary::clockMs()+2000)||!claim.read(prior,attempt)||
       !arbol_attempt::launchRequest(claim,requestPath,attempt)||
       ![attempt[@"bootstrap"] isEqual:transport[@"bootstrap"]]||![attempt[@"buildRoot"] isEqual:[NSString stringWithUTF8String:root.c_str()]]||
       ![attempt[@"buildGuard"] isEqual:[NSString stringWithUTF8String:guard.c_str()]]||
       ![attempt[@"stage"] isEqual:@"untransferred"]||attempt[@"engine"]!=NSNull.null||attempt[@"runtime"]!=NSNull.null||attempt[@"terminal"]!=NSNull.null) return fail(env);
    bool cancelled=[attempt[@"phase"] isEqual:@"cancelled"];
    if(!cancelled&&![attempt[@"phase"] isEqual:@"claimed"]) return fail(env);
    NSMutableDictionary* originalClaim=[attempt mutableCopy]; originalClaim[@"phase"]=@"claimed";
    std::string originalRaw=arbol_attempt::bytes(originalClaim);
    // Cancellation is terminal-only and may change ONLY phase. Its actual
    // native canonical reconstruction must match the real inherited capsule's
    // earlier claimed digest exactly. No cancelled original resumes adoption.
    if(![arbol_attempt::digest(cancelled?originalRaw:prior) isEqual:transport[@"claimDigest"]]||
       (!cancelled&&originalRaw!=prior)) return fail(env);
    NSDictionary* self=arbol_attempt::processRecord(getpid()); NSDictionary* outer=attempt[@"bootstrap"];
    if(!self || ![outer[@"executable"] isEqual:[NSString stringWithUTF8String:(bundle+"/Contents/MacOS/arbol-browser-native").c_str()]] ||
       ![self[@"executable"] isEqual:[NSString stringWithUTF8String:(bundle+"/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron").c_str()]] ||
       [outer[@"pidVersion"] isEqual:self[@"pidVersion"]] || !arbol_boundary::signature(bundle,false) ||
       !arbol_boundary::signature([self[@"executable"] UTF8String],true)) return fail(env);
    for(NSString* key in @[@"pid",@"uid",@"startId",@"group",@"session",@"parentStartId",@"parentPidVersion"])
      if(![outer[key] isEqual:self[key]]) return fail(env);
    if([self[@"group"] intValue]!=getpid()||getppid()!=1||!arbol_boundary::retainNativeImage()) return fail(env);
    adoptedNoUse=new arbol_exit::NoUseOriginal;
    adoptedNoUse->capture(requestPath,bundle,original,originalClaim,@"post-exec");
    auto terminalOnly=[&]() -> void {
      // Release only this short transition; original Build OFDs remain held.
      if(claim.fd>=0) { int held=claim.fd; claim.fd=-1; (void)close(held); }
      adoptedNoUse->terminate();
    };
    if(cancelled||[attempt[@"expires"] doubleValue]<=arbol_boundary::clockMs()) { terminalOnly(); return fail(env); }
    NSMutableDictionary* next=[attempt mutableCopy]; next[@"engine"]=self;
    std::string nextRaw=arbol_attempt::bytes(next);
    if(!arbol_attempt::transition(attempt,next,arbol_attempt::Role::engine)) { terminalOnly(); return fail(env); }
    bool installed=arbol_attempt::replace(claim.at,prior,false,nextRaw);
    bool captured=adoptedNoUse->acceptAdopted(claim,nextRaw);
    if(!installed||!captured||!arbol_boundary::lockIdentity(original)||fcntl(fd,F_SETFD,FD_CLOEXEC)||close(capsule)) {
      terminalOnly(); return fail(env);
    }
    auto* lock=new HeldLock{fd,guard,guardStat.st_dev,guardStat.st_ino,LOCK_SH,true};
    adoptedBuild=lock; liveLocks.insert(lock); napi_value out;
    if(napi_create_external(env,lock,finalize,nullptr,&out)!=napi_ok) { terminalOnly(); return fail(env); }
    return out;
  } @catch(NSException*) {
    if(adoptedNoUse) adoptedNoUse->terminate(); return fail(env);
  } } catch(...) {
    if(adoptedNoUse) adoptedNoUse->terminate(); return fail(env);
  } }
}

// Process-lifetime native custody is intentionally not garbage-collected. Once
// created it has no unlock/disarm export; retained originals survive JS failure.
struct RetainedPipe {
  int fd=-1,access=-1; struct stat identity{};
  bool retain(int actual,int direction) {
    if(fd>=0) return false; struct stat before{},after{};
    int flags=fcntl(actual,F_GETFL);
    if(flags<0||(flags&O_ACCMODE)!=direction||fstat(actual,&before)||!S_ISFIFO(before.st_mode)) return false;
    fd=fcntl(actual,F_DUPFD_CLOEXEC,10); access=direction;
    if(fd<0||fstat(fd,&after)||!S_ISFIFO(after.st_mode)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||
       (fcntl(fd,F_GETFL)&O_ACCMODE)!=direction) return false;
    identity=after; return true;
  }
  bool valid() const {
    struct stat now{}; int flags=fcntl(fd,F_GETFL),descriptorFlags=fcntl(fd,F_GETFD);
    return fd>=3&&flags>=0&&(flags&O_ACCMODE)==access&&descriptorFlags>=0&&(descriptorFlags&FD_CLOEXEC)&&
      !fstat(fd,&now)&&S_ISFIFO(now.st_mode)&&now.st_dev==identity.st_dev&&now.st_ino==identity.st_ino;
  }
  // No close/destructor/FD export. These exact native-created original pipe
  // descriptions last until actual main-process death, not Node teardown.
};
struct MarkerPermit;
struct SessionUseNative;
struct WebsiteSessionNative;
struct Custody {
  arbol_boundary::Context context; int capsule=-1; bool bound=false,continuousBuild=false,hostRequired=false,spawned=false;
  arbol_exit::HostCapability finalization;
  int reader=-1,writer=-1; bool endpointsPublished=false;
  RetainedPipe retainedReader,retainedWriter;
  MarkerPermit* mutation=nullptr; bool markerAttempted=false;
  SessionUseNative* sessionUse=nullptr; WebsiteSessionNative* websiteSession=nullptr; bool sessionAttempted=false;
  std::string policyDigest,compatibilityDigest;
};
static std::set<Custody*> nativeCustodies;
static bool custodyAttempted = false;
static Custody* custodyArgument(napi_env env, napi_value value) {
  void* data = nullptr; if (napi_get_value_external(env,value,&data) != napi_ok) return nullptr;
  auto* c = static_cast<Custody*>(data); return nativeCustodies.count(c) ? c : nullptr;
}
static arbol_boundary::Lock duplicateHeld(HeldLock* held) {
  struct stat st{}; if (!held || !liveLocks.count(held) || !matches(held,&st)) return {};
  int fd = fcntl(held->fd,F_DUPFD_CLOEXEC,10); if (fd < 0) return {};
  return {fd,held->path,(uint64_t)st.st_dev,st.st_ino,st.st_uid,0600,held->mode};
}
static napi_value prepareWatchdogCustody(napi_env env, napi_callback_info info) {
  napi_value args[4]; size_t n = 4; std::string bundle; char digest[65]{}; size_t length = 0; void *a = nullptr, *b = nullptr;
  if (custodyAttempted) return fail(env); custodyAttempted = true;
  if (napi_get_cb_info(env,info,&n,args,nullptr,nullptr) != napi_ok || n != 4 ||
      napi_get_value_external(env,args[0],&a) != napi_ok || napi_get_value_external(env,args[1],&b) != napi_ok ||
      !liveLocks.count(static_cast<HeldLock*>(a)) || !liveLocks.count(static_cast<HeldLock*>(b)) ||
      !string(env,args[2],bundle) || napi_get_value_string_utf8(env,args[3],digest,sizeof(digest),&length) != napi_ok || length != 64) return fail(env);
  for (size_t i=0;i<64;++i) if (!((digest[i]>='0' && digest[i]<='9') || (digest[i]>='a' && digest[i]<='f'))) return fail(env);
  auto* c = new Custody; c->context.bundle=bundle; c->context.digest=digest;
  c->continuousBuild=static_cast<HeldLock*>(b)->retained;
  c->context.owner=duplicateHeld(static_cast<HeldLock*>(a)); c->context.build=duplicateHeld(static_cast<HeldLock*>(b));
  if(c->continuousBuild) {
    if(!adoptedNoUse) return fail(env);
    adoptedNoUse->bindOwner(c->context.owner);
    if(!adoptedNoUse->matches(bundle,digest,c->context.build)) return fail(env);
  }
  c->context.session=getsid(0);
  bool valid=arbol_boundary::observe(getpid(),c->context.main)==1 && c->context.initial();
  if(valid) { c->capsule=arbol_boundary::capsuleDescriptor(arbol_boundary::capsuleBytes(c->context,true)); valid=c->capsule>=0; }
  if (!valid) { if(c->context.owner.fd>=0) close(c->context.owner.fd); if(c->context.build.fd>=0) close(c->context.build.fd); delete c; return fail(env); }
  nativeCustodies.insert(c); napi_value out;
  if(napi_create_external(env,c,nullptr,nullptr,&out)!=napi_ok) return fail(env); return out;
}
static napi_value custodyDescriptors(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg); if(!c) return fail(env);
  napi_value out; if(napi_create_array_with_length(env,3,&out)!=napi_ok || napi_set_element(env,out,0,number(env,c->context.owner.fd))!=napi_ok || napi_set_element(env,out,1,number(env,c->context.build.fd))!=napi_ok || napi_set_element(env,out,2,number(env,c->capsule))!=napi_ok) return fail(env); return out;
}
static NSDictionary* sealedObject(const std::string& path,std::string& digest);
static napi_value prepareHostFinalization(napi_env env,napi_callback_info info) {
  napi_value args[4]; size_t n=4; std::string input,policyDigest,compatibilityDigest;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=4||!boundedText(env,args[1],input)||
     !boundedText(env,args[2],policyDigest)||!boundedText(env,args[3],compatibilityDigest)||
     !arbol_attempt::pattern([NSString stringWithUTF8String:policyDigest.c_str()],@"^[0-9a-f]{64}$")||
     !arbol_attempt::pattern([NSString stringWithUTF8String:compatibilityDigest.c_str()],@"^[0-9a-f]{64}$")) return fail(env);
  auto* c=custodyArgument(env,args[0]); if(!c||c->hostRequired||c->spawned||!c->continuousBuild) return fail(env);
  c->hostRequired=true; // a failed host preparation cannot fall back to legacy
  @autoreleasepool { @try {
    if(!c->finalization.prepare(c->context,input,arbol_boundary::clockMs()+1000)) return fail(env);
    // Expected hashes arrive only through the canonical previously verified
    // HostCustody route. Capture both actual physical sealed files before any
    // enrollment; a consistent replacement pair cannot teach us new trust.
    std::string actualPolicy,actualCompatibility;
    NSDictionary* policy=sealedObject(c->context.bundle+"/Contents/Resources/host-policy.json",actualPolicy);
    NSDictionary* compatibility=sealedObject(c->context.bundle+"/Contents/Resources/native-compatibility.json",actualCompatibility);
    NSDictionary* attempt=c->finalization.value()[@"attempt"];
    if(!policy||!compatibility||actualPolicy!=policyDigest||actualCompatibility!=compatibilityDigest||
       ![policy[@"compatibilityDigest"] isEqual:[NSString stringWithUTF8String:compatibilityDigest.c_str()]]||
       ![attempt[@"candidateDigest"] isEqual:[NSString stringWithUTF8String:c->context.digest.c_str()]]||
       ![policy[@"build"] isEqual:attempt[@"build"]]||![policy[@"buildRoot"] isEqual:attempt[@"buildRoot"]]||
       ![policy[@"sourceDigest"] isEqual:attempt[@"sourceDigest"]]||![policy[@"productDigest"] isEqual:attempt[@"productDigest"]]||
       !arbol_boundary::lockIdentity(c->context.owner)||!arbol_boundary::lockIdentity(c->context.build)||
       !c->finalization.metadata()) return fail(env);
    c->policyDigest=actualPolicy; c->compatibilityDigest=actualCompatibility;
    napi_value out; napi_get_undefined(env,&out); return out;
  } @catch(NSException*) { return fail(env); } }
}
static bool retireCloseFile(const arbol_attempt::Claim& claim,const std::string& name,const struct stat& original) {
  struct stat actual{};
  return arbol_attempt::unchanged(claim.at)&&!fstatat(claim.at.directory,name.c_str(),&actual,AT_SYMLINK_NOFOLLOW)&&
    arbol_attempt::privateFile(actual)&&arbol_attempt::sameFile(original,actual)&&!unlinkat(claim.at.directory,name.c_str(),0)&&
    !fsync(claim.at.directory)&&arbol_attempt::unchanged(claim.at);
}
static bool beginClosing(Custody* custody,arbol_attempt::Claim& claim,const std::string& raw,NSDictionary* current,
  uint64_t received,uint64_t grace,uint64_t overall) {
  auto* state=custody->finalization.shared();
  uint64_t now=continuousUs(),earlier=state->closeGraceUs.load(std::memory_order_acquire);
  if(!now||now>=grace||(earlier&&now>=earlier)||!custody->finalization.ready(custody->context)) return false;
  state->installClose(received,grace,overall);
  if([current[@"phase"] isEqual:@"closing"]) return true;
  NSMutableDictionary* next=[current mutableCopy],*runtime=[current[@"runtime"] mutableCopy];
  next[@"phase"]=@"closing"; runtime[@"phase"]=@"closing"; next[@"runtime"]=runtime;
  return arbol_attempt::transition(current,next,arbol_attempt::Role::engine)&&arbol_attempt::replace(claim.at,raw,false,arbol_attempt::bytes(next));
}
static napi_value consumeCloseRequest(napi_env env,napi_callback_info info) {
  napi_value args[3]; size_t n=3; std::string request; int socket;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=3||!boundedText(env,args[1],request)||!integer(env,args[2],&socket)||
     !arbol_attempt::pattern([NSString stringWithUTF8String:request.c_str()],@"^req_[A-Za-z0-9_-]{22}$")) return fail(env);
  auto* c=custodyArgument(env,args[0]);
  if(!c||!c->hostRequired||!c->bound||getpid()!=c->context.main.pid||!c->finalization.ready(c->context)) return fail(env);
  @autoreleasepool { @try {
    NSDictionary* peer=kernelPeer(socket); if(!peer) return fail(env);
    arbol_attempt::Claim claim; std::string currentRaw,raw; NSDictionary* current=nil; struct stat file{};
    if(!c->finalization.currentAttempt(c->context,claim,currentRaw,current,arbol_boundary::clockMs()+250)||
       ![@[@"ready",@"closing"] containsObject:current[@"phase"]]||![current[@"stage"] isEqual:@"admitted"]||
       !managementSocketPath(socket,false,current[@"runtime"][@"managementSocket"])) return fail(env);
    std::string filename="close-"+request+".json";
    if(!arbol_exit::readNativeFile(claim.at.directory,filename,raw,file,arbol_attempt::limit)) return fail(env);
    NSDictionary* value=arbol_attempt::json(raw),*attempt=value[@"attempt"]; uint64_t received,grace,overall;
    if(!arbol_attempt::keys(value,@[@"format",@"kind",@"bootSession",@"requestId",@"issuer",@"attempt",@"receivedUs",@"graceUs",@"overallUs",@"file"])||
       ![value[@"format"] isEqual:@1]||![value[@"kind"] isEqual:@"management-close-budget"]||
       ![value[@"bootSession"] isEqual:c->finalization.value()[@"bootSession"]]||![value[@"requestId"] isEqual:[NSString stringWithUTF8String:request.c_str()]]||
       ![value[@"file"] isEqual:arbol_exit::fileIdentity(file)]||![value[@"issuer"] isEqual:peer]||!arbol_attempt::record(attempt)||
       !arbol_attempt::immutable(attempt,current)||![attempt[@"engine"] isEqual:current[@"engine"]]||![attempt[@"bootstrap"] isEqual:current[@"bootstrap"]]||
       !arbol_attempt::sameRuntimeBinding(attempt[@"runtime"],current[@"runtime"])||
       !arbol_attempt::uintNumber(value[@"receivedUs"],received)||!arbol_attempt::uintNumber(value[@"graceUs"],grace)||
       !arbol_attempt::uintNumber(value[@"overallUs"],overall)||!received||grace!=received+5000000||overall!=received+8000000||
       received>continuousUs()||![kernelPeer(socket) isEqual:peer]) return fail(env);
    if(continuousUs()>=grace) { (void)retireCloseFile(claim,filename,file); return fail(env); }
    if(!beginClosing(c,claim,currentRaw,current,received,grace,overall)||![kernelPeer(socket) isEqual:peer]||
       !managementSocketPath(socket,false,current[@"runtime"][@"managementSocket"])||!retireCloseFile(claim,filename,file)) { c->finalization.shared()->poison(arbol_exit::admissionLoss|arbol_exit::forced); return fail(env); }
    if(continuousUs()>=c->finalization.shared()->closeGraceUs.load(std::memory_order_acquire)) return fail(env);
    napi_value out; if(napi_create_object(env,&out)!=napi_ok||!budgetValue(env,out,
      c->finalization.shared()->closeReceivedUs.load(std::memory_order_acquire),c->finalization.shared()->closeGraceUs.load(std::memory_order_acquire),
      c->finalization.shared()->closeOverallUs.load(std::memory_order_acquire),"management")) return fail(env);
    return out;
  } @catch(NSException*) { if(c->finalization.present()) c->finalization.shared()->poison(arbol_exit::admissionLoss|arbol_exit::forced); return fail(env); } }
}
static napi_value armLocalClose(napi_env env,napi_callback_info info) {
  uint64_t received=continuousUs(); napi_value arg;
  if(!received||!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c||!c->hostRequired||!c->bound||getpid()!=c->context.main.pid||!c->finalization.ready(c->context)) return fail(env);
  @autoreleasepool { @try {
    arbol_attempt::Claim claim; std::string raw; NSDictionary* current=nil;
    if(!c->finalization.currentAttempt(c->context,claim,raw,current,std::min((double)(received+5000000)/1000,arbol_boundary::clockMs()+250))||
       ![@[@"claimed",@"ready",@"closing"] containsObject:current[@"phase"]]||![current[@"stage"] isEqual:@"admitted"]||
       !beginClosing(c,claim,raw,current,received,received+5000000,received+8000000)) return fail(env);
    if(continuousUs()>=c->finalization.shared()->closeGraceUs.load(std::memory_order_acquire)) return fail(env);
    napi_value out; if(napi_create_object(env,&out)!=napi_ok||!budgetValue(env,out,
      c->finalization.shared()->closeReceivedUs.load(std::memory_order_acquire),c->finalization.shared()->closeGraceUs.load(std::memory_order_acquire),
      c->finalization.shared()->closeOverallUs.load(std::memory_order_acquire),"local-window")) return fail(env);
    return out;
  } @catch(NSException*) { return fail(env); } }
}
static bool nativePipe(int (&ends)[2]) {
  int raw[2]; if(pipe(raw)) return false;
  ends[0]=fcntl(raw[0],F_DUPFD_CLOEXEC,10); ends[1]=fcntl(raw[1],F_DUPFD_CLOEXEC,10);
  close(raw[0]); close(raw[1]);
  if(ends[0]<0||ends[1]<0) { if(ends[0]>=0) close(ends[0]); if(ends[1]>=0) close(ends[1]); return false; } return true;
}
static napi_value spawnWatchdog(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c||c->spawned||c->bound||(c->continuousBuild&&!c->hostRequired)||(c->hostRequired&&!c->finalization.present())) return fail(env);
  if(c->continuousBuild) {
    if(!adoptedNoUse||!adoptedNoUse->matches(c->context.bundle,c->context.digest,c->context.build)) return fail(env);
    adoptedNoUse->spawnIntent(); // irreversible BEFORE any possible actual spawn
  }
  c->spawned=true;
  @autoreleasepool { @try {
    arbol_attempt::Claim claim; std::string old; NSDictionary* attempt=nil;
    if(c->hostRequired) {
      if(!c->finalization.currentAttempt(c->context,claim,old,attempt,arbol_boundary::clockMs()+1000)||
         ![attempt[@"phase"] isEqual:@"claimed"]||![attempt[@"stage"] isEqual:@"untransferred"]||
         [attempt[@"expires"] doubleValue]<=arbol_boundary::clockMs()) return fail(env);
      NSMutableDictionary* next=[attempt mutableCopy]; next[@"stage"]=@"transferring";
      if(!arbol_attempt::transition(attempt,next,arbol_attempt::Role::engine)||
         !arbol_attempt::replace(claim.at,old,false,arbol_attempt::bytes(next))) return fail(env);
      c->finalization.shared()->transfer.store(1,std::memory_order_release);
    }
    if(!c->context.initial()) return fail(env);
    int down[2]{-1,-1},up[2]{-1,-1};
    if(!nativePipe(down)) return fail(env);
    if(!nativePipe(up)) { close(down[0]); close(down[1]); return fail(env); }
    c->reader=up[0]; c->writer=down[1];
    // Provenance is the actual pipe() pair owned by this one native spawn,
    // never a caller-provided numeric FD whose fstat merely looks plausible.
    if(!c->retainedReader.retain(c->reader,O_RDONLY)||!c->retainedWriter.retain(c->writer,O_WRONLY)) return fail(env);
    posix_spawn_file_actions_t actions; posix_spawnattr_t attr; arbol_boundary::SpawnCopies copies;
    bool actionsReady=!posix_spawn_file_actions_init(&actions),attrReady=!posix_spawnattr_init(&attr);
    bool ok=actionsReady&&attrReady;
    if(ok) ok=copies.map(actions,c->context.owner.fd,3)&&copies.map(actions,c->context.build.fd,4)&&
      copies.map(actions,c->capsule,5)&&copies.map(actions,down[0],0)&&copies.map(actions,up[1],1)&&!posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)&&
      !posix_spawnattr_setflags(&attr,POSIX_SPAWN_CLOEXEC_DEFAULT);
    if(ok&&c->hostRequired) ok=c->finalization.spawnBindings(actions,copies,1);
    std::string helper=c->context.helper(); char* argv[]={helper.data(),(char*)"--watchdog",c->hostRequired?(char*)"--host-finalization":nullptr,nullptr};
    char* environment[]={(char*)"PATH=/usr/bin:/bin",nullptr}; pid_t pid=0;
    int result=ok?posix_spawn(&pid,helper.c_str(),&actions,&attr,argv,environment):EINVAL;
    if(actionsReady) posix_spawn_file_actions_destroy(&actions); if(attrReady) posix_spawnattr_destroy(&attr);
    bool copiesClosed=copies.closeCopies();
    close(down[0]); close(up[1]);
    if(result) return fail(env);
    if(c->hostRequired&&!c->finalization.spawned(1)) copiesClosed=false;
    arbol_boundary::Info birth{}; arbol_boundary::Identity original;
    if(arbol_boundary::observe(pid,original,&birth)!=1) return fail(env);
    c->context.primary=original; // retain the actual child even if validation fails
    if(birth.unique.parent!=c->context.main.start||birth.unique.originalParentVersion!=c->context.main.version||
       (!c->context.monitor(original,true)&&!c->context.monitor(original,false))) return fail(env);
    if(c->hostRequired&&!c->finalization.shared()->primary.bind(original,arbol_boundary::clockMs()+1000)) return fail(env);
    if(!copiesClosed) return fail(env);
    // The exact child executes cleanup even if its producer never resumes.
    // Its one legal setpgid may occur before/between the parent observations;
    // neither group alone is a substitute for the later actual C/G/J proof.
    for(int fd : {c->reader,c->writer}) { int flags=fcntl(fd,F_GETFL); if(flags<0||fcntl(fd,F_SETFL,flags|O_NONBLOCK)) return fail(env); }
    c->endpointsPublished=true; napi_value out;
    if(napi_create_object(env,&out)!=napi_ok||!property(env,out,"pid",number(env,pid))||
       !property(env,out,"reader",number(env,c->reader))||!property(env,out,"writer",number(env,c->writer))) return fail(env);
    return out;
  } @catch(NSException*) { return fail(env); } }
}
static napi_value captureWatchdog(napi_env env,napi_callback_info info) {
  napi_value args[2]; size_t n=2; int pid; arbol_boundary::Info detail{}; arbol_boundary::Identity child; std::string path;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=2||!integer(env,args[1],&pid)) return fail(env);
  auto* c=custodyArgument(env,args[0]); if(!c||!c->spawned||!c->endpointsPublished||c->bound||!c->context.primary.pid||pid!=c->context.primary.pid||
    arbol_boundary::observe(pid,child,&detail)!=1||!arbol_boundary::same(c->context.primary,child)||child.uid!=geteuid()||
    detail.unique.parent!=c->context.main.start||detail.unique.originalParentVersion!=c->context.main.version||
    !arbol_boundary::executable(child,path)||path!=c->context.helper()||!arbol_boundary::signature(path,false)||
    (!c->context.monitor(child,true)&&!c->context.monitor(child,false))) return fail(env);
  // Confirmation only: never replace the native spawn's original from a PID.
  napi_value out; napi_get_undefined(env,&out); return out;
}
static napi_value watchdogBind(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c || !c->spawned || !c->endpointsPublished || c->bound || !c->retainedReader.valid()||!c->retainedWriter.valid()||
     !c->context.monitor(c->context.primary,false)) return fail(env);
  std::vector<pid_t> pids(4097); int bytes=proc_listpids(PROC_PGRP_ONLY,c->context.main.group,pids.data(),(int)(pids.size()*sizeof(pid_t))); int found=0;
  if(bytes<0 || bytes%sizeof(pid_t) || (size_t)bytes>=pids.size()*sizeof(pid_t)) return fail(env);
  for(int i=0;i<bytes/(int)sizeof(pid_t);++i) { arbol_boundary::Identity id; arbol_boundary::Info detail{}; std::string path;
    if(pids[i]<=0) continue; if(arbol_boundary::observe(pids[i],id,&detail)!=1) return fail(env);
    if(arbol_boundary::executable(id,path) && path==c->context.helper()) {
      if(detail.unique.parent!=c->context.primary.start || !c->context.monitor(id,true)) return fail(env); c->context.custody=id; ++found;
    }
  }
  std::vector<arbol_boundary::Identity> engines;
  if(found!=1 || !c->context.census(engines) || !arbol_boundary::lockIdentity(c->context.owner) || !arbol_boundary::lockIdentity(c->context.build)) return fail(env);
  if(c->hostRequired) {
    if(!c->finalization.ready(c->context)) return fail(env);
    arbol_attempt::Claim claim; std::string raw; NSDictionary* current=nil;
    if(!c->finalization.currentAttempt(c->context,claim,raw,current,arbol_boundary::clockMs()+1000)||
       ![current[@"phase"] isEqual:@"claimed"]||![current[@"stage"] isEqual:@"transferring"]||
       [current[@"expires"] doubleValue]<=arbol_boundary::clockMs()) return fail(env);
    NSMutableDictionary* next=[current mutableCopy]; next[@"stage"]=@"retained";
    if(!arbol_attempt::transition(current,next,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(claim.at,raw,false,arbol_attempt::bytes(next))) return fail(env);
    c->finalization.shared()->transfer.store(2,std::memory_order_release);
  }
  c->bound=true; napi_value out; napi_get_undefined(env,&out); return out;
}

// Only the genuine prearmed host capability can own this one-shot mutation.
// It retains its original short Claim across the async atomic JS transaction.
struct MarkerPermit {
  Custody* custody=nullptr; arbol_attempt::Claim claim;
  std::string currentRaw,dirtyRaw; NSDictionary* attempt=nil; bool active=false,accepted=false;
  bool current() {
    if(!active||!custody||!custody->finalization.ready(custody->context)) return false;
    std::string raw; NSDictionary* value=nil;
    return claim.read(raw,value)&&raw==currentRaw&&[value isEqual:attempt]&&
      [value[@"phase"] isEqual:@"claimed"]&&[value[@"stage"] isEqual:@"mutation-started"]&&
      [value[@"expires"] doubleValue]>arbol_boundary::clockMs();
  }
  void relinquish() { active=false; if(claim.fd>=0) { close(claim.fd); claim.fd=-1; } }
};
static std::set<MarkerPermit*> markerPermits;
static MarkerPermit* markerArgument(napi_env env,napi_value value) {
  void* data=nullptr; if(napi_get_value_external(env,value,&data)!=napi_ok) return nullptr;
  auto* p=static_cast<MarkerPermit*>(data); return markerPermits.count(p)?p:nullptr;
}
static bool nativeMarker(NSDictionary* value) {
  uint64_t epoch;
  return arbol_attempt::keys(value,@[@"format",@"profileInstance",@"engine",@"dataEpoch",@"lastWriterBuild",@"lastWriterChromium",@"lastWriterElectron",@"requiredReader",@"cleanExit"])&&
    [value[@"format"] isEqual:@1]&&[value[@"engine"] isEqual:@"chromium"]&&
    arbol_attempt::pattern(value[@"profileInstance"],@"^prf_[A-Za-z0-9_-]{22}$")&&
    arbol_attempt::uintNumber(value[@"dataEpoch"],epoch)&&epoch>0&&
    arbol_attempt::pattern(value[@"lastWriterBuild"],@"^[1-9a-f][0-9a-f]{0,15}$")&&
    [value[@"lastWriterChromium"] isKindOfClass:NSString.class]&&[value[@"lastWriterChromium"] length]>0&&
    [value[@"lastWriterElectron"] isKindOfClass:NSString.class]&&[value[@"lastWriterElectron"] length]>0&&
    [value[@"requiredReader"] isKindOfClass:NSString.class]&&[value[@"requiredReader"] length]>0&&[value[@"requiredReader"] length]<=256&&
    CFGetTypeID((__bridge CFTypeRef)value[@"cleanExit"])==CFBooleanGetTypeID();
}
// Bytes and their identity come from ONE actual description, including the
// final path check before close. A second fstatat after a closed reader could
// otherwise pair old bytes with a replacement inode.
static bool markerAt(int directory,std::string& raw,struct stat& st,bool& absent) {
  raw.clear(); absent=false;
  int fd=openat(directory,"engine.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
  if(fd<0) { absent=errno==ENOENT; return absent; }
  struct stat before{},named{},last{},after{};
  bool ok=!fstat(fd,&before)&&!fstatat(directory,"engine.json",&named,AT_SYMLINK_NOFOLLOW)&&
    arbol_attempt::privateFile(before)&&arbol_attempt::sameFile(before,named)&&before.st_size>0&&before.st_size<16384;
  char buffer[4096];
  while(ok&&raw.size()<=(size_t)before.st_size) {
    ssize_t n=read(fd,buffer,std::min(sizeof(buffer),(size_t)before.st_size+1-raw.size()));
    if(n>0) raw.append(buffer,n); else if(!n) break; else if(errno!=EINTR) ok=false;
  }
  ok=ok&&raw.size()==(size_t)before.st_size&&!fstat(fd,&last)&&!fstatat(directory,"engine.json",&after,AT_SYMLINK_NOFOLLOW)&&
    arbol_attempt::sameFile(before,last)&&arbol_attempt::sameFile(last,after);
  if(ok) st=last; if(close(fd)) ok=false; return ok;
}
static bool currentMarker(Custody* c,std::string& raw,struct stat& st,bool& absent) {
  if(!c->finalization.present()||!c->finalization.metadata()) return false;
  NSDictionary* capability=c->finalization.value(); NSString* profile=capability[@"attempt"][@"profile"];
  int fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
  struct stat root{},named{},after{},lastName{};
  bool ok=!fstat(fd,&root)&&!lstat(profile.fileSystemRepresentation,&named)&&S_ISDIR(root.st_mode)&&
    [arbol_exit::fileIdentity(root) isEqual:capability[@"profileDirectory"]]&&root.st_dev==named.st_dev&&root.st_ino==named.st_ino&&
    markerAt(fd,raw,st,absent);
  if(ok&&!absent) ok=nativeMarker(arbol_attempt::json(raw))&&
    [arbol_attempt::json(raw)[@"profileInstance"] isEqual:capability[@"attempt"][@"profileInstance"]];
  ok=ok&&!fstat(fd,&after)&&!lstat(profile.fileSystemRepresentation,&lastName)&&
    [arbol_exit::fileIdentity(after) isEqual:capability[@"profileDirectory"]]&&after.st_dev==lastName.st_dev&&after.st_ino==lastName.st_ino&&
    arbol_boundary::lockIdentity(c->context.owner)&&arbol_boundary::lockIdentity(c->context.build);
  if(ok&&absent) { struct stat check{}; errno=0; ok=fstatat(fd,"engine.json",&check,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT; }
  if(close(fd)) ok=false; return ok;
}
static NSDictionary* sealedObject(const std::string& path,std::string& digest) {
  if(!arbol_boundary::canonical(path)) return nil;
  int fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC); if(fd<0) return nil;
  struct stat first{},named{},last{},after{}; std::string bytes;
  bool ok=!fstat(fd,&first)&&!lstat(path.c_str(),&named)&&S_ISREG(first.st_mode)&&first.st_nlink==1&&
    !(first.st_mode&0022)&&(first.st_uid==geteuid()||first.st_uid==0)&&arbol_attempt::sameFile(first,named)&&first.st_size>0&&first.st_size<16384;
  char buffer[4096];
  while(ok&&bytes.size()<=(size_t)first.st_size) {
    ssize_t n=read(fd,buffer,std::min(sizeof(buffer),(size_t)first.st_size+1-bytes.size()));
    if(n>0) bytes.append(buffer,n); else if(!n) break; else if(errno!=EINTR) ok=false;
  }
  ok=ok&&bytes.size()==(size_t)first.st_size&&!fstat(fd,&last)&&!lstat(path.c_str(),&after)&&
    arbol_attempt::sameFile(first,last)&&arbol_attempt::sameFile(last,after);
  if(close(fd)) ok=false; if(ok) digest=[arbol_attempt::digest(bytes) UTF8String]; return ok?arbol_attempt::json(bytes):nil;
}
static bool emptyNativeDirectory(NSString* path) {
  if(!arbol_boundary::canonical(path.fileSystemRepresentation)) return false;
  int fd=open(path.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
  DIR* directory=fdopendir(fd); if(!directory) { close(fd); return false; }
  bool empty=true; errno=0;
  while(auto* entry=readdir(directory)) if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,"..")) { empty=false; break; }
  if(errno) empty=false; if(closedir(directory)) empty=false; return empty;
}
static bool priorMarkerMatches(Custody* c,const std::string& raw,const struct stat& st,bool absent) {
  NSDictionary* capability=c->finalization.value(),*prior=capability[@"prior"],*attempt=capability[@"attempt"];
  if([prior[@"kind"] isEqual:@"absent"]) return absent;
  NSString* path=prior[@"path"],*state=[attempt[@"profile"] stringByDeletingLastPathComponent].stringByDeletingLastPathComponent;
  NSString* prefix=[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:attempt[@"profilePathHash"]];
  if(![path hasPrefix:[prefix stringByAppendingString:@"/"]]||
     ![@[@"activation.json",@"terminal.json"] containsObject:path.lastPathComponent]||!arbol_boundary::canonical(path.fileSystemRepresentation)) return false;
  int fd=open(path.stringByDeletingLastPathComponent.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
  std::string bytes; struct stat receiptIdentity{};
  bool ok=arbol_exit::readNativeFile(fd,path.lastPathComponent.UTF8String,bytes,receiptIdentity,arbol_exit::exitReceiptLimit)&&
    [arbol_attempt::digest(bytes) isEqual:prior[@"digest"]];
  if(close(fd)) ok=false;
  NSDictionary* receipt=arbol_exit::parseExitReceipt(bytes),*marker=receipt[@"marker"];
  ok=ok&&[receipt[@"format"] isEqual:@1]&&[receipt[@"profileInstance"] isEqual:attempt[@"profileInstance"]]&&
    [receipt[@"profilePathHash"] isEqual:attempt[@"profilePathHash"]]&&[receipt[@"profileDirectory"] isEqual:capability[@"profileDirectory"]];
  if(absent) return ok&&marker==(id)NSNull.null;
  return ok&&arbol_attempt::keys(marker,@[@"identity",@"digest",@"value"])&&
    [marker[@"identity"] isEqual:arbol_exit::fileIdentity(st)]&&[marker[@"digest"] isEqual:arbol_attempt::digest(raw)]&&
    [marker[@"value"] isEqual:arbol_attempt::json(raw)];
}
static bool signedDirty(Custody* c,const std::string& dirtyRaw,const std::string& previous,bool absent) {
  NSDictionary* dirty=arbol_attempt::json(dirtyRaw),*attempt=c->finalization.value()[@"attempt"];
  std::string policyHash,compatibilityHash;
  NSDictionary* policy=sealedObject(c->context.bundle+"/Contents/Resources/host-policy.json",policyHash);
  NSDictionary* compatibility=sealedObject(c->context.bundle+"/Contents/Resources/native-compatibility.json",compatibilityHash);
  if(policyHash!=c->policyDigest||compatibilityHash!=c->compatibilityDigest||!policy||!compatibility||!nativeMarker(dirty)||![dirty[@"cleanExit"] isEqual:@NO]||
     ![policy[@"purpose"] isEqual:@"isolated-qualification"]||![policy[@"build"] isEqual:attempt[@"build"]]||
     ![policy[@"buildRoot"] isEqual:attempt[@"buildRoot"]]||![policy[@"sourceDigest"] isEqual:attempt[@"sourceDigest"]]||
     ![policy[@"productDigest"] isEqual:attempt[@"productDigest"]]||
     ![policy[@"stateRoot"] isEqual:[attempt[@"profile"] stringByDeletingLastPathComponent].stringByDeletingLastPathComponent]||
     ![policy[@"readerKey"] isEqual:[@"host-isolated:1:" stringByAppendingString:attempt[@"productDigest"]]]||
     ![compatibility[@"writerKey"] isEqual:policy[@"readerKey"]]||
     ![compatibility[@"compatibleReaderKeys"] isEqual:policy[@"readableReaderKeys"]]||
     ![compatibility[@"readableDataEpochs"] isEqual:policy[@"readableDataEpochs"]]||
     ![compatibility[@"runtime"][@"electron"] isEqual:@"45.3.2"]||![compatibility[@"runtime"][@"chromium"] isEqual:@"156.0.8078.100"]||
     ![dirty[@"profileInstance"] isEqual:attempt[@"profileInstance"]]||![dirty[@"lastWriterBuild"] isEqual:attempt[@"build"]]||
     ![dirty[@"lastWriterChromium"] isEqual:compatibility[@"runtime"][@"chromium"]]||
     ![dirty[@"lastWriterElectron"] isEqual:compatibility[@"runtime"][@"electron"]]||
     ![dirty[@"requiredReader"] isEqual:policy[@"readerKey"]]||![dirty[@"dataEpoch"] isEqual:compatibility[@"dataEpoch"]]) return false;
  if(absent) return [dirty[@"dataEpoch"] isEqual:@1]&&
    emptyNativeDirectory([attempt[@"profile"] stringByAppendingPathComponent:@"data"])&&
    emptyNativeDirectory([attempt[@"profile"] stringByAppendingPathComponent:@"userData"]);
  NSDictionary* old=arbol_attempt::json(previous);
  return nativeMarker(old)&&[policy[@"readableReaderKeys"] containsObject:old[@"requiredReader"]]&&
    [policy[@"readableDataEpochs"] containsObject:old[@"dataEpoch"]];
}
static napi_value beginHostMarkerMutation(napi_env env,napi_callback_info info) {
  napi_value args[2]; size_t n=2; std::string dirty;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=2||!boundedText(env,args[1],dirty)) return fail(env);
  auto* c=custodyArgument(env,args[0]);
  if(!c||!c->bound||c->markerAttempted||!c->finalization.ready(c->context)) return fail(env);
  if(c->continuousBuild) { if(!adoptedNoUse) return fail(env); adoptedNoUse->markerPermission(); }
  c->markerAttempted=true;
  @autoreleasepool { @try {
    auto* permit=new MarkerPermit; permit->custody=c; markerPermits.insert(permit); c->mutation=permit;
    const double deadline=arbol_boundary::clockMs()+500;
    if(!c->finalization.currentAttempt(c->context,permit->claim,permit->currentRaw,permit->attempt,deadline)||
       ![permit->attempt[@"phase"] isEqual:@"claimed"]||![permit->attempt[@"stage"] isEqual:@"retained"]||
       [permit->attempt[@"expires"] doubleValue]<=arbol_boundary::clockMs()) return fail(env);
    std::string previous; struct stat st{}; bool absent;
    if(!currentMarker(c,previous,st,absent)||!priorMarkerMatches(c,previous,st,absent)||!signedDirty(c,dirty,previous,absent)||
       arbol_boundary::clockMs()>=deadline) { permit->relinquish(); return fail(env); }
    NSMutableDictionary* next=[permit->attempt mutableCopy]; next[@"stage"]=@"mutation-started";
    permit->dirtyRaw=dirty;
    if(!arbol_attempt::transition(permit->attempt,next,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(permit->claim.at,permit->currentRaw,false,arbol_attempt::bytes(next))) { permit->relinquish(); return fail(env); }
    permit->attempt=next; permit->currentRaw=arbol_attempt::bytes(next);
    std::string digest=[arbol_attempt::digest(dirty) UTF8String]; memcpy(c->finalization.shared()->expectedMarkerDigest,digest.c_str(),65);
    c->finalization.shared()->mutation.store(1,std::memory_order_release);
    permit->active=true; c->mutation=permit;
    napi_value out; if(napi_create_external(env,permit,nullptr,nullptr,&out)!=napi_ok) return fail(env); return out;
  } @catch(NSException*) { return fail(env); } }
}
static napi_value acceptHostMarkerMutation(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* permit=markerArgument(env,arg);
  if(!permit||!permit->current()) return fail(env); auto* c=permit->custody;
  @autoreleasepool { @try {
    std::string actual; struct stat st{}; bool absent;
    if(!currentMarker(c,actual,st,absent)||absent||actual!=permit->dirtyRaw) return fail(env);
    NSDictionary* marker=arbol_attempt::json(actual); auto* state=c->finalization.shared();
    std::string digest=[arbol_attempt::digest(actual) UTF8String],reader=[marker[@"requiredReader"] UTF8String];
    if(reader.size()>256||digest.size()!=64) return fail(env);
    state->marker.device=st.st_dev; state->marker.inode=st.st_ino; state->marker.uid=st.st_uid; state->marker.size=st.st_size;
    state->marker.dataEpoch=[marker[@"dataEpoch"] unsignedLongLongValue];
    memcpy(state->marker.digest,digest.c_str(),65); memcpy(state->marker.reader,reader.c_str(),reader.size()+1);
    NSMutableDictionary* next=[permit->attempt mutableCopy]; next[@"stage"]=@"marker-bound";
    if(!arbol_attempt::transition(permit->attempt,next,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(permit->claim.at,permit->currentRaw,false,arbol_attempt::bytes(next))) return fail(env);
    state->markerBound.store(1,std::memory_order_release); permit->accepted=true; permit->relinquish(); c->mutation=nullptr;
    napi_value out; napi_get_undefined(env,&out); return out;
  } @catch(NSException*) { return fail(env); } }
}
static napi_value assertHostMarker(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c||!c->finalization.ready(c->context)||c->mutation||c->finalization.shared()->markerBound.load(std::memory_order_acquire)!=1) return fail(env);
  @autoreleasepool { @try {
    std::string raw; struct stat st{}; bool absent; const auto& bound=c->finalization.shared()->marker;
    if(!currentMarker(c,raw,st,absent)||absent||(uint64_t)st.st_dev!=bound.device||st.st_ino!=bound.inode||st.st_uid!=bound.uid||
       (uint64_t)st.st_size!=bound.size||![arbol_attempt::digest(raw) isEqual:[NSString stringWithUTF8String:bound.digest]]||
       !c->finalization.controls(c->context,arbol_boundary::clockMs()+100)) return fail(env);
    napi_value out; napi_get_undefined(env,&out); return out;
  } @catch(NSException*) { return fail(env); } }
}
[[noreturn]] static void terminateCustody(Custody* c);
struct SessionUseNative {
  Custody* custody=nullptr; arbol_attempt::Claim claim; std::string raw; NSDictionary* attempt=nil,*marker=nil;
  bool active=false,accepted=false;
  bool relinquish() {
    bool ok=true; active=false; if(claim.fd>=0) { int held=claim.fd; claim.fd=-1; if(close(held)) ok=false; }
    if(custody&&custody->sessionUse==this) custody->sessionUse=nullptr;
    return ok;
  }
  bool current() {
    if(!active||!custody||!custody->finalization.ready(custody->context)||custody->mutation) return false;
    std::string actual; NSDictionary* value=nil;
    return claim.read(actual,value)&&actual==raw&&[value isEqual:attempt]&&[value[@"phase"] isEqual:@"claimed"]&&
      [value[@"stage"] isEqual:@"admitted"]&&[value[@"expires"] doubleValue]>arbol_boundary::clockMs()&&
      [custody->finalization.boundMarker(custody->context) isEqual:marker];
  }
};
struct WebsiteSessionNative { Custody* custody=nullptr; NSDictionary* marker=nil,*facts=nil; };
static std::set<SessionUseNative*> sessionUses;
static std::set<WebsiteSessionNative*> websiteSessions;
static SessionUseNative* sessionUseArgument(napi_env env,napi_value value) {
  void* raw=nullptr; if(napi_get_value_external(env,value,&raw)!=napi_ok) return nullptr;
  auto* permit=static_cast<SessionUseNative*>(raw); return sessionUses.count(permit)?permit:nullptr;
}
static WebsiteSessionNative* websiteSessionArgument(napi_env env,napi_value value) {
  void* raw=nullptr; if(napi_get_value_external(env,value,&raw)!=napi_ok) return nullptr;
  auto* receipt=static_cast<WebsiteSessionNative*>(raw); return websiteSessions.count(receipt)?receipt:nullptr;
}
static napi_value beginHostSessionUse(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c||!c->hostRequired||!c->bound||c->sessionAttempted||c->mutation||getpid()!=c->context.main.pid||
     !c->finalization.ready(c->context)||c->finalization.shared()->markerBound.load(std::memory_order_acquire)!=1||
     c->finalization.shared()->admitted.load(std::memory_order_acquire)) return fail(env);
  if(c->continuousBuild) { if(!adoptedNoUse) return fail(env); adoptedNoUse->sessionPermission(); }
  c->sessionAttempted=true;
  @autoreleasepool { @try {
    auto* permit=new SessionUseNative; permit->custody=c; sessionUses.insert(permit); c->sessionUse=permit;
    if(!c->finalization.currentAttempt(c->context,permit->claim,permit->raw,permit->attempt,arbol_boundary::clockMs()+250)||
       ![permit->attempt[@"phase"] isEqual:@"claimed"]||![permit->attempt[@"stage"] isEqual:@"marker-bound"]||
       [permit->attempt[@"expires"] doubleValue]<=arbol_boundary::clockMs()||
       !(permit->marker=c->finalization.boundMarker(c->context))) return fail(env);
    NSMutableDictionary* admitted=[permit->attempt mutableCopy]; admitted[@"stage"]=@"admitted";
    std::string next=arbol_attempt::bytes(admitted);
    if(!arbol_attempt::transition(permit->attempt,admitted,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(permit->claim.at,permit->raw,false,next)) return fail(env);
    // This is actual resource-admission linearization, before fromPath. Ready
    // remains separate. The same Claim stays held through real Session sealing.
    permit->attempt=admitted; permit->raw=next; permit->active=true;
    if(!permit->current()) return fail(env);
    napi_value out; if(napi_create_external(env,permit,nullptr,nullptr,&out)!=napi_ok) return fail(env); return out;
  } @catch(NSException*) { return fail(env); } }
}
static napi_value acceptHostSessionUse(napi_env env,napi_callback_info info) {
  napi_value args[2]; size_t n=2; std::string raw;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=2||!boundedText(env,args[1],raw)) return fail(env);
  auto* permit=sessionUseArgument(env,args[0]); if(!permit||!permit->current()||permit->accepted) return fail(env); auto* c=permit->custody;
  @autoreleasepool { @try {
    NSDictionary* facts=arbol_attempt::json(raw); NSString* expected=[permit->attempt[@"profile"] stringByAppendingPathComponent:@"data"];
    if(c->websiteSession||!arbol_attempt::keys(facts,@[@"format",@"websitePath",@"shellPartition",@"shellStoragePath"])||
       ![facts[@"format"] isEqual:@1]||![facts[@"websitePath"] isEqual:expected]||
       !arbol_boundary::canonical(expected.fileSystemRepresentation)||facts[@"shellStoragePath"]!=(id)NSNull.null||
       !arbol_attempt::pattern(facts[@"shellPartition"],@"^shell-[0-9a-f]{32}$")||!permit->current()) return fail(env);
    auto* receipt=new WebsiteSessionNative; receipt->custody=c; receipt->marker=permit->marker; receipt->facts=facts;
    websiteSessions.insert(receipt); c->websiteSession=receipt; permit->accepted=true;
    c->finalization.shared()->admitted.store(1,std::memory_order_release);
    if(!permit->relinquish()) return fail(env);
    napi_value out; if(napi_create_external(env,receipt,nullptr,nullptr,&out)!=napi_ok) return fail(env); return out;
  } @catch(NSException*) { return fail(env); } }
}
static napi_value abortHostSessionUse(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* permit=sessionUseArgument(env,arg);
  if(!permit||!permit->custody) return fail(env); auto* c=permit->custody;
  if(c->finalization.present()) c->finalization.shared()->poison(arbol_exit::admissionLoss|arbol_exit::forced);
  permit->relinquish(); terminateCustody(c);
}
static napi_value recordSessionShutdown(napi_env env,napi_callback_info info,unsigned step) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* receipt=websiteSessionArgument(env,arg);
  if(!receipt||!receipt->custody||step<1||step>4) return fail(env); auto* c=receipt->custody;
  if(c->websiteSession!=receipt||!c->hostRequired||!c->bound||getpid()!=c->context.main.pid||c->sessionUse||!c->finalization.ready(c->context)) return fail(env);
  @autoreleasepool { @try {
    auto* state=c->finalization.shared(); uint64_t grace=state->closeGraceUs.load(std::memory_order_acquire),now=continuousUs();
    if(!grace||!now||now>=grace||state->admitted.load(std::memory_order_acquire)!=1||
       ![c->finalization.boundMarker(c->context) isEqual:receipt->marker]) return fail(env);
    arbol_attempt::Claim claim; std::string raw; NSDictionary* attempt=nil;
    if(!c->finalization.currentAttempt(c->context,claim,raw,attempt,std::min((double)grace/1000,arbol_boundary::clockMs()+100))||
       ![attempt[@"phase"] isEqual:@"closing"]||![attempt[@"stage"] isEqual:@"admitted"]||
       ![c->finalization.boundMarker(c->context) isEqual:receipt->marker]) return fail(env);
    now=continuousUs(); if(!now||now>=grace||state->fatal.load(std::memory_order_acquire)) return fail(env);
    std::atomic<uint32_t>* flags[4]={&state->retiredPages,&state->domRequested,&state->cookieAcknowledged,&state->quitRequested};
    uint32_t old=state->shutdownOrder.load(std::memory_order_acquire);
    if(old>=step) {
      if(flags[step-1]->load(std::memory_order_acquire)!=1||!state->shutdownTimes[step-1].load(std::memory_order_acquire)) return fail(env);
    } else {
      if(old+1!=step) return fail(env);
      state->shutdownTimes[step-1].store(now,std::memory_order_release); flags[step-1]->store(1,std::memory_order_release);
      state->shutdownOrder.store(step,std::memory_order_release);
    }
    napi_value out; napi_get_undefined(env,&out); return out;
  } @catch(NSException*) { return fail(env); } }
}
static napi_value recordPagesRetired(napi_env env,napi_callback_info info) { return recordSessionShutdown(env,info,1); }
static napi_value recordDOMRequested(napi_env env,napi_callback_info info) { return recordSessionShutdown(env,info,2); }
static napi_value recordCookieAcknowledged(napi_env env,napi_callback_info info) { return recordSessionShutdown(env,info,3); }
static napi_value recordQuitIntended(napi_env env,napi_callback_info info) { return recordSessionShutdown(env,info,4); }
static napi_value abortHostMarkerMutation(napi_env env,napi_callback_info info);
[[noreturn]] static void terminateCustody(Custody* c);
static napi_value watchdogAssert(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(c&&c->hostRequired&&c->bound&&c->finalization.present()&&getpid()==c->context.main.pid&&arbol_boundary::current(c->context.main)==1) {
    uint64_t grace=c->finalization.shared()->closeGraceUs.load(std::memory_order_acquire);
    if(grace&&continuousUs()>=grace) terminateCustody(c);
  }
  if(!c || !c->bound || arbol_boundary::current(c->context.main)!=1 || arbol_boundary::current(c->context.primary)!=1 || arbol_boundary::current(c->context.custody)!=1 || !arbol_boundary::lockIdentity(c->context.owner) || !arbol_boundary::lockIdentity(c->context.build)) return fail(env);
  if(!c->retainedReader.valid()||!c->retainedWriter.valid()) return fail(env);
  if(c->hostRequired) {
    auto* state=c->finalization.shared(); uint64_t reasons=state->fatal.load(std::memory_order_acquire),cutoff=state->fatalCutoffUs.load(std::memory_order_acquire);
    if((reasons&~arbol_exit::admissionLoss)||(reasons&&(!cutoff||arbol_boundary::clockMs()*1000>=cutoff))||
       !c->finalization.held(c->context)||!(c->mutation?c->mutation->current():c->sessionUse?c->sessionUse->current():c->finalization.controls(c->context,arbol_boundary::clockMs()+100))) return fail(env);
  }
  napi_value out; napi_get_undefined(env,&out); return out;
}
static napi_value assertHostFinalization(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c||!c->hostRequired||!c->bound||!c->finalization.ready(c->context)||
     c->finalization.shared()->transfer.load(std::memory_order_acquire)!=2) return fail(env);
  napi_value out; napi_get_undefined(env,&out); return out;
}
static napi_value latchWatchdogFatal(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c||getpid()!=c->context.main.pid||arbol_boundary::current(c->context.main)!=1) return fail(env);
  if(c->finalization.present()) c->finalization.shared()->declareFatal();
  napi_value out; napi_get_undefined(env,&out); return out;
}

// No application/native-input cleanup is entered here. Both native lock
// descriptions remain retained for the lifetime of this nonreturning path.
[[noreturn]] static void terminateCustody(Custody* c) {
  if(c->continuousBuild&&adoptedNoUse&&adoptedNoUse->matches(c->context.bundle,c->context.digest,c->context.build)&&
     adoptedNoUse->mayFinalize()&&!c->spawned&&!c->markerAttempted&&!c->sessionAttempted) adoptedNoUse->terminate();
  // Irreversible attribution precedes discovery, retirement or any signal.
  if(c->finalization.present()) c->finalization.shared()->poison(arbol_exit::protocolLoss|arbol_exit::forced);
  if(c->mutation) { c->mutation->relinquish(); c->mutation=nullptr; }
  if(c->sessionUse) c->sessionUse->relinquish();
  for(;;) {
    (void)c->context.discoverCustody();
    c->context.enforce(true);
    arbol_boundary::reap(c->context.primary); arbol_boundary::reap(c->context.custody);
    if(c->context.engineGone(true)) {
      bool a=c->context.retireMonitorPeer(c->context.primary,true);
      bool b=!c->context.custody.pid ? c->context.originalGone(c->context.primary) : c->context.retireMonitorPeer(c->context.custody,true);
      arbol_boundary::reap(c->context.primary); arbol_boundary::reap(c->context.custody);
      if(a&&b&&c->context.engineGone(true)&&c->context.originalGone(c->context.primary)&&c->context.originalGone(c->context.custody)) {
        // The original MAIN is still alive and holds the actual descriptions.
        // Host mode cannot inherit the legacy signal-only release path. An
        // incomplete/failed pre-arm or transfer has no enrolled family proof:
        // retain it, and let the independent command return bounded refusal.
        bool mayExit=!c->continuousBuild&&!c->hostRequired;
        if(c->continuousBuild&&c->hostRequired&&c->finalization.present())
          mayExit=c->finalization.publishDirtyMain(c->context);
        if(mayExit) (void)arbol_boundary::signalExact(c->context.main,SIGKILL);
      }
    }
    // Uncertainty is retained fatal custody, never permission to return/unlock.
    usleep(10000);
  }
}
static napi_value terminateAdoptedHost(napi_env env,napi_callback_info info) {
  napi_value args[2]; size_t n=2; void *buildValue=nullptr,*ownerValue=nullptr; napi_valuetype kind;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=2||
     napi_get_value_external(env,args[0],&buildValue)!=napi_ok||napi_typeof(env,args[1],&kind)!=napi_ok||
     (kind!=napi_null&&napi_get_value_external(env,args[1],&ownerValue)!=napi_ok)) return fail(env);
  auto* build=static_cast<HeldLock*>(buildValue); struct stat identity{};
  if(!liveLocks.count(build)||build!=adoptedBuild||!build->retained||!matches(build,&identity)||!adoptedNoUse) return fail(env);
  if(kind!=napi_null) {
    auto* owner=static_cast<HeldLock*>(ownerValue); struct stat actual{};
    if(!liveLocks.count(owner)||owner->mode!=LOCK_EX||!matches(owner,&actual)) return fail(env);
    auto retained=duplicateHeld(owner); adoptedNoUse->bindOwner(retained);
    if(retained.fd>=0) (void)close(retained.fd); // NoUse owns its own genuine duplicate
  }
  if(adoptedNoUse->mayFinalize()) adoptedNoUse->terminate();
  for(auto* c:nativeCustodies) if(c->continuousBuild&&c->context.build.device==(uint64_t)build->dev&&
    c->context.build.inode==build->ino&&getpid()==c->context.main.pid) terminateCustody(c);
  // An original with possible transfer but no authentic captured custody must
  // retain its Build; no public kill or no-use downgrade can resolve it.
  adoptedNoUse->terminate();
}
static napi_value terminateProfileNow(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c||getpid()!=c->context.main.pid||arbol_boundary::current(c->context.main)!=1) return fail(env);
  terminateCustody(c);
}
static napi_value abortHostMarkerMutation(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* permit=markerArgument(env,arg);
  if(!permit||!permit->custody||getpid()!=permit->custody->context.main.pid||
     arbol_boundary::current(permit->custody->context.main)!=1) return fail(env);
  permit->custody->finalization.shared()->poison(arbol_exit::storageLoss|arbol_exit::forced);
  terminateCustody(permit->custody);
}
// Independent exit inspection never borrows a disappearing holder's JS state.
// Actual owner/old-Build descriptions and code lifetime survive a bounded
// caller's departure; blocking read-only kernel/FS work is off its event loop.
struct ExitInspection {
  std::atomic<int> state{0}; std::atomic<bool> cancelled{false};
  arbol_boundary::Lock owner,build,dataBuild,nextBuild; NSDictionary* input=nil; std::string result; double deadline=0;
  // Captured only on the owning N-API thread. Worker uses its private Context
  // fields and genuinely shared atomic state, never the live mutable Context
  // or global nativeCustodies container.
  arbol_boundary::Context hostContext; arbol_exit::SharedState* hostState=nullptr;
  NSDictionary* hostCapability=nil;
  std::thread* thread=nullptr;
  bool within() const { return !cancelled.load(std::memory_order_acquire)&&arbol_boundary::clockMs()<deadline&&
    arbol_boundary::lockIdentity(owner)&&arbol_boundary::lockIdentity(build)&&
    (dataBuild.fd<0||arbol_boundary::lockIdentity(dataBuild))&&(nextBuild.fd<0||arbol_boundary::lockIdentity(nextBuild)); }
};
static std::set<ExitInspection*> exitInspections;
static bool receiptIdentity(id value,arbol_boundary::Identity& out,bool withSession=false) {
  uint64_t pid,start,version,uid,group,session=0;
  if(!arbol_attempt::keys(value,withSession?@[@"pid",@"startId",@"pidVersion",@"uid",@"group",@"session"]:
    @[@"pid",@"startId",@"pidVersion",@"uid",@"group"])||
    !arbol_attempt::uintNumber(value[@"pid"],pid)||pid<=1||pid>INT_MAX||
    !arbol_attempt::pattern(value[@"startId"],@"^[1-9][0-9]{0,19}$")||
    !arbol_attempt::uintNumber(value[@"pidVersion"],version)||!version||version>INT_MAX||
    !arbol_attempt::uintNumber(value[@"uid"],uid)||uid!=geteuid()||
    !arbol_attempt::uintNumber(value[@"group"],group)||!group||group>INT_MAX||
    (withSession&&(!arbol_attempt::uintNumber(value[@"session"],session)||!session||session>INT_MAX))) return false;
  const char* text=[value[@"startId"] UTF8String]; errno=0; char* end=nullptr; start=strtoull(text,&end,10);
  if(errno||!end||*end||!start) return false;
  out={(int)pid,start,(int32_t)version,(uint32_t)uid,(uint32_t)group}; return true;
}
static bool exitReceiptAt(NSString* path,std::string& raw,NSDictionary* __strong& object,struct stat& identity) {
  if(!arbol_attempt::path(path)||!arbol_boundary::canonical(path.fileSystemRepresentation)||
     !arbol_boundary::privateAncestors(path.fileSystemRepresentation)) return false;
  arbol_exit::NativeFile directory;
  directory.fd=open(path.stringByDeletingLastPathComponent.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if(directory.fd<0||!arbol_exit::readNativeFile(directory.fd,path.lastPathComponent.UTF8String,raw,identity,arbol_exit::exitReceiptLimit)) return false;
  object=arbol_exit::parseExitReceipt(raw); return object&&directory.finish();
}
static bool receiptFrontier(NSDictionary* capability,NSDictionary* frontier,NSString* digest,ExitInspection& job) {
  if(!arbol_attempt::keys(frontier,@[@"format",@"capabilityDigest",@"streams"])||![frontier[@"format"] isEqual:@1]||
     ![frontier[@"capabilityDigest"] isEqual:digest]||![frontier[@"streams"] isKindOfClass:NSArray.class]||
     [frontier[@"streams"] count]!=3||![capability[@"family"] isKindOfClass:NSArray.class]||[capability[@"family"] count]!=3) return false;
  for(unsigned role=0;role<3;++role) {
    NSDictionary* stream=frontier[@"streams"][role],*original=capability[@"family"][role];
    uint64_t device,inode,uid,mode,size,modifiedNs,changedNs,count,offset,length;
    if(!job.within()||!arbol_attempt::keys(stream,@[@"role",@"path",@"device",@"inode",@"uid",@"mode",@"size",@"modified",@"modifiedNs",@"changed",@"changedNs",@"count",@"tailOffset",@"tailLength",@"chain",@"nonce"])||
       !arbol_attempt::keys(original,@[@"role",@"path",@"identity",@"nonce"])||![stream[@"role"] isEqual:@(role)]||![original[@"role"] isEqual:@(role)]||
       ![stream[@"path"] isEqual:original[@"path"]]||![stream[@"nonce"] isEqual:original[@"nonce"]]||
       ![stream[@"path"] isEqual:[capability[@"receiptDirectory"][@"path"] stringByAppendingPathComponent:@[@"family-main.log",@"family-primary.log",@"family-custody.log"][role]]]||
       !arbol_attempt::pattern(stream[@"nonce"],@"^[0-9a-f]{64}$")||!arbol_attempt::pattern(stream[@"chain"],@"^[0-9a-f]{64}$")||
       !arbol_attempt::uintNumber(stream[@"device"],device)||!arbol_attempt::uintNumber(stream[@"inode"],inode)||
       !arbol_attempt::uintNumber(stream[@"uid"],uid)||uid!=geteuid()||!arbol_attempt::uintNumber(stream[@"mode"],mode)||mode!=0600||
       !arbol_attempt::uintNumber(stream[@"size"],size)||size<sizeof(arbol_exit::LedgerHeader)||size>LLONG_MAX||
       !arbol_attempt::uintNumber(stream[@"modifiedNs"],modifiedNs)||modifiedNs>=1000000000||
       !arbol_attempt::uintNumber(stream[@"changedNs"],changedNs)||changedNs>=1000000000||
       !arbol_attempt::uintNumber(stream[@"count"],count)||!arbol_attempt::uintNumber(stream[@"tailOffset"],offset)||
       !arbol_attempt::uintNumber(stream[@"tailLength"],length)) return false;
    NSString* path=stream[@"path"]; if(!arbol_boundary::canonical(path.fileSystemRepresentation)) return false;
    arbol_exit::NativeFile file; file.fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    struct stat before{},after{},named{}; arbol_exit::LedgerHeader header{},expected{}; expected.role=role;
    memcpy(expected.capabilityDigest,digest.UTF8String,65); memcpy(expected.nonce,[stream[@"nonce"] UTF8String],65);
    arbol_exit::LedgerStamp stamp{device,inode,size,(uint32_t)uid,(uint32_t)mode,[stream[@"modified"] longLongValue],
      [stream[@"changed"] longLongValue],modifiedNs,changedNs};
    if(file.fd<0||fstat(file.fd,&before)||lstat(path.fileSystemRepresentation,&named)||!stamp.is(before)||!stamp.is(named)||
       ![arbol_exit::fileIdentity(before) isEqual:original[@"identity"]]||pread(file.fd,&header,sizeof(header),0)!=sizeof(header)||memcmp(&header,&expected,sizeof(header))) return false;
    if(!count) {
      if(size!=sizeof(header)||offset||length||![stream[@"chain"] isEqual:arbol_attempt::digest(std::string((const char*)&header,sizeof(header)))]) return false;
    } else {
      if(offset<sizeof(header)||!length||length>arbol_attempt::limit||offset>size||length!=size-offset) return false;
      std::string tail((size_t)length,'\0'); size_t at=0;
      while(at<tail.size()&&job.within()) { ssize_t n=pread(file.fd,tail.data()+at,tail.size()-at,(off_t)(offset+at));
        if(n>0) at+=n; else if(n<0&&errno==EINTR) continue; else return false; }
      NSDictionary* record=arbol_attempt::json(tail);
      if(at!=tail.size()||!record||![record[@"sequence"] isEqual:@(count)]||![record[@"writerRole"] isEqual:@(role)]||
         ![record[@"digest"] isEqual:stream[@"chain"]]) return false;
      NSMutableDictionary* core=[record mutableCopy]; [core removeObjectForKey:@"digest"];
      if(![arbol_attempt::digest(arbol_attempt::bytes(core)) isEqual:stream[@"chain"]]) return false;
    }
    if(fstat(file.fd,&after)||lstat(path.fileSystemRepresentation,&named)||!stamp.is(after)||!stamp.is(named)||!file.finish()) return false;
  }
  return job.within();
}
static bool receiptMetadata(NSDictionary* capability,NSDictionary* attempt,ExitInspection& job) {
  NSString* profile=attempt[@"profile"],*state=profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
  NSString* receipt=[[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:attempt[@"profilePathHash"]] stringByAppendingPathComponent:attempt[@"request"]];
  if(![capability[@"receiptDirectory"][@"path"] isEqual:receipt]||!arbol_boundary::canonical(profile.fileSystemRepresentation)||
     !arbol_boundary::canonical(receipt.fileSystemRepresentation)||!arbol_boundary::privateAncestors(std::string(profile.fileSystemRepresentation)+"/profile.json")) return false;
  arbol_exit::NativeFile root; root.fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  struct stat directory{},named{},record{},child{},receiptIdentity{}; std::string raw;
  if(root.fd<0||fstat(root.fd,&directory)||lstat(profile.fileSystemRepresentation,&named)||directory.st_dev!=named.st_dev||directory.st_ino!=named.st_ino||
     ![arbol_exit::fileIdentity(directory) isEqual:capability[@"profileDirectory"]]||
     !arbol_exit::readNativeFile(root.fd,"profile.json",raw,record,arbol_attempt::limit)||
     ![arbol_exit::fileIdentity(record) isEqual:capability[@"profileRecord"]]||![arbol_attempt::digest(raw) isEqual:capability[@"profileRecordDigest"]]||
     ![arbol_attempt::json(raw)[@"instance"] isEqual:attempt[@"profileInstance"]]) return false;
  for(NSString* name in @[@"data",@"userData"]) if(fstatat(root.fd,name.UTF8String,&child,AT_SYMLINK_NOFOLLOW)||
    !S_ISDIR(child.st_mode)||child.st_dev!=directory.st_dev||![arbol_exit::fileIdentity(child) isEqual:capability[@"directories"][name]]) return false;
  if(lstat(receipt.fileSystemRepresentation,&receiptIdentity)||!S_ISDIR(receiptIdentity.st_mode)||receiptIdentity.st_dev!=directory.st_dev||
     ![arbol_exit::fileIdentity(receiptIdentity) isEqual:capability[@"receiptDirectory"][@"identity"]]) return false;
  return root.finish()&&job.within();
}
static bool receiptMarker(NSDictionary* capability,id expected,ExitInspection& job) {
  NSString* profile=capability[@"attempt"][@"profile"]; arbol_exit::NativeFile root;
  root.fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  struct stat directory{},identity{},named{}; std::string raw; bool absent;
  if(root.fd<0||fstat(root.fd,&directory)||![arbol_exit::fileIdentity(directory) isEqual:capability[@"profileDirectory"]]||
     !markerAt(root.fd,raw,identity,absent)) return false;
  if(expected==(id)NSNull.null) { errno=0; return absent&&fstatat(root.fd,"engine.json",&named,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT&&root.finish()&&job.within(); }
  return !absent&&arbol_attempt::keys(expected,@[@"identity",@"digest",@"value"])&&nativeMarker(arbol_attempt::json(raw))&&
    [arbol_exit::fileIdentity(identity) isEqual:expected[@"identity"]]&&[arbol_attempt::digest(raw) isEqual:expected[@"digest"]]&&
    [arbol_attempt::json(raw) isEqual:expected[@"value"]]&&
    [arbol_attempt::json(raw)[@"profileInstance"] isEqual:job.input[@"profileInstance"]]&&root.finish()&&job.within();
}
static bool exitAllOriginalsGone(NSDictionary* capability,NSDictionary* proof,ExitInspection& job) {
  arbol_boundary::Identity main,primary,custody,last;
  if(!receiptIdentity(capability[@"main"],main,true)||!receiptIdentity(proof[@"main"],main,true)||
     ![proof[@"main"] isEqual:capability[@"main"]]||!receiptIdentity(proof[@"primary"],primary)||!receiptIdentity(proof[@"custody"],custody)||
     !receiptIdentity(proof[@"lastHolder"],last,true)||main.group!=(uint32_t)main.pid||custody.group!=main.group||
     (primary.group!=main.group&&primary.group!=(uint32_t)primary.pid)||
     ![proof[@"lastHolder"][@"session"] isEqual:capability[@"main"][@"session"]]||
     !(arbol_boundary::same(last,main)||arbol_boundary::same(last,primary)||arbol_boundary::same(last,custody))) return false;
  if(arbol_boundary::same(main,primary)||arbol_boundary::same(main,custody)||arbol_boundary::same(primary,custody)) return false;
  NSString* boot=arbol_exit::bootSession();
  if(!boot||!arbol_attempt::pattern(capability[@"bootSession"],@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")) return false;
  // Kernel boot-session change proves every identity in that earlier boot is
  // gone. Within one boot the complete original-kernel query/reuse provider is
  // mandatory, including the still-live identity captured by the last writer.
  if(![boot isEqual:capability[@"bootSession"]]) return job.within();
  arbol_boundary::OriginalExit observations[4]; arbol_boundary::Identity originals[]={main,primary,custody,last};
  while(job.within()) {
    bool gone=true; for(unsigned i=0;i<4;++i) if(!observations[i].absent(originals[i])) gone=false;
    if(gone) return true; usleep(10000);
  }
  return false;
}
static bool ordinaryExitStatus(uint64_t raw) {
  if(raw>INT_MAX) return false; int status=(int)raw; return WIFEXITED(status)&&WEXITSTATUS(status)==0;
}
static bool ordinaryReceipt(NSDictionary* ordinary,NSDictionary* storage,NSDictionary* capability,NSDictionary* activation) {
  if(!arbol_attempt::keys(ordinary,@[@"format",@"kind",@"capabilityDigest",@"bootSession",@"attempt",@"runtime",@"profileDirectory",@"profileRecordDigest",@"main",@"primary",@"custody",@"lastHolder",@"marker",@"family",@"quiescence",@"shutdown",@"mainExit",@"peerExit",@"consent",@"deadlineUs",@"collectedUs",@"storageScope"])||
     ![ordinary[@"format"] isEqual:@1]||![ordinary[@"kind"] isEqual:@"ordinary-post-exit"]||
     ![ordinary[@"capabilityDigest"] isEqual:activation[@"capabilityDigest"]]||![ordinary[@"bootSession"] isEqual:capability[@"bootSession"]]||
     ![ordinary[@"profileDirectory"] isEqual:capability[@"profileDirectory"]]||![ordinary[@"profileRecordDigest"] isEqual:capability[@"profileRecordDigest"]]||
     ![ordinary[@"runtime"] isEqual:capability[@"runtime"]]||![ordinary[@"lastHolder"] isEqual:activation[@"lastHolder"]]||
     !arbol_attempt::record(ordinary[@"attempt"])||![ordinary[@"attempt"][@"phase"] isEqual:@"closing"]||
     ![ordinary[@"attempt"][@"stage"] isEqual:@"admitted"]||!arbol_attempt::immutable(ordinary[@"attempt"],capability[@"attempt"])) return false;
  for(NSString* role in @[@"main",@"primary",@"custody"]) if(![ordinary[role] isEqual:activation[role]]) return false;
  NSDictionary* shutdown=ordinary[@"shutdown"],*main=ordinary[@"mainExit"],*peer=ordinary[@"peerExit"],*consent=ordinary[@"consent"],*quiet=ordinary[@"quiescence"];
  if(!arbol_attempt::keys(shutdown,@[@"pagesRetiredUs",@"domRequestUs",@"cookieCallbackUs",@"quitIntentUs"])||
     !arbol_attempt::keys(main,@[@"status",@"observedUs",@"limitUs"])||!arbol_attempt::keys(peer,@[@"status",@"observedUs",@"limitUs"])||
     !arbol_attempt::keys(consent,@[@"roundUs",@"primaryUs",@"custodyUs"])||
     !arbol_attempt::keys(quiet,@[@"mainExitStatus",@"mainObservedUs",@"quiescentUs",@"liveLimitUs",@"family"])) return false;
  uint64_t pages,dom,cookies,quit,mainStatus,peerStatus,mainAt,mainLimit,peerAt,peerLimit,round,primaryConsent,custodyConsent,quiescent,deadline,collected;
  if(!arbol_attempt::uintNumber(shutdown[@"pagesRetiredUs"],pages)||!pages||!arbol_attempt::uintNumber(shutdown[@"domRequestUs"],dom)||
     !arbol_attempt::uintNumber(shutdown[@"cookieCallbackUs"],cookies)||!arbol_attempt::uintNumber(shutdown[@"quitIntentUs"],quit)||
     !(pages<=dom&&dom<=cookies&&cookies<=quit)||!arbol_attempt::uintNumber(main[@"status"],mainStatus)||mainStatus>INT_MAX||
     !arbol_attempt::uintNumber(peer[@"status"],peerStatus)||peerStatus>INT_MAX||!ordinaryExitStatus(mainStatus)||
     !ordinaryExitStatus(peerStatus)||!arbol_attempt::uintNumber(main[@"observedUs"],mainAt)||
     !arbol_attempt::uintNumber(main[@"limitUs"],mainLimit)||!arbol_attempt::uintNumber(peer[@"observedUs"],peerAt)||
     !arbol_attempt::uintNumber(peer[@"limitUs"],peerLimit)||!arbol_attempt::uintNumber(consent[@"roundUs"],round)||
     !arbol_attempt::uintNumber(consent[@"primaryUs"],primaryConsent)||!arbol_attempt::uintNumber(consent[@"custodyUs"],custodyConsent)||
     !arbol_attempt::uintNumber(quiet[@"quiescentUs"],quiescent)||!arbol_attempt::uintNumber(ordinary[@"deadlineUs"],deadline)||
     !arbol_attempt::uintNumber(ordinary[@"collectedUs"],collected)||!deadline||
     !(quit<mainAt&&mainAt<=quiescent&&quiescent<mainLimit&&quiescent<=round&&round<=primaryConsent&&primaryConsent<peerLimit&&
       round<=custodyConsent&&custodyConsent<peerAt&&peerAt<peerLimit&&peerAt<=collected&&collected<deadline)||
     ![quiet[@"mainExitStatus"] isEqual:main[@"status"]]||![quiet[@"mainObservedUs"] isEqual:main[@"observedUs"]]||
     ![quiet[@"liveLimitUs"] isEqual:main[@"limitUs"]]||![quiet[@"family"] isEqual:ordinary[@"family"]]||
     ![ordinary[@"deadlineUs"] isEqual:activation[@"deadlineUs"]]) return false;
  if(!arbol_attempt::keys(storage,@[@"format",@"kind",@"ordinaryProofDigest",@"device",@"directories",@"files",@"directoryCount",@"metadataDigest",@"startedUs",@"completedUs",@"deadlineUs",@"fileOperation",@"directoryOperation",@"scope"])||
     ![storage[@"format"] isEqual:@1]||![storage[@"kind"] isEqual:@"native-emitted-storage-sync"]||
     ![storage[@"ordinaryProofDigest"] isEqual:arbol_attempt::digest(arbol_exit::exitReceiptBytes(ordinary))]||
     ![storage[@"directories"] isEqual:capability[@"directories"]]||![storage[@"deadlineUs"] isEqual:ordinary[@"deadlineUs"]]||
     ![storage[@"fileOperation"] isEqual:@"fsync+F_FULLFSYNC"]||![storage[@"directoryOperation"] isEqual:@"fsync"]||
     !arbol_attempt::pattern(storage[@"metadataDigest"],@"^[0-9a-f]{64}$")) return false;
  uint64_t started,completed,files,directories;
  return arbol_attempt::uintNumber(storage[@"startedUs"],started)&&arbol_attempt::uintNumber(storage[@"completedUs"],completed)&&
    arbol_attempt::uintNumber(storage[@"files"],files)&&arbol_attempt::uintNumber(storage[@"directoryCount"],directories)&&directories>=2&&
    collected<=started&&started<=completed&&completed<deadline;
}
static bool verifyClosedReceipt(NSDictionary* closed,NSDictionary* __strong& capability,NSDictionary* __strong& receipt,
  NSDictionary* __strong& frontier,ExitInspection& job,const arbol_boundary::Lock& proofBuild,NSString* bundle) {
  if(!arbol_attempt::record(closed)||![closed[@"phase"] isEqual:@"closed"]||closed[@"terminal"]==NSNull.null||closed[@"engine"]==NSNull.null) return false;
  NSString* path=closed[@"terminal"][@"path"],*profile=closed[@"profile"];
  NSString* state=profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
  NSString* parent=[[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:closed[@"profilePathHash"]] stringByAppendingPathComponent:closed[@"request"]];
  if(![path.stringByDeletingLastPathComponent isEqual:parent]||![@[@"activation.json",@"terminal.json"] containsObject:path.lastPathComponent]) return false;
  std::string raw,journalRaw; struct stat identity{},journalIdentity{}; NSDictionary* journal=nil;
  if(!exitReceiptAt(path,raw,receipt,identity)||![arbol_attempt::digest(raw) isEqual:closed[@"terminal"][@"digest"]]) return false;
  bool clean=[path.lastPathComponent isEqual:@"activation.json"];
  if(clean) {
    if(!arbol_attempt::keys(receipt,@[@"format",@"kind",@"bootSession",@"profileInstance",@"profilePathHash",@"request",@"build",@"sourceDigest",@"productDigest",@"candidateDigest",@"profileDirectory",@"capabilityDigest",@"marker",@"journal",@"main",@"primary",@"custody",@"lastHolder",@"deadlineUs"])||
       ![receipt[@"kind"] isEqual:@"activated-exit"]||!arbol_attempt::keys(receipt[@"journal"],@[@"path",@"identity",@"digest"])||
       ![receipt[@"journal"][@"path"] isEqual:[parent stringByAppendingPathComponent:@"proof.json"]]||
       !exitReceiptAt(receipt[@"journal"][@"path"],journalRaw,journal,journalIdentity)||
       ![arbol_attempt::digest(journalRaw) isEqual:receipt[@"journal"][@"digest"]]||
       ![arbol_exit::fileIdentity(journalIdentity) isEqual:receipt[@"journal"][@"identity"]]||
       !arbol_attempt::keys(journal,@[@"format",@"kind",@"capability",@"capabilityDigest",@"ordinary",@"storage",@"lastHolder"])||
       ![journal[@"format"] isEqual:@1]||![journal[@"kind"] isEqual:@"post-exit-journal"]||
       ![journal[@"lastHolder"] isEqual:receipt[@"lastHolder"]]||![journal[@"capabilityDigest"] isEqual:receipt[@"capabilityDigest"]]) return false;
    capability=journal[@"capability"]; frontier=journal[@"ordinary"][@"family"];
  } else {
    if(!arbol_attempt::keys(receipt,@[@"format",@"kind",@"disposition",@"bootSession",@"profileInstance",@"profilePathHash",@"profileDirectory",@"profileRecordDigest",@"request",@"build",@"sourceDigest",@"productDigest",@"candidateDigest",@"capability",@"capabilityDigest",@"attempt",@"runtime",@"main",@"primary",@"custody",@"lastHolder",@"lastRole",@"marker",@"family",@"nativeState",@"originalClose",@"observedUs",@"metadataDeadlineUs"])||
       ![receipt[@"kind"] isEqual:@"terminal-exit"]||![receipt[@"disposition"] isEqual:@"dirty"]||
       !arbol_attempt::record(receipt[@"attempt"])||!arbol_attempt::immutable(receipt[@"attempt"],closed)||
       ![receipt[@"attempt"][@"engine"] isEqual:closed[@"engine"]]||![receipt[@"attempt"][@"bootstrap"] isEqual:closed[@"bootstrap"]]||
       ![receipt[@"attempt"][@"runtime"] isEqual:closed[@"runtime"]]||![receipt[@"attempt"][@"stage"] isEqual:closed[@"stage"]]) return false;
    capability=receipt[@"capability"]; frontier=receipt[@"family"];
    NSDictionary* facts=receipt[@"nativeState"],*budget=receipt[@"originalClose"]; uint64_t fatal,fatalCutoff,enrolled,transfer,mutation,bound,session,activation,observed,limit,received,grace,overall;
    if(!arbol_attempt::keys(facts,@[@"fatal",@"fatalCutoffUs",@"enrolled",@"transfer",@"mutation",@"markerBound",@"sealedSession",@"activation"])||
       !arbol_attempt::uintNumber(facts[@"fatal"],fatal)||!fatal||!arbol_attempt::uintNumber(facts[@"fatalCutoffUs"],fatalCutoff)||
       !arbol_attempt::uintNumber(facts[@"enrolled"],enrolled)||enrolled!=7||
       !arbol_attempt::uintNumber(facts[@"transfer"],transfer)||(transfer!=1&&transfer!=2)||!arbol_attempt::uintNumber(facts[@"mutation"],mutation)||mutation>1||
       !arbol_attempt::uintNumber(facts[@"markerBound"],bound)||bound>1||!arbol_attempt::uintNumber(facts[@"sealedSession"],session)||session>1||
       !arbol_attempt::uintNumber(facts[@"activation"],activation)||(activation!=0&&activation!=4)||
       !arbol_attempt::uintNumber(receipt[@"observedUs"],observed)||!observed||!arbol_attempt::uintNumber(receipt[@"metadataDeadlineUs"],limit)||
       observed>=limit||limit-observed>1000000||!arbol_attempt::keys(budget,@[@"receivedUs",@"graceUs",@"overallUs"])||
       !arbol_attempt::uintNumber(budget[@"receivedUs"],received)||!arbol_attempt::uintNumber(budget[@"graceUs"],grace)||
       !arbol_attempt::uintNumber(budget[@"overallUs"],overall)||
       (received?(grace!=received+5000000||overall!=received+8000000):(grace||overall))) return false;
    NSString* stage=closed[@"stage"];
    bool beforeBind=transfer==1&&[stage isEqual:@"transferring"]&&!mutation&&!bound&&!session;
    bool retained=transfer==2&&(
      ([stage isEqual:@"retained"]&&!mutation&&!bound&&!session)||
      ([stage isEqual:@"mutation-started"]&&mutation==1&&!bound&&!session)||
      ([stage isEqual:@"marker-bound"]&&mutation==1&&bound==1&&!session)||
      ([stage isEqual:@"admitted"]&&mutation==1&&bound==1));
    if((!beforeBind&&!retained)||![receipt[@"profileRecordDigest"] isEqual:capability[@"profileRecordDigest"]]||
       ![receipt[@"runtime"] isEqual:capability[@"runtime"]]) return false;
    NSString* role=receipt[@"lastRole"]; arbol_boundary::Identity last,expected;
    id original=[role isEqual:@"main"]?receipt[@"main"]:[role isEqual:@"primary"]?receipt[@"primary"]:[role isEqual:@"custody"]?receipt[@"custody"]:nil;
    if(!receiptIdentity(receipt[@"lastHolder"],last,true)||!receiptIdentity(original,expected,[role isEqual:@"main"])||!arbol_boundary::same(last,expected)) return false;
  }
  if(!arbol_attempt::keys(capability,@[@"format",@"kind",@"bootSession",@"bundle",@"main",@"locks",@"attempt",@"attemptPath",@"profileDirectory",@"profileRecord",@"profileRecordDigest",@"directories",@"receiptDirectory",@"family",@"runtime",@"markerPath",@"prior"])||
     ![capability[@"format"] isEqual:@1]||![capability[@"kind"] isEqual:@"host-finalization"]||
     !arbol_attempt::record(capability[@"attempt"])||!arbol_attempt::immutable(capability[@"attempt"],closed)||
     ![capability[@"attempt"][@"engine"] isEqual:closed[@"engine"]]||![capability[@"attempt"][@"bootstrap"] isEqual:closed[@"bootstrap"]]||
     !arbol_attempt::sameRuntimeBinding(capability[@"runtime"],closed[@"runtime"])||
     ![capability[@"attemptPath"] isEqual:[job.input[@"runtimeLeaf"] stringByAppendingPathComponent:@"claim.json"]]||
     ![capability[@"bundle"] isEqual:bundle]||![capability[@"markerPath"] isEqual:[profile stringByAppendingPathComponent:@"engine.json"]]||
     ![capability[@"locks"][@"owner"] isEqual:arbol_boundary::capsuleLock(job.owner)]||
     ![capability[@"locks"][@"build"] isEqual:arbol_boundary::capsuleLock(proofBuild)]||
     ![receipt[@"format"] isEqual:@1]||![receipt[@"bootSession"] isEqual:capability[@"bootSession"]]||
     ![receipt[@"profileDirectory"] isEqual:capability[@"profileDirectory"]]||
     ![receipt[@"capabilityDigest"] isEqual:arbol_attempt::digest(arbol_attempt::bytes(capability))]) return false;
  for(NSString* key in @[@"profileInstance",@"profilePathHash",@"request",@"build",@"sourceDigest",@"productDigest",@"candidateDigest"])
    if(![receipt[key] isEqual:closed[key]]) return false;
  if(![capability[@"main"][@"pid"] isEqual:closed[@"engine"][@"pid"]]||
     ![capability[@"main"][@"startId"] isEqual:closed[@"engine"][@"startId"]]||
     ![capability[@"main"][@"pidVersion"] isEqual:closed[@"engine"][@"pidVersion"]]||
     ![capability[@"main"][@"uid"] isEqual:closed[@"engine"][@"uid"]]||
     ![capability[@"main"][@"session"] isEqual:closed[@"engine"][@"session"]]||
     ![capability[@"main"][@"group"] isEqual:closed[@"engine"][@"group"]]) return false;
  if(clean) {
    NSDictionary* dirty=journal[@"ordinary"][@"marker"],*marker=receipt[@"marker"];
    if(!arbol_attempt::keys(dirty,@[@"identity",@"digest",@"value"])||!nativeMarker(dirty[@"value"])||![dirty[@"value"][@"cleanExit"] isEqual:@NO]||
       !arbol_attempt::keys(marker,@[@"identity",@"digest",@"value"])||!nativeMarker(marker[@"value"])||![marker[@"value"][@"cleanExit"] isEqual:@YES]||
       !ordinaryReceipt(journal[@"ordinary"],journal[@"storage"],capability,receipt)) return false;
    NSMutableDictionary* expected=[dirty[@"value"] mutableCopy]; expected[@"cleanExit"]=@YES;
    arbol_boundary::Identity last,primary;
    if(![expected isEqual:marker[@"value"]]||!receiptIdentity(receipt[@"lastHolder"],last,true)||!receiptIdentity(receipt[@"primary"],primary)||
       !arbol_boundary::same(last,primary)||last.group!=(uint32_t)last.pid) return false;
  }
  return receiptMetadata(capability,closed,job)&&receiptFrontier(capability,frontier,receipt[@"capabilityDigest"],job)&&exitAllOriginalsGone(capability,receipt,job);
}
// A never-used original has a separate witness: no family, flush or clean
// claim can be inferred from it. Its prior data writer is verified separately.
static bool verifyUnusedReceipt(NSDictionary* closed,NSDictionary* __strong& receipt,ExitInspection& job) {
  using namespace arbol_attempt;
  if(!record(closed)||![closed[@"phase"] isEqual:@"closed"]||![closed[@"stage"] isEqual:@"untransferred"]||
     closed[@"bootstrap"]==NSNull.null||closed[@"terminal"]==NSNull.null) return false;
  NSString* path=closed[@"terminal"][@"path"],*profile=closed[@"profile"];
  NSString* parent=[[[profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent
    stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:closed[@"profilePathHash"]] stringByAppendingPathComponent:closed[@"request"]];
  std::string raw; struct stat identity{};
  if(![path isEqual:[parent stringByAppendingPathComponent:@"unused.json"]]||
     !exitReceiptAt(path,raw,receipt,identity)||![digest(raw) isEqual:closed[@"terminal"][@"digest"]]||
     !keys(receipt,@[@"format",@"kind",@"bootSession",@"actorStage",@"actor",@"attempt",@"baseline",@"baselineDigest",@"bundle",@"locks",@"priorDataClaim",@"marker",@"nativeFacts",@"census",@"observedUs",@"metadataDeadlineUs",@"originalAdmissionExpiryUs"])||
     ![receipt[@"format"] isEqual:@1]||![receipt[@"kind"] isEqual:@"unused-host-terminal"]||
     !pattern(receipt[@"bootSession"],@"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")||
     ![receipt[@"bundle"] isEqual:[closed[@"buildRoot"] stringByAppendingPathComponent:@"ArbolBrowser.app"]]||
     ![receipt[@"bundle"] isEqual:job.input[@"bundle"]]||
     !keys(receipt[@"locks"],@[@"build",@"owner"])||
     ![receipt[@"locks"][@"build"] isEqual:arbol_boundary::capsuleLock(job.build)]||
     ![receipt[@"marker"] isEqual:@{@"kind":@"unobserved"}]) return false;
  NSDictionary* attempt=receipt[@"attempt"],*baseline=receipt[@"baseline"],*actor=receipt[@"actor"],*facts=receipt[@"nativeFacts"];
  if(!record(attempt)||!record(baseline)||!immutable(attempt,closed)||!immutable(baseline,closed)||
     ![digest(bytes(baseline)) isEqual:receipt[@"baselineDigest"]]||![baseline[@"stage"] isEqual:@"untransferred"]||
     ![baseline[@"phase"] isEqual:@"claimed"]||baseline[@"terminal"]!=NSNull.null||
     ![@[@"claimed",@"cancelled"] containsObject:attempt[@"phase"]]||attempt[@"terminal"]!=NSNull.null||
     ![attempt[@"stage"] isEqual:closed[@"stage"]]||!sameRuntimeBinding(baseline[@"runtime"],attempt[@"runtime"])||
     !process(actor)||![actor[@"group"] isEqual:actor[@"pid"]]||
     !keys(facts,@[@"spawnIntent",@"markerPermission",@"sessionPermission",@"execIntent",@"execReturnedFailure",@"execError",@"ownerAcquired",@"fullEnrollmentClaimed"])) return false;
  for(NSString* key in @[@"stage",@"bootstrap",@"engine",@"runtime"])
    if(![attempt[key] isEqual:closed[key]]) return false;
  for(NSString* key in @[@"bootstrap",@"engine"]) if(![baseline[key] isEqual:attempt[key]]) return false;
  for(NSString* key in @[@"spawnIntent",@"markerPermission",@"sessionPermission",@"fullEnrollmentClaimed"])
    if(CFGetTypeID((__bridge CFTypeRef)facts[key])!=CFBooleanGetTypeID()||![facts[key] isEqual:@NO]) return false;
  for(NSString* key in @[@"execIntent",@"execReturnedFailure",@"ownerAcquired"])
    if(CFGetTypeID((__bridge CFTypeRef)facts[key])!=CFBooleanGetTypeID()) return false;
  uint64_t error,observed,limit,expiry;
  if(!uintNumber(facts[@"execError"],error)||error>INT_MAX||!uintNumber(receipt[@"observedUs"],observed)||!observed||
     !uintNumber(receipt[@"metadataDeadlineUs"],limit)||limit<=observed||limit-observed>1000000||
     !uintNumber(receipt[@"originalAdmissionExpiryUs"],expiry)||expiry!=(uint64_t)([closed[@"expires"] doubleValue]*1000)||
     ![receipt[@"census"] isEqual:@{@"kind":@"native-no-spawn-with-fresh-empty-supported-descendants",@"group":actor[@"group"],@"session":actor[@"session"]}]) return false;
  bool owned=[facts[@"ownerAcquired"] boolValue];
  if(owned?![receipt[@"locks"][@"owner"] isEqual:arbol_boundary::capsuleLock(job.owner)]:receipt[@"locks"][@"owner"]!=NSNull.null) return false;
  NSString* stage=receipt[@"actorStage"],*bundle=receipt[@"bundle"];
  if([stage isEqual:@"outer"]) {
    if(owned||attempt[@"runtime"]!=NSNull.null||baseline[@"runtime"]!=NSNull.null||
       ![actor isEqual:attempt[@"bootstrap"]]||attempt[@"engine"]!=NSNull.null||
       ![actor[@"executable"] isEqual:[bundle stringByAppendingPathComponent:@"Contents/MacOS/arbol-browser-native"]]||
       ([facts[@"execIntent"] boolValue]?(![facts[@"execReturnedFailure"] boolValue]||!error):([facts[@"execReturnedFailure"] boolValue]||error))) return false;
  } else if([@[@"post-exec",@"adopted"] containsObject:stage]) {
    if([facts[@"execIntent"] boolValue]||[facts[@"execReturnedFailure"] boolValue]||error||
       ![actor[@"executable"] isEqual:[bundle stringByAppendingPathComponent:@"Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron"]]) return false;
    for(NSString* key in @[@"pid",@"uid",@"startId",@"group",@"session",@"parentStartId",@"parentPidVersion"])
      if(![actor[key] isEqual:attempt[@"bootstrap"][key]]) return false;
    if([actor[@"pidVersion"] isEqual:attempt[@"bootstrap"][@"pidVersion"]]||
       ([stage isEqual:@"post-exec"]&&(owned||attempt[@"runtime"]!=NSNull.null||baseline[@"runtime"]!=NSNull.null))||
       ([stage isEqual:@"adopted"]?![actor isEqual:attempt[@"engine"]]:attempt[@"engine"]!=NSNull.null)) return false;
  } else return false;
  if(attempt[@"runtime"]!=NSNull.null&&(![attempt[@"runtime"][@"phase"] isEqual:@"starting"]||
     ![attempt[@"runtime"][@"pid"] isEqual:actor[@"pid"]]||![attempt[@"runtime"][@"processStartId"] isEqual:actor[@"startId"]])) return false;
  id data=receipt[@"priorDataClaim"];
  if(!data||![data isEqual:job.input[@"dataAttempt"]]||(data!=NSNull.null&&
     (!record(data)||![data[@"phase"] isEqual:@"closed"]||![data[@"profile"] isEqual:closed[@"profile"]]||
      ![data[@"profileInstance"] isEqual:closed[@"profileInstance"]]||![data[@"profilePathHash"] isEqual:closed[@"profilePathHash"]]||
      ![@[@"activation.json",@"terminal.json"] containsObject:[data[@"terminal"][@"path"] lastPathComponent]]))) return false;
  NSString* boot=arbol_exit::bootSession(); if(!boot) return false;
  if(![boot isEqual:receipt[@"bootSession"]]) return job.within();
  // The full original identity is queried later, independently of the writer's
  // live self observation. PID absence alone is never accepted.
  arbol_boundary::Identity original;
  if(!receiptIdentity(@{@"pid":actor[@"pid"],@"startId":actor[@"startId"],@"pidVersion":actor[@"pidVersion"],
    @"uid":actor[@"uid"],@"group":actor[@"group"],@"session":actor[@"session"]},original,true)) return false;
  arbol_boundary::OriginalExit gone;
  while(job.within()) { if(gone.absent(original)) return true; usleep(10000); }
  return false;
}
static bool writeExitHistory(int directory,const char* name,NSDictionary* object,ExitInspection& job) {
  std::string raw=arbol_attempt::bytes(object),temporary=".history-"+std::string(NSUUID.UUID.UUIDString.UTF8String);
  arbol_exit::NativeFile file; struct stat published{};
  return !raw.empty()&&job.within()&&arbol_exit::writeNativeFile(directory,temporary,raw,job.deadline,file)&&job.within()&&
    !renameat(directory,temporary.c_str(),directory,name)&&
    arbol_exit::publishedNativeFile(directory,name,raw,file,published,job.deadline)&&file.finish()&&job.within();
}

static bool inspectExit(ExitInspection& job) {
  using namespace arbol_attempt;
  NSDictionary* input=job.input,*expected=input[@"attempt"]; NSString* leaf=input[@"runtimeLeaf"],*profile=input[@"profile"];
  bool prior=[input[@"mode"] isEqual:@"prior"],hostMode=[input[@"mode"] isEqual:@"host"],
    retire=[input[@"mode"] isEqual:@"retire"],reserve=[input[@"mode"] isEqual:@"reserve"],withdraw=[input[@"mode"] isEqual:@"withdraw"];
  if(!job.within()||!keys(input,@[@"format",@"mode",@"profile",@"profileInstance",@"profilePathHash",@"runtimeLeaf",@"bundle",@"attempt",@"previous",@"dataAttempt",@"pending"])||
     ![input[@"format"] isEqual:@1]||![@[@"prior",@"host",@"full",@"retire",@"reserve",@"withdraw"] containsObject:input[@"mode"]]||
     !path(profile)||!path(leaf)||!path(input[@"bundle"])||!pattern(input[@"profileInstance"],@"^prf_[A-Za-z0-9_-]{22}$")||
     ![input[@"profilePathHash"] isEqual:digest(profile.UTF8String)]||
     ![leaf.lastPathComponent isEqual:[input[@"profilePathHash"] substringToIndex:32]]||
     job.owner.path!=std::string(profile.fileSystemRepresentation)+"/owner.lock"||
     (reserve?(job.nextBuild.fd<0||!record(input[@"pending"])):input[@"pending"]!=NSNull.null)) return false;
  arbol_exit::NativeFile history; struct stat historyIdentity{};
  NSString* state=profile.stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
  NSString* historyPath=[[state stringByAppendingPathComponent:@"exit-evidence"] stringByAppendingPathComponent:input[@"profilePathHash"]];
  if(reserve) {
    // Only private outside-profile attempt metadata is created here. Never
    // allocate the per-request receipt directory; native host preparation owns it.
    arbol_exit::NativeFile root,exits; struct stat rootId{},exitsId{},historyId{};
    if(!arbol_boundary::canonical(state.fileSystemRepresentation)||!arbol_boundary::privateAncestors(std::string(state.fileSystemRepresentation)+"/exit-evidence")) return false;
    root.fd=open(state.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(root.fd<0||fstat(root.fd,&rootId)||!S_ISDIR(rootId.st_mode)||rootId.st_uid!=geteuid()||(rootId.st_mode&07777)!=0700||
       !arbol_exit::privateDirectoryAt(root.fd,"exit-evidence",exitsId)||exitsId.st_dev!=rootId.st_dev) return false;
    exits.fd=openat(root.fd,"exit-evidence",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(exits.fd<0||!arbol_exit::privateDirectoryAt(exits.fd,[input[@"profilePathHash"] UTF8String],historyId)||
       historyId.st_dev!=rootId.st_dev||fsync(exits.fd)||fsync(root.fd)||!exits.finish()||!root.finish()) return false;
  }
  errno=0; history.fd=open(historyPath.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  bool historyMissing=history.fd<0&&errno==ENOENT;
  if(!historyMissing&&(history.fd<0||!arbol_boundary::canonical(historyPath.fileSystemRepresentation)||
    fstat(history.fd,&historyIdentity)||!S_ISDIR(historyIdentity.st_mode)||historyIdentity.st_uid!=geteuid()||(historyIdentity.st_mode&07777)!=0700)) return false;
  Claim claim; std::string currentRaw,headRaw,pointerRaw; bool absent,headAbsent=true,pointerAbsent=true;
  if(!claim.acquire(std::string(leaf.fileSystemRepresentation)+"/claim.json",job.deadline)||
     !readAt(claim.at.directory,"claim.json",currentRaw,absent)||
     (!historyMissing&&(!readAt(history.fd,"previous-claim.json",headRaw,headAbsent)||
       !readAt(history.fd,"current-attempt.json",pointerRaw,pointerAbsent)))||!job.within()) return false;
  NSDictionary* current=absent?nil:json(currentRaw),*head=headAbsent?nil:json(headRaw),*pointer=pointerAbsent?nil:json(pointerRaw);
  auto sameProfile=[&](NSDictionary* value) { return record(value)&&[value[@"profile"] isEqual:profile]&&
    [value[@"profileInstance"] isEqual:input[@"profileInstance"]]&&[value[@"profilePathHash"] isEqual:input[@"profilePathHash"]]; };
  if((current&&!sameProfile(current))||(head&&(!sameProfile(head)||![head[@"phase"] isEqual:@"closed"]))||
     (pointer&&(!sameProfile(pointer)||![pointer[@"phase"] isEqual:@"pending"]))||
     ((current||head)&&!pointer)||(pointer&&!immutable(pointer,current?:head))) return false;
  auto result=[&](NSString* kind,NSDictionary* data,NSString* request) {
    bool clean=[kind isEqual:@"activated"];
    NSDictionary* expectation=data?@{@"kind":clean?@"activated":@"terminal",@"path":data[@"terminal"][@"path"],@"digest":data[@"terminal"][@"digest"]}:@{@"kind":@"absent"};
    job.result=bytes(@{@"format":@1,@"kind":kind,@"clean":@(clean),@"prior":expectation,@"request":request?:(id)NSNull.null});
    return !job.result.empty()&&job.within();
  };
  if(withdraw) {
    // Owner custody grants cancellation only, never exit. A possible original
    // actor must still produce native no-use or complete enrolled closure.
    if(!current||!expected||![current isEqual:expected]||![current[@"stage"] isEqual:@"untransferred"]||
       ![@[@"pending",@"claimed",@"cancelled"] containsObject:current[@"phase"]]||current[@"terminal"]!=NSNull.null||
       job.build.path!=std::string([current[@"buildGuard"] UTF8String])||
       ![input[@"bundle"] isEqual:[current[@"buildRoot"] stringByAppendingPathComponent:@"ArbolBrowser.app"]]||
       !arbol_boundary::signature([input[@"bundle"] UTF8String],false)) return false;
    NSMutableDictionary* cancelled=[current mutableCopy]; cancelled[@"phase"]=@"cancelled";
    if(!record(cancelled)||!job.within()||!replace(claim.at,currentRaw,false,bytes(cancelled))) return false;
    return result(@"withdrawn",nil,current[@"request"]);
  }
  // Long read-only verification yields this same stable short Claim while
  // preserving actual Owner and every old/data/new Build open description.
  if(flock(claim.fd,LOCK_UN)) return false;
  auto reclaim=[&] {
    while(flock(claim.fd,LOCK_EX|LOCK_NB)) {
      if((errno!=EWOULDBLOCK&&errno!=EAGAIN)||!job.within()) return false; usleep(1000);
    }
    std::string checked; bool missing; struct stat heldHistory{},namedHistory{};
    bool stableHistory=historyMissing||(!fstat(history.fd,&heldHistory)&&!lstat(historyPath.fileSystemRepresentation,&namedHistory)&&
      heldHistory.st_dev==historyIdentity.st_dev&&heldHistory.st_ino==historyIdentity.st_ino&&
      heldHistory.st_dev==namedHistory.st_dev&&heldHistory.st_ino==namedHistory.st_ino&&
      S_ISDIR(namedHistory.st_mode)&&namedHistory.st_uid==geteuid()&&(namedHistory.st_mode&07777)==0700);
    if(historyMissing) { errno=0; stableHistory=lstat(historyPath.fileSystemRepresentation,&namedHistory)<0&&errno==ENOENT; }
    return job.within()&&stableHistory&&unchanged(claim.at)&&
      readAt(claim.at.directory,"claim.json",checked,missing)&&missing==absent&&checked==currentRaw&&
      (historyMissing||(readAt(history.fd,"previous-claim.json",checked,missing)&&missing==headAbsent&&checked==headRaw&&
        readAt(history.fd,"current-attempt.json",checked,missing)&&missing==pointerAbsent&&checked==pointerRaw))&&
      (!job.hostState||job.hostState->fatal.load(std::memory_order_acquire)==0);
  };
  NSDictionary* closed=current&&[current[@"phase"] isEqual:@"closed"]?current:head;
  bool unclaimed=current&&[current[@"stage"] isEqual:@"untransferred"]&&current[@"bootstrap"]==NSNull.null&&
    current[@"engine"]==NSNull.null&&current[@"runtime"]==NSNull.null&&current[@"terminal"]==NSNull.null&&
    ([current[@"phase"] isEqual:@"cancelled"]||([current[@"phase"] isEqual:@"pending"]&&[current[@"expires"] doubleValue]<=arbol_boundary::clockMs()));
  if(current&&![current[@"phase"] isEqual:@"closed"]&&!(unclaimed&&(reserve||[current[@"phase"] isEqual:@"cancelled"]))) {
    bool host=(prior||hostMode)&&[current[@"phase"] isEqual:@"claimed"]&&currentProcess(current[@"engine"],true)&&
      [current[@"expires"] doubleValue]>arbol_boundary::clockMs()&&
      [current[@"stage"] isEqual:prior?@"untransferred":@"retained"];
    if(!host) return false;
    if(hostMode) {
      auto& c=job.hostContext; auto* shared=job.hostState;
      if(!shared||!job.hostCapability||!immutable(job.hostCapability[@"attempt"],current)||
         ![job.hostCapability[@"attempt"][@"engine"] isEqual:current[@"engine"]]||
         ![arbol_boundary::capsuleLock(c.owner) isEqual:arbol_boundary::capsuleLock(job.owner)]||
         shared->enrolled.load(std::memory_order_acquire)!=7||shared->fatal.load(std::memory_order_acquire)||
         !shared->main.is(c.main)||!shared->primary.is(c.primary)||!shared->custody.is(c.custody)||
         arbol_boundary::current(c.main)!=1||!c.primaryMonitor()||!c.monitor(c.custody,true)||
         !arbol_boundary::lockIdentity(c.owner)||!arbol_boundary::lockIdentity(c.build)||
         !receiptMetadata(job.hostCapability,current,job)) return false;
    }
  } else if(hostMode) return false;
  NSDictionary* data=nil,*capability=nil,*receipt=nil,*frontier=nil,*unusedReceipt=nil;
  bool unused=closed&&[[closed[@"terminal"][@"path"] lastPathComponent] isEqual:@"unused.json"];
  auto verify=[&] {
    if(!closed) {
      if(expected!=(id)NSNull.null||input[@"dataAttempt"]!=NSNull.null||input[@"previous"]!=NSNull.null||retire) return false;
    } else {
      if(expected==(id)NSNull.null||![closed isEqual:expected]||!sameProfile(closed)||
         job.build.path!=std::string([closed[@"buildGuard"] UTF8String])||
         ![input[@"bundle"] isEqual:[closed[@"buildRoot"] stringByAppendingPathComponent:@"ArbolBrowser.app"]]||
         !arbol_boundary::signature([input[@"bundle"] UTF8String],false)) return false;
      if(unused) {
        if(!verifyUnusedReceipt(closed,unusedReceipt,job)) return false;
        data=unusedReceipt[@"priorDataClaim"]==NSNull.null?nil:unusedReceipt[@"priorDataClaim"];
      } else {
        if(input[@"dataAttempt"]!=NSNull.null) return false;
        data=closed;
      }
      if(data) {
        const auto& guard=unused?job.dataBuild:job.build;
        NSString* bundle=[data[@"buildRoot"] stringByAppendingPathComponent:@"ArbolBrowser.app"];
        if(guard.fd<0||guard.path!=std::string([data[@"buildGuard"] UTF8String])||!arbol_boundary::signature(bundle.UTF8String,false)||
           !verifyClosedReceipt(data,capability,receipt,frontier,job,guard,bundle)||
           (!prior&&!receiptMarker(capability,receipt[@"marker"],job))) return false;
      }
      if(input[@"previous"]!=NSNull.null) {
        NSDictionary* previous=input[@"previous"];
        bool latest=closed[@"runtime"]!=NSNull.null&&runtime(previous,closed)&&sameRuntimeBinding(previous,closed[@"runtime"]);
        bool writer=data&&data[@"runtime"]!=NSNull.null&&runtime(previous,data)&&sameRuntimeBinding(previous,data[@"runtime"]);
        // acquireInstance can publish the genuine starting record before the
        // next native preparation binds it into claim.json. A no-use original
        // still binds that physical starting identity through its full actor.
        bool prefix=unused&&runtime(previous,closed)&&[previous[@"phase"] isEqual:@"starting"]&&
          [previous[@"pid"] isEqual:unusedReceipt[@"actor"][@"pid"]]&&
          [previous[@"processStartId"] isEqual:unusedReceipt[@"actor"][@"startId"]];
        if(!latest&&!writer&&!prefix) return false;
      }
    }
    if(!data&&!prior) {
      arbol_exit::NativeFile root; root.fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      std::string raw; struct stat marker{}; bool missing;
      if(root.fd<0||!markerAt(root.fd,raw,marker,missing)||!missing||!root.finish()) return false;
    }
    return job.within();
  };
  auto physical=[&] {
    if(data&&(!receiptMetadata(capability,data,job)||!receiptFrontier(capability,frontier,receipt[@"capabilityDigest"],job)||
       (!prior&&!receiptMarker(capability,receipt[@"marker"],job)))) return false;
    if(unused) {
      std::string raw; NSDictionary* checked=nil; struct stat identity{};
      if(!exitReceiptAt(closed[@"terminal"][@"path"],raw,checked,identity)||
         ![digest(raw) isEqual:closed[@"terminal"][@"digest"]]||![checked isEqual:unusedReceipt]) return false;
    }
    return job.within();
  };
  if(!verify()||!physical()||!unchanged(claim.at)||!reclaim()) return false;
  if(reserve) {
    NSDictionary* next=input[@"pending"];
    // This privileged transition is distinct from generic Role::starter. Repeat
    // all terminal/prior-data/physical checks with this ONE genuine Claim held;
    // only then can the actual live starter replace the unchanged exact record.
    if(!verify()||!physical()||!sameProfile(next)||!transition(nil,next,Role::starter)||
       job.nextBuild.path!=std::string([next[@"buildGuard"] UTF8String])||
       !arbol_boundary::signature([[next[@"buildRoot"] stringByAppendingPathComponent:@"ArbolBrowser.app"] UTF8String],false)||
       (current&&[current[@"request"] isEqual:next[@"request"]])||historyMissing) return false;
    // Persist predecessor first, newest immutable reservation second, and only
    // then install pending atomically. Interrupted publication fails closed:
    // a missing/mismatched newest claim cannot fall back to an older witness.
    if(closed&&(!head||![head isEqual:closed])&&!writeExitHistory(history.fd,"previous-claim.json",closed,job)) return false;
    if(!writeExitHistory(history.fd,"current-attempt.json",next,job)||!job.within()||
       !replace(claim.at,currentRaw,absent,bytes(next))) return false;
  } else if(retire) {
    if(!current||![current isEqual:closed]||historyMissing||!verify()||
       !writeExitHistory(history.fd,"previous-claim.json",closed,job)||!job.within()||
       unlinkat(claim.at.directory,"claim.json",0)||fsync(claim.at.directory)||!unchanged(claim.at)) return false;
  }
  NSString* kind=data?([receipt[@"kind"] isEqual:@"activated-exit"]?@"activated":@"terminal"):@"never-opened";
  return result(kind,data,closed?closed[@"request"]:nil)&&(historyMissing||history.finish());
}
static napi_value beginExitInspection(napi_env env,napi_callback_info info) {
  napi_value args[6]; size_t n=6; void *ownerValue=nullptr,*buildValue=nullptr; std::string input; double deadline;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=6||napi_get_value_external(env,args[0],&ownerValue)!=napi_ok||
     napi_get_value_external(env,args[1],&buildValue)!=napi_ok||!boundedText(env,args[2],input,65536)||
     napi_get_value_double(env,args[3],&deadline)!=napi_ok||!std::isfinite(deadline)||deadline<=arbol_boundary::clockMs()||
     deadline>arbol_boundary::clockMs()+10000||!arbol_boundary::retainNativeImage()) return fail(env);
  auto* owner=static_cast<HeldLock*>(ownerValue); auto* build=static_cast<HeldLock*>(buildValue);
  if(!liveLocks.count(owner)||!liveLocks.count(build)||owner->mode!=LOCK_EX||build->mode!=LOCK_SH) return fail(env);
  HeldLock* additional[2]={nullptr,nullptr};
  for(unsigned i=0;i<2;++i) {
    napi_valuetype type; void* value=nullptr;
    if(napi_typeof(env,args[i+4],&type)!=napi_ok) return fail(env);
    if(type==napi_null) continue;
    if(napi_get_value_external(env,args[i+4],&value)!=napi_ok) return fail(env);
    additional[i]=static_cast<HeldLock*>(value);
    if(!liveLocks.count(additional[i])||additional[i]->mode!=LOCK_SH) return fail(env);
  }
  auto* job=new ExitInspection; job->owner=duplicateHeld(owner); job->build=duplicateHeld(build); job->deadline=deadline;
  // In-process command bytes are ordinary JSON, not a durable canonical exit
  // certificate. Parse immutable data, then enforce exact envelope keys and
  // each complete 16 KiB native attempt grammar independently below.
  NSData* command=[NSData dataWithBytes:input.data() length:input.size()];
  id parsed=[NSJSONSerialization JSONObjectWithData:command options:0 error:nil];
  job->input=[parsed isKindOfClass:NSDictionary.class]?parsed:nil;
  if(additional[0]) job->dataBuild=duplicateHeld(additional[0]);
  if(additional[1]) job->nextBuild=duplicateHeld(additional[1]);
  auto closeInputs=[&] { for(auto* lock:{&job->owner,&job->build,&job->dataBuild,&job->nextBuild}) if(lock->fd>=0) close(lock->fd); };
  if(!job->input||!job->within()||(additional[0]&&job->dataBuild.fd<0)||(additional[1]&&job->nextBuild.fd<0)) {
    closeInputs(); delete job; return fail(env);
  }
  for(NSString* key in @[@"attempt",@"dataAttempt",@"pending"]) if(job->input[key]!=NSNull.null&&
    (!arbol_attempt::record(job->input[key])||arbol_attempt::bytes(job->input[key]).empty())) { closeInputs(); delete job; return fail(env); }
  // The sole owning thread reads its own custody container and immutable role
  // fields before starting the worker. No worker calls HostCapability::held on
  // a live shared Context (primaryOutside and census maps are not atomic).
  if([job->input[@"mode"] isEqual:@"host"]) for(auto* c:nativeCustodies) {
    if(!c->hostRequired||!c->bound||!c->finalization.present()||
       ![c->finalization.value()[@"attempt"][@"profile"] isEqual:job->input[@"profile"]]||
       ![arbol_boundary::capsuleLock(c->context.owner) isEqual:arbol_boundary::capsuleLock(job->owner)]) continue;
    auto& copy=job->hostContext; copy.main=c->context.main; copy.primary=c->context.primary; copy.custody=c->context.custody;
    copy.bundle=c->context.bundle; copy.digest=c->context.digest; copy.session=c->context.session;
    copy.owner=c->context.owner; copy.build=c->context.build; copy.authenticated=c->context.authenticated; copy.primaryOutside=c->context.primaryOutside;
    job->hostState=c->finalization.shared(); job->hostCapability=c->finalization.value();
  }
  napi_value out;
  try {
    exitInspections.insert(job);
    if(napi_create_external(env,job,nullptr,nullptr,&out)!=napi_ok) {
      exitInspections.erase(job); closeInputs(); delete job; return fail(env);
    }
    job->thread=new std::thread([job] {
      bool ok=false;
      @autoreleasepool { @try { try { ok=inspectExit(*job); } catch(...) {} } @catch(NSException*) {} }
      for(auto* lock:{&job->owner,&job->build,&job->dataBuild,&job->nextBuild}) if(lock->fd>=0&&close(lock->fd)) ok=false;
      job->state.store(ok&&!job->cancelled.load(std::memory_order_acquire)&&arbol_boundary::clockMs()<job->deadline?1:-1,std::memory_order_release);
    });
    try { job->thread->detach(); } catch(...) {}
    return out; // no allocating publication can fail after the worker started
  } catch(...) { exitInspections.erase(job); closeInputs(); delete job; return fail(env); }
}
static ExitInspection* exitInspectionArgument(napi_env env,napi_callback_info info) {
  napi_value arg; void* data=nullptr;
  if(!argument(env,info,&arg)||napi_get_value_external(env,arg,&data)!=napi_ok) return nullptr;
  auto* job=static_cast<ExitInspection*>(data); return exitInspections.count(job)?job:nullptr;
}
static napi_value pollExitInspection(napi_env env,napi_callback_info info) {
  auto* job=exitInspectionArgument(env,info); if(!job) return fail(env);
  int state=job->state.load(std::memory_order_acquire);
  if(state<0||job->cancelled.load(std::memory_order_acquire)||arbol_boundary::clockMs()>=job->deadline) return fail(env);
  if(!state) { napi_value out; napi_get_null(env,&out); return out; }
  return text(env,job->result);
}
static napi_value cancelExitInspection(napi_env env,napi_callback_info info) {
  auto* job=exitInspectionArgument(env,info); if(!job) return fail(env);
  job->cancelled.store(true,std::memory_order_release); napi_value out; napi_get_undefined(env,&out); return out;
}

static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
    {"terminateAdoptedHost",nullptr,terminateAdoptedHost,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"beginExitInspection",nullptr,beginExitInspection,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"pollExitInspection",nullptr,pollExitInspection,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"cancelExitInspection",nullptr,cancelExitInspection,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"beginHostSessionUse",nullptr,beginHostSessionUse,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"acceptHostSessionUse",nullptr,acceptHostSessionUse,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"abortHostSessionUse",nullptr,abortHostSessionUse,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"recordPagesRetired",nullptr,recordPagesRetired,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"recordDOMRequested",nullptr,recordDOMRequested,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"recordCookieAcknowledged",nullptr,recordCookieAcknowledged,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"recordQuitIntended",nullptr,recordQuitIntended,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"captureCloseBudget",nullptr,captureCloseBudget,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"beginCloseStamp",nullptr,beginCloseStamp,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"pollCloseStamp",nullptr,pollCloseStamp,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"cancelCloseStamp",nullptr,cancelCloseStamp,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"beginCloseRetirement",nullptr,beginCloseRetirement,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"pollCloseRetirement",nullptr,pollCloseRetirement,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"consumeCloseRequest",nullptr,consumeCloseRequest,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"armLocalClose",nullptr,armLocalClose,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"beginHostMarkerMutation",nullptr,beginHostMarkerMutation,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"acceptHostMarkerMutation",nullptr,acceptHostMarkerMutation,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"assertHostMarker",nullptr,assertHostMarker,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"abortHostMarkerMutation",nullptr,abortHostMarkerMutation,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"prepareHostFinalization",nullptr,prepareHostFinalization,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"spawnWatchdog",nullptr,spawnWatchdog,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"assertHostFinalization",nullptr,assertHostFinalization,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"latchWatchdogFatal",nullptr,latchWatchdogFatal,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"adoptHostBuild",nullptr,adoptHostBuild,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"continuousTime",nullptr,continuousTime,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"processProvenance",nullptr,processProvenance,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"readLaunchAttempt",nullptr,readLaunchAttempt,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"writeLaunchAttempt",nullptr,writeLaunchAttempt,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"terminateProfileNow",nullptr,terminateProfileNow,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"prepareWatchdogCustody",nullptr,prepareWatchdogCustody,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"custodyDescriptors",nullptr,custodyDescriptors,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"captureWatchdog",nullptr,captureWatchdog,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"watchdogBind",nullptr,watchdogBind,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"watchdogAssert",nullptr,watchdogAssert,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"publishDirectory", nullptr, publishDirectory, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"trySharedLock", nullptr, trySharedLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"groupCensus", nullptr, groupCensus, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"tryLock", nullptr, tryLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"assertLock", nullptr, assertLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"releaseLock", nullptr, releaseLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"processIdentity", nullptr, processIdentity, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"peerIdentity", nullptr, peerIdentity, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) return fail(env);
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

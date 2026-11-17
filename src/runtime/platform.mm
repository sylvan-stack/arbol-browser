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

static bool boundedText(napi_env env, napi_value value, std::string& out) {
  size_t length = 0, written = 0;
  if (napi_get_value_string_utf8(env,value,nullptr,0,&length) != napi_ok || !length || length > arbol_attempt::limit) return false;
  out.resize(length+1);
  if (napi_get_value_string_utf8(env,value,out.data(),out.size(),&written) != napi_ok || written != length) return false;
  out.resize(length); return out.find('\0') == std::string::npos;
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
static napi_value adoptHostBuild(napi_env env,napi_callback_info info) {
  napi_value args[3]; size_t n=3; std::string requestPath,guard,bundle;
  if(adoptionAttempted) return fail(env); adoptionAttempted=true;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok || n!=3 || !string(env,args[0],requestPath) ||
      !string(env,args[1],guard) || !string(env,args[2],bundle)) return fail(env);
  @autoreleasepool { @try {
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
       !arbol_attempt::launchRequest(claim,requestPath,attempt)||![arbol_attempt::digest(prior) isEqual:transport[@"claimDigest"]] ||
       ![attempt[@"bootstrap"] isEqual:transport[@"bootstrap"]]||![attempt[@"buildRoot"] isEqual:[NSString stringWithUTF8String:root.c_str()]] ||
       ![attempt[@"buildGuard"] isEqual:[NSString stringWithUTF8String:guard.c_str()]] ||
       ![attempt[@"phase"] isEqual:@"claimed"] || ![attempt[@"stage"] isEqual:@"untransferred"] || attempt[@"engine"]!=NSNull.null) return fail(env);
    NSDictionary* self=arbol_attempt::processRecord(getpid()); NSDictionary* outer=attempt[@"bootstrap"];
    if(!self || ![outer[@"executable"] isEqual:[NSString stringWithUTF8String:(bundle+"/Contents/MacOS/arbol-browser-native").c_str()]] ||
       ![self[@"executable"] isEqual:[NSString stringWithUTF8String:(bundle+"/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron").c_str()]] ||
       [outer[@"pidVersion"] isEqual:self[@"pidVersion"]] || !arbol_boundary::signature(bundle,false) ||
       !arbol_boundary::signature([self[@"executable"] UTF8String],true)) return fail(env);
    for(NSString* key in @[@"pid",@"uid",@"startId",@"group",@"session",@"parentStartId",@"parentPidVersion"])
      if(![outer[key] isEqual:self[key]]) return fail(env);
    if([self[@"group"] intValue]!=getpid() || getppid()!=1) return fail(env);
    NSMutableDictionary* next=[attempt mutableCopy]; next[@"engine"]=self;
    if(!arbol_attempt::transition(attempt,next,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(claim.at,prior,false,arbol_attempt::bytes(next)) || !arbol_boundary::lockIdentity(original) ||
       fcntl(fd,F_SETFD,FD_CLOEXEC) || close(capsule)) return fail(env);
    auto* lock=new HeldLock{fd,guard,guardStat.st_dev,guardStat.st_ino,LOCK_SH,true};
    liveLocks.insert(lock); napi_value out;
    if(napi_create_external(env,lock,finalize,nullptr,&out)!=napi_ok) return fail(env); return out;
  } @catch(NSException*) { return fail(env); } }
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
struct Custody {
  arbol_boundary::Context context; int capsule=-1; bool bound=false,continuousBuild=false,hostRequired=false,spawned=false;
  arbol_exit::HostCapability finalization;
  int reader=-1,writer=-1; bool endpointsPublished=false;
  RetainedPipe retainedReader,retainedWriter;
  MarkerPermit* mutation=nullptr; bool markerAttempted=false;
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
static napi_value prepareHostFinalization(napi_env env,napi_callback_info info) {
  napi_value args[2]; size_t n=2; std::string input;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=2||!boundedText(env,args[1],input)) return fail(env);
  auto* c=custodyArgument(env,args[0]); if(!c||c->hostRequired||c->spawned||!c->continuousBuild) return fail(env);
  c->hostRequired=true; // a failed host preparation cannot fall back to legacy
  @autoreleasepool { @try {
    if(!c->finalization.prepare(c->context,input,arbol_boundary::clockMs()+1000)) return fail(env);
    napi_value out; napi_get_undefined(env,&out); return out;
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
    posix_spawn_file_actions_t actions; posix_spawnattr_t attr;
    bool actionsReady=!posix_spawn_file_actions_init(&actions),attrReady=!posix_spawnattr_init(&attr);
    bool ok=actionsReady&&attrReady;
    if(ok) ok=!posix_spawn_file_actions_adddup2(&actions,c->context.owner.fd,3)&&!posix_spawn_file_actions_adddup2(&actions,c->context.build.fd,4)&&
      !posix_spawn_file_actions_adddup2(&actions,c->capsule,5)&&!posix_spawn_file_actions_adddup2(&actions,down[0],0)&&
      !posix_spawn_file_actions_adddup2(&actions,up[1],1)&&!posix_spawn_file_actions_addopen(&actions,2,"/dev/null",O_WRONLY,0)&&
      !posix_spawnattr_setflags(&attr,POSIX_SPAWN_CLOEXEC_DEFAULT);
    if(ok&&c->hostRequired) ok=!posix_spawn_file_actions_adddup2(&actions,c->finalization.capsule(),8)&&
      !posix_spawn_file_actions_adddup2(&actions,c->finalization.stateDescriptor(),9);
    std::string helper=c->context.helper(); char* argv[]={helper.data(),(char*)"--watchdog",c->hostRequired?(char*)"--host-finalization":nullptr,nullptr};
    char* environment[]={(char*)"PATH=/usr/bin:/bin",nullptr}; pid_t pid=0;
    int result=ok?posix_spawn(&pid,helper.c_str(),&actions,&attr,argv,environment):EINVAL;
    if(actionsReady) posix_spawn_file_actions_destroy(&actions); if(attrReady) posix_spawnattr_destroy(&attr);
    close(down[0]); close(up[1]);
    if(result) return fail(env);
    arbol_boundary::Info birth{}; arbol_boundary::Identity original;
    if(arbol_boundary::observe(pid,original,&birth)!=1) return fail(env);
    c->context.primary=original; // retain the actual child even if validation fails
    if(birth.unique.parent!=c->context.main.start||birth.unique.originalParentVersion!=c->context.main.version||
       (!c->context.monitor(original,true)&&!c->context.monitor(original,false))) return fail(env);
    if(c->hostRequired&&!c->finalization.shared()->primary.bind(original,arbol_boundary::clockMs()+1000)) return fail(env);
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
static bool currentMarker(Custody* c,std::string& raw,struct stat& st,bool& absent) {
  if(!c->finalization.present()||!c->finalization.metadata()) return false;
  NSString* profile=c->finalization.value()[@"attempt"][@"profile"];
  int fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
  bool ok=arbol_attempt::readAt(fd,"engine.json",raw,absent);
  if(ok&&!absent) ok=!fstatat(fd,"engine.json",&st,AT_SYMLINK_NOFOLLOW)&&arbol_attempt::privateFile(st)&&nativeMarker(arbol_attempt::json(raw))&&
    [arbol_attempt::json(raw)[@"profileInstance"] isEqual:c->finalization.value()[@"attempt"][@"profileInstance"]];
  if(close(fd)) ok=false; return ok;
}
static NSDictionary* sealedObject(const std::string& path) {
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
  if(close(fd)) ok=false; return ok?arbol_attempt::json(bytes):nil;
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
  std::string bytes; bool missing;
  bool ok=arbol_attempt::readAt(fd,path.lastPathComponent.UTF8String,bytes,missing)&&!missing&&[arbol_attempt::digest(bytes) isEqual:prior[@"digest"]];
  if(close(fd)) ok=false;
  NSDictionary* receipt=arbol_attempt::json(bytes),*marker=receipt[@"marker"];
  ok=ok&&[receipt[@"format"] isEqual:@1]&&[receipt[@"profileInstance"] isEqual:attempt[@"profileInstance"]]&&
    [receipt[@"profilePathHash"] isEqual:attempt[@"profilePathHash"]]&&[receipt[@"profileDirectory"] isEqual:capability[@"profileDirectory"]];
  if(absent) return ok&&marker==(id)NSNull.null;
  return ok&&arbol_attempt::keys(marker,@[@"identity",@"digest",@"value"])&&
    [marker[@"identity"] isEqual:arbol_exit::fileIdentity(st)]&&[marker[@"digest"] isEqual:arbol_attempt::digest(raw)]&&
    [marker[@"value"] isEqual:arbol_attempt::json(raw)];
}
static bool signedDirty(Custody* c,const std::string& dirtyRaw,const std::string& previous,bool absent) {
  NSDictionary* dirty=arbol_attempt::json(dirtyRaw),*attempt=c->finalization.value()[@"attempt"];
  NSDictionary* policy=sealedObject(c->context.bundle+"/Contents/Resources/host-policy.json");
  NSDictionary* compatibility=sealedObject(c->context.bundle+"/Contents/Resources/native-compatibility.json");
  if(!policy||!compatibility||!nativeMarker(dirty)||![dirty[@"cleanExit"] isEqual:@NO]||
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
static napi_value abortHostMarkerMutation(napi_env env,napi_callback_info info);
static napi_value watchdogAssert(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c || !c->bound || arbol_boundary::current(c->context.main)!=1 || arbol_boundary::current(c->context.primary)!=1 || arbol_boundary::current(c->context.custody)!=1 || !arbol_boundary::lockIdentity(c->context.owner) || !arbol_boundary::lockIdentity(c->context.build)) return fail(env);
  if(!c->retainedReader.valid()||!c->retainedWriter.valid()) return fail(env);
  if(c->hostRequired) {
    auto* state=c->finalization.shared(); uint64_t reasons=state->fatal.load(std::memory_order_acquire),cutoff=state->fatalCutoffUs.load(std::memory_order_acquire);
    if((reasons&~arbol_exit::admissionLoss)||(reasons&&(!cutoff||arbol_boundary::clockMs()*1000>=cutoff))||
       !c->finalization.held(c->context)||!(c->mutation?c->mutation->current():c->finalization.controls(c->context,arbol_boundary::clockMs()+100))) return fail(env);
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
  // Irreversible attribution precedes discovery, retirement or any signal.
  if(c->finalization.present()) c->finalization.shared()->poison(arbol_exit::protocolLoss|arbol_exit::forced);
  if(c->mutation) { c->mutation->relinquish(); c->mutation=nullptr; }
  for(;;) {
    (void)c->context.discoverCustody();
    c->context.enforce(true);
    arbol_boundary::reap(c->context.primary); arbol_boundary::reap(c->context.custody);
    if(c->context.engineGone(true)) {
      bool a=c->context.retireMonitorPeer(c->context.primary,true);
      bool b=!c->context.custody.pid ? arbol_boundary::current(c->context.primary)==0 : c->context.retireMonitorPeer(c->context.custody,true);
      arbol_boundary::reap(c->context.primary); arbol_boundary::reap(c->context.custody);
      if(a && b && c->context.engineGone(true) && arbol_boundary::current(c->context.primary)==0 && arbol_boundary::current(c->context.custody)==0)
        (void)arbol_boundary::signalExact(c->context.main,SIGKILL);
    }
    // Uncertainty is retained fatal custody, never permission to return/unlock.
    usleep(10000);
  }
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
static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
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

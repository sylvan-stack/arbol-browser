// Private process support only (BRW-0.14, BRW-1.7, BRW-3.11), not native input ABI.
#import <Foundation/Foundation.h>
#include <node_api.h>
#include "../../watchdog/boundary.hpp"
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
struct HeldLock { int fd; std::string path; dev_t dev; ino_t ino; int mode; };
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

// Process-lifetime native custody is intentionally not garbage-collected. Once
// created it has no unlock/disarm export; retained originals survive JS failure.
struct Custody { arbol_boundary::Context context; std::string digest; bool bound = false; };
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
  auto* c = new Custody; c->context.bundle=bundle; c->digest=digest;
  c->context.owner=duplicateHeld(static_cast<HeldLock*>(a)); c->context.build=duplicateHeld(static_cast<HeldLock*>(b));
  c->context.session=getsid(0);
  bool valid=arbol_boundary::observe(getpid(),c->context.main)==1 && c->context.initial();
  if (!valid) { if(c->context.owner.fd>=0) close(c->context.owner.fd); if(c->context.build.fd>=0) close(c->context.build.fd); delete c; return fail(env); }
  nativeCustodies.insert(c); napi_value out;
  if(napi_create_external(env,c,nullptr,nullptr,&out)!=napi_ok) return fail(env); return out;
}
static NSDictionary* processRecord(const arbol_boundary::Identity& id, int session=0) {
  NSMutableDictionary* result=[@{@"pid":@(id.pid),@"startId":[NSString stringWithUTF8String:std::to_string(id.start).c_str()],@"pidVersion":@(id.version),@"uid":@(id.uid),@"group":@(id.group)} mutableCopy];
  if(session) result[@"session"]=@(session); return result;
}
static NSDictionary* lockRecord(const arbol_boundary::Lock& lock) {
  return @{@"path":[NSString stringWithUTF8String:lock.path.c_str()],@"device":[NSString stringWithUTF8String:std::to_string(lock.device).c_str()],@"inode":[NSString stringWithUTF8String:std::to_string(lock.inode).c_str()],@"uid":@(lock.uid),@"mode":@(lock.mode),@"heldMode":@(lock.heldMode)};
}
static napi_value custodyDescriptors(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg); if(!c) return fail(env);
  napi_value out; if(napi_create_array_with_length(env,2,&out)!=napi_ok || napi_set_element(env,out,0,number(env,c->context.owner.fd))!=napi_ok || napi_set_element(env,out,1,number(env,c->context.build.fd))!=napi_ok) return fail(env); return out;
}
static napi_value watchdogRecord(napi_env env,napi_callback_info info) {
  napi_value args[2]; size_t n=2; int pid; arbol_boundary::Info detail{}; arbol_boundary::Identity child; std::string path;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok || n!=2 || !integer(env,args[1],&pid)) return fail(env);
  auto* c=custodyArgument(env,args[0]); if(!c || c->context.primary.pid || c->bound || arbol_boundary::observe(pid,child,&detail)!=1 ||
    child.uid!=geteuid() || detail.unique.parent!=c->context.main.start || !arbol_boundary::executable(child,path) || path!=c->context.helper() || !arbol_boundary::signature(path,false)) return fail(env);
  c->context.primary=child; c->context.primary.group=(uint32_t)pid;
  @autoreleasepool {
    NSDictionary* record=@{@"format":@1,@"candidateSnapshotDigest":[NSString stringWithUTF8String:c->digest.c_str()],@"bundle":[NSString stringWithUTF8String:c->context.bundle.c_str()],@"main":processRecord(c->context.main,c->context.session),@"primary":processRecord(c->context.primary),@"locks":@{@"owner":lockRecord(c->context.owner),@"build":lockRecord(c->context.build)}};
    NSData* data=[NSJSONSerialization dataWithJSONObject:record options:0 error:nil];
    if(!data || data.length>16384) return fail(env); return text(env,std::string((const char*)data.bytes,data.length));
  }
}
static napi_value watchdogBind(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c || c->bound || !c->context.monitor(c->context.primary,false)) return fail(env);
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
  c->bound=true; napi_value out; napi_get_undefined(env,&out); return out;
}
static napi_value watchdogAssert(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c || !c->bound || arbol_boundary::current(c->context.main)!=1 || arbol_boundary::current(c->context.primary)!=1 || arbol_boundary::current(c->context.custody)!=1 || !arbol_boundary::lockIdentity(c->context.owner) || !arbol_boundary::lockIdentity(c->context.build)) return fail(env);
  napi_value out; napi_get_undefined(env,&out); return out;
}

// No application/native-input cleanup is entered here. Both native lock
// descriptions remain retained for the lifetime of this nonreturning path.
static napi_value terminateProfileNow(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg);
  if(!c || getpid()!=c->context.main.pid || arbol_boundary::current(c->context.main)!=1) return fail(env);
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
static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
    {"terminateProfileNow",nullptr,terminateProfileNow,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"prepareWatchdogCustody",nullptr,prepareWatchdogCustody,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"custodyDescriptors",nullptr,custodyDescriptors,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"watchdogRecord",nullptr,watchdogRecord,nullptr,nullptr,nullptr,napi_default,nullptr},
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

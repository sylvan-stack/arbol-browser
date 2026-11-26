// Private process support only (BRW-0.14, BRW-1.7, BRW-3.11), not native input ABI.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#include <node_api.h>
#include <os/log.h>
#include "../../watchdog/boundary.hpp"
#include "attempt.hpp"
#include "startup-proof.hpp"
#include "../../watchdog/exit.hpp"
#include <spawn.h>
#include <set>
#include <sys/file.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libproc.h>
#include <map>
#include <bsm/libbsm.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <cerrno>
#include <atomic>
#include <climits>
#include <cmath>
#include <dirent.h>
#include <cstdint>
#include <string>
#include <string_view>
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

// Process-local diagnostic only; no callback, allocation or I/O at refusal.
static std::atomic<unsigned> firstRefusalLine{0};
static std::atomic<bool> refusalLineEmitted{false};
static_assert(std::atomic<unsigned>::is_always_lock_free && std::atomic<bool>::is_always_lock_free);
static napi_value fail(napi_env env, unsigned line = __builtin_LINE()) {
  int saved=errno; unsigned empty=0;
  (void)firstRefusalLine.compare_exchange_strong(empty,line,std::memory_order_relaxed);
  napi_throw_error(env, "platform_unavailable", "Private OS support unavailable."); errno=saved; return nullptr;
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
static constexpr const char* historicalInitializationRoot = "/Users/msix/Builds/afm9-rollback-plan.49cXVsFk/qualification/fixture";
enum class LockAccess { ordinary, historicalInitialization, qualificationObserver };
static bool qualificationObserverGuard(const std::string& path, const std::string& root) {
  if (path == root + "/support/selection.lock") return true;
  const std::string prefix = root + "/arbol-browser/.uses/";
  if (path.compare(0, prefix.size(), prefix) != 0 || path.size() <= prefix.size() ||
      path.size() > prefix.size() + 16 || path[prefix.size()] == '0') return false;
  return path.find_first_not_of("0123456789abcdef", prefix.size()) == std::string::npos;
}
static napi_value acquireLock(napi_env env, napi_callback_info info, int mode, LockAccess access = LockAccess::ordinary) {
  napi_value arg; std::string path;
  if (!argument(env, info, &arg) || !string(env, arg, path)) return fail(env);
  const std::string fixed = historicalInitializationRoot;
  if (access == LockAccess::historicalInitialization && path != fixed+"/support/selection.lock" &&
      path != fixed+"/arbol-browser/.uses/1" && path != fixed+"/arbol-browser/.uses/1.mount") return fail(env);
  if (access == LockAccess::qualificationObserver && !qualificationObserverGuard(path, fixed)) return fail(env);
  int fd = open(path.c_str(), O_RDWR | (access == LockAccess::ordinary ? O_CREAT : 0) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
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
static napi_value tryExistingInitializationLock(napi_env env, napi_callback_info info) {
  return acquireLock(env, info, LOCK_EX, LockAccess::historicalInitialization);
}
static napi_value tryExistingQualificationObserverLock(napi_env env, napi_callback_info info) {
  return acquireLock(env, info, LOCK_EX, LockAccess::qualificationObserver);
}
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
// Installer-only no-replace publication. The raw EX capability is not exposed
// by PlatformPort and cannot publish profile/state or native custody evidence.
static napi_value publishInstallerFile(napi_env env,napi_callback_info info) {
  using namespace arbol_attempt;
  napi_value args[2]; size_t count=2; void* pointer=nullptr; std::string raw;
  if(profileFormat!=2||napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok||count!=2||
     napi_get_value_external(env,args[0],&pointer)!=napi_ok||!pointer||!boundedText(env,args[1],raw)) return fail(env);
  auto* selection=static_cast<HeldLock*>(pointer); struct stat held{};
  if(!liveLocks.count(selection)||selection->retained||selection->mode!=LOCK_EX||!matches(selection,&held)||
     !arbol_boundary::canonical(selection->path)||!arbol_boundary::privateAncestors(selection->path)) return fail(env);
  NSDictionary* request=json(raw);
  if(!keys(request,@[@"source",@"destination",@"identity",@"sha256"])||!path(request[@"source"])||
     !path(request[@"destination"])||!pattern(request[@"sha256"],@"^[0-9a-f]{64}$")) return fail(env);
  const std::string source=[request[@"source"] UTF8String],destination=[request[@"destination"] UTF8String];
  const auto parent=[](const std::string& value) { return value.substr(0,value.rfind('/')); };
  const std::string support=parent(selection->path);
  NSString* home=physicalAccountHome(); if(!home) return fail(env);
  const std::string installedUses=[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_USES].fileSystemRepresentation;
  const bool installed=support==parent(installedUses);
  if(selection->path!=support+"/selection.lock") return fail(env);
  if(!installed) {
    const std::string fixture=parent(support);
    MaintenanceDirectory root;
    if(support!=fixture+"/support"||!isolatedFromInstallation(fixture)||!root.openPath(fixture)) return fail(env);
  }
  if(parent(source)!=parent(destination)||source==destination||
     !pattern([NSString stringWithUTF8String:source.substr(source.rfind('/')+1).c_str()],@"^\\.(install|replace)-[0-9a-f]{24}$")) return fail(env);
  const std::string leaf=destination.substr(destination.rfind('/')+1),folder=parent(destination);
  const bool backup=destination==support+"/install-previous-launcher"||
    (folder==support+"/releases"&&pattern([NSString stringWithUTF8String:leaf.c_str()],@"^[1-9a-f][0-9a-f]{0,15}\\.launcher$"));
  const bool initialization=!installed&&support==std::string(historicalInitializationRoot)+"/support"&&
    destination==support+"/historical-initialization.json";
  const bool allowed=initialization||destination==support+"/install-transaction.json"||backup||
    (folder==support+"/images"&&pattern([NSString stringWithUTF8String:leaf.c_str()],@"^[1-9a-f][0-9a-f]{0,15}\\.dmg$"))||
    (folder==support+"/releases"&&pattern([NSString stringWithUTF8String:leaf.c_str()],@"^[1-9a-f][0-9a-f]{0,15}(\\.migration)?\\.json$"));
  if(!allowed) return fail(env);
  MaintenanceDirectory directory; MaintenanceFile input;
  const mode_t mode=backup?0755:0600; const double deadline=arbol_boundary::clockMs()+120000;
  if(!directory.openPath(folder)||!input.openPath(source,mode,1024LL*1024*1024)||
     input.identity.st_dev!=directory.identity.st_dev||
     ![maintenanceIdentity(input.identity) isEqual:request[@"identity"]]||
     ![input.sha256(deadline) isEqual:request[@"sha256"]]||fsync(input.fd)||!directory.current()||
     !input.current()||!matches(selection,&held)) return fail(env);
  const std::string from=source.substr(source.rfind('/')+1);
  if(renameatx_np(directory.fd,from.c_str(),directory.fd,leaf.c_str(),RENAME_EXCL)) return fail(env);
  struct stat published{},named{}; errno=0;
  if(fstat(input.fd,&published)||fstatat(directory.fd,leaf.c_str(),&named,AT_SYMLINK_NOFOLLOW)||
     !sameFile(published,named)||published.st_dev!=input.identity.st_dev||published.st_ino!=input.identity.st_ino||
     published.st_uid!=geteuid()||(published.st_mode&07777)!=mode||published.st_nlink!=1||
     !S_ISREG(published.st_mode)) return fail(env);
  input.path=destination; input.identity=published;
  errno=0;
  if(!fstatat(directory.fd,from.c_str(),&named,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT||
     !input.current()||![input.sha256(deadline) isEqual:request[@"sha256"]]||fsync(input.fd)||fsync(directory.fd)||
     !directory.current()||!input.current()||!matches(selection,&held)) return fail(env);
  napi_value result; napi_get_undefined(env,&result); return result;
}


// The fixed retirement namespace is never a general directory-move API.
static napi_value retireInstallerRollback(napi_env env,napi_callback_info info) {
  using namespace arbol_attempt;
  napi_value args[2]; size_t count=2; void* pointer=nullptr; std::string raw;
  if(profileFormat!=2||napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok||count!=2||
     napi_get_value_external(env,args[0],&pointer)!=napi_ok||!pointer||!boundedText(env,args[1],raw)) return fail(env);
  auto* selection=static_cast<HeldLock*>(pointer); struct stat held{};
  if(!liveLocks.count(selection)||selection->retained||selection->mode!=LOCK_EX||!matches(selection,&held)||
     !arbol_boundary::canonical(selection->path)||!arbol_boundary::privateAncestors(selection->path)) return fail(env);
  NSDictionary* request=json(raw);
  if(!keys(request,@[@"parent",@"directory"])) return fail(env);
  const auto parent=[](const std::string& p) { return p.substr(0,p.rfind('/')); };
  const std::string support=parent(selection->path);
  NSString* home=physicalAccountHome(); if(!home||selection->path!=support+"/selection.lock") return fail(env);
  const std::string uses=[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_USES].fileSystemRepresentation;
  if(support!=parent(uses)) {
    const std::string fixture=parent(support); MaintenanceDirectory root;
    if(support!=fixture+"/support"||!isolatedFromInstallation(fixture)||!root.openPath(fixture)) return fail(env);
  }
  MaintenanceDirectory directory,source;
  if(!directory.openPath(support,request[@"parent"])||
     !source.openPath(support+"/rollback-launchers",request[@"directory"])||
     directory.identity.st_dev!=source.identity.st_dev||!matches(selection,&held)) return fail(env);
  struct stat named{}; errno=0;
  if(!fstatat(directory.fd,"pre-format-2-rollback-launchers",&named,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT||
     !directory.current()||!source.current()||
     renameatx_np(directory.fd,"rollback-launchers",directory.fd,"pre-format-2-rollback-launchers",RENAME_EXCL)) return fail(env);
  source.path=support+"/pre-format-2-rollback-launchers";
  errno=0;
  if(!fstatat(directory.fd,"rollback-launchers",&named,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT||
     !source.current()||fsync(directory.fd)||!directory.current()||!source.current()||!matches(selection,&held)) return fail(env);
  napi_value result; napi_get_undefined(env,&result); return result;
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
static napi_value requestProfileOpen(napi_env env, napi_callback_info info) {
  napi_value args[2], out; size_t count = 2;
  std::string profile, instance;
  if (napi_get_cb_info(env, info, &count, args, nullptr, nullptr) != napi_ok || count != 2 ||
      !boundedText(env, args[0], profile, 64) || !boundedText(env, args[1], instance, 26)) return fail(env);
  @autoreleasepool { @try {
    NSString* id = [NSString stringWithUTF8String:profile.c_str()];
    NSString* key = [NSString stringWithUTF8String:instance.c_str()];
    if (![NSThread isMainThread] || !NSApp ||
        !arbol_attempt::pattern(id, @"^[a-z]([a-z0-9-]{0,62}[a-z0-9])?$") ||
        !arbol_attempt::pattern(key, @"^prf_[A-Za-z0-9_-]{22}$")) return fail(env);
    NSString* engine = arbol_attempt::processRecord(getpid())[@"executable"];
    NSString* suffix = @"/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron";
    if (![engine hasSuffix:suffix]) return fail(env);
    NSString* bundle = [engine substringToIndex:engine.length-suffix.length];
    arbol_attempt::PackagedLayout layout;
    if (!arbol_attempt::packagedLayout(bundle.fileSystemRepresentation, layout) || !layout.installed) return fail(env);
    NSWorkspaceOpenConfiguration* config = [NSWorkspaceOpenConfiguration configuration];
    config.createsNewApplicationInstance = YES;
    config.activates = NO;
    config.addsToRecentItems = NO;
    config.arguments = @[@"--arbol-profile-open", id, key];
    config.environment = @{};
    [[NSWorkspace sharedWorkspace] openApplicationAtURL:[NSURL fileURLWithPath:bundle] configuration:config completionHandler:nil];
    if (napi_get_boolean(env, true, &out) != napi_ok) return fail(env);
    return out;
  } @catch(NSException*) { return fail(env); } }
}
static napi_value activateProfileWindow(napi_env env, napi_callback_info info) {
  napi_value args[2], out; size_t count = 2, length = 0; int pid;
  char start[21]{};
  if (napi_get_cb_info(env, info, &count, args, nullptr, nullptr) != napi_ok || count != 2 ||
      !integer(env, args[0], &pid) || pid < 2 || pid == getpid() ||
      napi_get_value_string_utf8(env, args[1], start, sizeof(start), &length) != napi_ok) return fail(env);
  bool allowed = false;
  @autoreleasepool {
    if ([NSThread isMainThread] && NSApp.active) {
      NSRunningApplication* target = [NSRunningApplication runningApplicationWithProcessIdentifier:pid];
      NSRunningApplication* current = NSRunningApplication.currentApplication;
      arbol_boundary::Identity identity;
      char ownPath[PROC_PIDPATHINFO_MAXSIZE]{}, targetPath[PROC_PIDPATHINFO_MAXSIZE]{};
      if (target && !target.terminated && proc_pidpath(getpid(), ownPath, sizeof(ownPath)) > 0 &&
          proc_pidpath(pid, targetPath, sizeof(targetPath)) > 0 && !strcmp(ownPath, targetPath) &&
          arbol_boundary::observe(pid, identity) == 1 && identity.uid == geteuid() &&
          std::to_string(identity.start) == std::string_view(start, length)) {
        [NSApp yieldActivationToApplication:target];
        allowed = [target activateFromApplication:current options:0];
      }
    }
  }
  if (napi_get_boolean(env, allowed, &out) != napi_ok) return fail(env);
  return out;
}
// Reads one fixed same-user process invocation. Never returns argv or environment.
static napi_value seqoyaBackendArguments(napi_env env, napi_callback_info info) {
  napi_value args[5], out; size_t count = 5; int pid; std::string start, runtime, entry, lock;
  if (napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok || count!=5 ||
      !integer(env,args[0],&pid) || pid<2 || !string(env,args[1],start) ||
      !string(env,args[2],runtime) || !string(env,args[3],entry) || !string(env,args[4],lock)) return fail(env);
  const auto matches = [&]() -> bool {
    @autoreleasepool { @try {
      NSDictionary* before=arbol_attempt::processRecord(pid);
      if (!arbol_attempt::process(before) || start!=[before[@"startId"] UTF8String] ||
          runtime!=[before[@"executable"] UTF8String]) return false;
      int mib[3]={CTL_KERN,KERN_PROCARGS2,pid};
      std::vector<char> buffer(256*1024); size_t len=buffer.size();
      if (sysctl(mib,3,buffer.data(),&len,nullptr,0) || len<=sizeof(int) || len>buffer.size()) return false;
      int argc=0; memcpy(&argc,buffer.data(),sizeof(argc));
      if (argc!=5) return false;
      const char* cursor=buffer.data()+sizeof(argc); const char* end=buffer.data()+len;
      const auto read=[&](std::string_view& field) {
        if (cursor>=end) return false;
        const auto* zero=static_cast<const char*>(memchr(cursor,0,static_cast<size_t>(end-cursor)));
        if (!zero) return false;
        field=std::string_view(cursor,static_cast<size_t>(zero-cursor)); cursor=zero+1; return true;
      };
      std::string_view field;
      if (!read(field) || field!=runtime) return false;
      while (cursor<end && !*cursor) ++cursor;
      const std::string_view expected[]={runtime,"-I","-B",entry,"backend"};
      for (const auto arg:expected) if (!read(field) || field!=arg) return false;
      const int lockFd=open(lock.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
      if (lockFd<0) return false;
      struct stat held{}, named{};
      const bool owned=fstat(lockFd,&held)==0 && lstat(lock.c_str(),&named)==0 && S_ISREG(held.st_mode) &&
        held.st_uid==geteuid() && held.st_nlink==1 && (held.st_mode&07777)==0600 &&
        held.st_dev==named.st_dev && held.st_ino==named.st_ino;
      const bool locked=owned && flock(lockFd,LOCK_EX|LOCK_NB)!=0 && (errno==EWOULDBLOCK || errno==EAGAIN);
      char pidRecord[64]={};
      const ssize_t bytes=locked?pread(lockFd,pidRecord,sizeof(pidRecord),0):-1;
      close(lockFd);
      const std::string expectedPid="{\"pid\": "+std::to_string(pid)+"}\n";
      if (bytes!=static_cast<ssize_t>(expectedPid.size()) || memcmp(pidRecord,expectedPid.data(),expectedPid.size())) return false;
      NSDictionary* after=arbol_attempt::processRecord(pid);
      return after && [after isEqualToDictionary:before];
    } @catch(NSException*) { return false; } }
  };
  if (napi_get_boolean(env,matches(),&out)!=napi_ok) return fail(env);
  return out;
}
static napi_value prepareQualificationInterruptionPipes(napi_env env, napi_callback_info info) {
  using namespace arbol_attempt;
  napi_value arg,out; bool preparation=false;
  if (profileFormat!=2 || !argument(env,info,&arg) || napi_get_value_bool(env,arg,&preparation)!=napi_ok) return fail(env);
  @autoreleasepool { @try {
    if (!qualificationProducer(processRecord(getpid()))) return fail(env);
    NSMutableSet* originals=[NSMutableSet new];
    const int last=preparation?qualificationPreparationEventDescriptor:qualificationInstallerEventDescriptor;
    for (int fd=qualificationInstallerStopDescriptor; fd<=last; ++fd) {
      const bool reading=fd==qualificationInstallerStopDescriptor || fd==qualificationPreparationAckDescriptor;
      NSString* identity=qualificationPipe(fd,reading?O_RDONLY:O_WRONLY,true);
      if (!identity || [originals containsObject:identity]) return fail(env);
      [originals addObject:identity];
    }
    if (napi_get_boolean(env,true,&out)!=napi_ok) return fail(env);
    return out;
  } @catch(NSException*) { return fail(env); } }
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
// Pure selection hint. No file, guard, receipt or predecessor is trusted here;
// the later native inspection independently rederives applicability and proof.
static napi_value canonicalMigrationClaimDigest(napi_env env,napi_callback_info info) {
  napi_value arg; std::string raw;
  if(arbol_attempt::profileFormat!=2||!argument(env,info,&arg)||!boundedText(env,arg,raw)) return fail(env);
  @autoreleasepool { @try {
    NSDictionary* value=arbol_attempt::json(raw);
    if(!arbol_attempt::record(value)||![value[@"phase"] isEqual:@"closed"]) return fail(env);
    std::string canonical=arbol_attempt::bytes(value);
    if(canonical.empty()) return fail(env);
    return text(env,[arbol_attempt::digest(canonical) UTF8String]);
  } @catch(NSException*) { return fail(env); } }
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
static std::unique_ptr<arbol_startup_proof::RetainedAppPackage> adoptedPackage;
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
    arbol_attempt::Claim claim; std::string prior; NSDictionary* attempt=nil; arbol_attempt::PackagedLayout layout;
    if(!claim.acquire(requestPath,arbol_boundary::clockMs()+2000)||!claim.read(prior,attempt)||
       !arbol_attempt::launchRequest(claim,requestPath,attempt)||
       !arbol_attempt::claimedLayout(attempt,layout)||layout.bundle!=bundle||layout.buildRoot!=root||layout.guard!=guard||
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
    if(!self || ![outer[@"executable"] isEqual:[NSString stringWithUTF8String:layout.bootstrap.c_str()]] ||
       ![self[@"executable"] isEqual:[NSString stringWithUTF8String:layout.engine.c_str()]] ||
       [outer[@"pidVersion"] isEqual:self[@"pidVersion"]]) return fail(env);
    for(NSString* key in @[@"pid",@"uid",@"startId",@"group",@"session",@"parentStartId",@"parentPidVersion"])
      if(![outer[key] isEqual:self[key]]) return fail(env);
    if([self[@"group"] intValue]!=getpid()||getppid()!=1) return fail(env);
    auto package = std::make_unique<arbol_startup_proof::RetainedAppPackage>();
    const bool originalPackage = !cancelled && package->capture(layout, [attempt[@"expires"] doubleValue], attempt[@"candidateDigest"]);
    if (!originalPackage && (!arbol_boundary::signature(bundle,false) || !arbol_boundary::signature(layout.engine,true)))
      return fail(env);
    if ((originalPackage && !package->current()) || !arbol_attempt::currentProcess(self,true) ||
        !arbol_boundary::retainNativeImage()) return fail(env);
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
    if (originalPackage) adoptedPackage=std::move(package);
    return out;
  } @catch(NSException*) {
    if(adoptedNoUse) adoptedNoUse->terminate(); return fail(env);
  } } catch(...) {
    if(adoptedNoUse) adoptedNoUse->terminate(); return fail(env);
  } }
}

// Kept until process exit, including failed adoption. Neither GC nor any
// public lock operation can release the inherited maintenance descriptions.
struct QualificationStagingWriter {
  NSDictionary* entry = nil;
  std::string profile, staging, progress;
  arbol_attempt::MaintenanceDirectory progressDirectory;
  NSDictionary* record = nil;
  NSDictionary* marker = nil;
  NSDictionary* staged = nil;
};
struct QualificationProgressProof {
  NSDictionary* receipt = nil;
  NSDictionary* receiptsParent = nil;
  std::vector<std::pair<std::string,struct stat>> files;
  std::vector<std::pair<std::string,struct stat>> directories;
  std::vector<std::pair<std::string,struct stat>> unchangedDirectories;
  std::string staging, absentMarker;
  struct stat stagingStamp{};
};
struct QualificationProgressProfile {
  std::unique_ptr<QualificationProgressProof> proof;
  NSDictionary* committed = nil;
  struct stat committedStamp{};
};
struct QualificationProgressWriter {
  NSArray* profiles = nil;
  std::map<std::string,QualificationProgressProfile> byHash;
  NSDictionary* stagingParent = nil;
  NSDictionary* completion = nil;
  struct stat completionStamp{};
};
struct MaintenanceCustody {
  bool installed = false;
  arbol_attempt::IsolatedMaintenanceAdmission isolated;
  arbol_attempt::InstalledMaintenanceAdmission production;
  arbol_attempt::MaintenanceDirectory installedRuntime;
  NSDictionary* parent = nil;
  NSString* epoch = nil;
  HeldLock* oldBuild = nullptr;
  HeldLock* newBuild = nullptr;
  bool accepted = false;
  NSDictionary* interruption = nil;
  NSDictionary* interruptionWorker = nil;
  std::atomic<bool> interruptionConsumed{false};
  NSString* publishedTransactionAttempt = nil;
  NSDictionary* publishedTransaction = nil;
  NSDictionary* publishedTransactionParent = nil;
  NSDictionary* publishedCurrent = nil;
  NSDictionary* publishedCurrentParent = nil;
  NSDictionary* publishedProgressParent = nil;
  NSMutableDictionary* nativeStagedPublications = nil; // Owning N-API thread only.
  NSMutableDictionary* nativeStagingParents = nil; // Owning N-API thread only.
  NSString* interruptionAttempt = nil;
  NSString* interruptionArchiveDigest = nil;
  std::unique_ptr<arbol_attempt::MaintenanceFile> interruptionArchive;
  std::unique_ptr<arbol_attempt::MaintenanceDirectory> interruptionProfiles;
  HeldLock* interruptionRegistry = nullptr;
  std::vector<HeldLock*> interruptionOwners;
  std::set<std::string> interruptionProfileNames;
  QualificationStagingWriter stagingWriter;
  QualificationProgressWriter progressWriter; // Owning N-API thread only.
  const arbol_attempt::PackagedLayout& layout() const { return installed ? production.layout : isolated.authority.layout; }
  arbol_attempt::MaintenanceGuard& oldGuard() { return installed ? production.oldBuild : isolated.oldBuild; }
  arbol_attempt::MaintenanceGuard& newGuard() { return installed ? production.newBuild : isolated.newBuild; }
  arbol_attempt::MaintenanceFile& journal() { return installed ? production.journal : isolated.journal; }
  arbol_attempt::MaintenanceFile& hostPolicy() { return installed ? production.hostPolicy : isolated.authority.hostPolicy; }
  arbol_attempt::MaintenanceFile& launcher() { return installed ? production.launcher : isolated.authority.launcher; }
  arbol_attempt::MaintenanceDirectory& runtime() { return installed ? installedRuntime : isolated.authority.runtime; }
  const arbol_attempt::MaintenanceSelectionSnapshot& selection() const { return installed ? production.selected : isolated.selected; }
  NSDictionary* journalObject() const { return installed ? production.journalObject : isolated.journalObject; }
  NSString* launcherDigest() const { return installed ? production.launcherDigest : isolated.authority.launcherDigest; }
  NSString* stateRoot() { return arbol_attempt::policyStateRoot(arbol_attempt::json(hostPolicy().content),layout()); }
  bool current() const { return installed ? production.current() && installedRuntime.current() : isolated.current(); }
  bool originalInterruption() const {
    using namespace arbol_attempt;
    if (!interruption || installed) return false;
    NSDictionary* producer=interruption[@"parent"];
    return arbol_boundary::clockMs()<[interruption[@"deadline"] doubleValue] &&
      [parent[@"pid"] intValue]==getppid() && currentProcess(parent) && currentProcess(interruptionWorker,true) &&
      [parent[@"parentStartId"] isEqual:producer[@"startId"]] && [parent[@"parentPidVersion"] isEqual:producer[@"pidVersion"]] &&
      qualificationProducer(producer) && qualificationInterruptionBinding(interruption,isolated) &&
      qualificationPipes(qualificationStopDescriptor,qualificationEventDescriptor,interruption);
  }
  // Used only by checked writer boundaries. A false return aborts the active
  // writer. Unarmed and nonmatching points leave its ordinary path unchanged.
  bool parkInterruption(NSString* point, NSDictionary* witness, double writerDeadline,
                       const std::function<bool()>& writerCurrent) {
    using namespace arbol_attempt;
    if (!interruption || ![interruption[@"point"] isEqual:point]) return true;
    const double now=arbol_boundary::clockMs();
    const double deadline=std::min({now+5000,writerDeadline,[interruption[@"deadline"] doubleValue]});
    if (!accepted || !enabledQualificationEnginePoint(point) || !std::isfinite(writerDeadline) || deadline<=now ||
        interruptionConsumed.exchange(true) || !originalInterruption() || !writerCurrent() ||
        !keys(witness,@[@"attempt",@"transactionSha256",@"profileSha256",@"artifacts"]) ||
        !qualificationNonce(witness[@"attempt"]) || !qualificationDigest(witness[@"transactionSha256"]) ||
        (witness[@"profileSha256"]!=NSNull.null && !qualificationDigest(witness[@"profileSha256"])) ||
        ![witness[@"artifacts"] isKindOfClass:NSArray.class] || [witness[@"artifacts"] count]>8) return false;
    NSDictionary* actor=qualificationActor(interruptionWorker), *reference=journal().record();
    NSString* size=[NSString stringWithUTF8String:std::to_string(journal().identity.st_size).c_str()];
    NSDictionary* observed=@{@"kind":@"journal",@"identity":reference[@"identity"],@"size":size,@"sha256":reference[@"sha256"]};
    NSDictionary* notice=@{@"schema":@1,@"event":@"parked",@"requestSha256":interruption[@"requestSha256"],
      @"nonce":interruption[@"nonce"],@"point":point,@"actor":actor,@"journal":observed,@"attempt":witness[@"attempt"],
      @"transactionSha256":witness[@"transactionSha256"],@"profileSha256":witness[@"profileSha256"],@"artifacts":witness[@"artifacts"]};
    if (!writeQualificationEvent(qualificationEventDescriptor,notice,deadline)) return false;
    const std::string raw=readQualificationStop(qualificationStopDescriptor,deadline);
    NSDictionary* stop=qualificationObject(raw,1024); uint64_t schema=0;
    if (!keys(stop,@[@"schema",@"action",@"requestSha256",@"nonce",@"point"]) || !uintNumber(stop[@"schema"],schema) || schema!=1 ||
        ![stop[@"action"] isEqual:@"interrupt"] || ![stop[@"requestSha256"] isEqual:interruption[@"requestSha256"]] ||
        ![stop[@"nonce"] isEqual:interruption[@"nonce"]] || ![stop[@"point"] isEqual:point] ||
        !originalInterruption() || !writerCurrent() || arbol_boundary::clockMs()>=deadline) return false;
    NSDictionary* acknowledgement=@{@"schema":@1,@"event":@"stop-accepted",@"requestSha256":interruption[@"requestSha256"],
      @"nonce":interruption[@"nonce"],@"point":point,@"actor":actor,@"stopSha256":digest(raw)};
    if (!writeQualificationEvent(qualificationEventDescriptor,acknowledgement,deadline)) return false;
    (void)kill(getpid(),SIGKILL);
    return false;
  }
};
static MaintenanceCustody* maintenanceCustody = nullptr;
static bool qualificationFileAbsent(const std::string& path);
struct MaintenanceStateRoot {
  arbol_attempt::MaintenanceDirectory parent;
  int fd = -1; std::string path, leaf; struct stat identity{};
  bool captured = false, absent = false;
  bool current() const {
    auto* custody = maintenanceCustody; struct stat named{}, held{}; char actual[PATH_MAX]{};
    if (!captured || !custody || !custody->accepted || !custody->current() || !parent.current() ||
        [custody->parent[@"pid"] intValue] != getppid() || !arbol_attempt::currentProcess(custody->parent) ||
        ![custody->stateRoot() isEqual:[NSString stringWithUTF8String:path.c_str()]]) return false;
    errno = 0; int result = fstatat(parent.fd,leaf.c_str(),&named,AT_SYMLINK_NOFOLLOW);
    if (absent) return result < 0 && errno == ENOENT && fd < 0;
    return !result && fd >= 0 && !fstat(fd,&held) && !fcntl(fd,F_GETPATH,actual) && path == actual &&
      arbol_boundary::canonical(path) && S_ISDIR(named.st_mode) && S_ISDIR(held.st_mode) && named.st_uid == geteuid() &&
      named.st_dev == identity.st_dev && named.st_ino == identity.st_ino && named.st_mode == identity.st_mode &&
      named.st_dev == held.st_dev && named.st_ino == held.st_ino && named.st_mode == held.st_mode && held.st_uid == named.st_uid &&
      (named.st_mode & 07777) == 0700;
  }
  bool capture() {
    auto* custody = maintenanceCustody;
    if (captured) return current();
    if (!custody || !custody->accepted || !custody->current()) return false;
    NSString* state = custody->stateRoot(); if (!arbol_attempt::path(state)) return false;
    path = state.fileSystemRepresentation; leaf = state.lastPathComponent.UTF8String;
    if (!parent.openPath(state.stringByDeletingLastPathComponent.fileSystemRepresentation)) return false;
    errno = 0;
    if (fstatat(parent.fd,leaf.c_str(),&identity,AT_SYMLINK_NOFOLLOW)) {
      if (errno != ENOENT) return false; absent = true;
    } else {
      if (!S_ISDIR(identity.st_mode) || identity.st_uid != geteuid() || (identity.st_mode & 07777) != 0700) return false;
      fd = openat(parent.fd,leaf.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if (fd < 0) return false;
    }
    captured = true; return current();
  }
};
static MaintenanceStateRoot* maintenanceStateRoot = nullptr;
static bool maintenanceHandle(napi_env env, napi_callback_info info) {
  napi_value arg; void* raw = nullptr;
  return arbol_attempt::profileFormat == 2 && argument(env,info,&arg) &&
    napi_get_value_external(env,arg,&raw) == napi_ok && raw && raw == maintenanceCustody && maintenanceCustody->accepted;
}
static napi_value observeMaintenanceStateRoot(napi_env env, napi_callback_info info) {
  if (!maintenanceHandle(env,info)) return fail(env);
  @autoreleasepool { try { @try {
    if (!maintenanceStateRoot) maintenanceStateRoot = new MaintenanceStateRoot;
    auto* root = maintenanceStateRoot; auto* custody = maintenanceCustody;
    if (!root->capture()) return fail(env);
    NSDictionary* record = @{ @"path":[NSString stringWithUTF8String:root->path.c_str()],
      @"initial":root->absent ? @"absent" : @"present",
      @"identity":root->absent ? (id)NSNull.null : arbol_attempt::maintenanceIdentity(root->identity),
      @"parent":@{@"path":[NSString stringWithUTF8String:root->parent.path.c_str()],
        @"identity":arbol_attempt::maintenanceIdentity(root->parent.identity)},
      @"policySha256":arbol_attempt::digest(custody->hostPolicy().content),@"epoch":custody->epoch };
    return text(env,arbol_attempt::bytes(record));
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}
static napi_value assertMaintenanceStateRoot(napi_env env, napi_callback_info info) {
  if (!maintenanceHandle(env,info)) return fail(env);
  @autoreleasepool { try { @try {
    if (!maintenanceStateRoot || !maintenanceStateRoot->current()) return fail(env);
    napi_value result; if (napi_get_undefined(env,&result) != napi_ok) return fail(env); return result;
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}
static napi_value adoptMaintenanceCustody(napi_env env, napi_callback_info info) {
  if (arbol_attempt::profileFormat != 2 || maintenanceCustody) return fail(env);
  size_t count = 3; napi_value args[3]; std::string bundle, policy, runtime;
  if (napi_get_cb_info(env,info,&count,args,nullptr,nullptr) != napi_ok || count != 3 || !string(env,args[0],bundle)) return fail(env);
  arbol_attempt::PackagedLayout layout;
  if (!arbol_attempt::packagedLayout(bundle,layout)) return fail(env);
  if (layout.installed) {
    napi_valuetype policyType, runtimeType;
    if (napi_typeof(env,args[1],&policyType) != napi_ok || napi_typeof(env,args[2],&runtimeType) != napi_ok ||
        policyType != napi_null || runtimeType != napi_null) return fail(env);
  } else if (!string(env,args[1],policy) || !string(env,args[2],runtime)) return fail(env);
  maintenanceCustody = new MaintenanceCustody;
  auto* custody = maintenanceCustody; custody->installed = layout.installed;
  @autoreleasepool { try { @try {
    NSDictionary* packet = arbol_attempt::readMaintenanceCapsule(!custody->installed);
    const int parentPid = getppid();
    NSDictionary* parent = arbol_attempt::processRecord(parentPid);
    NSDictionary* self = arbol_attempt::processRecord(getpid());
    if (!packet || !parent || !self || parentPid <= 1 || ![packet[@"parent"] isEqual:parent] ||
        ![packet[@"bundle"] isEqual:[NSString stringWithUTF8String:bundle.c_str()]] ) return fail(env);
    NSDictionary* interruption=packet[@"qualification"];
    if (interruption && (!arbol_attempt::enabledQualificationEnginePoint(interruption[@"point"]) ||
        runtime!=std::string(arbol_attempt::qualificationFixture)+"/runtime" ||
        !arbol_attempt::qualificationPipes(arbol_attempt::qualificationStopDescriptor,arbol_attempt::qualificationEventDescriptor,interruption,true)))
      return fail(env);
    if (custody->installed) {
      NSString* home = arbol_attempt::physicalAccountHome();
      NSString* installedRuntime = [[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_ROOT] stringByAppendingPathComponent:@"runtime"];
      if (!home || !custody->production.admit([packet[@"deadline"] doubleValue],packet) ||
          !custody->installedRuntime.openPath(installedRuntime.fileSystemRepresentation)) return fail(env);
    } else if (!custody->isolated.admit(policy,runtime,bundle,[packet[@"deadline"] doubleValue],packet)) return fail(env);
    if (![parent[@"executable"] isEqual:[NSString stringWithUTF8String:custody->launcher().path.c_str()]] ||
        ![self[@"executable"] isEqual:[NSString stringWithUTF8String:custody->layout().engine.c_str()]] ||
        !arbol_boundary::signature(custody->layout().engine,true) ||
        getppid() != parentPid || !arbol_attempt::currentProcess(parent) || !arbol_attempt::currentProcess(self,true) ||
        !custody->current()) return fail(env);
    custody->parent = parent;
    if (interruption) {
      custody->interruption=interruption; custody->interruptionWorker=self;
      if (!custody->originalInterruption() || (arbol_attempt::qualificationTransactionStartPoint(interruption[@"point"]) &&
          !qualificationFileAbsent(custody->runtime().path+"/browser-profile-migration/current"))) return fail(env);
    }
    // Recovery re-adopts new process descriptions under the same durable
    // admission. Parent identity and deadline remain independently enforced;
    // the durable epoch binds exact journal bytes and original lock records.
    custody->epoch = arbol_attempt::digest(custody->journal().content + arbol_attempt::bytes(
      @{@"selectionLock":packet[@"selectionLock"],@"oldBuildLock":packet[@"oldBuildLock"],@"newBuildLock":packet[@"newBuildLock"]}));
    auto handleFor = [&](arbol_attempt::MaintenanceGuard& guard, HeldLock*& retained) -> napi_value {
      napi_value result;
      if (guard.lock.fd < 0) { if (napi_get_null(env,&result) != napi_ok) return nullptr; return result; }
      retained = new HeldLock{guard.lock.fd,guard.lock.path,dev_t(guard.lock.device),ino_t(guard.lock.inode),LOCK_EX,true};
      liveLocks.insert(retained);
      return napi_create_external(env,retained,finalize,nullptr,&result) == napi_ok ? result : nullptr;
    };
    napi_value handle, result, remaining;
    napi_value oldHandle = handleFor(custody->oldGuard(),custody->oldBuild);
    napi_value newHandle = handleFor(custody->newGuard(),custody->newBuild);
    const double duration = [packet[@"deadline"] doubleValue] - arbol_boundary::clockMs();
    if (!oldHandle || !newHandle || !std::isfinite(duration) || duration <= 0 || duration > 60000 ||
        napi_create_external(env,custody,nullptr,nullptr,&handle) != napi_ok ||
        napi_create_object(env,&result) != napi_ok || napi_create_double(env,duration,&remaining) != napi_ok) return fail(env);
    NSDictionary* selected = custody->selection().absent ? (id)NSNull.null :
      @{ @"identity":arbol_attempt::maintenanceIdentity(custody->selection().file),
         @"sha256":arbol_attempt::digest(custody->selection().bytes) };
    NSString* state = custody->stateRoot(); if (!state) return fail(env);
    NSDictionary* facts = @{ @"scope":custody->installed ? @"installed" : @"isolated",@"epoch":custody->epoch,
      @"bundle":[NSString stringWithUTF8String:bundle.c_str()],
      @"runtime":[NSString stringWithUTF8String:custody->runtime().path.c_str()],
      @"stateRoot":state,@"registry":[state stringByAppendingPathComponent:@"profiles"],
      @"runtimeIdentity":arbol_attempt::maintenanceIdentity(custody->runtime().identity),
      @"policySha256":arbol_attempt::digest(custody->installed ? custody->hostPolicy().content : custody->isolated.authority.policy.content),
      @"hostPolicySha256":arbol_attempt::digest(custody->hostPolicy().content),@"launcherSha256":custody->launcherDigest(),
      @"imageSha256":custody->journalObject()[@"after"][@"selection"][@"imageSha256"],
      @"journalPath":[NSString stringWithUTF8String:custody->journal().path.c_str()],
      @"journal":custody->journal().record(),@"selection":selected,
      @"oldBuildPath":custody->oldBuild ? (id)[NSString stringWithUTF8String:custody->oldBuild->path.c_str()] : NSNull.null,
      @"newBuildPath":[NSString stringWithUTF8String:custody->newBuild->path.c_str()] };
    if (!property(env,result,"handle",handle) || !property(env,result,"oldBuild",oldHandle) ||
        !property(env,result,"newBuild",newHandle) || !property(env,result,"remaining",remaining) ||
        !property(env,result,"facts",text(env,arbol_attempt::bytes(facts)))) return fail(env);
    custody->accepted = true;
    return result;
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}
static napi_value assertMaintenanceCustody(napi_env env, napi_callback_info info) {
  napi_value arg; void* raw = nullptr;
  if (arbol_attempt::profileFormat != 2 || !argument(env,info,&arg) ||
      napi_get_value_external(env,arg,&raw) != napi_ok || !raw || raw != maintenanceCustody ||
      !maintenanceCustody->accepted) return fail(env);
  @autoreleasepool { try { @try {
    if (!maintenanceCustody->current() ||
        [maintenanceCustody->parent[@"pid"] intValue] != getppid() ||
        !arbol_attempt::currentProcess(maintenanceCustody->parent)) return fail(env);
    napi_value result; if (napi_get_undefined(env,&result) != napi_ok) return fail(env); return result;
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}

static napi_value maintenanceInterruptionMatches(napi_env env, napi_callback_info info) {
  napi_value args[2], out; size_t count=2; void* raw=nullptr; std::string point;
  if (napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok || count!=2 ||
      napi_get_value_external(env,args[0],&raw)!=napi_ok || !raw || raw!=maintenanceCustody || !maintenanceCustody->accepted ||
      !boundedText(env,args[1],point) || point.size()>48) return fail(env);
  @autoreleasepool { @try {
    NSString* name=[NSString stringWithUTF8String:point.c_str()];
    if (!arbol_attempt::qualificationEnginePoint(name)) return fail(env);
    const bool matches=maintenanceCustody->interruption && [maintenanceCustody->interruption[@"point"] isEqual:name];
    if ((matches && !maintenanceCustody->originalInterruption()) || napi_get_boolean(env,matches,&out)!=napi_ok) return fail(env);
    return out;
  } @catch(NSException*) { return fail(env); } }
}

static constexpr off_t qualificationTransactionLimit=4096LL*(4*87384+8192)+65536;
static constexpr const char* qualificationMercury="/Volumes/Mercury";
static constexpr const char* qualificationMercuryArchive="/Volumes/Mercury/Arbol/backups/browser-profile-format-2/";

static NSDictionary* qualificationFileReference(const arbol_attempt::MaintenanceFile& file, NSString* sha256) {
  return @{@"identity":arbol_attempt::maintenanceIdentity(file.identity),@"sha256":sha256};
}
static NSDictionary* qualificationArtifact(NSString* kind,const arbol_attempt::MaintenanceFile& file,NSString* sha256) {
  return @{@"kind":kind,@"identity":arbol_attempt::maintenanceIdentity(file.identity),@"sha256":sha256,
    @"size":[NSString stringWithUTF8String:std::to_string(file.identity.st_size).c_str()]};
}
static bool qualificationFileAbsent(const std::string& path) {
  std::string resolved; struct stat named{};
  return arbol_attempt::physicalFuturePath(path,resolved) && resolved==path && lstat(path.c_str(),&named)<0 && errno==ENOENT;
}
static bool qualificationMercuryFile(const arbol_attempt::MaintenanceFile& file) {
  struct statfs held{},named{};
  if (!file.current() || fstatfs(file.fd,&held) || statfs(qualificationMercury,&named) ||
      strcmp(held.f_mntonname,qualificationMercury) || strcmp(named.f_mntonname,qualificationMercury) ||
      memcmp(&held.f_fsid,&named.f_fsid,sizeof(held.f_fsid))) return false;
  struct attrlist attrs{}; attrs.bitmapcount=ATTR_BIT_MAP_COUNT; attrs.volattr=ATTR_VOL_INFO|ATTR_VOL_UUID;
  struct { uint32_t length; unsigned char uuid[16]; } reply{};
  if (fgetattrlist(file.fd,&attrs,&reply,sizeof(reply),0) || reply.length!=sizeof(reply)) return false;
  NSUUID* volume=[[NSUUID alloc] initWithUUIDBytes:reply.uuid];
  return [volume.UUIDString isEqual:@"AE1E97B8-CE93-4019-B6DC-21482165C3F2"] && file.current();
}
static bool openQualificationFile(arbol_attempt::MaintenanceFile& file,const std::string& path,NSDictionary* expected,
                                  off_t maximum,double deadline, bool readBytes=false) {
  using namespace arbol_attempt;
  return arbol_exit::migrationFile(expected) && qualificationDigest(expected[@"sha256"]) &&
    file.openPath(path,0600,maximum,readBytes) && [maintenanceIdentity(file.identity) isEqual:expected[@"identity"]] &&
    [file.sha256(deadline) isEqual:expected[@"sha256"]];
}
static bool qualificationPointer(const arbol_attempt::MaintenanceFile& file,NSString* attempt,NSString* transactionSha256) {
  using namespace arbol_attempt;
  NSDictionary* value=qualificationObject(file.content,limit); uint64_t format=0;
  return keys(value,@[@"format",@"attempt",@"transactionSha256"]) && uintNumber(value[@"format"],format) && format==1 &&
    [value[@"attempt"] isEqual:attempt] && [value[@"transactionSha256"] isEqual:transactionSha256];
}

static bool qualificationGuard(HeldLock* handle,const std::string& path) {
  if (!handle || !liveLocks.count(handle) || handle->mode!=LOCK_EX || handle->path!=path) return false;
  const arbol_boundary::Lock lock{handle->fd,path,uint64_t(handle->dev),handle->ino,geteuid(),0600,LOCK_EX};
  return arbol_boundary::lockIdentity(lock);
}
static bool qualificationDirectoryUnchanged(const arbol_attempt::MaintenanceDirectory& directory,const struct stat& before) {
  struct stat after{};
  return directory.current() && !fstat(directory.fd,&after) &&
    before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec &&
    before.st_ctimespec.tv_sec==after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec==after.st_ctimespec.tv_nsec;
}
static bool qualificationDirectoryNames(const arbol_attempt::MaintenanceDirectory& held,const std::set<std::string>& names) {
  struct stat before{};
  if (!held.current() || fstat(held.fd,&before)) return false;
  const int fd=openat(held.fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if (fd<0) return false;
  DIR* directory=fdopendir(fd);
  if (!directory) { close(fd); return false; }
  std::set<std::string> seen; bool valid=true;
  for (;;) {
    errno=0; const auto* entry=readdir(directory);
    if (!entry) { valid=valid&&!errno; break; }
    const std::string name=entry->d_name;
    if (name=="." || name=="..") continue;
    if (!names.count(name) || !seen.insert(name).second) { valid=false; break; }
  }
  return !closedir(directory) && valid && seen==names && qualificationDirectoryUnchanged(held,before);
}
static bool qualificationTransactionGuards(const MaintenanceCustody& custody) {
  const auto* state=maintenanceStateRoot;
  if (!state || !state->current()) return false;
  if (state->absent) return !custody.interruptionProfiles && !custody.interruptionRegistry && custody.interruptionOwners.empty();
  if (!custody.interruptionProfiles || !custody.interruptionProfiles->current() ||
      !qualificationGuard(custody.interruptionRegistry,state->path+"/registry.lock")) return false;
  for (auto* owner:custody.interruptionOwners) {
    if (!liveLocks.count(owner) || !qualificationGuard(owner,owner->path)) return false;
  }
  return qualificationDirectoryNames(*custody.interruptionProfiles,custody.interruptionProfileNames);
}
static bool qualificationTransactionArchive(const MaintenanceCustody& custody,NSString* attempt,NSString* sha256) {
  return custody.interruptionArchive && [attempt isEqual:custody.interruptionAttempt] &&
    [sha256 isEqual:custody.interruptionArchiveDigest] && qualificationMercuryFile(*custody.interruptionArchive);
}
static bool qualificationGuardIdentity(HeldLock* guard,NSDictionary* expected) {
  struct stat held{};
  return liveLocks.count(guard) && !fstat(guard->fd,&held) &&
    [arbol_attempt::maintenanceIdentity(held) isEqual:expected];
}
static bool prepareQualificationStaging(MaintenanceCustody& custody,const arbol_attempt::MaintenanceFile& file) {
  using namespace arbol_attempt;
  auto& writer=custody.stagingWriter;
  NSString* point=custody.interruption[@"point"];
  NSDictionary* transaction=arbol_exit::strictManagementObject(file.content,qualificationTransactionLimit);
  NSDictionary* root=transaction[@"root"];
  if (writer.entry || !arbol_exit::migrationTransaction(transaction) || !maintenanceStateRoot || maintenanceStateRoot->absent ||
      !custody.interruptionProfiles || ![transaction[@"attempt"] isEqual:custody.interruptionAttempt] ||
      ![transaction[@"epoch"] isEqual:custody.epoch] || ![transaction[@"journal"] isEqual:custody.journal().record()] ||
      ![transaction[@"runtime"] isEqual:maintenanceIdentity(custody.runtime().identity)] ||
      ![root[@"path"] isEqual:custody.stateRoot()] || ![root[@"identity"] isEqual:maintenanceIdentity(maintenanceStateRoot->identity)] ||
      ![root[@"profiles"] isEqual:maintenanceIdentity(custody.interruptionProfiles->identity)] ||
      !qualificationGuardIdentity(custody.interruptionRegistry,root[@"registry"])) return false;
  const bool requiresMarker=[@[@"staged-marker",@"marker-rename",@"marker-durable"] containsObject:point];
  NSDictionary* selected=nil;
  for (NSDictionary* entry in transaction[@"profiles"]) {
    if (!requiresMarker || entry[@"targetMarker"]!=NSNull.null) { selected=entry; break; }
  }
  if (!selected) return false;
  const std::string profile=custody.interruptionProfiles->path+"/"+[selected[@"id"] UTF8String];
  if (![digest(profile) isEqual:selected[@"pathSha256"]]) return false;
  const auto owner=std::find_if(custody.interruptionOwners.begin(),custody.interruptionOwners.end(),[&](HeldLock* handle){
    return qualificationGuard(handle,profile+"/owner.lock");
  });
  if (owner==custody.interruptionOwners.end() || !qualificationGuardIdentity(*owner,selected[@"ownerLock"])) return false;
  const std::string hash=[selected[@"pathSha256"] UTF8String], attempt=custody.interruptionAttempt.UTF8String;
  const std::string progress=custody.runtime().path+"/browser-profile-migration/"+attempt+"/progress";
  if (!writer.progressDirectory.openPath(progress) || writer.progressDirectory.identity.st_dev!=file.identity.st_dev) return false;
  writer.entry=selected; writer.profile=profile;
  writer.staging=maintenanceStateRoot->path+"/migration-staged/"+attempt+"/"+hash;
  writer.progress=progress+"/"+hash;
  return true;
}
static bool prepareQualificationProgress(MaintenanceCustody& custody,const arbol_attempt::MaintenanceFile& file) {
  using namespace arbol_attempt;
  auto& writer=custody.progressWriter;
  NSDictionary* transaction=arbol_exit::strictManagementObject(file.content,qualificationTransactionLimit);
  NSDictionary* root=transaction[@"root"];
  if (writer.profiles || !maintenanceStateRoot || !arbol_exit::migrationTransaction(transaction) ||
      ![transaction[@"attempt"] isEqual:custody.interruptionAttempt] ||
      ![transaction[@"epoch"] isEqual:custody.epoch] || ![transaction[@"journal"] isEqual:custody.journal().record()] ||
      ![transaction[@"runtime"] isEqual:maintenanceIdentity(custody.runtime().identity)] ||
      ![root[@"path"] isEqual:custody.stateRoot()]) return false;
  if (maintenanceStateRoot->absent) {
    if (![root[@"initial"] isEqual:@"absent"]) return false;
  } else if (!custody.interruptionProfiles ||
      ![root[@"identity"] isEqual:maintenanceIdentity(maintenanceStateRoot->identity)] ||
      ![root[@"profiles"] isEqual:maintenanceIdentity(custody.interruptionProfiles->identity)] ||
      !qualificationGuardIdentity(custody.interruptionRegistry,root[@"registry"])) return false;
  NSMutableArray* profiles=[NSMutableArray new];
  for (NSDictionary* profile in transaction[@"profiles"]) {
    NSString* hash=profile[@"pathSha256"];
    [profiles addObject:hash];
    writer.byHash.try_emplace(hash.UTF8String);
  }
  if (!profiles.count && [custody.interruption[@"point"] isEqual:@"committed-progress"]) return false;
  writer.profiles=[profiles copy];
  return true;
}
static NSDictionary* qualificationCompletion(const MaintenanceCustody& custody) {
  const auto& writer=custody.progressWriter;
  if (!writer.profiles) return nil;
  NSMutableArray* entries=[NSMutableArray new];
  for (NSString* hash in writer.profiles) {
    const auto& profile=writer.byHash.at(hash.UTF8String);
    if (!profile.proof || !profile.committed) return nil;
    [entries addObject:@{@"profileSha256":hash,@"receiptSha256":profile.proof->receipt[@"sha256"]}];
  }
  return @{@"format":@1,@"attempt":custody.publishedTransactionAttempt,
    @"transactionSha256":custody.publishedTransaction[@"sha256"],@"profiles":entries};
}

static napi_value bindMaintenanceTransaction(napi_env env,napi_callback_info info) {
  napi_value args[5],out; size_t count=5; void* raw=nullptr; std::string encoded; double deadline=0;
  if (napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok || count!=5 ||
      napi_get_value_external(env,args[0],&raw)!=napi_ok || !raw || raw!=maintenanceCustody || !maintenanceCustody->accepted ||
      !boundedText(env,args[1],encoded) || napi_get_value_double(env,args[4],&deadline)!=napi_ok || !std::isfinite(deadline) ||
      deadline<=arbol_boundary::clockMs() || deadline>arbol_boundary::clockMs()+10000) return fail(env);
  @autoreleasepool { try { @try {
    using namespace arbol_attempt;
    auto& custody=*maintenanceCustody;
    auto* state=maintenanceStateRoot;
    if (!qualificationTransactionStartPoint(custody.interruption[@"point"]) || custody.interruptionArchive ||
        !custody.originalInterruption() || !state || !state->current() ||
        !qualificationFileAbsent(custody.runtime().path+"/browser-profile-migration/current")) return fail(env);
    NSDictionary* witness=arbol_exit::strictManagementObject(encoded);
    if (!keys(witness,@[@"attempt",@"archive"]) || !qualificationNonce(witness[@"attempt"])) return fail(env);
    NSString* attempt=witness[@"attempt"];
    bool array=false; uint32_t size=0;
    if (napi_is_array(env,args[3],&array)!=napi_ok || !array || napi_get_array_length(env,args[3],&size)!=napi_ok || size>4096)
      return fail(env);
    if (state->absent) {
      napi_valuetype registryType;
      if (size || napi_typeof(env,args[2],&registryType)!=napi_ok || registryType!=napi_null) return fail(env);
    } else {
      void* handle=nullptr;
      if (napi_get_value_external(env,args[2],&handle)!=napi_ok ||
          !qualificationGuard(static_cast<HeldLock*>(handle),state->path+"/registry.lock")) return fail(env);
      custody.interruptionRegistry=static_cast<HeldLock*>(handle);
      const std::string profiles=state->path+"/profiles", prefix=profiles+"/", suffix="/owner.lock";
      custody.interruptionProfiles=std::make_unique<MaintenanceDirectory>();
      if (!custody.interruptionProfiles->openPath(profiles) || custody.interruptionProfiles->identity.st_dev!=state->identity.st_dev)
        return fail(env);
      for (uint32_t i=0;i<size;++i) {
        napi_value element;
        if (napi_get_element(env,args[3],i,&element)!=napi_ok || napi_get_value_external(env,element,&handle)!=napi_ok) return fail(env);
        auto* owner=static_cast<HeldLock*>(handle);
        if (!liveLocks.count(owner) || owner->path.size()<=prefix.size()+suffix.size() ||
            owner->path.compare(0,prefix.size(),prefix) || owner->path.compare(owner->path.size()-suffix.size(),suffix.size(),suffix))
          return fail(env);
        const std::string profile=owner->path.substr(prefix.size(),owner->path.size()-prefix.size()-suffix.size());
        if (!pattern([NSString stringWithUTF8String:profile.c_str()],@"\\A[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?\\z") ||
            !custody.interruptionProfileNames.insert(profile).second || !qualificationGuard(owner,prefix+profile+suffix)) return fail(env);
        custody.interruptionOwners.push_back(owner);
      }
    }
    auto archive=std::make_unique<MaintenanceFile>();
    const std::string path=std::string(qualificationMercuryArchive)+attempt.UTF8String+"/transaction.json";
    if (!openQualificationFile(*archive,path,witness[@"archive"],qualificationTransactionLimit,deadline) ||
        !qualificationMercuryFile(*archive) || !qualificationTransactionGuards(custody) ||
        !custody.originalInterruption() || arbol_boundary::clockMs()>=deadline) return fail(env);
    custody.interruptionAttempt=attempt; custody.interruptionArchiveDigest=witness[@"archive"][@"sha256"];
    custody.interruptionArchive=std::move(archive);
    return napi_get_undefined(env,&out)==napi_ok ? out : fail(env);
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}

// Branded JS preflight holds the registry and original owners throughout this
// synchronous call. Only a matching adopted interruption can reach the pipe.
// Recover every observable reference independently from its fixed writer path.
static napi_value parkMaintenanceTransaction(napi_env env,napi_callback_info info) {
  napi_value args[4]; size_t count=4; void* raw=nullptr;
  std::string point,encoded; double deadline=0;
  if (napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok || count!=4 ||
      napi_get_value_external(env,args[0],&raw)!=napi_ok || !raw || raw!=maintenanceCustody || !maintenanceCustody->accepted ||
      !boundedText(env,args[1],point,48) || !boundedText(env,args[2],encoded) ||
      napi_get_value_double(env,args[3],&deadline)!=napi_ok || !std::isfinite(deadline) ||
      deadline<=arbol_boundary::clockMs() || deadline>arbol_boundary::clockMs()+10000) return fail(env);
  @autoreleasepool { try { @try {
    using namespace arbol_attempt;
    const bool archive=point=="before-transaction", afterTransaction=point=="transaction-publication", afterCurrent=point=="current-publication";
    if (!archive&&!afterTransaction&&!afterCurrent) return fail(env);
    NSString* name=[NSString stringWithUTF8String:point.c_str()];
    auto& custody=*maintenanceCustody;
    if (![custody.interruption[@"point"] isEqual:name] || !custody.originalInterruption()) return fail(env);
    NSDictionary* request=arbol_exit::strictManagementObject(encoded);
    if (!keys(request,@[@"attempt",@"transaction",@"current"]) || !qualificationNonce(request[@"attempt"]) ||
        (!afterCurrent && request[@"current"]!=NSNull.null)) return fail(env);
    NSString* attempt=request[@"attempt"];
    NSDictionary* original=request[@"transaction"], *current=request[@"current"];
    if (!arbol_exit::migrationFile(original) || !qualificationTransactionArchive(custody,attempt,original[@"sha256"]) ||
        !qualificationTransactionGuards(custody) || ![custody.interruptionArchive->sha256(deadline) isEqual:original[@"sha256"]]) return fail(env);
    const std::string root=custody.runtime().path+"/browser-profile-migration", currentPath=root+"/current";
    const std::string localPath=root+"/"+attempt.UTF8String+"/transaction.json";
    if (archive ? bool(custody.publishedTransaction) :
        (![attempt isEqual:custody.publishedTransactionAttempt] || ![original isEqual:custody.publishedTransaction])) return fail(env);
    if (afterCurrent ? ![current isEqual:custody.publishedCurrent] : bool(custody.publishedCurrent)) return fail(env);
    MaintenanceFile local,pointer;
    const MaintenanceFile& transaction=archive ? *custody.interruptionArchive : local;
    if ((archive ? ![qualificationFileReference(transaction,original[@"sha256"]) isEqual:original] :
         !openQualificationFile(local,localPath,original,qualificationTransactionLimit,deadline)) ||
        (afterCurrent && (!openQualificationFile(pointer,currentPath,current,limit,deadline,true) ||
         !qualificationPointer(pointer,attempt,original[@"sha256"])))) return fail(env);
    const auto writerCurrent=[&] {
      return transaction.current() && (afterCurrent ? pointer.current() : qualificationFileAbsent(currentPath)) &&
        qualificationTransactionArchive(custody,attempt,original[@"sha256"]) && qualificationTransactionGuards(custody) &&
        (!archive || qualificationFileAbsent(localPath));
    };
    NSArray* artifacts=@[qualificationArtifact(archive?@"mercury-transaction":@"transaction",transaction,original[@"sha256"])];
    if (afterCurrent) artifacts=[artifacts arrayByAddingObject:qualificationArtifact(@"current",pointer,current[@"sha256"])];
    NSDictionary* witness=@{@"attempt":attempt,@"transactionSha256":original[@"sha256"],@"profileSha256":NSNull.null,@"artifacts":artifacts};
    custody.parkInterruption(name,witness,deadline,writerCurrent);
    return fail(env);
  } @catch(NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}

static napi_value parkMaintenanceStaging(napi_env env,napi_callback_info info) {
  napi_value args[4]; size_t count=4; void* raw=nullptr; std::string point,encoded; double deadline=0;
  if (napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok || count!=4 ||
      napi_get_value_external(env,args[0],&raw)!=napi_ok || !raw || raw!=maintenanceCustody || !maintenanceCustody->accepted ||
      !boundedText(env,args[1],point,48) || !boundedText(env,args[2],encoded) ||
      napi_get_value_double(env,args[3],&deadline)!=napi_ok || !std::isfinite(deadline) ||
      deadline<=arbol_boundary::clockMs() || deadline>arbol_boundary::clockMs()+10000) return fail(env);
  @autoreleasepool { try { @try {
    using namespace arbol_attempt;
    auto& custody=*maintenanceCustody;
    const auto& writer=custody.stagingWriter;
    NSString* name=[NSString stringWithUTF8String:point.c_str()];
    if (!qualificationStagingPoint(name) || ![custody.interruption[@"point"] isEqual:name] || !writer.entry ||
        !custody.originalInterruption()) return fail(env);
    const bool scratch=point=="empty-staging" || point=="partial-staging";
    const bool renamed=point=="marker-rename" || point=="marker-durable";
    const bool progress=renamed || point=="staged-progress";
    const bool hasMarker=writer.entry[@"targetMarker"]!=NSNull.null;
    const bool targetMarker=(progress && hasMarker) || point=="staged-marker";
    NSDictionary* request=arbol_exit::strictManagementObject(encoded);
    NSString* attempt=request[@"attempt"], *hash=request[@"profileSha256"];
    NSString* transactionHash=custody.publishedTransaction[@"sha256"];
    if (!keys(request,@[@"attempt",@"profileSha256",@"staging",@"scratch"]) || ![attempt isEqual:custody.publishedTransactionAttempt] ||
        ![hash isEqual:writer.entry[@"pathSha256"]] || !qualificationTransactionArchive(custody,attempt,transactionHash) ||
        !qualificationTransactionGuards(custody) || (!scratch && request[@"scratch"]!=NSNull.null) ||
        !arbol_exit::migrationIdentity(request[@"staging"],0700) ||
        !custody.publishedCurrentParent || !custody.publishedTransactionParent ||
        (targetMarker && !hasMarker) || (renamed && !hasMarker)) return fail(env);
    const std::string root=custody.runtime().path+"/browser-profile-migration", local=root+"/"+attempt.UTF8String;
    const std::string recordPath=writer.profile+"/profile.json", markerPath=writer.profile+"/engine.json";
    const std::string stagedRecordPath=writer.staging+"/profile.json", stagedMarkerPath=writer.staging+"/engine.json";
    const std::string stagedPath=writer.progress+".staged.json";
    MaintenanceDirectory runtime,attemptDirectory,profile,staging,data,userData;
    MaintenanceFile transaction,current,oldRecord,marker,stagedRecord,stagedMarker,stagedFile,temporary;
    struct stat stagingStamp{};
    const auto original=[&](MaintenanceFile& file,const std::string& path,NSDictionary* ref) {
      return openQualificationFile(file,path,@{@"identity":ref[@"identity"],@"sha256":ref[@"sha256"]},65536,deadline);
    };
    if (!runtime.openPath(root,custody.publishedCurrentParent) ||
        !attemptDirectory.openPath(local,custody.publishedTransactionParent) || !writer.progressDirectory.current() ||
        !openQualificationFile(transaction,local+"/transaction.json",custody.publishedTransaction,qualificationTransactionLimit,deadline) ||
        !openQualificationFile(current,root+"/current",custody.publishedCurrent,limit,deadline,true) ||
        !qualificationPointer(current,attempt,transactionHash) ||
        !profile.openPath(writer.profile,writer.entry[@"directory"]) || !staging.openPath(writer.staging,request[@"staging"]) ||
        staging.identity.st_dev!=profile.identity.st_dev || fstat(staging.fd,&stagingStamp) ||
        !data.openPath(writer.profile+"/data",writer.entry[@"dataDirectory"]) ||
        !userData.openPath(writer.profile+"/userData",writer.entry[@"userDataDirectory"]) ||
        !original(oldRecord,recordPath,writer.entry[@"originalRecord"])) return fail(env);
    std::set<std::string> files;
    NSMutableArray* artifacts=[NSMutableArray new];
    if (scratch) {
      NSDictionary* ref=request[@"scratch"];
      if (!keys(ref,@[@"name",@"identity"]) || !pattern(ref[@"name"],@"\\A\\.migration-[0-9a-f]{32}\\z") ||
          !arbol_exit::migrationIdentity(ref[@"identity"],0600) || writer.record || writer.marker || writer.staged) return fail(env);
      const std::string leaf=[ref[@"name"] UTF8String];
      NSData* bytes=[[NSData alloc] initWithBase64EncodedString:writer.entry[@"targetRecord"][@"base64"] options:0];
      if (bytes.length<2) return fail(env);
      const size_t length=point=="partial-staging" ? bytes.length/2 : 0;
      if (!temporary.openPath(writer.staging+"/"+leaf,0600,off_t(length),true,off_t(length)) ||
          ![maintenanceIdentity(temporary.identity) isEqual:ref[@"identity"]] ||
          temporary.content!=std::string(static_cast<const char*>(bytes.bytes),length)) return fail(env);
      files.insert(leaf);
      [artifacts addObject:qualificationArtifact(@"scratch",temporary,digest(temporary.content))];
    } else {
      if (![writer.record[@"sha256"] isEqual:writer.entry[@"targetRecord"][@"sha256"]] ||
          !openQualificationFile(stagedRecord,stagedRecordPath,writer.record,65536,deadline)) return fail(env);
      files.insert("profile.json");
      if (targetMarker) {
        MaintenanceFile& target=renamed ? marker : stagedMarker;
        if (![writer.marker[@"sha256"] isEqual:writer.entry[@"targetMarker"][@"sha256"]] ||
            !openQualificationFile(target,renamed ? markerPath : stagedMarkerPath,writer.marker,65536,deadline)) return fail(env);
        if (!renamed) files.insert("engine.json");
      }
      if (progress) {
        if (!openQualificationFile(stagedFile,stagedPath,writer.staged,limit,deadline,true)) return fail(env);
        NSDictionary* value=arbol_exit::strictManagementObject(stagedFile.content);
        NSDictionary* expected=@{@"format":@1,@"attempt":attempt,@"profileSha256":hash,@"record":writer.record,
          @"marker":targetMarker ? (id)writer.marker : NSNull.null};
        if (!arbol_exit::migrationFormat(value[@"format"],1) || ![value isEqual:expected]) return fail(env);
        [artifacts addObject:qualificationArtifact(@"staged-progress",stagedFile,writer.staged[@"sha256"])];
        if (renamed) [artifacts addObject:qualificationArtifact(@"marker",marker,writer.marker[@"sha256"])];
      } else if (point=="staged-record") {
        [artifacts addObject:qualificationArtifact(@"staged-record",stagedRecord,writer.record[@"sha256"])];
      } else {
        [artifacts addObject:qualificationArtifact(@"staged-marker",stagedMarker,writer.marker[@"sha256"])];
      }
    }
    if (hasMarker && !renamed && !original(marker,markerPath,writer.entry[@"originalMarker"])) return fail(env);
    const auto writerCurrent=[&] {
      return qualificationTransactionArchive(custody,attempt,transactionHash) && qualificationTransactionGuards(custody) &&
        runtime.current() && attemptDirectory.current() && writer.progressDirectory.current() &&
        current.current() && transaction.current() && profile.current() && data.current() && userData.current() &&
        oldRecord.current() && qualificationDirectoryNames(staging,files) &&
        (hasMarker ? marker.current() : qualificationFileAbsent(markerPath)) &&
        (scratch ? temporary.current() : stagedRecord.current()) &&
        (!targetMarker || renamed || stagedMarker.current()) &&
        (progress ? stagedFile.current() : qualificationFileAbsent(stagedPath)) &&
        qualificationFileAbsent(writer.progress+".committed.json") && qualificationFileAbsent(root+"/receipts/"+hash.UTF8String+".json") &&
        qualificationFileAbsent(local+"/completed.json") && qualificationDirectoryUnchanged(staging,stagingStamp);
    };
    NSDictionary* witness=@{@"attempt":attempt,@"transactionSha256":transactionHash,@"profileSha256":hash,@"artifacts":artifacts};
    custody.parkInterruption(name,witness,deadline,writerCurrent);
    return fail(env);
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}

static bool qualificationProgressCurrent(const QualificationProgressProfile& profile,
    const arbol_attempt::MaintenanceDirectory& progress,const arbol_attempt::MaintenanceDirectory& receipts,
    const std::string& hash) {
  using namespace arbol_attempt;
  if (!profile.proof || !profile.committed ||
      ![maintenanceIdentity(receipts.identity) isEqual:profile.proof->receiptsParent]) return false;
  struct stat named{};
  if (fstatat(progress.fd,(hash+".committed.json").c_str(),&named,AT_SYMLINK_NOFOLLOW) ||
      !sameFile(named,profile.committedStamp)) return false;
  for (const auto& [path, stamp]:profile.proof->files) {
    if (!arbol_boundary::canonical(path) || lstat(path.c_str(),&named) || !sameFile(stamp,named)) return false;
  }
  for (const auto& [path, stamp]:profile.proof->directories) {
    if (!arbol_boundary::canonical(path) || lstat(path.c_str(),&named) || !S_ISDIR(named.st_mode) ||
        named.st_dev!=stamp.st_dev || named.st_ino!=stamp.st_ino || named.st_uid!=stamp.st_uid || named.st_mode!=stamp.st_mode)
      return false;
  }
  for (const auto& [path, stamp]:profile.proof->unchangedDirectories) {
    MaintenanceDirectory directory;
    if (!directory.openPath(path,maintenanceIdentity(stamp)) || !qualificationDirectoryUnchanged(directory,stamp)) return false;
  }
  MaintenanceDirectory staging;
  return (profile.proof->absentMarker.empty() || qualificationFileAbsent(profile.proof->absentMarker)) &&
    staging.openPath(profile.proof->staging,maintenanceIdentity(profile.proof->stagingStamp)) &&
    qualificationDirectoryUnchanged(staging,profile.proof->stagingStamp);
}

static napi_value parkMaintenanceProgress(napi_env env,napi_callback_info info) {
  napi_value args[4]; size_t count=4; void* raw=nullptr; std::string point,encoded; double deadline=0;
  if (napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok || count!=4 ||
      napi_get_value_external(env,args[0],&raw)!=napi_ok || !raw || raw!=maintenanceCustody || !maintenanceCustody->accepted ||
      !boundedText(env,args[1],point,48) || !boundedText(env,args[2],encoded) ||
      napi_get_value_double(env,args[3],&deadline)!=napi_ok || !std::isfinite(deadline) ||
      deadline<=arbol_boundary::clockMs() || deadline>arbol_boundary::clockMs()+10000) return fail(env);
  @autoreleasepool { try { @try {
    using namespace arbol_attempt;
    auto& custody=*maintenanceCustody;
    auto& writer=custody.progressWriter;
    NSString* name=[NSString stringWithUTF8String:point.c_str()];
    NSDictionary* witness=arbol_exit::strictManagementObject(encoded);
    if (!qualificationProgressPoint(name) || ![custody.interruption[@"point"] isEqual:name] ||
        !custody.originalInterruption() || !writer.profiles || !keys(witness,@[@"attempt",@"profileSha256",@"file"]) ||
        !custody.publishedCurrentParent || !custody.publishedTransactionParent || !custody.publishedProgressParent) return fail(env);
    NSString* attempt=witness[@"attempt"], *transactionHash=custody.publishedTransaction[@"sha256"];
    id hash=witness[@"profileSha256"];
    const bool complete=point=="completion";
    if (![attempt isEqual:custody.publishedTransactionAttempt] || !qualificationTransactionArchive(custody,attempt,transactionHash) ||
        !qualificationTransactionGuards(custody) ||
        (complete ? hash!=NSNull.null : !qualificationDigest(hash) || ![hash isEqual:writer.profiles.firstObject])) return fail(env);
    NSArray* profiles=complete ? writer.profiles : @[hash];
    const auto* profile=complete ? nullptr : &writer.byHash.at([hash UTF8String]);
    if (profile && !profile->proof) return fail(env);
    NSDictionary* expected=complete ? writer.completion : profile->committed;
    if (!expected || ![witness[@"file"] isEqual:expected]) return fail(env);
    const std::string rootPath=custody.runtime().path+"/browser-profile-migration", attemptPath=rootPath+"/"+attempt.UTF8String;
    const std::string completedPath=attemptPath+"/completed.json", receiptsPath=rootPath+"/receipts";
    const std::string stagingPath=std::string(custody.stateRoot().fileSystemRepresentation)+"/migration-staged/"+attempt.UTF8String;
    MaintenanceDirectory root,local,progress,receipts,staging;
    MaintenanceFile pointer,transaction,output,receipt;
    struct stat progressStamp{},receiptsStamp{},stagingStamp{};
    std::set<std::string> progressNames,receiptNames,stagingNames;
    if (!root.openPath(rootPath,custody.publishedCurrentParent) ||
        !local.openPath(attemptPath,custody.publishedTransactionParent) ||
        !progress.openPath(attemptPath+"/progress",custody.publishedProgressParent) ||
        fstat(progress.fd,&progressStamp) ||
        !openQualificationFile(pointer,rootPath+"/current",custody.publishedCurrent,limit,deadline,true) ||
        !qualificationPointer(pointer,attempt,transactionHash) ||
        !openQualificationFile(transaction,attemptPath+"/transaction.json",custody.publishedTransaction,qualificationTransactionLimit,deadline))
      return fail(env);
    if (profiles.count) {
      const auto& first=writer.byHash.at([profiles.firstObject UTF8String]);
      if (!first.proof || !receipts.openPath(receiptsPath,first.proof->receiptsParent) || fstat(receipts.fd,&receiptsStamp) ||
          !writer.stagingParent || !staging.openPath(stagingPath,writer.stagingParent) || fstat(staging.fd,&stagingStamp)) return fail(env);
      for (NSString* member in profiles) {
        const std::string leaf=member.UTF8String;
        progressNames.insert(leaf+".staged.json"); progressNames.insert(leaf+".committed.json");
        receiptNames.insert(leaf+".json");
        stagingNames.insert(leaf);
      }
    }
    if (complete) {
      if (!openQualificationFile(output,completedPath,expected,1048576,deadline,true) ||
          !sameFile(output.identity,writer.completionStamp) ||
          ![arbol_exit::strictManagementObject(output.content,1048576) isEqual:qualificationCompletion(custody)]) return fail(env);
    } else {
      const std::string leaf=[hash UTF8String];
      if (!openQualificationFile(output,progress.path+"/"+leaf+".committed.json",expected,limit,deadline) ||
          !sameFile(output.identity,profile->committedStamp) ||
          !openQualificationFile(receipt,receipts.path+"/"+leaf+".json",profile->proof->receipt,arbol_exit::exitReceiptLimit,deadline))
        return fail(env);
    }
    const auto current=[&] {
      if (!qualificationTransactionArchive(custody,attempt,transactionHash) || !qualificationTransactionGuards(custody) ||
          !root.current() || !local.current() || !progress.current() || !pointer.current() ||
          !transaction.current() || !output.current() ||
          (!complete && (!receipt.current() || !qualificationFileAbsent(completedPath)))) return false;
      if (!profiles.count) {
        return !writer.stagingParent && qualificationDirectoryNames(progress,{}) && qualificationFileAbsent(receiptsPath) &&
          qualificationFileAbsent(stagingPath) &&
          qualificationDirectoryUnchanged(progress,progressStamp);
      }
      if (!qualificationDirectoryNames(progress,progressNames) || !qualificationDirectoryNames(receipts,receiptNames) ||
          !qualificationDirectoryNames(staging,stagingNames)) return false;
      for (NSString* member in profiles) {
        if (arbol_boundary::clockMs()>=deadline ||
            !qualificationProgressCurrent(writer.byHash.at(member.UTF8String),progress,receipts,member.UTF8String)) return false;
      }
      return qualificationDirectoryUnchanged(receipts,receiptsStamp) &&
        qualificationDirectoryUnchanged(progress,progressStamp) &&
        qualificationDirectoryUnchanged(staging,stagingStamp) && output.current();
    };
    NSArray* artifacts=complete ? @[qualificationArtifact(@"completion",output,expected[@"sha256"])] :
      @[qualificationArtifact(@"receipt",receipt,profile->proof->receipt[@"sha256"]),
        qualificationArtifact(@"committed",output,expected[@"sha256"])];
    NSDictionary* frame=@{@"attempt":attempt,@"transactionSha256":transactionHash,@"profileSha256":hash,@"artifacts":artifacts};
    custody.parkInterruption(name,frame,deadline,current);
    return fail(env);
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}

// Management publication only; ordinary profile metadata and retained native
// receipts have their own, stronger publication/permit routes. A single-link
// inode moves atomically, including when this process dies during publication.
static napi_value publishMaintenanceFile(napi_env env,napi_callback_info info) {
  napi_value args[5]; size_t count=5; void* raw=nullptr; std::string source,destination,encoded; double deadline=0;
  if(arbol_attempt::profileFormat!=2||napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok||count!=5||
     napi_get_value_external(env,args[0],&raw)!=napi_ok||!raw||raw!=maintenanceCustody||!maintenanceCustody->accepted||
     !boundedText(env,args[1],source)||!boundedText(env,args[2],destination)||!boundedText(env,args[3],encoded)||
     napi_get_value_double(env,args[4],&deadline)!=napi_ok||!std::isfinite(deadline)||
     deadline<=arbol_boundary::clockMs()||deadline>arbol_boundary::clockMs()+10000) return fail(env);
  @autoreleasepool { try { @try {
    using namespace arbol_attempt;
    auto custody=[] { return maintenanceCustody&&maintenanceCustody->accepted&&maintenanceCustody->current()&&
      [maintenanceCustody->parent[@"pid"] intValue]==getppid()&&currentProcess(maintenanceCustody->parent); };
    const size_t a=source.rfind('/'),b=destination.rfind('/');
    if(a==std::string::npos||b==std::string::npos||a==0||source.substr(0,a)!=destination.substr(0,b)||source==destination)
      return fail(env);
    const std::string parentPath=source.substr(0,a),from=source.substr(a+1),to=destination.substr(b+1);
    const std::string runtimeRoot=maintenanceCustody->runtime().path+"/browser-profile-migration";
    NSString* point=maintenanceCustody->interruption[@"point"];
    const bool currentPointer=destination==runtimeRoot+"/current";
    const bool beforeTransaction=[point isEqual:@"before-transaction"], afterTransaction=[point isEqual:@"transaction-publication"];
    const bool afterCurrent=[point isEqual:@"current-publication"], beforePointerSync=[point isEqual:@"native-rename-excl"];
    const bool stagingControl=qualificationStagingPoint(point);
    const bool progressControl=qualificationProgressPoint(point);
    const bool nativeControl=qualificationNativePublicationPoint(point) || progressControl;
    NSString* transactionAttempt=nil;
    if (qualificationTransactionStartPoint(point) && to=="transaction.json" && within(parentPath,runtimeRoot)) {
      transactionAttempt=[NSString stringWithUTF8String:parentPath.c_str()+runtimeRoot.size()+1];
      if (!qualificationNonce(transactionAttempt) || beforeTransaction || maintenanceCustody->publishedTransaction) return fail(env);
    }
    if (currentPointer && (beforeTransaction || afterTransaction)) return fail(env);
    const bool trackPointer=currentPointer && (afterCurrent || beforePointerSync || stagingControl || nativeControl);
    auto& writer=maintenanceCustody->stagingWriter;
    const bool stageRecord=writer.entry && destination==writer.staging+"/profile.json";
    const bool stageMarker=writer.entry && destination==writer.staging+"/engine.json";
    const bool stageProgress=writer.entry && destination==writer.progress+".staged.json";
    NSString* state=maintenanceCustody->stateRoot(); if(!path(state)) return fail(env);
    const std::string stagingRoot=std::string(state.fileSystemRepresentation)+"/migration-staged";
    if((parentPath!=runtimeRoot&&!within(parentPath,runtimeRoot)&&!within(parentPath,stagingRoot))||
       !pattern([NSString stringWithUTF8String:from.c_str()],@"^\\.migration-[0-9a-f]{32}$")||
       to.empty()||to=="."||to==".."||!arbol_boundary::canonical(source)||!custody()) return fail(env);
    NSDictionary* expected=json(encoded);
    if(!keys(expected,@[@"parent",@"file"])||!keys(expected[@"file"],@[@"identity",@"sha256"])||
       !pattern(expected[@"file"][@"sha256"],@"^[0-9a-f]{64}$")) return fail(env);
    NSString* originalAttempt=maintenanceCustody->publishedTransactionAttempt;
    NSDictionary* originalTransaction=maintenanceCustody->publishedTransaction;
    const std::string originalPath=originalAttempt ? runtimeRoot+"/"+originalAttempt.UTF8String : std::string{};
    NSString* progressName=[NSString stringWithUTF8String:to.c_str()];
    const bool writeCommitted=progressControl && originalAttempt && parentPath==originalPath+"/progress" &&
      pattern(progressName,@"\\A[0-9a-f]{64}\\.committed\\.json\\z");
    const bool writeCompletion=progressControl && originalAttempt && parentPath==originalPath && to=="completed.json";
    const bool progressOutput=writeCommitted || writeCompletion;
    const off_t maximum=writeCompletion?1048576:(trackPointer||writeCommitted)?off_t(limit):1500000000;
    MaintenanceDirectory parent; MaintenanceFile file,transaction;
    if(!parent.openPath(parentPath,expected[@"parent"])||!file.openPath(source,0600,maximum,trackPointer || progressOutput)||
       file.identity.st_dev!=parent.identity.st_dev||
       ![maintenanceIdentity(file.identity) isEqual:expected[@"file"][@"identity"]]||
       ![file.sha256(deadline) isEqual:expected[@"file"][@"sha256"]]) return fail(env);
    const bool nativeProgress=nativeControl && parentPath==originalPath+"/progress" &&
      pattern(progressName,@"\\A[0-9a-f]{64}\\.staged\\.json\\z");
    const std::string nativeStageRoot=originalAttempt ? stagingRoot+"/"+originalAttempt.UTF8String : std::string{};
    NSString* nativeStageHash=nativeControl && originalAttempt && to=="profile.json" && within(parentPath,nativeStageRoot) ?
      [NSString stringWithUTF8String:parentPath.c_str()+nativeStageRoot.size()+1] : nil;
    const bool nativeRecord=qualificationDigest(nativeStageHash);
    if (trackPointer && (!qualificationNonce(originalAttempt) || !originalTransaction || maintenanceCustody->publishedCurrent ||
        !qualificationPointer(file,originalAttempt,originalTransaction[@"sha256"]) ||
        !openQualificationFile(transaction,originalPath+"/transaction.json",originalTransaction,
          qualificationTransactionLimit,deadline,stagingControl || progressControl))) return fail(env);
    MaintenanceDirectory transactionParent,progressParent;
    if (trackPointer && (stagingControl || nativeControl) && (!maintenanceCustody->publishedTransactionParent ||
        !transactionParent.openPath(originalPath,maintenanceCustody->publishedTransactionParent) ||
        (stagingControl && !prepareQualificationStaging(*maintenanceCustody,transaction)) ||
        (progressControl && !prepareQualificationProgress(*maintenanceCustody,transaction)) ||
        (nativeControl && !progressParent.openPath(originalPath+"/progress")))) return fail(env);
    if (nativeProgress && (!maintenanceCustody->nativeStagedPublications ||
        ![maintenanceIdentity(parent.identity) isEqual:maintenanceCustody->publishedProgressParent])) return fail(env);
    if (nativeRecord && (!maintenanceCustody->nativeStagingParents ||
        maintenanceCustody->nativeStagingParents[nativeStageHash])) return fail(env);
    auto& progressWriter=maintenanceCustody->progressWriter;
    MaintenanceDirectory stagingAttempt;
    if (nativeRecord && progressControl && !stagingAttempt.openPath(nativeStageRoot,progressWriter.stagingParent)) return fail(env);
    QualificationProgressProfile* committed=nullptr;
    if (writeCommitted) {
      NSString* hash=[progressName substringToIndex:64];
      auto found=progressWriter.byHash.find(hash.UTF8String);
      if (found==progressWriter.byHash.end() || !found->second.proof || found->second.committed ||
          ![maintenanceIdentity(parent.identity) isEqual:maintenanceCustody->publishedProgressParent] ||
          ([point isEqual:@"committed-progress"] && ![hash isEqual:progressWriter.profiles.firstObject])) return fail(env);
      committed=&found->second;
      NSDictionary* actual=arbol_exit::strictManagementObject(file.content);
      NSDictionary* expected=@{@"format":@1,@"attempt":originalAttempt,@"profileSha256":hash,@"receipt":committed->proof->receipt};
      if (!arbol_exit::migrationFormat(actual[@"format"],1) || ![actual isEqual:expected]) return fail(env);
    }
    if (writeCompletion) {
      NSDictionary* actual=arbol_exit::strictManagementObject(file.content,1048576);
      if (![point isEqual:@"completion"] || progressWriter.completion ||
          ![maintenanceIdentity(parent.identity) isEqual:maintenanceCustody->publishedTransactionParent] ||
          !arbol_exit::migrationFormat(actual[@"format"],1) || ![actual isEqual:qualificationCompletion(*maintenanceCustody)]) return fail(env);
    }
    const bool stageArtifact=stageRecord || stageMarker || stageProgress || nativeProgress || nativeRecord || progressOutput;
    NSString* attempt=(trackPointer || stageArtifact)?originalAttempt:transactionAttempt;
    NSString* transactionHash=(trackPointer || stageArtifact)?originalTransaction[@"sha256"]:expected[@"file"][@"sha256"];
    auto current=[&] {
      return custody()&&parent.current()&&file.current()&&(!trackPointer||transaction.current())&&
        (!(trackPointer && (stagingControl || nativeControl)) || transactionParent.current()) &&
        (!(trackPointer && nativeControl) || progressParent.current()) &&
        (stagingAttempt.fd<0 || stagingAttempt.current()) &&
        (!stageProgress || (writer.progressDirectory.current() &&
           [maintenanceIdentity(parent.identity) isEqual:maintenanceIdentity(writer.progressDirectory.identity)])) &&
        (!attempt || (qualificationTransactionArchive(*maintenanceCustody,attempt,transactionHash) &&
          qualificationTransactionGuards(*maintenanceCustody)))&&
        arbol_boundary::clockMs()<deadline;
    };
    if (trackPointer && beforePointerSync && (!current() ||
        ![maintenanceCustody->interruptionArchive->sha256(deadline) isEqual:transactionHash])) return fail(env);
    if(!current()||fsync(file.fd)||fcntl(file.fd,F_FULLFSYNC)||!current()||
       renameatx_np(parent.fd,from.c_str(),parent.fd,to.c_str(),RENAME_EXCL)) return fail(env);
    struct stat held{},named{},old{};
    if(fstat(file.fd,&held)||fstatat(parent.fd,to.c_str(),&named,AT_SYMLINK_NOFOLLOW)||!sameFile(held,named)) return fail(env);
    // Rename may change ctime, and only ctime. Rebase that observation only
    // after the same original inode and every other file property agree.
    struct stat renamedExpected=file.identity; renamedExpected.st_ctimespec=held.st_ctimespec;
    if(!sameFile(renamedExpected,held)||![maintenanceIdentity(held) isEqual:expected[@"file"][@"identity"]]) return fail(env);
    file.path=destination; file.identity=held;
    auto temporaryGone=[&] { errno=0; return fstatat(parent.fd,from.c_str(),&old,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT; };
    if (!temporaryGone()) return fail(env);
    if (currentPointer && beforePointerSync) {
      NSArray* artifacts=@[qualificationArtifact(@"transaction",transaction,originalTransaction[@"sha256"]),
        qualificationArtifact(@"current",file,expected[@"file"][@"sha256"])];
      NSDictionary* witness=@{@"attempt":originalAttempt,@"transactionSha256":originalTransaction[@"sha256"],
        @"profileSha256":NSNull.null,@"artifacts":artifacts};
      maintenanceCustody->parkInterruption(@"native-rename-excl",witness,deadline,[&]{return current()&&temporaryGone();});
      return fail(env);
    }
    if(!current()||![file.sha256(deadline) isEqual:expected[@"file"][@"sha256"]]||
       fsync(file.fd)||fcntl(file.fd,F_FULLFSYNC)||fsync(parent.fd)||!current()) return fail(env);
    if (transactionAttempt) {
      maintenanceCustody->publishedTransactionAttempt=transactionAttempt;
      maintenanceCustody->publishedTransaction=qualificationFileReference(file,expected[@"file"][@"sha256"]);
      maintenanceCustody->publishedTransactionParent=maintenanceIdentity(parent.identity);
    }
    if (trackPointer) {
      maintenanceCustody->publishedCurrent=qualificationFileReference(file,expected[@"file"][@"sha256"]);
      maintenanceCustody->publishedCurrentParent=maintenanceIdentity(parent.identity);
      if (nativeControl) {
        maintenanceCustody->publishedProgressParent=maintenanceIdentity(progressParent.identity);
        maintenanceCustody->nativeStagedPublications=[NSMutableDictionary new];
        maintenanceCustody->nativeStagingParents=[NSMutableDictionary new];
      }
    }
    if (stageRecord) writer.record=qualificationFileReference(file,expected[@"file"][@"sha256"]);
    if (stageMarker) writer.marker=qualificationFileReference(file,expected[@"file"][@"sha256"]);
    if (stageProgress) writer.staged=qualificationFileReference(file,expected[@"file"][@"sha256"]);
    if (nativeProgress)
      maintenanceCustody->nativeStagedPublications[progressName]=qualificationFileReference(file,expected[@"file"][@"sha256"]);
    if (nativeRecord) maintenanceCustody->nativeStagingParents[nativeStageHash]=maintenanceIdentity(parent.identity);
    if (stagingAttempt.fd>=0 && !progressWriter.stagingParent) progressWriter.stagingParent=maintenanceIdentity(stagingAttempt.identity);
    if (committed) {
      committed->committed=qualificationFileReference(file,expected[@"file"][@"sha256"]);
      committed->committedStamp=file.identity;
    }
    if (writeCompletion) {
      progressWriter.completion=qualificationFileReference(file,expected[@"file"][@"sha256"]);
      progressWriter.completionStamp=file.identity;
    }
    napi_value out; if(napi_get_undefined(env,&out)!=napi_ok) return fail(env); return out;
  } @catch(NSException*) { return fail(env); } } catch(...) { return fail(env); } }
}

static napi_value adoptInstalledLaunch(napi_env env, napi_callback_info info) {
  static bool attempted = false;
  if (attempted) return fail(env);
  attempted = true;
  napi_value arg;
  std::string bundle;
  if (!argument(env, info, &arg) || !string(env, arg, bundle)) return fail(env);
  @autoreleasepool { try { @try {
    arbol_attempt::PackagedLayout layout;
    if (!arbol_attempt::packagedLayout(bundle, layout) || !layout.installed || !arbol_boundary::canonical(bundle))
      return fail(env);
    constexpr int capsule = arbol_attempt::cliCapsuleDescriptor, fd = arbol_attempt::cliBuildDescriptor;
    struct stat before{}, after{}, guard{};
    if (fstat(capsule, &before) || !S_ISREG(before.st_mode) || before.st_uid != geteuid() || before.st_nlink ||
        (before.st_mode & 07777) != 0600 || before.st_size < 1 || before.st_size > (off_t)arbol_attempt::limit ||
        (fcntl(capsule, F_GETFL) & O_ACCMODE) != O_RDONLY || fcntl(capsule, F_SETFD, FD_CLOEXEC) ||
        fstat(fd, &guard) || (fcntl(fd, F_GETFL) & O_ACCMODE) != O_RDWR || fcntl(fd, F_SETFD, FD_CLOEXEC)) return fail(env);
    std::string raw(size_t(before.st_size), '\0');
    size_t offset = 0;
    while (offset < raw.size()) {
      ssize_t count = pread(capsule, raw.data() + offset, raw.size() - offset, off_t(offset));
      if (count > 0) offset += size_t(count);
      else if (count != -1 || errno != EINTR) return fail(env);
    }
    if (fstat(capsule, &after) || after.st_nlink || after.st_dev != before.st_dev || after.st_ino != before.st_ino ||
        after.st_mode != before.st_mode || after.st_size != before.st_size || after.st_uid != before.st_uid ||
        after.st_mtimespec.tv_sec != before.st_mtimespec.tv_sec || after.st_mtimespec.tv_nsec != before.st_mtimespec.tv_nsec ||
        after.st_ctimespec.tv_sec != before.st_ctimespec.tv_sec || after.st_ctimespec.tv_nsec != before.st_ctimespec.tv_nsec ||
        close(capsule)) return fail(env);
    NSDictionary* packet = arbol_attempt::json(raw);
    const int parentPid = getppid();
    NSDictionary* parent = arbol_attempt::processRecord(parentPid);
    const std::string launcher = arbol_attempt::stableLauncherPath(arbol_attempt::physicalAccountHome());
    NSDictionary* self = arbol_attempt::processRecord(getpid());
    if (!arbol_attempt::keys(packet, @[@"format", @"parent", @"deadline", @"guard", @"bundle"]) ||
        ![packet[@"format"] isEqual:@1] || ![packet[@"bundle"] isEqual:[NSString stringWithUTF8String:bundle.c_str()]] ||
        parentPid <= 1 || ![packet[@"parent"] isEqual:parent] ||
        ![parent[@"executable"] isEqual:[NSString stringWithUTF8String:launcher.c_str()]] ||
        ![self[@"executable"] isEqual:[NSString stringWithUTF8String:layout.engine.c_str()]] ||
        ![packet[@"deadline"] isKindOfClass:NSNumber.class] ||
        !arbol_attempt::signedIdentity(launcher, @"com.sylvan-stack.arbol-browser.launcher") ||
        ![parent isEqual:arbol_attempt::processRecord(parentPid)] || getppid() != parentPid) return fail(env);
    arbol_boundary::Lock original{fd,layout.guard,uint64_t(guard.st_dev),guard.st_ino,guard.st_uid,0600,LOCK_SH};
    if (!arbol_boundary::lockIdentity(original) || ![packet[@"guard"] isEqual:arbol_boundary::capsuleLock(original)] ||
        flock(fd, LOCK_SH | LOCK_NB) || !arbol_boundary::lockIdentity(original)) return fail(env);
    const double remaining = [packet[@"deadline"] doubleValue] - arbol_boundary::clockMs();
    if (!std::isfinite(remaining) || remaining <= 0 || remaining > 60000) return fail(env);
    auto* lock = new HeldLock{fd,layout.guard,guard.st_dev,guard.st_ino,LOCK_SH};
    napi_value handle, result, duration;
    if (napi_create_external(env, lock, finalize, nullptr, &handle) != napi_ok) {
      finalize(env, lock, nullptr); return fail(env);
    }
    liveLocks.insert(lock);
    if (napi_create_double(env, remaining, &duration) != napi_ok || napi_create_object(env, &result) != napi_ok ||
        !property(env, result, "lock", handle) || !property(env, result, "remaining", duration)) return fail(env);
    return result;
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
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
  arbol_boundary::Lock appStartup;
  arbol_boundary::ReadOnlyMonitorImage monitorImage;
  arbol_exit::HostCapability finalization;
  int reader=-1,writer=-1; bool endpointsPublished=false;
  RetainedPipe retainedReader,retainedWriter;
  MarkerPermit* mutation=nullptr; bool markerAttempted=false;
  SessionUseNative* sessionUse=nullptr; WebsiteSessionNative* websiteSession=nullptr; bool sessionAttempted=false,readyAttempted=false;
  std::string policyDigest,compatibilityDigest;
};
static std::set<Custody*> nativeCustodies;
static bool custodyAttempted = false;
static Custody* custodyArgument(napi_env env, napi_value value) {
  void* data = nullptr; if (napi_get_value_external(env,value,&data) != napi_ok) return nullptr;
  auto* c = static_cast<Custody*>(data); return nativeCustodies.count(c) ? c : nullptr;
}
// Observe only after the original irreversible fatal on the same genuine host.
static void observeNativeRefusal(Custody* c) noexcept {
  int saved=errno;
  @autoreleasepool { @try { try {
    unsigned line=firstRefusalLine.load(std::memory_order_relaxed);
    if(line&&c&&nativeCustodies.count(c)&&c->continuousBuild&&c->hostRequired&&c->finalization.present()&&
       c->finalization.shared()->fatal.load(std::memory_order_acquire)&&
       getpid()==c->context.main.pid&&arbol_boundary::current(c->context.main)==1&&
       arbol_boundary::lockIdentity(c->context.owner)&&arbol_boundary::lockIdentity(c->context.build)&&
       !refusalLineEmitted.exchange(true,std::memory_order_relaxed))
      os_log_with_type(OS_LOG_DEFAULT,OS_LOG_TYPE_DEFAULT,"arbol-browser native-refusal %{public}u",line);
  } catch(...) {} } @catch(NSException*) {} }
  errno=saved;
}
// Fixed local milestones only. Neither an observation failure nor a valid
// handle can acquire admission, a Claim, or change retained native state.
static const char* const hostStartupStages[]={"arm-readback","native-install-snapshot","native-feature-addon-preflight",
  "engine-authority","owned-lease-policy","engine-owner-policy","marker-read","existing-marker-compatibility",
  "fresh-marker-compatibility","verified-prior-exit","native-marker-permit",
  "watchdog-spawn-loss","watchdog-readiness-loss","watchdog-pipe-error","watchdog-pipe-end","watchdog-ack-malformed","watchdog-ack-order","watchdog-ack-expiry","watchdog-custody-refusal","watchdog-termination","watchdog-transport-loss","native_integrity_unavailable","native_retirement_unavailable","native_watchdog_unavailable","native_boundary_unavailable",
  "host-session-configure-before",
  "host-session-configure-after",
  "host-session-bind-before",
  "host-session-bind-after",
  "host-control-prepare-before",
  "host-control-prepare-after",
  "host-shell-port-before",
  "host-shell-port-after",
  "host-shell-integrate-before",
  "host-shell-integrate-after",
  "host-control-bind-before",
  "host-control-bind-after",
  "host-listeners-before",
  "host-listeners-after",
  "host-lifecycle-bind-before",
  "host-lifecycle-bind-after",
  "host-shell-load-before",
  "host-shell-load-after",
  "host-lifecycle-ready-before",
  "host-lifecycle-ready-after",
  "lifecycle-control-proof-before",
  "lifecycle-control-proof-after",
  "lifecycle-arm-before",
  "lifecycle-arm-after",
  "lifecycle-readiness-prepare-before",
  "lifecycle-readiness-prepare-after",
  "lifecycle-native-proof-before",
  "lifecycle-native-proof-after",
  "lifecycle-engine-proof-before",
  "lifecycle-engine-proof-after",
  "lifecycle-build-proof-before",
  "lifecycle-build-proof-after",
  "lifecycle-owner-proof-before",
  "lifecycle-owner-proof-after",
  "lifecycle-public-ready-before",
  "lifecycle-public-ready-after",
  "lifecycle-final-trust-before",
  "lifecycle-final-trust-after",
  "protected-ready-validate-before",
  "protected-ready-validate-after",
  "protected-claim-ready-before",
  "protected-claim-ready-after",
  "ready-trust-metadata-before",
  "ready-trust-metadata-after",
  "ready-trust-isolation-before",
  "ready-trust-isolation-after",
  "ready-trust-guard-before",
  "ready-trust-guard-after",
  "ready-trust-directories-before",
  "ready-trust-directories-after",
  "ready-trust-snapshot-before",
  "ready-trust-snapshot-after",
  "ready-trust-consume-before",
  "ready-trust-consume-after",
  "armed-trust-failure-bundle-selection",
  "armed-trust-failure-initial-snapshot",
  "armed-trust-failure-outer-signature-verification",
  "armed-trust-failure-outer-signature-details",
  "armed-trust-failure-outer-signature-entitlements",
  "armed-trust-failure-nested-signature-verification",
  "armed-trust-failure-nested-signature-details",
  "armed-trust-failure-nested-signature-entitlements",
  "armed-trust-failure-publisher",
  "armed-trust-failure-compatibility",
  "armed-trust-failure-inventory",
  "armed-trust-failure-final-snapshot",
  "armed-trust-failure-final-physical-comparison",
  "armed-trust-failure-repeated-snapshot",
  "armed-trust-failure-repeated-physical",
  "armed-trust-failure-repeated-manifest",
  "armed-trust-failure-repeated-cutoff",
  "armed-trust-failure-snapshot-receipt",
  "armed-trust-failure-verification-cutoff",
  "armed-trust-failure-snapshot-root-identity",
  "armed-trust-failure-snapshot-root-change-time",
  "armed-trust-failure-snapshot-entry-identity",
  "armed-trust-failure-snapshot-file-description",
  "armed-trust-failure-snapshot-file-read",
  "armed-trust-failure-storage-context",
  "armed-trust-failure-snapshot-symlink",
  "armed-trust-failure-snapshot-directory-membership",
  "armed-trust-failure-snapshot-encoded-mismatch",
  "armed-trust-failure-snapshot-filesystem"};
// New failure labels alone may observe a genuine pre-bind fatal context.
// Ordinary milestone guards below, including bound, remain unchanged.
static constexpr int hostLossStart=11;
static std::atomic<bool> hostLossEmitted{false};
static void observeHostLoss(Custody* c,int stage) noexcept {
  int saved=errno;
  @autoreleasepool { @try { try {
    if(stage>=hostLossStart&&stage<=24&&
       c&&nativeCustodies.count(c)&&c->continuousBuild&&c->hostRequired&&c->finalization.present()&&
       c->finalization.shared()->fatal.load(std::memory_order_acquire)&&
       getpid()==c->context.main.pid&&arbol_boundary::current(c->context.main)==1&&
       arbol_boundary::lockIdentity(c->context.owner)&&arbol_boundary::lockIdentity(c->context.build)&&
       !hostLossEmitted.exchange(true,std::memory_order_relaxed))
      os_log_with_type(OS_LOG_DEFAULT,OS_LOG_TYPE_DEFAULT,"arbol-browser retained-stage %{public}s",hostStartupStages[stage]);
  } catch(...) {} } @catch(NSException*) {} }
  errno=saved;
}
static void observeHostStartup(Custody* c,int stage) noexcept {
  if(stage>=hostLossStart&&stage<=24) { observeHostLoss(c,stage); return; }
  int saved=errno;
  @autoreleasepool { @try { try {
    if(c&&nativeCustodies.count(c)&&stage>=0&&stage<(int)(sizeof(hostStartupStages)/sizeof(hostStartupStages[0]))&&
       c->continuousBuild&&c->hostRequired&&c->bound&&c->finalization.present()&&
       getpid()==c->context.main.pid&&arbol_boundary::current(c->context.main)==1&&
       arbol_boundary::lockIdentity(c->context.owner)&&arbol_boundary::lockIdentity(c->context.build))
      os_log_with_type(OS_LOG_DEFAULT,OS_LOG_TYPE_DEFAULT,"arbol-browser retained-stage %{public}s",hostStartupStages[stage]);
  } catch(...) {} } @catch(NSException*) {} }
  errno=saved;
}
static napi_value noteHostStartup(napi_env env,napi_callback_info info) {
  napi_value args[2],out; size_t count=2; int stage;
  if(napi_get_cb_info(env,info,&count,args,nullptr,nullptr)==napi_ok&&count==2&&integer(env,args[1],&stage))
    observeHostStartup(custodyArgument(env,args[0]),stage);
  napi_get_undefined(env,&out); return out;
}
static arbol_boundary::Lock duplicateHeld(HeldLock* held) {
  struct stat st{}; if (!held || !liveLocks.count(held) || !matches(held,&st)) return {};
  int fd = fcntl(held->fd,F_DUPFD_CLOEXEC,10); if (fd < 0) return {};
  return {fd,held->path,(uint64_t)st.st_dev,st.st_ino,st.st_uid,0600,held->mode};
}
static napi_value browserAppAvailable(napi_env env, napi_callback_info) {
  arbol_boundary::Identity app;
  auto admission=arbol_boundary::appAdmission(app);
  const bool ready=admission.fd>=0 && !close(admission.fd);
  napi_value out; if(napi_get_boolean(env,ready,&out)!=napi_ok) return fail(env);
  return out;
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
  arbol_attempt::PackagedLayout layout;
  const bool installed=arbol_attempt::packagedLayout(bundle,layout)&&layout.installed;
  if(installed) c->appStartup=arbol_boundary::appAdmission(c->context.app);
  c->context.session=getsid(0);
  bool valid=(!installed||c->appStartup.fd>=0) && arbol_boundary::observe(getpid(),c->context.main)==1 && c->context.initial();
  if(valid) { c->capsule=arbol_boundary::capsuleDescriptor(arbol_boundary::capsuleBytes(c->context,true)); valid=c->capsule>=0; }
  if (!valid) { if(c->appStartup.fd>=0) close(c->appStartup.fd); if(c->context.owner.fd>=0) close(c->context.owner.fd); if(c->context.build.fd>=0) close(c->context.build.fd); delete c; return fail(env); }
  nativeCustodies.insert(c); napi_value out;
  if(napi_create_external(env,c,nullptr,nullptr,&out)!=napi_ok) return fail(env); return out;
}
static napi_value custodyDescriptors(napi_env env,napi_callback_info info) {
  napi_value arg; if(!argument(env,info,&arg)) return fail(env); auto* c=custodyArgument(env,arg); if(!c) return fail(env);
  napi_value out; if(napi_create_array_with_length(env,3,&out)!=napi_ok || napi_set_element(env,out,0,number(env,c->context.owner.fd))!=napi_ok || napi_set_element(env,out,1,number(env,c->context.build.fd))!=napi_ok || napi_set_element(env,out,2,number(env,c->capsule))!=napi_ok) return fail(env); return out;
}
enum class SignedObjectPurpose { policy, compatibility };
static NSDictionary* sealedObject(Custody* custody,SignedObjectPurpose purpose,const std::string& expected,
  double deadline,std::string& digest);
static napi_value prepareHostFinalization(napi_env env,napi_callback_info info) {
  napi_value args[4]; size_t n=4; std::string input,policyDigest,compatibilityDigest;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||n!=4||!boundedText(env,args[1],input)||
     !boundedText(env,args[2],policyDigest)||!boundedText(env,args[3],compatibilityDigest)||
     !arbol_attempt::pattern([NSString stringWithUTF8String:policyDigest.c_str()],@"^[0-9a-f]{64}$")||
     !arbol_attempt::pattern([NSString stringWithUTF8String:compatibilityDigest.c_str()],@"^[0-9a-f]{64}$")) return fail(env);
  auto* c=custodyArgument(env,args[0]); if(!c||c->hostRequired||c->spawned||!c->continuousBuild) return fail(env);
  c->hostRequired=true; // a failed host preparation cannot fall back to legacy
  @autoreleasepool { @try {
    const double deadline=arbol_boundary::clockMs()+1000;
    if(!c->finalization.prepare(c->context,input,deadline)) return fail(env);
    // Expected hashes arrive only through the canonical previously verified
    // HostCustody route. Capture both actual physical sealed files before any
    // enrollment; a consistent replacement pair cannot teach us new trust.
    std::string actualPolicy,actualCompatibility;
    NSDictionary* attempt=c->finalization.value()[@"attempt"];
    const double readDeadline=std::min(deadline,[attempt[@"expires"] doubleValue]);
    NSDictionary* policy=sealedObject(c,SignedObjectPurpose::policy,policyDigest,readDeadline,actualPolicy);
    NSDictionary* compatibility=sealedObject(c,SignedObjectPurpose::compatibility,compatibilityDigest,readDeadline,actualCompatibility);
    arbol_attempt::PackagedLayout layout;
    if(!arbol_attempt::claimedLayout(attempt,layout)) return fail(env);
    NSString* stateRoot=arbol_attempt::policyStateRoot(policy,layout);
    if(!stateRoot||![stateRoot isEqual:[attempt[@"profile"] stringByDeletingLastPathComponent].stringByDeletingLastPathComponent]||
       !compatibility||actualPolicy!=policyDigest||actualCompatibility!=compatibilityDigest||
       ![policy[@"compatibilityDigest"] isEqual:[NSString stringWithUTF8String:compatibilityDigest.c_str()]]||
       ![attempt[@"candidateDigest"] isEqual:[NSString stringWithUTF8String:c->context.digest.c_str()]]||
       ![policy[@"sourceDigest"] isEqual:attempt[@"sourceDigest"]]||![policy[@"productDigest"] isEqual:attempt[@"productDigest"]]||
       !arbol_boundary::lockIdentity(c->context.owner)||!arbol_boundary::lockIdentity(c->context.build)||
       !c->finalization.metadata()||arbol_boundary::clockMs()>=readDeadline) return fail(env);
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
    !arbol_boundary::executable(child,path)||path!=c->context.helper()||!c->context.helperSignature(child,path)||
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
    if(!c->finalization.ready(c->context)||!c->monitorImage.capture(c->context.helper())) return fail(env);
    arbol_attempt::Claim claim; std::string raw; NSDictionary* current=nil;
    if(!c->finalization.currentAttempt(c->context,claim,raw,current,arbol_boundary::clockMs()+1000)||
       ![current[@"phase"] isEqual:@"claimed"]||![current[@"stage"] isEqual:@"transferring"]||
       [current[@"expires"] doubleValue]<=arbol_boundary::clockMs()) return fail(env);
    NSMutableDictionary* next=[current mutableCopy]; next[@"stage"]=@"retained";
    if(!arbol_attempt::transition(current,next,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(claim.at,raw,false,arbol_attempt::bytes(next))) return fail(env);
    c->finalization.shared()->transfer.store(2,std::memory_order_release);
  }
  c->bound=true; observeHostStartup(c,0);
  napi_value out; napi_get_undefined(env,&out); return out;
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
static bool nativeMarker(NSDictionary* value, bool evidence = false) {
  uint64_t epoch;
  return arbol_attempt::keys(value,@[@"format",@"profileInstance",@"engine",@"dataEpoch",@"lastWriterBuild",@"lastWriterChromium",@"lastWriterElectron",@"requiredReader",@"cleanExit"])&&
    (evidence ? ([value[@"format"] isEqual:@1] || (arbol_attempt::profileFormat == 2 && [value[@"format"] isEqual:@2])) :
      [value[@"format"] isEqual:@(arbol_attempt::profileFormat)])&&[value[@"engine"] isEqual:@"chromium"]&&
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
// Only this exact signed compatibility inventory has the package's one-MiB
// codec. Small policy, all attempts/Close/markers and the separate exit receipt
// codecs retain their original independent bounds and schemas.
static NSDictionary* sealedObject(Custody* custody,SignedObjectPurpose purpose,const std::string& expected,
  double deadline,std::string& digest) {
  digest.clear();
  if(!custody||!nativeCustodies.count(custody)||!std::isfinite(deadline)||arbol_boundary::clockMs()>=deadline||
     !arbol_attempt::pattern([NSString stringWithUTF8String:expected.c_str()],@"^[0-9a-f]{64}$")) return nil;
  std::string path; size_t maximum;
  switch(purpose) {
    case SignedObjectPurpose::policy: path=custody->context.bundle+"/Contents/Resources/host-policy.json"; maximum=16383; break;
    case SignedObjectPurpose::compatibility: path=custody->context.bundle+"/Contents/Resources/native-compatibility.json"; maximum=1048576; break;
    default: return nil;
  }
  if(!arbol_boundary::canonical(path)||arbol_boundary::clockMs()>=deadline) return nil;
  arbol_exit::NativeFile file; file.fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
  const int fd=file.fd; if(fd<0) return nil;
  struct stat first{},named{},last{},after{}; std::string bytes;
  bool ok=arbol_boundary::clockMs()<deadline&&!fstat(fd,&first)&&!lstat(path.c_str(),&named)&&S_ISREG(first.st_mode)&&first.st_nlink==1&&
    !(first.st_mode&0022)&&(first.st_uid==geteuid()||first.st_uid==0)&&arbol_attempt::sameFile(first,named)&&
    first.st_size>0&&(uint64_t)first.st_size<=maximum;
  char buffer[4096];
  while(ok&&bytes.size()<=(size_t)first.st_size) {
    if(arbol_boundary::clockMs()>=deadline) { ok=false; break; }
    ssize_t n=read(fd,buffer,std::min(sizeof(buffer),(size_t)first.st_size+1-bytes.size()));
    if(n>0) bytes.append(buffer,n); else if(!n) break; else if(errno!=EINTR) ok=false;
  }
  ok=ok&&arbol_boundary::clockMs()<deadline&&bytes.size()==(size_t)first.st_size&&!fstat(fd,&last)&&!lstat(path.c_str(),&after)&&
    arbol_attempt::sameFile(first,last)&&arbol_attempt::sameFile(last,after)&&arbol_boundary::canonical(path);
  NSDictionary* value=nil;
  if(ok) {
    // The independently preverified/retained expected digest is checked before
    // UTF-8 or JSON decoding. These exact same-description bytes teach no trust.
    digest=[arbol_attempt::digest(bytes) UTF8String];
    ok=digest==expected&&arbol_boundary::clockMs()<deadline;
  }
  if(ok) {
    if(purpose==SignedObjectPurpose::policy) value=arbol_attempt::json(bytes);
    else if(bytes.find('\0')==std::string::npos) {
      NSData* data=[NSData dataWithBytes:bytes.data() length:bytes.size()];
      if([[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding]&&arbol_boundary::clockMs()<deadline) {
        NSError* error=nil; id decoded=[NSJSONSerialization JSONObjectWithData:data options:0 error:&error];
        if(!error&&[decoded isKindOfClass:NSDictionary.class]) value=decoded;
      }
    }
    ok=value&&arbol_boundary::clockMs()<deadline&&!fstat(fd,&last)&&!lstat(path.c_str(),&after)&&
      arbol_attempt::sameFile(first,last)&&arbol_attempt::sameFile(last,after)&&arbol_boundary::canonical(path);
  }
  if(!file.finish()) ok=false;
  return ok&&arbol_boundary::clockMs()<deadline?value:nil;
}
static bool emptyNativeDirectory(NSString* path) {
  if(!arbol_boundary::canonical(path.fileSystemRepresentation)) return false;
  int fd=open(path.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
  DIR* directory=fdopendir(fd); if(!directory) { close(fd); return false; }
  bool empty=true; errno=0;
  while(auto* entry=readdir(directory)) if(strcmp(entry->d_name,".")&&strcmp(entry->d_name,"..")) { empty=false; break; }
  if(errno) empty=false; if(closedir(directory)) empty=false; return empty;
}
static bool absentEngineRootStorage(NSDictionary* capability,double deadline) {
  NSString* profile=capability[@"attempt"][@"profile"];
  if(arbol_boundary::clockMs()>=deadline||!arbol_boundary::canonical(profile.fileSystemRepresentation)) return false;
  int fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(fd<0) return false;
  struct stat held{},after{},named{};
  std::vector<std::string> names;
  bool ok=!fstat(fd,&held)&&S_ISDIR(held.st_mode)&&(held.st_mode&07777)==0700&&held.st_uid==geteuid()&&
    [arbol_exit::fileIdentity(held) isEqual:capability[@"profileDirectory"]]&&arbol_exit::storageNames(fd,deadline,names)&&
    std::none_of(names.begin(),names.end(),arbol_exit::engineRootStorageName)&&
    !fstat(fd,&after)&&!lstat(profile.fileSystemRepresentation,&named)&&
    arbol_exit::sameStorageNode(held,after)&&arbol_exit::sameStorageNode(after,named);
  if(close(fd)) ok=false;
  return ok&&arbol_boundary::clockMs()<deadline;
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
  NSDictionary* receipt=arbol_exit::parseExitReceipt(bytes); id marker=receipt[@"marker"];
  ok=ok&&[receipt[@"format"] isEqual:@1]&&[receipt[@"profileInstance"] isEqual:attempt[@"profileInstance"]]&&
    [receipt[@"profilePathHash"] isEqual:attempt[@"profilePathHash"]]&&[receipt[@"profileDirectory"] isEqual:capability[@"profileDirectory"]];
  if(prior[@"migration"]&&!arbol_exit::migrationPriorMarker(prior,attempt,capability[@"profileDirectory"],marker,marker)) return false;
  if(absent) return ok&&marker==(id)NSNull.null;
  return ok&&arbol_attempt::keys(marker,@[@"identity",@"digest",@"value"])&&
    [marker[@"identity"] isEqual:arbol_exit::fileIdentity(st)]&&[marker[@"digest"] isEqual:arbol_attempt::digest(raw)]&&
    [marker[@"value"] isEqual:arbol_attempt::json(raw)];
}
static bool signedDirty(Custody* c,const std::string& dirtyRaw,const std::string& previous,bool absent,double deadline) {
  NSDictionary* dirty=arbol_attempt::json(dirtyRaw),*attempt=c->finalization.value()[@"attempt"];
  std::string policyHash,compatibilityHash;
  NSDictionary* policy=sealedObject(c,SignedObjectPurpose::policy,c->policyDigest,deadline,policyHash);
  NSDictionary* compatibility=sealedObject(c,SignedObjectPurpose::compatibility,c->compatibilityDigest,deadline,compatibilityHash);
  arbol_attempt::PackagedLayout layout;
  if(!arbol_attempt::claimedLayout(attempt,layout)) return false;
  NSString* stateRoot=arbol_attempt::policyStateRoot(policy,layout);
  NSString* readerPrefix=layout.installed?@"host-production:1:":@"host-isolated:1:";
  if(policyHash!=c->policyDigest||compatibilityHash!=c->compatibilityDigest||!policy||!compatibility||!nativeMarker(dirty)||![dirty[@"cleanExit"] isEqual:@NO]||
     !stateRoot||![policy[@"sourceDigest"] isEqual:attempt[@"sourceDigest"]]||
     ![policy[@"productDigest"] isEqual:attempt[@"productDigest"]]||
     ![stateRoot isEqual:[attempt[@"profile"] stringByDeletingLastPathComponent].stringByDeletingLastPathComponent]||
     ![policy[@"readerKey"] isEqual:[readerPrefix stringByAppendingString:attempt[@"productDigest"]]]||
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
    emptyNativeDirectory([attempt[@"profile"] stringByAppendingPathComponent:@"userData"])&&
    absentEngineRootStorage(c->finalization.value(),deadline);
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
    const double mutationDeadline=std::min(deadline,[permit->attempt[@"expires"] doubleValue]);
    std::string previous; struct stat st{}; bool absent;
    if(!currentMarker(c,previous,st,absent)||!priorMarkerMatches(c,previous,st,absent)||!signedDirty(c,dirty,previous,absent,mutationDeadline)||
       arbol_boundary::clockMs()>=mutationDeadline) { permit->relinquish(); return fail(env); }
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
    if(reasons&~arbol_exit::admissionLoss) return fail(env);
    if(reasons&&!cutoff) return fail(env);
    if(reasons&&arbol_boundary::clockMs()*1000>=cutoff) return fail(env);
    const auto* retained=state->closeGraceUs.load(std::memory_order_acquire)?nullptr:c->monitorImage.retained();
    if(!c->finalization.held(c->context,retained)) return fail(env);
    if(c->mutation) {
      if(!c->mutation->current()) return fail(env);
    } else if(c->sessionUse) {
      if(!c->sessionUse->current()) return fail(env);
    } else if(!c->finalization.controls(c->context,arbol_boundary::clockMs()+100)) return fail(env);
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
  if(c->finalization.present()) { c->finalization.shared()->declareFatal(); observeNativeRefusal(c); }
  napi_value out; napi_get_undefined(env,&out); return out;
}

// The protected listeners and existing public record are already bound while
// the JS admission gate is closed. This sole private producer durably writes
// the existing native engine-ready Claim; it accepts no caller-selected role.
static bool readyListener(int fd,NSString* expected,struct stat& named) {
  if(fd<3) return false;
  // Darwin exposes the listening bit in descriptor info. getsockopt with
  // SO_ACCEPTCONN can refuse a genuine listener with ENOPROTOOPT.
  socket_fdinfo descriptor{};
  if(proc_pidfdinfo(getpid(),fd,PROC_PIDFDSOCKETINFO,&descriptor,sizeof(descriptor))!=sizeof(descriptor)) return false;
  const auto& socket=descriptor.psi;
  struct stat held{};
  return socket.soi_kind==SOCKINFO_UN&&socket.soi_family==AF_UNIX&&socket.soi_type==SOCK_STREAM&&
    (socket.soi_options&SO_ACCEPTCONN)&&
    !fstat(fd,&held)&&S_ISSOCK(held.st_mode)&&managementSocketPath(fd,false,expected)&&
    !lstat(expected.fileSystemRepresentation,&named)&&S_ISSOCK(named.st_mode)&&named.st_uid==geteuid()&&
    named.st_nlink==1&&(named.st_mode&07777)==0600;
}
static napi_value publishHostReady(napi_env env,napi_callback_info info) {
  napi_value args[4]; size_t count=4; std::string encoded; int agent,management;
  if(napi_get_cb_info(env,info,&count,args,nullptr,nullptr)!=napi_ok||count!=4||!boundedText(env,args[1],encoded)||
     !integer(env,args[2],&agent)||!integer(env,args[3],&management)) return fail(env);
  auto* c=custodyArgument(env,args[0]);
  if(!c||!c->hostRequired||!c->bound||getpid()!=c->context.main.pid||!c->finalization.present()) return fail(env);
  auto reject=[&](unsigned line = __builtin_LINE()) {
    c->finalization.shared()->declareFatal(); auto failure=fail(env,line);
    observeNativeRefusal(c); return failure;
  };
  if(c->readyAttempted) return reject(); c->readyAttempted=true;
  @autoreleasepool { @try { try {
    auto* state=c->finalization.shared(); NSDictionary* runtime=arbol_attempt::json(encoded);
    if(!runtime||agent==management||!c->websiteSession||c->sessionUse||c->mutation||
       !c->finalization.ready(c->context)||!c->retainedReader.valid()||!c->retainedWriter.valid()||
       state->fatal.load(std::memory_order_acquire)||state->enrolled.load(std::memory_order_acquire)!=7||
       state->transfer.load(std::memory_order_acquire)!=2||state->markerBound.load(std::memory_order_acquire)!=1||
       state->admitted.load(std::memory_order_acquire)!=1||
       state->closeReceivedUs.load(std::memory_order_acquire)||![runtime[@"phase"] isEqual:@"ready"]) return reject();
    double deadline=std::min([c->finalization.value()[@"attempt"][@"expires"] doubleValue],arbol_boundary::clockMs()+1000);
    arbol_attempt::Claim claim; std::string raw; NSDictionary* current=nil;
    if(!c->finalization.currentAttempt(c->context,claim,raw,current,deadline)||
       ![current[@"phase"] isEqual:@"claimed"]||![current[@"stage"] isEqual:@"admitted"]||
       !arbol_attempt::currentProcess(current[@"engine"],true)||[current[@"expires"] doubleValue]<=arbol_boundary::clockMs()||
       !arbol_attempt::runtime(runtime,current)||!arbol_attempt::sameRuntimeBinding(current[@"runtime"],runtime)||
       ![c->finalization.boundMarker(c->context) isEqual:c->websiteSession->marker]) return reject();
    struct stat agentBefore{},managementBefore{},runtimeBefore{},named{},runtimeAfter{};
    if(!readyListener(agent,runtime[@"agentSocket"],agentBefore)||!readyListener(management,runtime[@"managementSocket"],managementBefore)) return reject();
    arbol_exit::NativeFile published; published.fd=openat(claim.at.directory,"runtime.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(published.fd<0||fstat(published.fd,&runtimeBefore)||!arbol_attempt::privateFile(runtimeBefore)||
       runtimeBefore.st_size<1||runtimeBefore.st_size>(off_t)arbol_attempt::limit||
       fstatat(claim.at.directory,"runtime.json",&named,AT_SYMLINK_NOFOLLOW)||!arbol_attempt::sameFile(runtimeBefore,named)) return reject();
    std::string actual((size_t)runtimeBefore.st_size+1,'\0'); size_t at=0;
    while(at<actual.size()) {
      if(arbol_boundary::clockMs()>=deadline) return reject();
      ssize_t n=pread(published.fd,actual.data()+at,actual.size()-at,(off_t)at);
      if(n>0) at+=(size_t)n; else if(n<0&&errno==EINTR) continue; else if(!n) break; else return reject();
    }
    if(at!=(size_t)runtimeBefore.st_size) return reject(); actual.resize(at);
    if(![arbol_attempt::json(actual) isEqual:runtime]||fsync(published.fd)||fcntl(published.fd,F_FULLFSYNC)||fsync(claim.at.directory)||
       fstat(published.fd,&runtimeAfter)||fstatat(claim.at.directory,"runtime.json",&named,AT_SYMLINK_NOFOLLOW)||
       !arbol_attempt::sameFile(runtimeBefore,runtimeAfter)||!arbol_attempt::sameFile(runtimeAfter,named)||
       !c->finalization.ready(c->context)||arbol_boundary::clockMs()>=deadline) return reject();
    NSMutableDictionary* next=[current mutableCopy]; next[@"phase"]=@"ready"; next[@"runtime"]=runtime;
    std::string nextRaw=arbol_attempt::bytes(next);
    if(!arbol_attempt::transition(current,next,arbol_attempt::Role::engine)||
       !arbol_attempt::replace(claim.at,raw,false,nextRaw)) return reject();
    // Keep sole attestation family claim.json, and require its exact physical
    // bytes/identity and full durable file+directory completion before return.
    arbol_exit::NativeFile ready; ready.fd=openat(claim.at.directory,"claim.json",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    struct stat first{},checked{},last{}; std::string checkedRaw; bool absent;
    if(ready.fd<0||fstat(ready.fd,&first)||!arbol_attempt::privateFile(first)||fsync(ready.fd)||fcntl(ready.fd,F_FULLFSYNC)||fsync(claim.at.directory)||
       !arbol_attempt::readAt(claim.at.directory,"claim.json",checkedRaw,absent)||absent||checkedRaw!=nextRaw||
       fstat(ready.fd,&last)||fstatat(claim.at.directory,"claim.json",&checked,AT_SYMLINK_NOFOLLOW)||
       !arbol_attempt::sameFile(first,last)||!arbol_attempt::sameFile(last,checked)||
       fstat(published.fd,&runtimeAfter)||fstatat(claim.at.directory,"runtime.json",&named,AT_SYMLINK_NOFOLLOW)||
       !arbol_attempt::sameFile(runtimeBefore,runtimeAfter)||!arbol_attempt::sameFile(runtimeAfter,named)) return reject();
    struct stat agentAfter{},managementAfter{};
    if(!readyListener(agent,runtime[@"agentSocket"],agentAfter)||!readyListener(management,runtime[@"managementSocket"],managementAfter)||
       agentBefore.st_dev!=agentAfter.st_dev||agentBefore.st_ino!=agentAfter.st_ino||
       managementBefore.st_dev!=managementAfter.st_dev||managementBefore.st_ino!=managementAfter.st_ino||
       !arbol_attempt::unchanged(claim.at)||!c->finalization.ready(c->context)||state->fatal.load(std::memory_order_acquire)||
       arbol_boundary::clockMs()>=deadline||!ready.finish()||!published.finish()) return reject();
    if(c->context.app.pid) {
      if(!c->context.ownerRunning()||!arbol_boundary::lockIdentity(c->appStartup)) return reject();
      const int fd=c->appStartup.fd; c->appStartup.fd=-1;
      if(close(fd)) return reject();
    }
    napi_value out; napi_get_undefined(env,&out); return out;
  } catch(...) { return reject(); } } @catch(NSException*) { return reject(); } }
}

// No application/native-input cleanup is entered here. Both native lock
// descriptions remain retained for the lifetime of this nonreturning path.
[[noreturn]] static void terminateCustody(Custody* c) {
  if(c->continuousBuild&&adoptedNoUse&&adoptedNoUse->matches(c->context.bundle,c->context.digest,c->context.build)&&
     adoptedNoUse->mayFinalize()&&!c->spawned&&!c->markerAttempted&&!c->sessionAttempted) adoptedNoUse->terminate();
  // Irreversible attribution precedes discovery, retirement or any signal.
  if(c->finalization.present()) { c->finalization.shared()->poison(arbol_exit::protocolLoss|arbol_exit::forced); observeNativeRefusal(c); }
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
static bool migrationInspectionMode(id mode) {
  return arbol_attempt::profileFormat == 2 && [@[@"migrate-verify",@"migrate-commit",@"migrate-recover",@"migrate-receipt-progress",@"migrate-committed-check"] containsObject:mode];
}
static bool originalMaintenanceBuild(const arbol_boundary::Lock& lock) {
  if (arbol_attempt::profileFormat != 2 || !maintenanceCustody || !maintenanceCustody->accepted ||
      !maintenanceStateRoot || !maintenanceStateRoot->current() || lock.heldMode != LOCK_EX ||
      !arbol_boundary::lockIdentity(lock)) return false;
  for (const auto* original : {maintenanceCustody->oldBuild,maintenanceCustody->newBuild})
    if (original && original->retained && original->mode == LOCK_EX && lock.path == original->path &&
        lock.device == uint64_t(original->dev) && lock.inode == original->ino && lock.uid == geteuid() && lock.mode == 0600)
      return true;
  return false;
}
static bool originalMaintenanceBuildHandle(HeldLock* value) {
  return maintenanceCustody && maintenanceCustody->accepted && value && value->retained && value->mode == LOCK_EX &&
    (value == maintenanceCustody->oldBuild || value == maintenanceCustody->newBuild) &&
    maintenanceStateRoot && maintenanceStateRoot->current();
}
// Native capture lives in the existing private exit-evidence authority. Its
// immutable name is the exact receipt digest, and its body binds the attempt,
// transaction, profile and original physical source observations. This is the
// accepted signed-native/owner-private trust model, not a new cryptographic
// signature or a substitute for rederiving the original terminal proof.
struct RetainedMigrationProof {
  arbol_exit::MigrationChain chain;
  arbol_attempt::MaintenanceFile captureFile,closedFile,dataFile;
  NSDictionary* capture=nil,*closed=nil,*data=nil;
  bool current() const {
    return chain.current()&&captureFile.current()&&(!closed||closedFile.current())&&
      (!data||data==closed||dataFile.current());
  }
  static NSDictionary* policyContent(id value) {
    uint64_t mode;
    if(!arbol_attempt::keys(value,@[@"identity",@"sha256",@"base64"])||
       !arbol_attempt::uintNumber(value[@"identity"][@"mode"],mode)||(mode!=0600&&mode!=0444&&mode!=0644)||
       !arbol_exit::migrationIdentity(value[@"identity"],(unsigned)mode)) return nil;
    NSMutableDictionary* normalized=[value mutableCopy],*identity=[value[@"identity"] mutableCopy];
    identity[@"mode"]=@0600; normalized[@"identity"]=identity;
    return arbol_exit::migrationContent(normalized,true);
  }
  static bool source(id value,NSDictionary* claim) {
    using namespace arbol_attempt; using namespace arbol_exit;
    if(!claim) return value==NSNull.null;
    PackagedLayout layout; uint64_t uid,mode,held;
    if(!record(claim)||!claimedLayout(claim,layout)||!keys(value,@[@"claimSha256",@"bundle",@"guard"])||
       ![value[@"claimSha256"] isEqual:digest(bytes(claim))]) return false;
    id bundle=value[@"bundle"],guard=value[@"guard"];
    if(!keys(bundle,@[@"path",@"identity",@"policy",@"sourceDigest",@"productDigest",@"candidateDigest"])||
       ![bundle[@"path"] isEqual:[NSString stringWithUTF8String:layout.bundle.c_str()]]||
       !keys(bundle[@"identity"],@[@"device",@"inode",@"uid",@"mode"])||
       !uintNumber(bundle[@"identity"][@"mode"],mode)||(mode&0022)||!(mode&0100)||mode>0777||
       !migrationIdentity(bundle[@"identity"],(unsigned)mode)||!policyContent(bundle[@"policy"])||
       !keys(guard,@[@"path",@"device",@"inode",@"uid",@"mode",@"heldMode"])||
       ![guard[@"path"] isEqual:claim[@"buildGuard"]]||
       !pattern(guard[@"device"],@"^[0-9]{1,20}$")||!pattern(guard[@"inode"],@"^[1-9][0-9]{0,19}$")||
       !uintNumber(guard[@"uid"],uid)||uid!=geteuid()||!uintNumber(guard[@"mode"],mode)||mode!=0600||
       !uintNumber(guard[@"heldMode"],held)||held!=LOCK_SH) return false;
    NSDictionary* policy=policyContent(bundle[@"policy"]);
    if(![policyStateRoot(policy,layout) isEqual:[claim[@"profile"] stringByDeletingLastPathComponent].stringByDeletingLastPathComponent]||
       ![policy[@"sourceDigest"] isEqual:claim[@"sourceDigest"]]||![policy[@"productDigest"] isEqual:claim[@"productDigest"]]) return false;
    for(NSString* key in @[@"sourceDigest",@"productDigest",@"candidateDigest"])
      if(![bundle[key] isEqual:claim[key]]) return false;
    return true;
  }
  bool readClaim(id hash,arbol_attempt::MaintenanceFile& file,NSDictionary* __strong& out) {
    using namespace arbol_attempt;
    if(hash==NSNull.null) { out=nil; return true; }
    NSString* state=chain.transaction[@"root"][@"path"];
    std::string path=std::string(state.fileSystemRepresentation)+"/exit-evidence/"+
      [chain.receipt[@"profileSha256"] UTF8String]+"/claims/"+[hash UTF8String]+".json";
    if(!file.openPath(path,0600,limit,true)) return false;
    out=arbol_exit::strictManagementObject(file.content);
    return record(out)&&[out[@"phase"] isEqual:@"closed"]&&out[@"terminal"]!=NSNull.null&&bytes(out)==file.content&&
      [digest(file.content) isEqual:hash]&&[out[@"profile"] isEqual:chain.receipt[@"profilePath"]]&&
      [out[@"profileInstance"] isEqual:chain.receipt[@"instance"]]&&[out[@"profilePathHash"] isEqual:chain.receipt[@"profileSha256"]];
  }
  bool open(NSString* runtime,NSString* state,NSString* hash,NSString* instance,bool completed=true) {
    using namespace arbol_attempt;
    if(!chain.open(runtime,state,hash,instance,completed)) return false;
    NSString* receiptDigest=digest(chain.receiptFile.content);
    if(!captureFile.openPath(std::string(state.fileSystemRepresentation)+"/exit-evidence/"+hash.UTF8String+
       "/migration/"+receiptDigest.UTF8String+".json",0600,arbol_exit::exitReceiptLimit,true)) return false;
    capture=arbol_exit::parseExitReceipt(captureFile.content);
    if(!keys(capture,@[@"format",@"kind",@"receiptSha256",@"transactionSha256",@"attempt",@"epoch",@"profileSha256",@"instance",@"directory",@"closed",@"data"])||
       !arbol_exit::migrationFormat(capture[@"format"],1)||![capture[@"kind"] isEqual:@"native-migration-evidence"]||
       ![capture[@"receiptSha256"] isEqual:receiptDigest]||![capture[@"epoch"] isEqual:chain.transaction[@"epoch"]]) return false;
    for(NSString* key in @[@"transactionSha256",@"attempt",@"profileSha256",@"instance",@"directory"])
      if(![capture[key] isEqual:chain.receipt[key]]) return false;
    id evidence=chain.receipt[@"evidence"];
    if(!readClaim(evidence[@"closedClaimSha256"],closedFile,closed)) return false;
    if([evidence[@"dataClaimSha256"] isEqual:evidence[@"closedClaimSha256"]]) data=closed;
    else if(!readClaim(evidence[@"dataClaimSha256"],dataFile,data)) return false;
    if(!source(capture[@"closed"],closed)||!source(capture[@"data"],data)) return false;
    if(closed&&data&&[closed isEqual:data]&&![capture[@"closed"] isEqual:capture[@"data"]]) return false;
    if(data&&(![data[@"terminal"][@"path"] isEqual:evidence[@"terminalPath"]]||
       ![data[@"terminal"][@"digest"] isEqual:evidence[@"terminalSha256"]])) return false;
    return current();
  }
  bool buildRecord(id recorded,NSDictionary* claim) const {
    if(!claim||!current()) return false;
    if(closed&&[claim isEqual:closed]) return [recorded isEqual:capture[@"closed"][@"guard"]];
    if(data&&[claim isEqual:data]) return [recorded isEqual:capture[@"data"][@"guard"]];
    return false;
  }
};
// Reproduce manifest.ts completeSnapshot/stable from the actual immutable
// adopted candidate. Neither a caller's expected digest nor its enumeration
// supplies authority. English collation and JSON string escaping are the
// established snapshot encoding; files, modes, directories and internal links
// all participate, including the outer signature seal.
static bool stableSnapshotNode(const struct stat& a,const struct stat& b) {
  return a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_mode==b.st_mode&&a.st_uid==b.st_uid&&a.st_gid==b.st_gid&&
    a.st_nlink==b.st_nlink&&a.st_size==b.st_size&&
    a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec&&
    a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec&&a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec&&
    a.st_birthtimespec.tv_sec==b.st_birthtimespec.tv_sec&&a.st_birthtimespec.tv_nsec==b.st_birthtimespec.tv_nsec;
}
static NSString* nativeCandidateDigest(const std::string& root,double deadline,const std::function<bool()>& current) {
  using namespace arbol_attempt; using namespace arbol_exit;
  if(!current()) return nil;
  std::vector<std::pair<NSString*,NSString*>> entries; size_t count=0;
  auto string=[](const char* bytes,size_t length) -> NSString* {
    NSData* data=[NSData dataWithBytes:bytes length:length];
    NSString* value=[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return value&&[[value dataUsingEncoding:NSUTF8StringEncoding] isEqual:data]?value:nil;
  };
  auto lexical=[](NSString* a,NSString* b) {
    const NSUInteger length=std::min(a.length,b.length);
    for(NSUInteger i=0;i<length;++i) { auto x=[a characterAtIndex:i],y=[b characterAtIndex:i]; if(x!=y) return x<y; }
    return a.length<b.length;
  };
  auto names=[&](int fd,std::vector<std::string>& values) {
    int copy=openat(fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if(copy<0) return false;
    DIR* directory=fdopendir(copy); if(!directory) { close(copy); return false; }
    bool ok=true; errno=0;
    while(auto* entry=readdir(directory)) {
      std::string name=entry->d_name; if(name=="."||name=="..") continue;
      if(values.size()>=4096||name.empty()||name.size()>255||!string(name.data(),name.size())||
         arbol_boundary::clockMs()>=deadline) { ok=false; break; }
      values.push_back(name); errno=0;
    }
    if(errno||closedir(directory)) ok=false;
    std::sort(values.begin(),values.end(),[&](const auto& a,const auto& b) { return lexical(string(a.data(),a.size()),string(b.data(),b.size())); });
    return ok&&std::adjacent_find(values.begin(),values.end())==values.end();
  };
  auto fileDigest=[&](int parent,const std::string& name,const std::string& path,const struct stat& original) -> NSString* {
    NativeFile file; file.fd=openat(parent,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    struct stat first{},last{},named{};
    if(file.fd<0||fstat(file.fd,&first)||!stableSnapshotNode(first,original)||!S_ISREG(first.st_mode)||first.st_nlink!=1||
       first.st_size<0||!arbol_boundary::canonical(path)) return nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_SHA256_CTX hash; CC_SHA256_Init(&hash); std::vector<char> bytes(512*1024); off_t offset=0;
    while(offset<first.st_size) {
      if(arbol_boundary::clockMs()>=deadline) return nil;
      ssize_t n=pread(file.fd,bytes.data(),size_t(std::min(off_t(bytes.size()),first.st_size-offset)),offset);
      if(n>0) { CC_SHA256_Update(&hash,bytes.data(),CC_LONG(n)); offset+=n; }
      else if(n<0&&errno==EINTR) continue; else return nil;
    }
    char overflow; if(pread(file.fd,&overflow,1,offset)!=0||fstat(file.fd,&last)||
       fstatat(parent,name.c_str(),&named,AT_SYMLINK_NOFOLLOW)||!stableSnapshotNode(first,last)||!stableSnapshotNode(last,named)||!file.finish()) return nil;
    unsigned char output[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(output,&hash);
#pragma clang diagnostic pop
    NSMutableString* value=[NSMutableString new]; for(unsigned char byte:output) [value appendFormat:@"%02x",byte]; return value;
  };
  std::function<bool(const std::string&)> walk;
  walk=[&](const std::string& path) {
    if(path.size()>=PATH_MAX||arbol_boundary::clockMs()>=deadline||!arbol_boundary::canonical(path)) return false;
    NativeFile directory; directory.fd=open(path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat before{},after{},named{}; std::vector<std::string> first,last;
    if(directory.fd<0||fstat(directory.fd,&before)||lstat(path.c_str(),&named)||!stableSnapshotNode(before,named)||
       !S_ISDIR(before.st_mode)||!names(directory.fd,first)||count+first.size()>4096) return false;
    count+=first.size();
    for(const auto& name:first) {
      const std::string full=path+"/"+name,key=full.substr(root.size()+1); struct stat initial{},checked{};
      if(full.size()>=PATH_MAX||fstatat(directory.fd,name.c_str(),&initial,AT_SYMLINK_NOFOLLOW)||arbol_boundary::clockMs()>=deadline) return false;
      NSString* value=nil;
      if(S_ISDIR(initial.st_mode)) {
        value=[NSString stringWithFormat:@"directory:%u",initial.st_mode&07777];
        entries.emplace_back(string(key.data(),key.size()),value); if(!walk(full)) return false;
      } else if(S_ISREG(initial.st_mode)) {
        NSString* hash=fileDigest(directory.fd,name,full,initial); if(!hash) return false;
        value=[NSString stringWithFormat:@"file:%u:%@",initial.st_mode&07777,hash];
        entries.emplace_back(string(key.data(),key.size()),value);
      } else if(S_ISLNK(initial.st_mode)) {
        char raw[PATH_MAX]{},again[PATH_MAX]{},resolved[PATH_MAX]{};
        ssize_t length=readlinkat(directory.fd,name.c_str(),raw,sizeof(raw));
        if(length<=0||length>=PATH_MAX||memchr(raw,'\0',length)||!realpath(full.c_str(),resolved)||!within(resolved,root)||
           readlinkat(directory.fd,name.c_str(),again,sizeof(again))!=length||memcmp(raw,again,length)) return false;
        NSString* link=string(raw,length); if(!link) return false;
        // Resolve dot segments lexically without expanding a tilde or following
        // any link, matching path.resolve(dirname(path), link).
        std::string joined=raw[0]=='/'?std::string(raw,length):path+"/"+std::string(raw,length);
        std::vector<std::string> components; size_t start=1;
        for(size_t i=1;i<=joined.size();++i) if(i==joined.size()||joined[i]=='/') {
          std::string part=joined.substr(start,i-start); start=i+1;
          if(part.empty()||part==".") continue;
          if(part=="..") { if(!components.empty()) components.pop_back(); } else components.push_back(part);
        }
        std::string normalized; for(const auto& part:components) normalized+="/"+part;
        if(!within(normalized,root)) return false;
        value=[@"symlink:" stringByAppendingString:link]; entries.emplace_back(string(key.data(),key.size()),value);
      } else return false;
      if(fstatat(directory.fd,name.c_str(),&checked,AT_SYMLINK_NOFOLLOW)||!stableSnapshotNode(initial,checked)) return false;
    }
    return names(directory.fd,last)&&first==last&&!fstat(directory.fd,&after)&&!lstat(path.c_str(),&named)&&
      stableSnapshotNode(before,after)&&stableSnapshotNode(after,named)&&directory.finish();
  };
  if(!walk(root)||!current()) return nil;
  NSLocale* english=[[NSLocale alloc] initWithLocaleIdentifier:@"en"];
  std::stable_sort(entries.begin(),entries.end(),[&](const auto& a,const auto& b) {
    return [a.first compare:b.first options:0 range:NSMakeRange(0,a.first.length) locale:english]==NSOrderedAscending;
  });
  auto quote=[](NSString* text) {
    NSData* data=[text dataUsingEncoding:NSUTF8StringEncoding]; const unsigned char* bytes=(const unsigned char*)data.bytes;
    std::string out="\""; const char* digits="0123456789abcdef";
    for(NSUInteger i=0;i<data.length;++i) {
      unsigned char c=bytes[i];
      if(c=='"'||c=='\\') { out+='\\'; out+=char(c); }
      else if(c=='\b') out+="\\b"; else if(c=='\f') out+="\\f"; else if(c=='\n') out+="\\n";
      else if(c=='\r') out+="\\r"; else if(c=='\t') out+="\\t";
      else if(c<32) { out+="\\u00"; out+=digits[c>>4]; out+=digits[c&15]; } else out+=char(c);
    }
    return out+"\"";
  };
  std::string encoded="{"; bool first=true;
  for(const auto& entry:entries) { if(!first) encoded+=','; first=false; encoded+=quote(entry.first)+":"+quote(entry.second); }
  encoded+='}'; if(!current()) return nil;
  return digest(encoded);
}
static NSString* maintenanceCandidateDigest(double deadline) {
  static std::mutex mutex; static bool attempted=false; static NSString* retained=nil;
  while(!mutex.try_lock()) { if(arbol_boundary::clockMs()>=deadline) return nil; usleep(1000); }
  std::unique_lock<std::mutex> held(mutex,std::adopt_lock);
  auto current=[&] { return maintenanceCustody&&maintenanceCustody->accepted&&
    arbol_boundary::clockMs()<deadline&&maintenanceCustody->current(); };
  if(!current()) return nil;
  if(attempted) return retained; attempted=true;
  retained=nativeCandidateDigest(maintenanceCustody->layout().bundle,deadline,current); return retained;
}

struct MigrationPublication {
  arbol_attempt::MaintenanceDirectory root,attempt,profile,staging,qualificationProgress;
  arbol_attempt::MaintenanceFile currentFile,transactionFile,stagedFile,recordFile,markerFile,stagedRecord;
  NSDictionary* transaction=nil,*entry=nil,*staged=nil,*receipt=nil;
  bool recovery=false,replaced=false;
  arbol_attempt::MaintenanceFile& targetRecord() { return recovery?stagedRecord:recordFile; }
  bool current() const {
    struct stat st{};
    if(!receipt||!maintenanceStateRoot||!maintenanceStateRoot->current()||!root.current()||!attempt.current()||
       !profile.current()||!currentFile.current()||!transactionFile.current()||!stagedFile.current()||
       (qualificationProgress.fd>=0&&!qualificationProgress.current())||
       (staging.fd>=0&&!staging.current())||
       (recovery?(!stagedRecord.current()||(!replaced&&!recordFile.current())):!recordFile.current())) return false;
    if(receipt[@"convertedMarker"]!=NSNull.null) return markerFile.current();
    errno=0; return fstatat(profile.fd,"engine.json",&st,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT;
  }
  bool open(NSDictionary* input,bool recover,double deadline,NSDictionary* sealedStaging=nil) {
    using namespace arbol_attempt; using namespace arbol_exit;
    recovery=recover;
    id request=input[@"migration"];
    if(profileFormat!=2||!maintenanceStateRoot||!maintenanceStateRoot->current()||maintenanceStateRoot->absent||
       !keys(request,@[@"attempt",@"transactionSha256"])||!pattern(request[@"attempt"],@"^[0-9a-f]{32}$")||
       !migrationDigest(request[@"transactionSha256"])||!migrationDigest(input[@"profilePathHash"])||
       !root.openPath(maintenanceCustody->runtime().path+"/browser-profile-migration")||
       !currentFile.openPath(root.path+"/current",0600,limit,true)||
       !attempt.openPath(root.path+"/"+[request[@"attempt"] UTF8String])) return false;
    id pointer=strictManagementObject(currentFile.content);
    if(!keys(pointer,@[@"format",@"attempt",@"transactionSha256"])||!migrationFormat(pointer[@"format"],1)||
       ![pointer[@"attempt"] isEqual:request[@"attempt"]]||![pointer[@"transactionSha256"] isEqual:request[@"transactionSha256"]]) return false;
    constexpr off_t maximum=4096LL*(4*87384+8192)+65536;
    if(!transactionFile.openPath(attempt.path+"/transaction.json",0600,maximum,true)||
       ![digest(transactionFile.content) isEqual:request[@"transactionSha256"]]) return false;
    transaction=strictManagementObject(transactionFile.content,maximum);
    const auto& selection=maintenanceCustody->selection();
    id selected=selection.absent?(id)NSNull.null:json(selection.bytes);
    id selectedFile=selection.absent?(id)NSNull.null:@{@"identity":maintenanceIdentity(selection.file),@"sha256":digest(selection.bytes)};
    NSDictionary* policy=json(maintenanceCustody->hostPolicy().content);
    if(!migrationTransaction(transaction)||![transaction[@"attempt"] isEqual:request[@"attempt"]]||
       ![transaction[@"epoch"] isEqual:maintenanceCustody->epoch]||
       ![transaction[@"runtime"] isEqual:maintenanceIdentity(maintenanceCustody->runtime().identity)]||
       ![transaction[@"root"][@"path"] isEqual:maintenanceCustody->stateRoot()]||
       ![transaction[@"root"][@"identity"] isEqual:maintenanceIdentity(maintenanceStateRoot->identity)]||
       ![transaction[@"journal"] isEqual:maintenanceCustody->journal().record()]||
       ![transaction[@"selection"] isEqual:selected]||![transaction[@"selectionFile"] isEqual:selectedFile]||
       ![transaction[@"oldBuild"] isEqual:maintenanceCustody->journalObject()[@"before"]]||
       ![transaction[@"newBuild"] isEqual:maintenanceCustody->journalObject()[@"after"]]||
       ![transaction[@"sourceSha256"] isEqual:policy[@"sourceDigest"]]||![transaction[@"productSha256"] isEqual:policy[@"productDigest"]]||
       ![transaction[@"candidateSha256"] isEqual:maintenanceCandidateDigest(deadline)]) return false;
    for(id candidate in transaction[@"profiles"]) if([candidate[@"pathSha256"] isEqual:input[@"profilePathHash"]]) entry=candidate;
    if(!entry) return false;
    NSString* expected=[[maintenanceCustody->stateRoot() stringByAppendingPathComponent:@"profiles"] stringByAppendingPathComponent:entry[@"id"]];
    if(!entry||![entry[@"instance"] isEqual:input[@"profileInstance"]]||![input[@"profile"] isEqual:expected]||
       !profile.openPath(expected.UTF8String,entry[@"directory"])||
       !stagedFile.openPath(attempt.path+"/progress/"+[input[@"profilePathHash"] UTF8String]+".staged.json",0600,limit,true)) return false;
    staged=strictManagementObject(stagedFile.content);
    if(!keys(staged,@[@"format",@"attempt",@"profileSha256",@"record",@"marker"])||!migrationFormat(staged[@"format"],1)||
       ![staged[@"attempt"] isEqual:request[@"attempt"]]||![staged[@"profileSha256"] isEqual:input[@"profilePathHash"]]||
       !migrationFile(staged[@"record"])||![staged[@"record"][@"sha256"] isEqual:entry[@"targetRecord"][@"sha256"]]||
       !recordFile.openPath(profile.path+"/profile.json",0600,65536,true)) return false;
    const auto openStaging=[&] {
      return staging.openPath(std::string([maintenanceCustody->stateRoot() UTF8String])+"/migration-staged/"+
          [request[@"attempt"] UTF8String]+"/"+[input[@"profilePathHash"] UTF8String],sealedStaging)&&
        staging.identity.st_dev==profile.identity.st_dev;
    };
    if(recovery) {
      if(![maintenanceIdentity(recordFile.identity) isEqual:entry[@"originalRecord"][@"identity"]]||
         ![digest(recordFile.content) isEqual:entry[@"originalRecord"][@"sha256"]]||
         ![strictManagementObject(recordFile.content,65536) isEqual:migrationContent(entry[@"originalRecord"],true)]||
         !openStaging()||
         !stagedRecord.openPath(staging.path+"/profile.json",0600,65536,true)) return false;
    } else if(sealedStaging&&!openStaging()) return false;
    if(![targetRecord().record() isEqual:staged[@"record"]]||
       ![strictManagementObject(targetRecord().content,65536) isEqual:migrationContent(entry[@"targetRecord"],false)]) return false;
    id convertedMarker=NSNull.null;
    if(entry[@"targetMarker"]==NSNull.null) {
      struct stat st{}; errno=0;
      if(staged[@"marker"]!=NSNull.null||!fstatat(profile.fd,"engine.json",&st,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT) return false;
    } else {
      if(!migrationFile(staged[@"marker"])||![staged[@"marker"][@"sha256"] isEqual:entry[@"targetMarker"][@"sha256"]]||
         !markerFile.openPath(profile.path+"/engine.json",0600,65536,true)||![markerFile.record() isEqual:staged[@"marker"]]||
         ![strictManagementObject(markerFile.content,65536) isEqual:migrationContent(entry[@"targetMarker"],false)]) return false;
      convertedMarker=@{@"identity":maintenanceIdentity(markerFile.identity),@"sha256":digest(markerFile.content),
        @"base64":[[NSData dataWithBytes:markerFile.content.data() length:markerFile.content.size()] base64EncodedStringWithOptions:0]};
    }
    NSString* boot=bootSession(); NSDictionary* writer=processRecord(getpid()); if(!boot||!writer) return false;
    receipt=@{@"format":@1,@"kind":@"browser-profile-migration-receipt",@"attempt":request[@"attempt"],
      @"transactionSha256":request[@"transactionSha256"],@"profilePath":input[@"profile"],@"profileSha256":input[@"profilePathHash"],
      @"instance":entry[@"instance"],@"directory":entry[@"directory"],@"evidence":entry[@"evidence"],
      @"originalRecord":@{@"identity":entry[@"originalRecord"][@"identity"],@"sha256":entry[@"originalRecord"][@"sha256"]},
      @"convertedRecord":targetRecord().record(),@"originalMarker":entry[@"originalMarker"],@"convertedMarker":convertedMarker,
      @"bootSession":boot,@"writer":writer,@"sourceSha256":transaction[@"sourceSha256"],@"productSha256":transaction[@"productSha256"],
      @"candidateSha256":transaction[@"candidateSha256"]};
    return migrationReceipt(receipt)&&current();
  }
  bool replaceRecord(const std::function<bool(NSString*)>& checkpoint) {
    using namespace arbol_attempt;
    if(!recovery||replaced||!current()) return false;
    // Both exact source and destination were checked with their held native
    // descriptions under the same owner/registry/Claim custody. No caller path
    // or file contents enter this one permitted atomic operation.
    if(renameat(staging.fd,"profile.json",profile.fd,"profile.json")) return false;
    replaced=true;
    struct stat held{},named{};
    if(fstat(stagedRecord.fd,&held)||fstatat(profile.fd,"profile.json",&named,AT_SYMLINK_NOFOLLOW)||
       !privateFile(held)||!sameFile(held,named)||
       ![maintenanceIdentity(held) isEqual:staged[@"record"][@"identity"]]||
       held.st_size!=(off_t)stagedRecord.content.size()) return false;
    std::string actual(stagedRecord.content.size()+1,'\0'); size_t count=0;
    while(count<actual.size()) {
      ssize_t n=pread(stagedRecord.fd,actual.data()+count,actual.size()-count,count);
      if(n>0) count+=n; else if(n<0&&errno==EINTR) continue; else if(!n) break; else return false;
    }
    actual.resize(count); if(actual!=stagedRecord.content) return false;
    // A successful rename can change ctime. Rebase only this retained original
    // staged description after checking its exact staged inode and bytes.
    stagedRecord.path=profile.path+"/profile.json"; stagedRecord.identity=held;
    return checkpoint(@"record-rename")&&!fsync(profile.fd)&&!fsync(staging.fd)&&current()&&checkpoint(@"record-durable");
  }
};
struct OrdinaryMigrationAuthority {
  arbol_attempt::PackagedLayout layout;
  arbol_attempt::MaintenanceFile policy,fixture;
  arbol_attempt::MaintenanceDirectory runtime;
  arbol_attempt::IsolatedMaintenance isolated;
  arbol_exit::NativeFile bundle;
  arbol_boundary::Lock guard;
  const arbol_startup_proof::RetainedAppPackage* startupPackage=nullptr;
  struct stat identity{}; struct statfs filesystem{};
  NSString* state=nil; bool available=false;
  std::string runtimePath;
  bool current() const {
    struct stat held{},named{}; struct statfs fs{}; char path[PATH_MAX]{};
    return bundle.fd>=0&&arbol_boundary::lockIdentity(guard)&&guard.heldMode==LOCK_SH&&
      !fstat(bundle.fd,&held)&&!lstat(layout.bundle.c_str(),&named)&&!fcntl(bundle.fd,F_GETPATH,path)&&layout.bundle==path&&
      stableSnapshotNode(identity,held)&&stableSnapshotNode(held,named)&&!fstatfs(bundle.fd,&fs)&&
      (fs.f_flags&MNT_RDONLY)&&(fs.f_flags&MNT_LOCAL)&&fs.f_fsid.val[0]==filesystem.f_fsid.val[0]&&fs.f_fsid.val[1]==filesystem.f_fsid.val[1]&&
      policy.current()&&(!startupPackage||startupPackage->current())&&
      (!available||(layout.installed?runtime.current():isolated.current()));
  }
  bool open(const std::string& ownBundle,NSString* profile,const arbol_boundary::Lock& ownGuard,double deadline,
            const arbol_startup_proof::RetainedAppPackage* candidate,NSString* snapshot) {
    using namespace arbol_attempt;
    if(profileFormat!=2||!packagedLayout(ownBundle,layout)||layout.guard!=ownGuard.path||ownGuard.heldMode!=LOCK_SH||
       !arbol_boundary::lockIdentity(ownGuard)||!arbol_boundary::canonical(ownBundle)) return false;
    if(layout.installed&&candidate&&candidate->witnessed()&&candidate->matches(layout,snapshot)) {
      if(!candidate->current()) return false;
      startupPackage=candidate;
      os_log(OS_LOG_DEFAULT,"arbol-browser receipt authority reused its verified installed package");
    } else if(!signedIdentity(ownBundle,layout.installed?@"com.sylvan-stack.arbol-browser":@"com.sylvan-stack.arbol-browser.native-candidate",true)) return false;
    if(!layout.installed) {
      struct stat sealed{}; errno=0;
      if(lstat((ownBundle+"/Contents/Resources/maintenance-fixture.json").c_str(),&sealed)) return errno==ENOENT;
    }
    guard=ownGuard; bundle.fd=::open(ownBundle.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(bundle.fd<0||fstat(bundle.fd,&identity)||!S_ISDIR(identity.st_mode)||fstatfs(bundle.fd,&filesystem)||
       !(filesystem.f_flags&MNT_RDONLY)||!(filesystem.f_flags&MNT_LOCAL)||
       !policy.openPath(ownBundle+"/Contents/Resources/host-policy.json",0600,limit,true)) return false;
    state=policyStateRoot(json(policy.content),layout);
    if(!state||![profile.stringByDeletingLastPathComponent isEqual:[state stringByAppendingPathComponent:@"profiles"]]) return false;
    if(layout.installed) {
      NSString* home=physicalAccountHome(); if(!home) return false;
      NSString* path=[[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_ROOT] stringByAppendingPathComponent:@"runtime"];
      if(!runtime.openPath(path.fileSystemRepresentation)) return false;
      runtimePath=runtime.path; available=true;
    } else {
      const std::string path=ownBundle+"/Contents/Resources/maintenance-fixture.json"; struct stat st{}; errno=0;
      if(lstat(path.c_str(),&st)) {
        // A normal isolated host without a sealed migration policy cannot
        // acquire receipt authority or choose a runtime. Its existing native
        // predecessor checks remain in force, without any rewritten evidence.
        return false; // a previously observed sealed fixture disappeared
      }
      if(!fixture.openPath(path,0600,limit,true)) return false;
      id record=json(fixture.content); if(!arbol_attempt::path(record[@"runtime"])) return false;
      if(!isolated.admit(path,[record[@"runtime"] UTF8String],ownBundle,deadline)||
         isolated.stateRoot!=state.UTF8String) return false;
      runtimePath=isolated.runtime.path; available=true;
    }
    return current();
  }
};
struct ExitInspection;
static NSString* migrationSourceStamp(const struct stat& value) {
  return [NSString stringWithFormat:@"%llu:%llu:%u:%u:%u:%llu:%lld:%lld:%lld:%lld",
    (unsigned long long)value.st_dev,(unsigned long long)value.st_ino,(unsigned)value.st_mode,(unsigned)value.st_uid,
    (unsigned)value.st_gid,(unsigned long long)value.st_nlink,(long long)value.st_size,
    (long long)value.st_mtimespec.tv_sec*1000000000LL+value.st_mtimespec.tv_nsec,
    (long long)value.st_ctimespec.tv_sec*1000000000LL+value.st_ctimespec.tv_nsec,
    (long long)value.st_birthtimespec.tv_sec*1000000000LL+value.st_birthtimespec.tv_nsec];
}
struct MigrationSourceCapture {
  arbol_exit::NativeFile bundle;
  arbol_attempt::MaintenanceFile policy,image;
  arbol_attempt::MaintenancePayload payload;
  arbol_attempt::MaintenanceBacking backing;
  struct stat identity{}; std::string path;
  arbol_boundary::Lock guard; NSDictionary* value=nil;
  bool current() const {
    struct stat held{},named{}; char actual[PATH_MAX]{};
    return value&&bundle.fd>=0&&!fstat(bundle.fd,&held)&&!lstat(path.c_str(),&named)&&!fcntl(bundle.fd,F_GETPATH,actual)&&
      path==actual&&arbol_boundary::canonical(path)&&stableSnapshotNode(identity,held)&&stableSnapshotNode(held,named)&&
      policy.current()&&payload.current()&&backing.current(image)&&arbol_boundary::lockIdentity(guard);
  }
  bool take(NSDictionary* claim,const arbol_boundary::Lock& held,NSDictionary* expected,ExitInspection& job);
};
struct ExitInspection {
  std::atomic<int> state{0}; std::atomic<bool> cancelled{false};
  std::atomic<int> recoveryPermit{0}; std::string recoveryReady;
  arbol_boundary::Lock owner,build,dataBuild,nextBuild,registry,activeBuild; NSDictionary* input=nil; std::string result,activeBundle; double deadline=0;
  // Captured only on the owning N-API thread. Worker uses its private Context
  // fields and genuinely shared atomic state, never the live mutable Context
  // or global nativeCustodies container.
  arbol_boundary::Context hostContext; arbol_exit::SharedState* hostState=nullptr;
  NSDictionary* hostCapability=nil;
  bool maintenance = false;
  RetainedMigrationProof* migrated = nullptr; // stack-owned native validator only; never a JS option
  MigrationPublication* publication = nullptr;
  OrdinaryMigrationAuthority* receiptAuthority = nullptr;
  MigrationSourceCapture* originalClosed=nullptr; MigrationSourceCapture* originalData=nullptr;
  NSDictionary* appliedMigration = nil;
  NSString* qualificationPoint = nil;
  NSDictionary* qualificationStaged = nil;
  NSDictionary* qualificationStagingParent = nil;
  std::unique_ptr<QualificationProgressProof> qualificationProgress;
  QualificationProgressProof* qualificationProofCapture = nullptr; // Stack-scoped in native receipt validation.
  std::thread* thread=nullptr;
  bool within() const { return !cancelled.load(std::memory_order_acquire)&&arbol_boundary::clockMs()<deadline&&
    arbol_boundary::lockIdentity(owner)&&arbol_boundary::lockIdentity(build)&&
    (dataBuild.fd<0||arbol_boundary::lockIdentity(dataBuild))&&(nextBuild.fd<0||arbol_boundary::lockIdentity(nextBuild))&&
    (!maintenance || (maintenanceStateRoot && maintenanceStateRoot->current() && registry.heldMode==LOCK_EX && arbol_boundary::lockIdentity(registry))) &&
    (build.heldMode==LOCK_SH||(maintenance&&originalMaintenanceBuild(build)))&&
    (dataBuild.fd<0||dataBuild.heldMode==LOCK_SH||(maintenance&&originalMaintenanceBuild(dataBuild)))&&
    (nextBuild.fd<0||nextBuild.heldMode==LOCK_SH||(maintenance&&originalMaintenanceBuild(nextBuild)))&&
    (activeBuild.fd<0||arbol_boundary::lockIdentity(activeBuild))&&
    (!migrated||migrated->current())&&(!publication||publication->current())&&(!receiptAuthority||receiptAuthority->current())&&
    (!originalClosed||originalClosed->current())&&(!originalData||originalData->current()); }
  bool historicalBuildLock(id record, const arbol_boundary::Lock& actual, NSDictionary* claim=nil) const {
    if(migrated) return migrated->buildRecord(record,claim);
    if (actual.heldMode == LOCK_SH) return [record isEqual:arbol_boundary::capsuleLock(actual)];
    if (!maintenance || !originalMaintenanceBuild(actual)) return false;
    // Normalize only the historical record comparison. The actual retained
    // description stays exclusive; no flock downgrade or unlock is issued.
    auto historical = actual; historical.heldMode = LOCK_SH;
    return [record isEqual:arbol_boundary::capsuleLock(historical)];
  }
};
// The worker owns duplicates of the original registry/owner/Build locks. It
// checks only those and immutable publication observations from the owning
// thread, never the mutable liveLocks table.
static bool qualificationWorkerTransaction(ExitInspection& job) {
  using namespace arbol_attempt;
  auto* custody=maintenanceCustody;
  const auto* publication=job.publication;
  if (!custody || !publication || !job.qualificationPoint || !job.qualificationStaged || !job.within()) return false;
  NSDictionary* receipt=publication->receipt;
  return [receipt[@"attempt"] isEqual:custody->publishedTransactionAttempt] &&
    qualificationTransactionArchive(*custody,receipt[@"attempt"],receipt[@"transactionSha256"]) &&
    [receipt[@"transactionSha256"] isEqual:custody->publishedTransaction[@"sha256"]] &&
    [maintenanceIdentity(publication->transactionFile.identity) isEqual:custody->publishedTransaction[@"identity"]] &&
    [publication->currentFile.record() isEqual:custody->publishedCurrent] &&
    [maintenanceIdentity(publication->root.identity) isEqual:custody->publishedCurrentParent] &&
    [maintenanceIdentity(publication->attempt.identity) isEqual:custody->publishedTransactionParent] &&
    publication->staging.current() && [maintenanceIdentity(publication->staging.identity) isEqual:job.qualificationStagingParent] &&
    publication->qualificationProgress.current() && [publication->stagedFile.record() isEqual:job.qualificationStaged] &&
    custody->interruptionProfiles && qualificationDirectoryNames(*custody->interruptionProfiles,custody->interruptionProfileNames);
}
static std::set<ExitInspection*> exitInspections;
using arbol_exit::strictManagementObject;
struct MigrationObservation {
  static constexpr size_t metadataLimit = 65536;
  arbol_attempt::MaintenanceDirectory directory;
  arbol_attempt::MaintenanceFile record, marker;
  bool markerAbsent = false;
  NSDictionary* profileRecord = nil;
  NSDictionary* engineMarker = nil;
  bool current() const {
    if (!directory.current() || !record.current()) return false;
    struct stat st{}; errno = 0;
    return markerAbsent ? fstatat(directory.fd,"engine.json",&st,AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT : marker.current();
  }
  bool capture(ExitInspection& job) {
    using namespace arbol_attempt;
    NSString* profile = job.input[@"profile"];
    NSString* state = maintenanceCustody ? maintenanceCustody->stateRoot() : nil;
    if (!job.maintenance || !job.within() || !state || !maintenanceStateRoot || maintenanceStateRoot->absent ||
        maintenanceCustody->journalObject()[@"before"] == NSNull.null ||
        ![profile.stringByDeletingLastPathComponent isEqual:[state stringByAppendingPathComponent:@"profiles"]] ||
        !pattern(profile.lastPathComponent,@"^[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$") ||
        !directory.openPath(profile.fileSystemRepresentation) ||
        !record.openPath(directory.path + "/profile.json",0600,metadataLimit,true)) return false;
    profileRecord = strictManagementObject(record.content,metadataLimit);
    uint64_t format = 0;
    if (!keys(profileRecord,@[@"format",@"id",@"instance",@"creationRequest",@"createdAt"]) ||
        !uintNumber(profileRecord[@"format"],format) || format != 1 || ![profileRecord[@"id"] isEqual:profile.lastPathComponent] ||
        ![profileRecord[@"instance"] isEqual:job.input[@"profileInstance"]] ||
        !pattern(profileRecord[@"creationRequest"],@"^create_[A-Za-z0-9_-]{22}$") ||
        !pattern(profileRecord[@"createdAt"],@"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]+)?Z$")) return false;
    NSISO8601DateFormatter* dates = [NSISO8601DateFormatter new];
    dates.formatOptions = NSISO8601DateFormatWithInternetDateTime |
      ([profileRecord[@"createdAt"] containsString:@"."] ? NSISO8601DateFormatWithFractionalSeconds : 0);
    if (![dates dateFromString:profileRecord[@"createdAt"]]) return false;
    struct stat st{}; errno = 0;
    if (fstatat(directory.fd,"engine.json",&st,AT_SYMLINK_NOFOLLOW)) { if (errno != ENOENT) return false; markerAbsent = true; }
    else {
      if (!marker.openPath(directory.path + "/engine.json",0600,metadataLimit,true)) return false;
      engineMarker = strictManagementObject(marker.content,metadataLimit);
      if (!nativeMarker(engineMarker,true) || !uintNumber(engineMarker[@"format"],format) || format != 1 ||
          ![engineMarker[@"profileInstance"] isEqual:profileRecord[@"instance"]]) return false;
      NSDictionary* policy = json(maintenanceCustody->hostPolicy().content);
      if (![policy[@"readableReaderKeys"] isKindOfClass:NSArray.class] || ![policy[@"readableDataEpochs"] isKindOfClass:NSArray.class] ||
          ![policy[@"readableReaderKeys"] containsObject:engineMarker[@"requiredReader"]] ||
          ![policy[@"readableDataEpochs"] containsObject:engineMarker[@"dataEpoch"]]) return false;
    }
    return current() && job.within();
  }
  bool neverOpened(ExitInspection& job) const {
    if (!markerAbsent || !current()) return false;
    int duplicate = openat(directory.fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC); if (duplicate < 0) return false;
    DIR* entries = fdopendir(duplicate); if (!entries) { close(duplicate); return false; }
    bool valid = true; size_t count = 0; errno = 0;
    while (auto* entry = readdir(entries)) {
      std::string name = entry->d_name;
      if (name == "." || name == "..") continue;
      if (++count > 131072 || !job.within()) { valid = false; break; }
      // A missing marker cannot adopt native storage. This is the existing
      // compatibility.ts fresh-marker rule, not an inference from empty data.
      if (name != "profile.json" && name != "owner.lock" && name != "logs" && name != "data" && name != "userData") { valid = false; break; }
      struct stat st{};
      if (fstatat(directory.fd,name.c_str(),&st,AT_SYMLINK_NOFOLLOW) || st.st_dev != directory.identity.st_dev || st.st_uid != geteuid() ||
          ((name == "profile.json" || name == "owner.lock") ? !arbol_attempt::privateFile(st) :
            (!S_ISDIR(st.st_mode) || (st.st_mode & 07777) != 0700))) { valid = false; break; }
      errno = 0;
    }
    if (errno || closedir(entries)) valid = false;
    return valid && emptyNativeDirectory([job.input[@"profile"] stringByAppendingPathComponent:@"data"]) &&
      emptyNativeDirectory([job.input[@"profile"] stringByAppendingPathComponent:@"userData"]) && current() && job.within();
  }
};
struct MissingMigrationRuntime {
  int temporary = -1, parent = -1; struct stat temporaryIdentity{}, parentIdentity{};
  std::string rootName, leafName;
  bool parentAbsent = false;
  ~MissingMigrationRuntime() { if (parent >= 0) close(parent); if (temporary >= 0) close(temporary); }
  bool current() const {
    struct stat value{};
    struct stat named{};
    if (temporary<0 || fstat(temporary,&value) || lstat("/private/tmp",&named) || !S_ISDIR(value.st_mode) ||
        value.st_uid!=0 || (value.st_mode&07777)!=01777 || value.st_dev!=temporaryIdentity.st_dev ||
        value.st_ino!=temporaryIdentity.st_ino || value.st_dev!=named.st_dev || value.st_ino!=named.st_ino ||
        value.st_uid!=named.st_uid || value.st_mode!=named.st_mode) return false;
    errno=0;
    if (parentAbsent) return fstatat(temporary,rootName.c_str(),&value,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
    char actual[PATH_MAX]{};
    if (parent<0 || fstat(parent,&value) || fstatat(temporary,rootName.c_str(),&named,AT_SYMLINK_NOFOLLOW) ||
        !S_ISDIR(value.st_mode) || !S_ISDIR(named.st_mode) || value.st_uid!=geteuid() || (value.st_mode&07777)!=0700 ||
        value.st_dev!=parentIdentity.st_dev || value.st_ino!=parentIdentity.st_ino || value.st_dev!=named.st_dev || value.st_ino!=named.st_ino ||
        value.st_mode!=named.st_mode || value.st_uid!=named.st_uid ||
        fcntl(parent,F_GETPATH,actual) || std::string(actual)!="/private/tmp/"+rootName) return false;
    errno=0; return fstatat(parent,leafName.c_str(),&value,AT_SYMLINK_NOFOLLOW)<0 && errno==ENOENT;
  }
  bool capture(NSString* leaf, NSString* hash) {
    rootName="ab-"+std::to_string(geteuid()); leafName=[[hash substringToIndex:32] UTF8String];
    const std::string expected="/private/tmp/"+rootName+"/"+leafName;
    if (![leaf isEqual:[NSString stringWithUTF8String:expected.c_str()]]) return false;
    temporary=open("/private/tmp",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat root{};
    if (temporary<0 || fstat(temporary,&temporaryIdentity) || !arbol_boundary::canonical("/private/tmp")) return false;
    errno=0;
    if (fstatat(temporary,rootName.c_str(),&root,AT_SYMLINK_NOFOLLOW)) { if(errno!=ENOENT) return false; parentAbsent=true; }
    else {
      parent=openat(temporary,rootName.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      if (parent<0 || fstat(parent,&parentIdentity)) return false;
    }
    return current();
  }
};
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
    if(job.qualificationProofCapture) job.qualificationProofCapture->files.emplace_back(path.fileSystemRepresentation,after);
  }
  return job.within();
}
static bool migrationPublishedMetadata(NSDictionary* receipt,NSDictionary* entry,NSDictionary* transaction,ExitInspection& job) {
  using namespace arbol_attempt; using namespace arbol_exit;
  NSDictionary* rootRecord=transaction[@"root"];
  const bool original=job.publication&&!job.migrated&&job.publication->recovery&&!job.publication->replaced;
  MaintenanceDirectory state,profiles,profile; MaintenanceFile record,marker;
  NSString* path=receipt[@"profilePath"];
  if(!job.within()||![rootRecord[@"initial"] isEqual:@"present"]||
     !state.openPath([rootRecord[@"path"] UTF8String],rootRecord[@"identity"])||
     !profiles.openPath(state.path+"/profiles",rootRecord[@"profiles"])||
     !profile.openPath(path.UTF8String,receipt[@"directory"])||
     !record.openPath(profile.path+"/profile.json",0600,65536,true)||
     ![record.record() isEqual:receipt[original?@"originalRecord":@"convertedRecord"]]||
     ([receipt[@"originalRecord"][@"identity"][@"device"] isEqual:receipt[@"convertedRecord"][@"identity"][@"device"]]&&
      [receipt[@"originalRecord"][@"identity"][@"inode"] isEqual:receipt[@"convertedRecord"][@"identity"][@"inode"]])||
     ![strictManagementObject(record.content,65536) isEqual:migrationContent(entry[original?@"originalRecord":@"targetRecord"],original)]||
     job.owner.path!=profile.path+"/owner.lock") return false;
  struct stat registry{},owner{},child{};
  if(fstatat(state.fd,"registry.lock",&registry,AT_SYMLINK_NOFOLLOW)||!privateFile(registry)||
     ![maintenanceIdentity(registry) isEqual:rootRecord[@"registry"]]||
     fstat(job.owner.fd,&owner)||![maintenanceIdentity(owner) isEqual:entry[@"ownerLock"]]) return false;
  for(NSString* name in @[@"data",@"userData"]) {
    NSString* key=[name isEqual:@"data"]?@"dataDirectory":@"userDataDirectory";
    if(fstatat(profile.fd,name.UTF8String,&child,AT_SYMLINK_NOFOLLOW)||!S_ISDIR(child.st_mode)||
       child.st_dev!=profile.identity.st_dev||![maintenanceIdentity(child) isEqual:entry[key]]) return false;
  }
  if(receipt[@"convertedMarker"]==NSNull.null) {
    errno=0; if(!fstatat(profile.fd,"engine.json",&child,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT) return false;
  } else if(!marker.openPath(profile.path+"/engine.json",0600,65536,true)||
      ([receipt[@"originalMarker"][@"identity"][@"device"] isEqual:receipt[@"convertedMarker"][@"identity"][@"device"]]&&
       [receipt[@"originalMarker"][@"identity"][@"inode"] isEqual:receipt[@"convertedMarker"][@"identity"][@"inode"]])||
      ![maintenanceIdentity(marker.identity) isEqual:receipt[@"convertedMarker"][@"identity"]]||
      ![digest(marker.content) isEqual:receipt[@"convertedMarker"][@"sha256"]]||
      ![strictManagementObject(marker.content,65536) isEqual:migrationContent(receipt[@"convertedMarker"],true)]) return false;
  return state.current()&&profiles.current()&&profile.current()&&record.current()&&
    (receipt[@"convertedMarker"]==NSNull.null||marker.current())&&job.within();
}
static bool migrationPublishedMetadata(RetainedMigrationProof& proof,ExitInspection& job) {
  return proof.current()&&migrationPublishedMetadata(proof.chain.receipt,proof.chain.entry,proof.chain.transaction,job);
}
static NSDictionary* rewrittenMigrationReceipt(ExitInspection& job) {
  return job.migrated?job.migrated->chain.receipt:job.publication?job.publication->receipt:nil;
}
static bool rewrittenMigrationMetadata(ExitInspection& job) {
  if(job.migrated) return migrationPublishedMetadata(*job.migrated,job);
  return job.publication&&job.publication->current()&&
    migrationPublishedMetadata(job.publication->receipt,job.publication->entry,job.publication->transaction,job);
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
     (rewrittenMigrationReceipt(job)?
       (!rewrittenMigrationMetadata(job)||
        ![rewrittenMigrationReceipt(job)[@"originalRecord"][@"identity"] isEqual:capability[@"profileRecord"]]||
        ![rewrittenMigrationReceipt(job)[@"originalRecord"][@"sha256"] isEqual:capability[@"profileRecordDigest"]]):
       (![arbol_exit::fileIdentity(record) isEqual:capability[@"profileRecord"]]||![arbol_attempt::digest(raw) isEqual:capability[@"profileRecordDigest"]]))||
     ![arbol_attempt::json(raw)[@"instance"] isEqual:attempt[@"profileInstance"]]) return false;
  for(NSString* name in @[@"data",@"userData"]) if(fstatat(root.fd,name.UTF8String,&child,AT_SYMLINK_NOFOLLOW)||
    !S_ISDIR(child.st_mode)||child.st_dev!=directory.st_dev||![arbol_exit::fileIdentity(child) isEqual:capability[@"directories"][name]]) return false;
  if(lstat(receipt.fileSystemRepresentation,&receiptIdentity)||!S_ISDIR(receiptIdentity.st_mode)||receiptIdentity.st_dev!=directory.st_dev||
     ![arbol_exit::fileIdentity(receiptIdentity) isEqual:capability[@"receiptDirectory"][@"identity"]]) return false;
  if(job.qualificationProofCapture) job.qualificationProofCapture->directories.emplace_back(receipt.fileSystemRepresentation,receiptIdentity);
  return root.finish()&&job.within();
}
static bool receiptMarker(NSDictionary* capability,id expected,ExitInspection& job) {
  if(rewrittenMigrationReceipt(job)) {
    id original=rewrittenMigrationReceipt(job)[@"originalMarker"];
    if(original==NSNull.null) { if(expected!=(id)NSNull.null) return false; }
    else if(!arbol_attempt::keys(expected,@[@"identity",@"digest",@"value"])||
        ![original[@"identity"] isEqual:expected[@"identity"]]||![original[@"sha256"] isEqual:expected[@"digest"]]||
        ![arbol_exit::migrationContent(original,true) isEqual:expected[@"value"]]) return false;
    id converted=rewrittenMigrationReceipt(job)[@"convertedMarker"];
    expected=converted==NSNull.null?(id)NSNull.null:@{@"identity":converted[@"identity"],@"digest":converted[@"sha256"],
      @"value":arbol_exit::migrationContent(converted,true)};
  }
  NSString* profile=capability[@"attempt"][@"profile"]; arbol_exit::NativeFile root;
  root.fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  struct stat directory{},identity{},named{}; std::string raw; bool absent;
  if(root.fd<0||fstat(root.fd,&directory)||![arbol_exit::fileIdentity(directory) isEqual:capability[@"profileDirectory"]]||
     !markerAt(root.fd,raw,identity,absent)) return false;
  if(expected==(id)NSNull.null) { errno=0; return absent&&fstatat(root.fd,"engine.json",&named,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT&&root.finish()&&job.within(); }
  return !absent&&arbol_attempt::keys(expected,@[@"identity",@"digest",@"value"])&&nativeMarker(arbol_attempt::json(raw),job.maintenance)&&
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
  arbol_attempt::PackagedLayout layout;
  if(!arbol_attempt::record(closed)||!arbol_attempt::claimedLayout(closed,layout)||layout.bundle!=bundle.UTF8String||
     (!job.migrated&&layout.guard!=proofBuild.path)||![closed[@"phase"] isEqual:@"closed"]||closed[@"terminal"]==NSNull.null||closed[@"engine"]==NSNull.null) return false;
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
     !job.historicalBuildLock(capability[@"locks"][@"build"],proofBuild,closed)||
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
    if(!arbol_attempt::keys(dirty,@[@"identity",@"digest",@"value"])||!nativeMarker(dirty[@"value"],true)||![dirty[@"value"][@"cleanExit"] isEqual:@NO]||
       !arbol_attempt::keys(marker,@[@"identity",@"digest",@"value"])||!nativeMarker(marker[@"value"],true)||![marker[@"value"][@"cleanExit"] isEqual:@YES]||
       !ordinaryReceipt(journal[@"ordinary"],journal[@"storage"],capability,receipt)) return false;
    NSMutableDictionary* expected=[dirty[@"value"] mutableCopy]; expected[@"cleanExit"]=@YES;
    arbol_boundary::Identity last,primary;
    if(![expected isEqual:marker[@"value"]]||!receiptIdentity(receipt[@"lastHolder"],last,true)||!receiptIdentity(receipt[@"primary"],primary)||
       !arbol_boundary::same(last,primary)||last.group!=(uint32_t)last.pid) return false;
  }
  if(!receiptMetadata(capability,closed,job)||!receiptFrontier(capability,frontier,receipt[@"capabilityDigest"],job)||
     !exitAllOriginalsGone(capability,receipt,job)) return false;
  if(auto* proof=job.qualificationProofCapture) {
    proof->files.emplace_back(path.fileSystemRepresentation,identity);
    if(clean) proof->files.emplace_back([[parent stringByAppendingPathComponent:@"proof.json"] fileSystemRepresentation],journalIdentity);
  }
  return true;
}
// A never-used original has a separate witness: no family, flush or clean
// claim can be inferred from it. Its prior data writer is verified separately.
static bool verifyUnusedReceipt(NSDictionary* closed,NSDictionary* __strong& receipt,ExitInspection& job) {
  using namespace arbol_attempt;
  PackagedLayout layout;
  if(!claimedLayout(closed,layout)||!record(closed)||![closed[@"phase"] isEqual:@"closed"]||![closed[@"stage"] isEqual:@"untransferred"]||
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
     ![receipt[@"bundle"] isEqual:[NSString stringWithUTF8String:layout.bundle.c_str()]]||
     (!job.migrated&&![receipt[@"bundle"] isEqual:job.input[@"bundle"]])||
     !keys(receipt[@"locks"],@[@"build",@"owner"])||
     !job.historicalBuildLock(receipt[@"locks"][@"build"],job.build,closed)||
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
  id expectedData=job.migrated?(job.migrated->data?:(id)NSNull.null):job.input[@"dataAttempt"];
  if(!data||![data isEqual:expectedData]||(data!=NSNull.null&&
     (!record(data)||![data[@"phase"] isEqual:@"closed"]||![data[@"profile"] isEqual:closed[@"profile"]]||
      ![data[@"profileInstance"] isEqual:closed[@"profileInstance"]]||![data[@"profilePathHash"] isEqual:closed[@"profilePathHash"]]||
      ![@[@"activation.json",@"terminal.json"] containsObject:[data[@"terminal"][@"path"] lastPathComponent]]))) return false;
  NSString* boot=arbol_exit::bootSession(); if(!boot) return false;
  if(job.qualificationProofCapture) job.qualificationProofCapture->files.emplace_back(path.fileSystemRepresentation,identity);
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

// Keep original signed bundle and guard observations alive through native
// verification and immutable capture. Historical candidate identity comes
// from the canonical native Claim/terminal capability; the current signed
// policy independently binds its source/product and physical state root.
bool MigrationSourceCapture::take(NSDictionary* claim,const arbol_boundary::Lock& held,NSDictionary* expected,ExitInspection& job) {
    using namespace arbol_attempt;
    PackagedLayout layout;
    if(!job.maintenance||job.migrated||!job.within()||!keys(expected,@[@"bundle",@"bundleStamp",@"policy",@"policyStamp"])||
       !record(claim)||!claimedLayout(claim,layout)||
       layout.guard!=held.path||!arbol_boundary::lockIdentity(held)||
       (held.heldMode!=LOCK_SH&&!originalMaintenanceBuild(held))||!arbol_boundary::signature(layout.bundle,false)) return false;
    path=layout.bundle; guard=held;
    bundle.fd=open(path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(bundle.fd<0||fstat(bundle.fd,&identity)||!S_ISDIR(identity.st_mode)||identity.st_uid!=geteuid()||
       (identity.st_mode&0022)||!(identity.st_mode&0100)) return false;
    const std::string policyPath=path+"/Contents/Resources/host-policy.json"; struct stat policyIdentity{};
    if(lstat(policyPath.c_str(),&policyIdentity)||((policyIdentity.st_mode&07777)!=0600&&
       (policyIdentity.st_mode&07777)!=0644&&(policyIdentity.st_mode&07777)!=0444)||
       !policy.openPath(policyPath,policyIdentity.st_mode&07777,limit,true)||
       ![expected[@"bundle"] isEqual:maintenanceIdentity(identity)]||![expected[@"bundleStamp"] isEqual:migrationSourceStamp(identity)]||
       ![expected[@"policy"] isEqual:policy.record()]||![expected[@"policyStamp"] isEqual:migrationSourceStamp(policy.identity)]) return false;
    auto parent=[](const std::string& path) { return path.substr(0,path.rfind('/')); };
    const std::string support=layout.installed?parent(parent(layout.guard)):parent(parent(layout.buildRoot))+"/support";
    payload.mount=layout.buildRoot+"/app";
    payload.root=open(payload.mount.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(payload.root<0||fstat(payload.root,&payload.identity)||fstatfs(payload.root,&payload.filesystem)||!payload.current()||
       !image.openPath(support+"/images/"+layout.build+".dmg",0600,1024LL*1024*1024)||
       !maintenanceMount(payload.mount,image,job.deadline,backing)) return false;
    NSData* content=[NSData dataWithBytes:policy.content.data() length:policy.content.size()];
    auto historical=guard; historical.heldMode=LOCK_SH;
    value=@{@"claimSha256":digest(bytes(claim)),@"guard":arbol_boundary::capsuleLock(historical),
      @"bundle":@{@"path":[NSString stringWithUTF8String:path.c_str()],@"identity":maintenanceIdentity(identity),
        @"policy":@{@"identity":maintenanceIdentity(policy.identity),@"sha256":digest(policy.content),@"base64":[content base64EncodedStringWithOptions:0]},
        @"sourceDigest":claim[@"sourceDigest"],@"productDigest":claim[@"productDigest"],@"candidateDigest":claim[@"candidateDigest"]}};
    // Independently authenticate the actual original signed tree against the
    // Claim's snapshot digest while its exact readonly image is pinned. A new
    // pathname or later signature can never become the captured baseline.
    auto continuous=[&] { return current()&&job.within(); };
    return RetainedMigrationProof::source(value,claim)&&continuous()&&
      [nativeCandidateDigest(path,job.deadline,continuous) isEqual:claim[@"candidateDigest"]]&&continuous();
  }

static bool migrationNeverOpened(NSDictionary* receipt,ExitInspection& job) {
  using namespace arbol_attempt;
    // A no-use witness is not evidence of empty storage. Repeat the exact
    // missing-marker management inventory and empty data-directory checks.
    if(receipt[@"originalMarker"]!=NSNull.null||receipt[@"convertedMarker"]!=NSNull.null) return false;
    MaintenanceDirectory profile;
    if(!profile.openPath([job.input[@"profile"] UTF8String],receipt[@"directory"])) return false;
  auto* proof=job.qualificationProofCapture;
  struct stat profileStamp{};
  if(proof&&fstat(profile.fd,&profileStamp)) return false;
    int duplicate=openat(profile.fd,".",O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if(duplicate<0) return false; DIR* entries=fdopendir(duplicate); if(!entries) { close(duplicate); return false; }
    bool valid=true; size_t count=0; errno=0;
    while(auto* entry=readdir(entries)) {
      std::string name=entry->d_name; if(name=="."||name=="..") continue;
      if(++count>131072||!job.within()||
         (name!="profile.json"&&name!="owner.lock"&&name!="logs"&&name!="data"&&name!="userData")) { valid=false; break; }
      struct stat st{};
      if(fstatat(profile.fd,name.c_str(),&st,AT_SYMLINK_NOFOLLOW)||st.st_dev!=profile.identity.st_dev||st.st_uid!=geteuid()||
         ((name=="profile.json"||name=="owner.lock")?!privateFile(st):(!S_ISDIR(st.st_mode)||(st.st_mode&07777)!=0700))) { valid=false; break; }
      errno=0;
    }
    if(errno||closedir(entries)) valid=false;
    if(!valid) return false;
    if(proof) {
      if(!job.migrated) return false;
      for(NSString* leaf in @[@"data",@"userData"]) {
        MaintenanceDirectory child; struct stat stamp{};
        const std::string path=profile.path+"/"+leaf.UTF8String;
        NSString* key=[leaf isEqual:@"data"]?@"dataDirectory":@"userDataDirectory";
        if(!child.openPath(path,job.migrated->chain.entry[key]) || fstat(child.fd,&stamp) ||
           !qualificationDirectoryNames(child,{}) || !qualificationDirectoryUnchanged(child,stamp)) return false;
        proof->unchangedDirectories.emplace_back(path,stamp);
      }
      if(!qualificationDirectoryUnchanged(profile,profileStamp)) return false;
      proof->unchangedDirectories.emplace_back(profile.path,profileStamp);
    } else if(!emptyNativeDirectory([job.input[@"profile"] stringByAppendingPathComponent:@"data"])||
              !emptyNativeDirectory([job.input[@"profile"] stringByAppendingPathComponent:@"userData"])) return false;
    if(!profile.current()) return false;
  return job.within();
}

// Internal only: callers in subsequent native receipt modes must open the
// chain from their independently verified policy runtime. A parsed receipt or
// a JavaScript classification cannot construct this temporary authority.
[[maybe_unused]] static bool verifyRetainedMigration(RetainedMigrationProof& proof,ExitInspection& job) {
  using namespace arbol_attempt;
  if(profileFormat!=2||job.migrated||(!proof.chain.completed&&!job.maintenance)||!job.within()||!proof.current()||
     ![proof.chain.receipt[@"profilePath"] isEqual:job.input[@"profile"]]||
     ![proof.chain.receipt[@"profileSha256"] isEqual:job.input[@"profilePathHash"]]||
     ![proof.chain.receipt[@"instance"] isEqual:job.input[@"profileInstance"]]) return false;
  struct Scope {
    ExitInspection& job;
    Scope(ExitInspection& job,RetainedMigrationProof& proof):job(job) { job.migrated=&proof; }
    ~Scope() { job.migrated=nullptr; }
  } scope(job,proof);
  if(!migrationPublishedMetadata(proof,job)) return false;
  NSDictionary* closed=proof.closed,*data=proof.data,*receipt=nil,*capability=nil,*frontier=nil;
  bool unused=closed&&[[closed[@"terminal"][@"path"] lastPathComponent] isEqual:@"unused.json"];
  if(unused) {
    if(!verifyUnusedReceipt(closed,receipt,job)) return false;
    id previous=data?:(id)NSNull.null;
    if(![receipt[@"priorDataClaim"] isEqual:previous]||
       (data&&![digest(bytes(receipt[@"priorDataClaim"])) isEqual:proof.chain.receipt[@"evidence"][@"dataClaimSha256"]])) return false;
  } else if(closed?!data||![closed isEqual:data]:data!=nil) return false;
  bool clean=false;
  if(data) {
    PackagedLayout layout; if(!claimedLayout(data,layout)) return false;
    NSString* bundle=[NSString stringWithUTF8String:layout.bundle.c_str()];
    if(!verifyClosedReceipt(data,capability,receipt,frontier,job,job.build,bundle)||
       !receiptMarker(capability,receipt[@"marker"],job)) return false;
    clean=[[data[@"terminal"][@"path"] lastPathComponent] isEqual:@"activation.json"];
  } else {
    if(!migrationNeverOpened(proof.chain.receipt,job)) return false;
  }
  NSDictionary* derived=@{@"classification":data?(clean?@"clean":@"dirty"):@"never-opened",@"clean":@(clean),
    @"closedClaimSha256":closed?(id)digest(bytes(closed)):NSNull.null,@"dataClaimSha256":data?(id)digest(bytes(data)):NSNull.null,
    @"terminalPath":data?data[@"terminal"][@"path"]:(id)NSNull.null,@"terminalSha256":data?data[@"terminal"][@"digest"]:(id)NSNull.null};
  return [derived isEqual:proof.chain.receipt[@"evidence"]]&&migrationPublishedMetadata(proof,job)&&proof.current()&&job.within();
}

static bool parkQualificationWorker(ExitInspection& job,NSString* point,NSArray* artifacts,
                                    const std::function<bool()>& boundary) {
  if(![job.qualificationPoint isEqual:point]) return true;
  auto& publication=*job.publication;
  NSDictionary* receipt=publication.receipt;
  NSString* hash=receipt[@"profileSha256"];
  struct stat stagingStamp{};
  if(fstat(publication.staging.fd,&stagingStamp)) return false;
  const auto current=[&] {
    return qualificationWorkerTransaction(job)&&boundary()&&
      qualificationDirectoryNames(publication.staging,{})&&
      qualificationFileAbsent(publication.qualificationProgress.path+"/"+hash.UTF8String+".committed.json")&&
      qualificationFileAbsent(publication.attempt.path+"/completed.json")&&
      ([point isEqual:@"receipt-durable"] ||
       qualificationFileAbsent(publication.root.path+"/receipts/"+hash.UTF8String+".json"))&&
      qualificationDirectoryUnchanged(publication.staging,stagingStamp);
  };
  NSDictionary* witness=@{@"attempt":receipt[@"attempt"],@"transactionSha256":receipt[@"transactionSha256"],
    @"profileSha256":hash,@"artifacts":artifacts};
  return maintenanceCustody->parkInterruption(point,witness,job.deadline,current);
}

static bool publishMigration(ExitInspection& job,NSDictionary* closed,NSDictionary* data,NSDictionary* derived,
                             const std::function<bool()>& claimsCurrent,const std::function<bool(int)>& bindHistory,
                             bool historyWasAbsent,const std::function<bool()>& reverify) {
  using namespace arbol_attempt; using namespace arbol_exit;
  auto* publication=job.publication;
  if(!job.maintenance||job.migrated||!publication||!job.within()||!publication->current()||
     !claimsCurrent()||![derived isEqual:publication->entry[@"evidence"]]||!rewrittenMigrationMetadata(job)||
     (!data&&!migrationNeverOpened(publication->receipt,job))) return false;
  const bool same=closed&&data&&[closed isEqual:data];
  auto* closedSource=job.originalClosed; auto* dataSource=same?closedSource:job.originalData;
  if((closed&&(!closedSource||!closedSource->current()||![closedSource->value[@"claimSha256"] isEqual:digest(bytes(closed))]))||
     (data&&(!dataSource||!dataSource->current()||![dataSource->value[@"claimSha256"] isEqual:digest(bytes(data))]))) return false;
  NSMutableDictionary* receipt=[publication->receipt mutableCopy]; receipt[@"evidence"]=derived;
  if(!migrationReceipt(receipt)) return false;
  std::string raw=exitReceiptBytes(receipt); if(raw.empty()) return false;
  NSString* hash=digest(raw);
  NSDictionary* capture=@{@"format":@1,@"kind":@"native-migration-evidence",@"receiptSha256":hash,
    @"transactionSha256":receipt[@"transactionSha256"],@"attempt":receipt[@"attempt"],@"epoch":maintenanceCustody->epoch,
    @"profileSha256":receipt[@"profileSha256"],@"instance":receipt[@"instance"],@"directory":receipt[@"directory"],
    @"closed":closed?closedSource->value:(id)NSNull.null,@"data":data?dataSource->value:(id)NSNull.null};
  auto current=[&] { return job.within()&&claimsCurrent()&&publication->current()&&rewrittenMigrationMetadata(job)&&
    (!closed||closedSource->current())&&(!data||dataSource->current()); };
  if(!current()) return false;
  MaintenanceDirectory state,exits,history,claims,captures,receipts; struct stat identity{};
  auto directory=[&](MaintenanceDirectory& parent,const std::string& name,MaintenanceDirectory& child,bool historyNode=false) {
    return current()&&privateDirectoryAt(parent.fd,name.c_str(),identity,historyNode&&historyWasAbsent)&&identity.st_dev==parent.identity.st_dev&&
      child.openPath(parent.path+"/"+name,maintenanceIdentity(identity))&&(!historyNode||bindHistory(child.fd))&&
      parent.current()&&child.current()&&current();
  };
  if(!state.openPath([maintenanceCustody->stateRoot() UTF8String],publication->transaction[@"root"][@"identity"])||
     !directory(state,"exit-evidence",exits)||!directory(exits,[receipt[@"profileSha256"] UTF8String],history,true)||
     !directory(history,"claims",claims)||!directory(history,"migration",captures)||
     !directory(publication->root,"receipts",receipts)) return false;
  const std::string captureName=std::string(hash.UTF8String)+".json";
  const std::string name=std::string([receipt[@"profileSha256"] UTF8String])+".json";
  const bool qualifyEvidence=[@[@"claim-retained",@"capture-durable",@"receipt-durable"] containsObject:job.qualificationPoint];
  MaintenanceFile retainedClosed,retainedData,retainedCapture,retainedReceipt;
  auto observe=[&](MaintenanceFile& file,const MaintenanceDirectory& parent,const std::string& leaf,
                   const std::string& bytes,const struct stat& published) {
    return file.openPath(parent.path+"/"+leaf,0600,exitReceiptLimit,true)&&sameFile(published,file.identity)&&
      file.content==bytes&&parent.current()&&current();
  };
  auto parkEvidence=[&](NSString* point,NSString* kind,const MaintenanceFile& artifact) {
    if(![job.qualificationPoint isEqual:point]) return true;
    const auto original=[&] {
      return current()&&reverify&&reverify()&&(!data?migrationNeverOpened(publication->receipt,job):true)&&
        state.current()&&exits.current()&&history.current()&&claims.current()&&captures.current()&&receipts.current()&&
        (retainedClosed.fd<0||retainedClosed.current())&&(retainedData.fd<0||retainedData.current())&&
        (retainedCapture.fd<0||retainedCapture.current())&&artifact.current()&&
        (![point isEqual:@"claim-retained"]||qualificationFileAbsent(captures.path+"/"+captureName));
    };
    return parkQualificationWorker(job,point,@[qualificationArtifact(kind,artifact,digest(artifact.content))],original);
  };
  // Immutable native evidence is idempotent only for byte-identical existing
  // material at the exact digest-derived name. Never overwrite a receipt.
  auto retain=[&](MaintenanceDirectory& parent,const std::string& leaf,const std::string& bytes,MaintenanceFile& file,
                  NSString* point,NSString* kind) {
    if(bytes.empty()||!parent.current()||!current()) return false;
    struct stat identity{}; errno=0;
    const bool exists=!fstatat(parent.fd,leaf.c_str(),&identity,AT_SYMLINK_NOFOLLOW);
    if(exists) {
      std::string existing;
      if(!readNativeFile(parent.fd,leaf,existing,identity,exitReceiptLimit)||existing!=bytes) return false;
    } else if(errno!=ENOENT||!publishNativeReceipt(parent.fd,leaf,bytes,job.deadline,identity)) return false;
    if(!parent.current()||!current()) return false;
    if(qualifyEvidence) {
      if(!observe(file,parent,leaf,bytes,identity)) return false;
      // An existing matching object remains usable, but only this successful
      // fresh immutable publication can earn the selected writer stop.
      if(!exists&&!parkEvidence(point,kind,file)) return false;
    }
    return true;
  };
  if(closed&&!retain(claims,std::string([derived[@"closedClaimSha256"] UTF8String])+".json",bytes(closed),
       retainedClosed,@"claim-retained",@"retained-claim")) return false;
  if(data&&!same&&!retain(claims,std::string([derived[@"dataClaimSha256"] UTF8String])+".json",bytes(data),
       retainedData,@"claim-retained",@"retained-claim")) return false;
  if(!retain(captures,captureName,exitReceiptBytes(capture),retainedCapture,@"capture-durable",@"capture")||!current()) return false;
  struct stat published{};
  if(!publishNativeReceipt(receipts.fd,name,raw,job.deadline,published)||!current()||!receipts.current()) return false;
  if([job.qualificationPoint isEqual:@"receipt-durable"]&&
     (!observe(retainedReceipt,receipts,name,raw,published)||!parkEvidence(@"receipt-durable",@"receipt",retainedReceipt))) return false;
  // Re-open the exact published chain and retained evidence before returning.
  // No completed record exists yet: only the maintenance native mode can use
  // this transaction-to-receipt path. Ordinary receipt admission requires it.
  RetainedMigrationProof check;
  if(!check.open([NSString stringWithUTF8String:maintenanceCustody->runtime().path.c_str()],maintenanceCustody->stateRoot(),
       receipt[@"profileSha256"],receipt[@"instance"],false)) return false;
  std::unique_ptr<QualificationProgressProof> proof;
  if(qualificationProgressPoint(job.qualificationPoint)) proof=std::make_unique<QualificationProgressProof>();
  {
    struct CaptureScope {
      ExitInspection& job;
      ~CaptureScope() { job.qualificationProofCapture=nullptr; }
    } captureScope{job};
    job.qualificationProofCapture=proof.get();
    if(!verifyRetainedMigration(check,job)||!current()) return false;
  }
  if(proof) {
    // Transfer only bounded inode stamps and the genuine verified receipt
    // reference. The output roster never retains an FD per proof member.
    proof->receipt=check.chain.receiptFile.record();
    proof->receiptsParent=maintenanceIdentity(receipts.identity);
    for(const auto* file:{&check.chain.receiptFile,&check.captureFile,&check.closedFile,&check.dataFile,
                          &publication->stagedFile,&publication->recordFile,&publication->markerFile}) {
      if(file->fd>=0) proof->files.emplace_back(file->path,file->identity);
    }
    for(const auto* directory:{&exits,&history,&claims,&captures,&publication->profile}) {
      if(!directory->current()) return false;
      proof->directories.emplace_back(directory->path,directory->identity);
    }
    if(publication->markerFile.fd<0) proof->absentMarker=publication->profile.path+"/engine.json";
    for(NSString* leaf in @[@"data",@"userData"]) {
      struct stat held{};
      NSString* key=[leaf isEqual:@"data"]?@"dataDirectory":@"userDataDirectory";
      if(fstatat(publication->profile.fd,leaf.UTF8String,&held,AT_SYMLINK_NOFOLLOW) ||
         !S_ISDIR(held.st_mode) || ![maintenanceIdentity(held) isEqual:publication->entry[key]]) return false;
      proof->directories.emplace_back(publication->profile.path+"/"+leaf.UTF8String,held);
    }
    proof->staging=publication->staging.path;
    if(!sameFile(published,check.chain.receiptFile.identity) || !receipts.current() || !check.current() ||
       fstat(publication->staging.fd,&proof->stagingStamp) || !qualificationDirectoryNames(publication->staging,{}) ||
       !qualificationDirectoryUnchanged(publication->staging,proof->stagingStamp)) return false;
    job.qualificationProgress=std::move(proof);
  }
  job.result=bytes(@{@"format":@1,@"kind":@"migration-committed",@"epoch":maintenanceCustody->epoch,
    @"attempt":receipt[@"attempt"],@"profileInstance":receipt[@"instance"],@"profilePathHash":receipt[@"profileSha256"],
    @"receipt":@{@"identity":maintenanceIdentity(published),@"sha256":hash}});
  return !job.result.empty()&&current();
}

static bool inspectExit(ExitInspection& job) {
  using namespace arbol_attempt;
  NSDictionary* input=job.input,*expected=input[@"attempt"]; NSString* leaf=input[@"runtimeLeaf"],*profile=input[@"profile"];
  bool prior=[input[@"mode"] isEqual:@"prior"],hostMode=[input[@"mode"] isEqual:@"host"],
    retire=[input[@"mode"] isEqual:@"retire"],reserve=[input[@"mode"] isEqual:@"reserve"],withdraw=[input[@"mode"] isEqual:@"withdraw"];
  bool progress=[input[@"mode"] isEqual:@"migrate-receipt-progress"],checked=[input[@"mode"] isEqual:@"migrate-committed-check"],
    recover=[input[@"mode"] isEqual:@"migrate-recover"],commit=[input[@"mode"] isEqual:@"migrate-commit"],
    migration=progress||checked||recover||commit||[input[@"mode"] isEqual:@"migrate-verify"];
  NSArray* inputKeys=@[@"format",@"mode",@"profile",@"profileInstance",@"profilePathHash",@"runtimeLeaf",@"bundle",@"attempt",@"previous",@"dataAttempt",@"pending"];
  if(commit||recover||progress||checked) inputKeys=[inputKeys arrayByAddingObject:@"migration"];
  if(migration&&!progress&&!checked) inputKeys=[inputKeys arrayByAddingObject:@"sources"];
  if(!job.within()||!keys(input,inputKeys)||
     ![input[@"format"] isEqual:@1]||(![@[@"prior",@"host",@"full",@"retire",@"reserve",@"withdraw"] containsObject:input[@"mode"]]&&!migration)||
     (migration&&!job.maintenance)||
     !path(profile)||!path(leaf)||!path(input[@"bundle"])||!pattern(input[@"profileInstance"],@"^prf_[A-Za-z0-9_-]{22}$")||
     ![input[@"profilePathHash"] isEqual:digest(profile.UTF8String)]||
     ![leaf.lastPathComponent isEqual:[input[@"profilePathHash"] substringToIndex:32]]||
     job.owner.path!=std::string(profile.fileSystemRepresentation)+"/owner.lock"||
     (reserve?(job.nextBuild.fd<0||!record(input[@"pending"])):input[@"pending"]!=NSNull.null)) return false;
  PackagedLayout inputLayout;
  if(!packagedLayout([input[@"bundle"] UTF8String],inputLayout)||inputLayout.guard!=job.build.path) return false;
  MigrationSourceCapture originalClosed,originalData;
  struct SourceScope { ExitInspection& job; ~SourceScope() { job.originalClosed=nullptr; job.originalData=nullptr; } } sourceScope{job};
  if(migration&&!progress&&!checked) {
    id sources=input[@"sources"];
    if(!keys(sources,@[@"closed",@"data"])) return false;
    for(NSString* key in @[@"closed",@"data"]) {
      bool data=[key isEqual:@"data"]; id claim=data?input[@"dataAttempt"]:expected;
      if(claim==NSNull.null) { if(sources[key]!=NSNull.null) return false; continue; }
      auto& source=data?originalData:originalClosed;
      if(!source.take(claim,data?job.dataBuild:job.build,sources[key],job)) return false;
      if(data) job.originalData=&source; else job.originalClosed=&source;
    }
  }
  MigrationObservation migrationSource;
  MigrationPublication publication;
  struct PublicationScope { ExitInspection& job; ~PublicationScope() { job.publication=nullptr; } } publicationScope{job};
  if(commit||recover||progress||checked) {
    if(!publication.open(input,recover,job.deadline,job.qualificationStagingParent)) return false; job.publication=&publication;
    if(job.qualificationPoint && (!maintenanceCustody->publishedProgressParent ||
       !publication.qualificationProgress.openPath(publication.attempt.path+"/progress",maintenanceCustody->publishedProgressParent) ||
       !qualificationWorkerTransaction(job))) return false;
    if(!rewrittenMigrationMetadata(job)) return false;
  } else if(migration&&!migrationSource.capture(job)) return false;
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
  MaintenanceDirectory historyAuthority;
  if(migration&&!historyMissing&&(!historyAuthority.openPath(historyPath.fileSystemRepresentation)||
     historyAuthority.identity.st_dev!=historyIdentity.st_dev||historyAuthority.identity.st_ino!=historyIdentity.st_ino)) return false;
  Claim claim; std::string currentRaw,headRaw,pointerRaw; bool absent=true,headAbsent=true,pointerAbsent=true;
  MissingMigrationRuntime missingRuntime; bool runtimeMissing=false; struct stat runtimeIdentity{};
  if(migration&&lstat(leaf.fileSystemRepresentation,&runtimeIdentity)) {
    if(errno!=ENOENT||!missingRuntime.capture(leaf,input[@"profilePathHash"])) return false; runtimeMissing=true;
  }
  if((!runtimeMissing&&(!claim.acquire(std::string(leaf.fileSystemRepresentation)+"/claim.json",job.deadline)||
     !readAt(claim.at.directory,"claim.json",currentRaw,absent)))||
     (!historyMissing&&(!readAt(history.fd,"previous-claim.json",headRaw,headAbsent)||
       !readAt(history.fd,"current-attempt.json",pointerRaw,pointerAbsent)))||!job.within()) return false;
  NSDictionary* current=absent?nil:(migration?strictManagementObject(currentRaw):json(currentRaw)),
    *head=headAbsent?nil:(migration?strictManagementObject(headRaw):json(headRaw)),
    *pointer=pointerAbsent?nil:(migration?strictManagementObject(pointerRaw):json(pointerRaw));
  if(migration&&((!absent&&!current)||(!headAbsent&&!head)||(!pointerAbsent&&!pointer))) return false;
  auto sameProfile=[&](NSDictionary* value) { return record(value)&&[value[@"profile"] isEqual:profile]&&
    [value[@"profileInstance"] isEqual:input[@"profileInstance"]]&&[value[@"profilePathHash"] isEqual:input[@"profilePathHash"]]; };
  if((current&&!sameProfile(current))||(head&&(!sameProfile(head)||![head[@"phase"] isEqual:@"closed"]))||
     (pointer&&(!sameProfile(pointer)||![pointer[@"phase"] isEqual:@"pending"]))||
     ((current||head)&&!pointer)||(pointer&&!immutable(pointer,current?:head))) return false;
  std::function<bool()> reverify;
  auto result=[&](NSString* kind,NSDictionary* data,NSString* request) {
    bool clean=[kind isEqual:@"activated"];
    if(migration) {
      if(!commit&&!recover&&(!migrationSource.current()||(!data&&!migrationSource.neverOpened(job)))) return false;
      id closed=expected==(id)NSNull.null?nil:expected;
      NSDictionary* evidence=@{@"classification":data?(clean?@"clean":@"dirty"):@"never-opened",@"clean":@(clean),
        @"closedClaimSha256":closed?(id)digest(bytes(closed)):NSNull.null,@"dataClaimSha256":data?(id)digest(bytes(data)):NSNull.null,
        @"terminalPath":data?data[@"terminal"][@"path"]:(id)NSNull.null,
        @"terminalSha256":data?data[@"terminal"][@"digest"]:(id)NSNull.null};
      if(commit||recover) {
        auto claimsCurrent=[&] {
          std::string actual; bool missing=true;
          if(runtimeMissing) { if(!missingRuntime.current()) return false; }
          else if(!unchanged(claim.at)||!readAt(claim.at.directory,"claim.json",actual,missing)||
            missing!=absent||actual!=currentRaw) return false;
          int historyFd=history.fd;
          if(historyAuthority.fd<0) {
            struct stat named{}; errno=0;
            return historyMissing&&lstat(historyPath.fileSystemRepresentation,&named)<0&&errno==ENOENT;
          }
          if(!historyAuthority.current()) return false;
          historyFd=historyAuthority.fd;
          if(!readAt(historyFd,"previous-claim.json",actual,missing)||missing!=headAbsent||actual!=headRaw||
             !readAt(historyFd,"current-attempt.json",actual,missing)||missing!=pointerAbsent||actual!=pointerRaw) return false;
          return historyAuthority.current();
        };
        if(recover) {
          if(!reverify||!claimsCurrent()||![evidence isEqual:publication.entry[@"evidence"]]||
             !rewrittenMigrationMetadata(job)||(!data&&!migrationNeverOpened(publication.receipt,job))) return false;
          job.recoveryReady=bytes(@{@"format":@1,@"kind":@"migration-record-permit",@"epoch":maintenanceCustody->epoch,
            @"attempt":publication.receipt[@"attempt"],@"profileInstance":input[@"profileInstance"],@"profilePathHash":input[@"profilePathHash"],
            @"record":publication.targetRecord().record()});
          if(job.recoveryReady.empty()||!job.within()) return false;
          job.recoveryPermit.store(1,std::memory_order_release);
          while(job.recoveryPermit.load(std::memory_order_acquire)==1) {
            if(!job.within()||!claimsCurrent()) return false; usleep(10000);
          }
          int requested=2;
          const auto checkpoint=[&](NSString* point) {
            if(![job.qualificationPoint isEqual:point]) return true;
            const auto original=[&] {
              struct stat replaced{};
              return job.recoveryPermit.load(std::memory_order_acquire)==3&&publication.replaced&&
                !fstat(publication.recordFile.fd,&replaced)&&replaced.st_nlink==0&&
                claimsCurrent()&&reverify()&&rewrittenMigrationMetadata(job)&&
                (data||migrationNeverOpened(publication.receipt,job));
            };
            NSArray* artifacts=@[qualificationArtifact(@"staged-progress",publication.stagedFile,
                job.qualificationStaged[@"sha256"]),
              qualificationArtifact(@"record",publication.targetRecord(),publication.staged[@"record"][@"sha256"])];
            return parkQualificationWorker(job,point,artifacts,original);
          };
          if(!job.recoveryPermit.compare_exchange_strong(requested,3,std::memory_order_acq_rel)||
             !job.within()||!claimsCurrent()||!reverify()||!publication.replaceRecord(checkpoint)||
             !claimsCurrent()||!reverify()||!rewrittenMigrationMetadata(job)||
             (!data&&!migrationNeverOpened(publication.receipt,job))) return false;
          job.result=bytes(@{@"format":@1,@"kind":@"migration-record-recovered",@"epoch":maintenanceCustody->epoch,
            @"attempt":publication.receipt[@"attempt"],@"profileInstance":input[@"profileInstance"],@"profilePathHash":input[@"profilePathHash"],
            @"record":publication.targetRecord().record()});
          return !job.result.empty()&&job.within()&&claimsCurrent();
        }
        auto bindHistory=[&](int original) {
          struct stat held{}; if(fstat(original,&held)) return false;
          if(historyAuthority.fd<0&&(!historyMissing||!historyAuthority.openPath(historyPath.fileSystemRepresentation))) return false;
          return historyAuthority.current()&&historyAuthority.identity.st_dev==held.st_dev&&historyAuthority.identity.st_ino==held.st_ino&&claimsCurrent();
        };
        return publishMigration(job,closed,data,evidence,claimsCurrent,bindHistory,historyMissing,reverify)&&claimsCurrent();
      }
      job.result=bytes(@{@"format":@1,@"kind":@"migration-verification",@"epoch":maintenanceCustody->epoch,
        @"profileInstance":input[@"profileInstance"],@"profilePathHash":input[@"profilePathHash"],@"evidence":evidence,
        @"profileDirectory":maintenanceIdentity(migrationSource.directory.identity),@"record":migrationSource.record.record(),
        @"marker":migrationSource.markerAbsent?(id)NSNull.null:migrationSource.marker.record()});
      return !job.result.empty()&&job.within()&&migrationSource.current()&&(!runtimeMissing||missingRuntime.current());
    }
    NSDictionary* expectation=data?@{@"kind":clean?@"activated":@"terminal",@"path":data[@"terminal"][@"path"],@"digest":data[@"terminal"][@"digest"]}:@{@"kind":@"absent"};
    if(data&&job.appliedMigration) {
      NSMutableDictionary* migrated=[expectation mutableCopy]; migrated[@"migration"]=job.appliedMigration; expectation=migrated;
    }
    job.result=bytes(@{@"format":@1,@"kind":kind,@"clean":@(clean),@"prior":expectation,@"request":request?:(id)NSNull.null});
    return !job.result.empty()&&job.within();
  };
  if(withdraw) {
    // Owner custody grants cancellation only, never exit. A possible original
    // actor must still produce native no-use or complete enrolled closure.
    PackagedLayout layout;
    if(!current||!claimedLayout(current,layout)||!expected||![current isEqual:expected]||![current[@"stage"] isEqual:@"untransferred"]||
       ![@[@"pending",@"claimed",@"cancelled"] containsObject:current[@"phase"]]||current[@"terminal"]!=NSNull.null||
       job.build.path!=std::string([current[@"buildGuard"] UTF8String])||
       ![input[@"bundle"] isEqual:[NSString stringWithUTF8String:layout.bundle.c_str()]]||
       !arbol_boundary::signature([input[@"bundle"] UTF8String],false)) return false;
    NSMutableDictionary* cancelled=[current mutableCopy]; cancelled[@"phase"]=@"cancelled";
    if(!record(cancelled)||!job.within()||!replace(claim.at,currentRaw,false,bytes(cancelled))) return false;
    return result(@"withdrawn",nil,current[@"request"]);
  }
  // Long read-only verification yields this same stable short Claim while
  // preserving actual Owner and every old/data/new Build open description.
  if(!runtimeMissing&&!migration&&flock(claim.fd,LOCK_UN)) return false;
  auto reclaim=[&] {
    while(!runtimeMissing&&!migration&&flock(claim.fd,LOCK_EX|LOCK_NB)) {
      if((errno!=EWOULDBLOCK&&errno!=EAGAIN)||!job.within()) return false; usleep(1000);
    }
    std::string checked; bool missing; struct stat heldHistory{},namedHistory{};
    bool stableHistory=historyMissing||(!fstat(history.fd,&heldHistory)&&!lstat(historyPath.fileSystemRepresentation,&namedHistory)&&
      heldHistory.st_dev==historyIdentity.st_dev&&heldHistory.st_ino==historyIdentity.st_ino&&
      heldHistory.st_dev==namedHistory.st_dev&&heldHistory.st_ino==namedHistory.st_ino&&
      S_ISDIR(namedHistory.st_mode)&&namedHistory.st_uid==geteuid()&&(namedHistory.st_mode&07777)==0700);
    if(historyMissing) { errno=0; stableHistory=lstat(historyPath.fileSystemRepresentation,&namedHistory)<0&&errno==ENOENT; }
    return job.within()&&stableHistory&&
      (runtimeMissing?missingRuntime.current():(unchanged(claim.at)&&
        readAt(claim.at.directory,"claim.json",checked,missing)&&missing==absent&&checked==currentRaw))&&
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
  if(progress||checked) {
    if(!originalMaintenanceBuild(job.build)||job.build.path!=maintenanceCustody->newGuard().lock.path||
       ![input[@"bundle"] isEqual:[NSString stringWithUTF8String:maintenanceCustody->layout().bundle.c_str()]]||
       (closed?![closed isEqual:expected]:expected!=(id)NSNull.null)||!reclaim()) return false;
    struct stat completeIdentity{}; errno=0;
    bool completed=!fstatat(publication.attempt.fd,"completed.json",&completeIdentity,AT_SYMLINK_NOFOLLOW);
    if((!completed&&errno!=ENOENT)||(progress&&completed)) return false;
    RetainedMigrationProof proof;
    if(!proof.open([NSString stringWithUTF8String:maintenanceCustody->runtime().path.c_str()],maintenanceCustody->stateRoot(),
         input[@"profilePathHash"],input[@"profileInstance"],completed)||
       ![proof.chain.receipt[@"attempt"] isEqual:input[@"migration"][@"attempt"]]||
       ![proof.chain.receipt[@"transactionSha256"] isEqual:input[@"migration"][@"transactionSha256"]]||
       ![proof.chain.transaction isEqual:publication.transaction]||
       (closed?![closed isEqual:proof.closed]:proof.closed!=nil)) return false;
    bool unused=closed&&[[closed[@"terminal"][@"path"] lastPathComponent] isEqual:@"unused.json"];
    id expectedData=unused&&proof.data?proof.data:(id)NSNull.null;
    if(![input[@"dataAttempt"] isEqual:expectedData]) return false;
    MaintenanceDirectory progressAuthority;
    if(!progressAuthority.openPath(publication.attempt.path+"/progress")) return false;
    const std::string committed=std::string([input[@"profilePathHash"] UTF8String])+".committed.json";
    MaintenanceFile committedFile;
    if(checked) {
      if(!committedFile.openPath(progressAuthority.path+"/"+committed,0600,limit,true)) return false;
      id value=strictManagementObject(committedFile.content);
      if(!keys(value,@[@"format",@"attempt",@"profileSha256",@"receipt"])||!arbol_exit::migrationFormat(value[@"format"],1)||
         ![value[@"attempt"] isEqual:proof.chain.receipt[@"attempt"]]||![value[@"profileSha256"] isEqual:input[@"profilePathHash"]]||
         ![value[@"receipt"] isEqual:proof.chain.receiptFile.record()]) return false;
    }
    auto continuity=[&] {
      std::string raw; bool missing; struct stat named{};
      if(!job.within()||!publication.current()||!proof.current()) return false;
      if(runtimeMissing) { if(!missingRuntime.current()) return false; }
      else if(!unchanged(claim.at)||!readAt(claim.at.directory,"claim.json",raw,missing)||missing!=absent||raw!=currentRaw) return false;
      // A published receipt necessarily retained normal native evidence here.
      if(historyMissing||!historyAuthority.current()||
         !readAt(historyAuthority.fd,"previous-claim.json",raw,missing)||missing!=headAbsent||raw!=headRaw||
         !readAt(historyAuthority.fd,"current-attempt.json",raw,missing)||missing!=pointerAbsent||raw!=pointerRaw) return false;
      if(!completed) { errno=0; if(!fstatat(publication.attempt.fd,"completed.json",&named,AT_SYMLINK_NOFOLLOW)||errno!=ENOENT) return false; }
      if(!progressAuthority.current()) return false;
      if(checked) return committedFile.current()&&proof.current();
      errno=0; return fstatat(progressAuthority.fd,committed.c_str(),&named,AT_SYMLINK_NOFOLLOW)<0&&errno==ENOENT&&progressAuthority.current();
    };
    if(!continuity()||!verifyRetainedMigration(proof,job)||!continuity()) return false;
    if(input[@"previous"]!=NSNull.null) {
      id previous=input[@"previous"];
      bool latest=closed&&closed[@"runtime"]!=NSNull.null&&runtime(previous,closed)&&sameRuntimeBinding(previous,closed[@"runtime"]);
      bool writer=proof.data&&proof.data[@"runtime"]!=NSNull.null&&runtime(previous,proof.data)&&sameRuntimeBinding(previous,proof.data[@"runtime"]);
      bool prefix=false;
      if(unused) {
        std::string raw; NSDictionary* witness=nil; struct stat identity{};
        if(!exitReceiptAt(closed[@"terminal"][@"path"],raw,witness,identity)||![digest(raw) isEqual:closed[@"terminal"][@"digest"]]) return false;
        prefix=runtime(previous,closed)&&[previous[@"phase"] isEqual:@"starting"]&&
          [previous[@"pid"] isEqual:witness[@"actor"][@"pid"]]&&[previous[@"processStartId"] isEqual:witness[@"actor"][@"startId"]];
      }
      if(!latest&&!writer&&!prefix) return false;
    }
    NSMutableDictionary* result=[@{@"format":@1,@"kind":checked?@"migration-committed-validated":@"migration-receipt-progress",@"epoch":maintenanceCustody->epoch,
      @"attempt":proof.chain.receipt[@"attempt"],@"profileInstance":input[@"profileInstance"],@"profilePathHash":input[@"profilePathHash"],
      @"receipt":proof.chain.receiptFile.record()} mutableCopy];
    if(checked) { result[@"committed"]=committedFile.record(); result[@"completion"]=completed?(id)proof.chain.completionFile.record():NSNull.null; }
    job.result=bytes(result);
    return !job.result.empty()&&continuity();
  }
  arbol_startup_proof::RetainedAppPackage reservationPackage;
  const arbol_startup_proof::RetainedAppPackage* activePackage=nullptr;
  OrdinaryMigrationAuthority ordinaryAuthority;
  MaintenanceFile candidateFile; NSDictionary* candidateReceipt=nil;
  RetainedMigrationProof appliedProof; bool applied=false,wholeReceipt=false;
  struct ReceiptAuthorityScope { ExitInspection& job; ~ReceiptAuthorityScope() { job.receiptAuthority=nullptr; } } receiptAuthorityScope{job};
  if(profileFormat==2&&!migration) {
    NSString* snapshot=nil;
    if(prior||hostMode) {
      snapshot=current[@"candidateDigest"];
      activePackage=adoptedPackage.get();
    } else if(reserve) {
      PackagedLayout selection;
      NSDictionary* pending=input[@"pending"];
      snapshot=pending[@"candidateDigest"];
      if(claimedLayout(pending,selection)&&selection.bundle==job.activeBundle&&selection.guard==job.nextBuild.path&&
         reservationPackage.capture(selection,std::min(job.deadline,arbol_boundary::clockMs()+250),snapshot))
        activePackage=&reservationPackage;
    }
    if(job.activeBuild.fd<0||job.activeBundle.empty()||
       !ordinaryAuthority.open(job.activeBundle,profile,job.activeBuild,job.deadline,activePackage,snapshot)) return false;
    if(ordinaryAuthority.available) {
      const std::string path=ordinaryAuthority.runtimePath+"/browser-profile-migration/receipts/"+[input[@"profilePathHash"] UTF8String]+".json";
      struct stat st{}; errno=0;
      if(lstat(path.c_str(),&st)) { if(errno!=ENOENT) return false; }
      else {
        if(!candidateFile.openPath(path,0600,arbol_exit::exitReceiptLimit,true)) return false;
        id candidate=strictManagementObject(candidateFile.content,arbol_exit::exitReceiptLimit);
        if(!arbol_exit::migrationReceipt(candidate)||![candidate[@"profilePath"] isEqual:profile]||
           ![candidate[@"profileSha256"] isEqual:input[@"profilePathHash"]]) return false;
        // Recreated instances and superseded data keep the ordinary proof.
        // No invalid applicable receipt ever falls back to retired Build I/O.
        if([candidate[@"instance"] isEqual:input[@"profileInstance"]]) candidateReceipt=candidate;
      }
    }
    if(candidateReceipt) wholeReceipt=closed?
      [digest(bytes(closed)) isEqual:candidateReceipt[@"evidence"][@"closedClaimSha256"]]:
      candidateReceipt[@"evidence"][@"closedClaimSha256"]==NSNull.null&&candidateReceipt[@"evidence"][@"dataClaimSha256"]==NSNull.null;
  }
  auto applyReceipt=[&](NSDictionary* observedData,bool whole) {
    if(!candidateReceipt||!candidateFile.current()||!ordinaryAuthority.current()) return false;
    if(!applied) {
      if(!appliedProof.open([NSString stringWithUTF8String:ordinaryAuthority.runtimePath.c_str()],ordinaryAuthority.state,
           input[@"profilePathHash"],input[@"profileInstance"],true)||
         ![appliedProof.chain.receiptFile.record() isEqual:candidateFile.record()]||
         ![appliedProof.chain.receipt isEqual:candidateReceipt]) return false;
      job.receiptAuthority=&ordinaryAuthority; applied=true;
    }
    if(whole?(closed?![closed isEqual:appliedProof.closed]:appliedProof.closed!=nil):
        (!observedData||![observedData isEqual:appliedProof.data])) return false;
    if(!verifyRetainedMigration(appliedProof,job)) return false;
    job.appliedMigration=@{@"path":[NSString stringWithUTF8String:candidateFile.path.c_str()],@"digest":digest(candidateFile.content)};
    return job.within();
  };
  auto withReceipt=[&](const std::function<bool()>& operation) {
    if(!applied) return operation();
    if(job.migrated||!appliedProof.current()) return false;
    struct Scope { ExitInspection& job; ~Scope() { job.migrated=nullptr; } } scope{job};
    job.migrated=&appliedProof; return operation();
  };
  NSDictionary* data=nil,*capability=nil,*receipt=nil,*frontier=nil,*unusedReceipt=nil;
  bool unused=closed&&[[closed[@"terminal"][@"path"] lastPathComponent] isEqual:@"unused.json"];
  std::map<std::pair<std::string,std::string>,std::unique_ptr<arbol_startup_proof::RetainedAppPackage>> verifiedPackages;
  auto verifiedSignature=[&](const PackagedLayout& layout, NSDictionary* attempt) {
    NSString* digest=attempt[@"candidateDigest"];
    if(reserve&&activePackage&&activePackage->witnessed()&&activePackage->matches(layout,digest))
      return activePackage->current();
    if (!migration && (prior || hostMode) && adoptedPackage && adoptedPackage->matches(layout,digest))
      return adoptedPackage->current();
    // After watchdog enrollment, the process family admits no Apple tools.
    if (!migration && (prior || reserve) && layout.installed) {
      if (!pattern(digest,@"^[0-9a-f]{64}$")) return false;
      auto key=std::make_pair(layout.bundle,std::string(digest.UTF8String));
      auto [entry, inserted]=verifiedPackages.try_emplace(key);
      if (inserted) {
        auto proof=std::make_unique<arbol_startup_proof::RetainedAppPackage>();
        if (proof->capture(layout,job.deadline,digest)) entry->second=std::move(proof);
      }
      if (entry->second) return entry->second->current();
    }
    return arbol_boundary::signature(layout.bundle,false);
  };
  auto verify=[&] {
    if(wholeReceipt) {
      if((closed?![closed isEqual:expected]:expected!=(id)NSNull.null)||!applyReceipt(nil,true)) return false;
      data=appliedProof.data;
      id expectedData=unused&&data?data:(id)NSNull.null;
      if(![input[@"dataAttempt"] isEqual:expectedData]) return false;
      if(unused) {
        std::string raw; struct stat identity{};
        if(!exitReceiptAt(closed[@"terminal"][@"path"],raw,unusedReceipt,identity)||
           ![digest(raw) isEqual:closed[@"terminal"][@"digest"]]) return false;
      }
      if(!closed&&(input[@"previous"]!=NSNull.null||retire)) return false;
    } else if(!closed) {
      if(expected!=(id)NSNull.null||input[@"dataAttempt"]!=NSNull.null||input[@"previous"]!=NSNull.null||retire) return false;
    } else {
      PackagedLayout layout;
      if(!claimedLayout(closed,layout)||expected==(id)NSNull.null||![closed isEqual:expected]||!sameProfile(closed)||
         job.build.path!=std::string([closed[@"buildGuard"] UTF8String])||
         ![input[@"bundle"] isEqual:[NSString stringWithUTF8String:layout.bundle.c_str()]]||
         !verifiedSignature(layout,closed)) return false;
      if(unused) {
        if(!verifyUnusedReceipt(closed,unusedReceipt,job)) return false;
        data=unusedReceipt[@"priorDataClaim"]==NSNull.null?nil:unusedReceipt[@"priorDataClaim"];
      } else {
        if(input[@"dataAttempt"]!=NSNull.null) return false;
        data=closed;
      }
    }
      if(data) {
        const auto& guard=unused?job.dataBuild:job.build;
        PackagedLayout dataLayout; if(!claimedLayout(data,dataLayout)) return false;
        NSString* bundle=[NSString stringWithUTF8String:dataLayout.bundle.c_str()];
        bool covered=wholeReceipt||(unused&&candidateReceipt&&[digest(bytes(data)) isEqual:candidateReceipt[@"evidence"][@"dataClaimSha256"]]);
        if(covered) {
          if(!applyReceipt(data,wholeReceipt)||!withReceipt([&] {
            return verifyClosedReceipt(data,capability,receipt,frontier,job,job.build,bundle)&&
              (prior||receiptMarker(capability,receipt[@"marker"],job));
          })) return false;
        } else if(guard.fd<0||guard.path!=std::string([data[@"buildGuard"] UTF8String])||!verifiedSignature(dataLayout,data)||
            !verifyClosedReceipt(data,capability,receipt,frontier,job,guard,bundle)||
            (!prior&&!receiptMarker(capability,receipt[@"marker"],job))) return false;
      }
      if(closed&&input[@"previous"]!=NSNull.null) {
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
    if(!data&&!prior) {
      arbol_exit::NativeFile root; root.fd=open(profile.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
      std::string raw; struct stat marker{}; bool missing;
      if(root.fd<0||!markerAt(root.fd,raw,marker,missing)||!missing||!root.finish()) return false;
    }
    return job.within();
  };
  auto physical=[&] {
    if(data&&!withReceipt([&] { return receiptMetadata(capability,data,job)&&receiptFrontier(capability,frontier,receipt[@"capabilityDigest"],job)&&
       (prior||receiptMarker(capability,receipt[@"marker"],job)); })) return false;
    if(unused) {
      std::string raw; NSDictionary* checked=nil; struct stat identity{};
      if(!exitReceiptAt(closed[@"terminal"][@"path"],raw,checked,identity)||
         ![digest(raw) isEqual:closed[@"terminal"][@"digest"]]||![checked isEqual:unusedReceipt]) return false;
    }
    return job.within();
  };
  if(!verify()||!physical()||(!runtimeMissing&&!unchanged(claim.at))||!reclaim()) return false;
  reverify=[&] { return verify()&&physical()&&(!runtimeMissing?unchanged(claim.at):missingRuntime.current()); };
  if(reserve) {
    NSDictionary* next=input[@"pending"]; PackagedLayout nextLayout;
    // This privileged transition is distinct from generic Role::starter. Repeat
    // all terminal/prior-data/physical checks with this ONE genuine Claim held;
    // only then can the actual live starter replace the unchanged exact record.
    if(!verify()||!physical()||!sameProfile(next)||!claimedLayout(next,nextLayout)||!transition(nil,next,Role::starter)||
       job.nextBuild.path!=std::string([next[@"buildGuard"] UTF8String])||
       !verifiedSignature(nextLayout,next)||
       (current&&[current[@"request"] isEqual:next[@"request"]])||historyMissing) return false;
    // Persist predecessor first, newest immutable reservation second, and only
    // then install pending atomically. Interrupted publication fails closed:
    // a missing/mismatched newest claim cannot fall back to an older witness.
    if(closed&&(!head||![head isEqual:closed])&&!writeExitHistory(history.fd,"previous-claim.json",closed,job)) return false;
    if(!writeExitHistory(history.fd,"current-attempt.json",next,job)||
       !std::all_of(verifiedPackages.begin(),verifiedPackages.end(),[](const auto& item) { return !item.second||item.second->current(); })||
       !job.within()||
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
  napi_value args[8]; size_t n=8; void *ownerValue=nullptr,*buildValue=nullptr; std::string input; double deadline;
  if(napi_get_cb_info(env,info,&n,args,nullptr,nullptr)!=napi_ok||(n!=6&&n!=8)||napi_get_value_external(env,args[0],&ownerValue)!=napi_ok||
     napi_get_value_external(env,args[1],&buildValue)!=napi_ok||!boundedText(env,args[2],input,65536)||
     napi_get_value_double(env,args[3],&deadline)!=napi_ok||!std::isfinite(deadline)||deadline<=arbol_boundary::clockMs()||
     deadline>arbol_boundary::clockMs()+10000||!arbol_boundary::retainNativeImage()) return fail(env);
  auto* owner=static_cast<HeldLock*>(ownerValue); auto* build=static_cast<HeldLock*>(buildValue);
  NSData* command=[NSData dataWithBytes:input.data() length:input.size()];
  id parsed=[NSJSONSerialization JSONObjectWithData:command options:0 error:nil];
  if (![parsed isKindOfClass:NSDictionary.class]) return fail(env);
  bool migration = migrationInspectionMode(parsed[@"mode"]);
  HeldLock* registry=nullptr;
  NSString* qualificationPoint=nil;
  NSDictionary* qualificationStaged=nil;
  NSDictionary* qualificationStagingParent=nil;
  if (migration) {
    void *registryValue=nullptr,*custodyValue=nullptr;
    if(n!=8||!maintenanceStateRoot||!maintenanceStateRoot->current()||
       napi_get_value_external(env,args[6],&registryValue)!=napi_ok||napi_get_value_external(env,args[7],&custodyValue)!=napi_ok||
       custodyValue!=maintenanceCustody) return fail(env);
    registry=static_cast<HeldLock*>(registryValue);
    if(!liveLocks.count(registry)||registry->mode!=LOCK_EX||
       registry->path!=std::string([maintenanceCustody->stateRoot() UTF8String])+"/registry.lock") return fail(env);
  } else if(n!=6) return fail(env);
  if(!liveLocks.count(owner)||!liveLocks.count(build)||owner->mode!=LOCK_EX||
     (build->mode!=LOCK_SH&&!(migration&&originalMaintenanceBuildHandle(build)))) return fail(env);
  if(migration && (arbol_attempt::qualificationNativePublicationPoint(maintenanceCustody->interruption[@"point"]) ||
     arbol_attempt::qualificationProgressPoint(maintenanceCustody->interruption[@"point"])) &&
     [@[@"migrate-recover",@"migrate-commit"] containsObject:parsed[@"mode"]]) {
    auto& custody=*maintenanceCustody;
    if(!arbol_attempt::qualificationDigest(parsed[@"profilePathHash"]) || !custody.originalInterruption() ||
       !qualificationTransactionGuards(custody) || registry!=custody.interruptionRegistry ||
       std::find(custody.interruptionOwners.begin(),custody.interruptionOwners.end(),owner)==custody.interruptionOwners.end()) return fail(env);
    qualificationPoint=custody.interruption[@"point"];
    qualificationStaged=custody.nativeStagedPublications[[parsed[@"profilePathHash"] stringByAppendingString:@".staged.json"]];
    qualificationStagingParent=custody.nativeStagingParents[parsed[@"profilePathHash"]];
    if(!arbol_exit::migrationFile(qualificationStaged)||!arbol_exit::migrationIdentity(qualificationStagingParent,0700)) return fail(env);
  }
  HeldLock* additional[2]={nullptr,nullptr};
  for(unsigned i=0;i<2;++i) {
    napi_valuetype type; void* value=nullptr;
    if(napi_typeof(env,args[i+4],&type)!=napi_ok) return fail(env);
    if(type==napi_null) continue;
    if(napi_get_value_external(env,args[i+4],&value)!=napi_ok) return fail(env);
    additional[i]=static_cast<HeldLock*>(value);
    if(!liveLocks.count(additional[i])||(additional[i]->mode!=LOCK_SH&&!(migration&&originalMaintenanceBuildHandle(additional[i])))) return fail(env);
  }
  auto* job=new ExitInspection; job->owner=duplicateHeld(owner); job->build=duplicateHeld(build); job->deadline=deadline;
  if(arbol_attempt::profileFormat==2&&!migration) {
    NSDictionary* self=arbol_attempt::processRecord(getpid());
    NSString* executable=self[@"executable"];
    NSString* suffix=@"/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron";
    if([executable hasSuffix:suffix]) {
      NSString* bundle=[executable substringToIndex:executable.length-suffix.length];
      arbol_attempt::PackagedLayout own;
      if(arbol_attempt::packagedLayout(bundle.UTF8String,own)) {
        job->activeBundle=own.bundle;
        for(auto* held:liveLocks) if(held->mode==LOCK_SH&&held->path==own.guard) {
          job->activeBuild=duplicateHeld(held); if(job->activeBuild.fd>=0) break;
        }
      }
    }
  }
  // In-process command bytes are ordinary JSON, not a durable canonical exit
  // certificate. Parse immutable data, then enforce exact envelope keys and
  // each complete 16 KiB native attempt grammar independently below.
  job->input=[parsed isKindOfClass:NSDictionary.class]?parsed:nil;
  job->maintenance=migration;
  job->qualificationPoint=qualificationPoint; job->qualificationStaged=qualificationStaged;
  job->qualificationStagingParent=qualificationStagingParent;
  if(registry) job->registry=duplicateHeld(registry);
  if(additional[0]) job->dataBuild=duplicateHeld(additional[0]);
  if(additional[1]) job->nextBuild=duplicateHeld(additional[1]);
  auto closeInputs=[&] { for(auto* lock:{&job->owner,&job->build,&job->dataBuild,&job->nextBuild,&job->registry,&job->activeBuild}) if(lock->fd>=0) close(lock->fd); };
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
    copy.bundle=c->context.bundle; copy.digest=c->context.digest; copy.session=c->context.session; copy.app=c->context.app;
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
      for(auto* lock:{&job->owner,&job->build,&job->dataBuild,&job->nextBuild,&job->registry,&job->activeBuild}) if(lock->fd>=0&&close(lock->fd)) ok=false;
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
  if(job->qualificationProgress) {
    auto& writer=maintenanceCustody->progressWriter;
    auto profile=writer.byHash.find([job->input[@"profilePathHash"] UTF8String]);
    if(profile==writer.byHash.end() || profile->second.proof || !maintenanceCustody->originalInterruption()) return fail(env);
    profile->second.proof=std::move(job->qualificationProgress);
  }
  return text(env,job->result);
}
static napi_value pollMigrationRecovery(napi_env env,napi_callback_info info) {
  auto* job=exitInspectionArgument(env,info);
  if(!job||!job->maintenance||![job->input[@"mode"] isEqual:@"migrate-recover"]||
     job->state.load(std::memory_order_acquire)<0||job->cancelled.load(std::memory_order_acquire)||
     arbol_boundary::clockMs()>=job->deadline) return fail(env);
  int permission=job->recoveryPermit.load(std::memory_order_acquire);
  if(!permission) { napi_value out; napi_get_null(env,&out); return out; }
  return permission==1?text(env,job->recoveryReady):fail(env);
}
static napi_value consumeMigrationRecovery(napi_env env,napi_callback_info info) {
  auto* job=exitInspectionArgument(env,info); int ready=1;
  if(!job||!job->maintenance||![job->input[@"mode"] isEqual:@"migrate-recover"]||
     job->state.load(std::memory_order_acquire)!=0||job->cancelled.load(std::memory_order_acquire)||
     arbol_boundary::clockMs()>=job->deadline||!job->recoveryPermit.compare_exchange_strong(ready,2,std::memory_order_acq_rel)) return fail(env);
  napi_value out; napi_get_undefined(env,&out); return out;
}
static napi_value cancelExitInspection(napi_env env,napi_callback_info info) {
  auto* job=exitInspectionArgument(env,info); if(!job) return fail(env);
  job->cancelled.store(true,std::memory_order_release); napi_value out; napi_get_undefined(env,&out); return out;
}

static napi_value inspectInstalledMountTopology(napi_env env, napi_callback_info info) {
  size_t count = 2;
  napi_value args[2];
  std::string bundle;
  int32_t fd = -1;
  if (napi_get_cb_info(env, info, &count, args, nullptr, nullptr) != napi_ok || count != 2 ||
      !string(env, args[0], bundle) || napi_get_value_int32(env, args[1], &fd) != napi_ok || fd < 3) return fail(env);
  @autoreleasepool { try { @try {
    arbol_attempt::PackagedLayout layout;
    struct stat held{}, named{}, device{};
    struct statfs filesystem{}, current{};
    char original[PATH_MAX]{};
    if (!arbol_attempt::packagedLayout(bundle, layout) || !layout.installed || !arbol_boundary::canonical(bundle) ||
        fstat(fd, &held) || !S_ISDIR(held.st_mode) || lstat(bundle.c_str(), &named) ||
        held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        fcntl(fd, F_GETPATH, original) || bundle != original ||
        fstatfs(fd, &filesystem) || layout.buildRoot + "/app" != filesystem.f_mntonname ||
        (filesystem.f_flags & (MNT_RDONLY | MNT_LOCAL)) != (MNT_RDONLY | MNT_LOCAL) ||
        strcmp(filesystem.f_fstypename, "apfs") || lstat(filesystem.f_mntfromname, &device) ||
        !S_ISBLK(device.st_mode) || device.st_rdev != held.st_dev) return fail(env);
    const int available = getfsstat(nullptr, 0, MNT_NOWAIT);
    if (available < 1 || available >= 4096) return fail(env);
    std::vector<struct statfs> mounts(size_t(available) + 1);
    const int received = getfsstat(mounts.data(), int(mounts.size() * sizeof(struct statfs)), MNT_NOWAIT);
    if (received < 1 || size_t(received) >= mounts.size()) return fail(env);
    size_t matching = 0;
    for (int index = 0; index < received; ++index) {
      const struct statfs& mount = mounts[size_t(index)];
      if (arbol_attempt::within(mount.f_mntonname, filesystem.f_mntonname)) return fail(env);
      if (!strcmp(mount.f_mntonname, filesystem.f_mntonname)) {
        if (memcmp(&mount.f_fsid, &filesystem.f_fsid, sizeof(fsid_t))) return fail(env);
        ++matching;
      }
    }
    if (matching != 1 || statfs(bundle.c_str(), &current) ||
        memcmp(&current.f_fsid, &filesystem.f_fsid, sizeof(fsid_t)) ||
        (current.f_flags & (MNT_RDONLY | MNT_LOCAL)) != (MNT_RDONLY | MNT_LOCAL) ||
        strcmp(current.f_mntfromname, filesystem.f_mntfromname) ||
        strcmp(current.f_mntonname, filesystem.f_mntonname)) return fail(env);
    return text(env, std::to_string(filesystem.f_fsid.val[0]) + ":" + std::to_string(filesystem.f_fsid.val[1]));
  } @catch (NSException*) { return fail(env); } } catch (...) { return fail(env); } }
}

static napi_value init(napi_env env, napi_value exports) {
  napi_property_descriptor properties[] = {
    {"noteHostStartup",nullptr,noteHostStartup,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"publishHostReady",nullptr,publishHostReady,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"terminateAdoptedHost",nullptr,terminateAdoptedHost,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"beginExitInspection",nullptr,beginExitInspection,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"pollExitInspection",nullptr,pollExitInspection,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"pollMigrationRecovery",nullptr,pollMigrationRecovery,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"consumeMigrationRecovery",nullptr,consumeMigrationRecovery,nullptr,nullptr,nullptr,napi_default,nullptr},
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
    {"adoptInstalledLaunch",nullptr,adoptInstalledLaunch,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"inspectInstalledMountTopology",nullptr,inspectInstalledMountTopology,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"adoptMaintenanceCustody",nullptr,adoptMaintenanceCustody,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"assertMaintenanceCustody",nullptr,assertMaintenanceCustody,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"maintenanceInterruptionMatches",nullptr,maintenanceInterruptionMatches,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"bindMaintenanceTransaction",nullptr,bindMaintenanceTransaction,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"parkMaintenanceTransaction",nullptr,parkMaintenanceTransaction,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"parkMaintenanceStaging",nullptr,parkMaintenanceStaging,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"parkMaintenanceProgress",nullptr,parkMaintenanceProgress,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"prepareQualificationInterruptionPipes",nullptr,prepareQualificationInterruptionPipes,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"publishMaintenanceFile",nullptr,publishMaintenanceFile,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"observeMaintenanceStateRoot",nullptr,observeMaintenanceStateRoot,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"assertMaintenanceStateRoot",nullptr,assertMaintenanceStateRoot,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"continuousTime",nullptr,continuousTime,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"processProvenance",nullptr,processProvenance,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"requestProfileOpen",nullptr,requestProfileOpen,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"browserAppAvailable",nullptr,browserAppAvailable,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"activateProfileWindow",nullptr,activateProfileWindow,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"seqoyaBackendArguments",nullptr,seqoyaBackendArguments,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"readLaunchAttempt",nullptr,readLaunchAttempt,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"canonicalMigrationClaimDigest",nullptr,canonicalMigrationClaimDigest,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"writeLaunchAttempt",nullptr,writeLaunchAttempt,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"terminateProfileNow",nullptr,terminateProfileNow,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"prepareWatchdogCustody",nullptr,prepareWatchdogCustody,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"custodyDescriptors",nullptr,custodyDescriptors,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"captureWatchdog",nullptr,captureWatchdog,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"watchdogBind",nullptr,watchdogBind,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"watchdogAssert",nullptr,watchdogAssert,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"publishDirectory", nullptr, publishDirectory, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"retireInstallerRollback", nullptr, retireInstallerRollback, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"publishInstallerFile", nullptr, publishInstallerFile, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"trySharedLock", nullptr, trySharedLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"groupCensus", nullptr, groupCensus, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"tryLock", nullptr, tryLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"tryExistingInitializationLock", nullptr, tryExistingInitializationLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"tryExistingQualificationObserverLock", nullptr, tryExistingQualificationObserverLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"assertLock", nullptr, assertLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"releaseLock", nullptr, releaseLock, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"processIdentity", nullptr, processIdentity, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"peerIdentity", nullptr, peerIdentity, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, sizeof(properties) / sizeof(properties[0]), properties) != napi_ok) return fail(env);
  return exports;
}
NAPI_MODULE(NODE_GYP_MODULE_NAME, init)

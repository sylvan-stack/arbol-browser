#pragma once
// One native grammar/transaction for the CLI addon and signed fixed-exec outer.
// These are intent records, never watchdog, engine-exit or flush certificates.
#include "../../watchdog/boundary.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <cmath>
#include <pwd.h>
namespace arbol_attempt {
using arbol_boundary::Identity;
constexpr size_t limit = 16384;
inline bool keys(NSDictionary* object, NSArray* expected) {
  return [object isKindOfClass:NSDictionary.class] && [[NSSet setWithArray:object.allKeys] isEqual:[NSSet setWithArray:expected]];
}
inline bool pattern(id value, NSString* expression) {
  if (![value isKindOfClass:NSString.class]) return false;
  return [[NSRegularExpression regularExpressionWithPattern:expression options:0 error:nil]
    numberOfMatchesInString:value options:0 range:NSMakeRange(0, [value length])] == 1;
}
inline bool path(id value) {
  if (![value isKindOfClass:NSString.class] || [value length] == 0 || [value length] >= PATH_MAX) return false;
  NSData* encoded = [value dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO];
  // Shape only: no Foundation alias rewriting or filesystem resolution.
  // Reserve one byte for the NUL required by the actual filesystem consumers.
  size_t length = encoded.length;
  if (!encoded || !length || length >= PATH_MAX) return false;
  const unsigned char* bytes = (const unsigned char*)encoded.bytes;
  if (bytes[0] != '/') return false;
  if (length == 1) return true;
  size_t component = 1;
  for (size_t i = 1; i <= length; ++i) {
    if (i < length && bytes[i] != '/') {
      if (!bytes[i]) return false;
      continue;
    }
    size_t count = i - component;
    if (!count || (count == 1 && bytes[component] == '.') ||
        (count == 2 && bytes[component] == '.' && bytes[component + 1] == '.')) return false;
    component = i + 1;
  }
  return true;
}
inline bool uintNumber(id value, uint64_t& out) {
  if (![value isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) return false;
  double n = [value doubleValue]; if (!std::isfinite(n) || n < 0 || n > 9007199254740991.0 || n != floor(n)) return false;
  out = (uint64_t)n; return true;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
inline NSString* digest(const std::string& bytes) {
  unsigned char hash[CC_SHA256_DIGEST_LENGTH]; CC_SHA256(bytes.data(),(CC_LONG)bytes.size(),hash);
  NSMutableString* value = [NSMutableString new]; for (unsigned char byte : hash) [value appendFormat:@"%02x",byte]; return value;
}
#pragma clang diagnostic pop
inline bool process(NSDictionary* p) {
  uint64_t pid, uid, version, group, session, parentVersion;
  return keys(p,@[@"pid",@"uid",@"startId",@"pidVersion",@"group",@"session",@"parentStartId",@"parentPidVersion",@"executable"]) &&
    uintNumber(p[@"pid"],pid) && pid > 1 && pid <= INT_MAX && uintNumber(p[@"uid"],uid) && uid == geteuid() &&
    uintNumber(p[@"pidVersion"],version) && version > 0 && version <= INT_MAX && uintNumber(p[@"group"],group) && group > 0 && group <= INT_MAX &&
    uintNumber(p[@"session"],session) && session > 0 && session <= INT_MAX &&
    uintNumber(p[@"parentPidVersion"],parentVersion) && parentVersion <= INT_MAX &&
    pattern(p[@"startId"],@"^[1-9][0-9]{0,19}$") && pattern(p[@"parentStartId"],@"^(0|[1-9][0-9]{0,19})$") && path(p[@"executable"]);
}
inline NSDictionary* processRecord(int pid) {
  arbol_boundary::Info details{}; Identity id; std::string image;
  if (arbol_boundary::observe(pid,id,&details) != 1 || !arbol_boundary::executable(id,image)) return nil;
  int session = getsid(pid); if (session < 1 || id.uid != geteuid()) return nil;
  return @{@"pid":@(id.pid),@"uid":@(id.uid),@"startId":[NSString stringWithUTF8String:std::to_string(id.start).c_str()],
    @"pidVersion":@(id.version),@"group":@(id.group),@"session":@(session),
    @"parentStartId":[NSString stringWithUTF8String:std::to_string(details.unique.parent).c_str()],
    @"parentPidVersion":@(details.unique.originalParentVersion),@"executable":[NSString stringWithUTF8String:image.c_str()]};
}
inline bool currentProcess(NSDictionary* p, bool self = false) {
  if (!process(p) || (self && [p[@"pid"] intValue] != getpid())) return false;
  NSDictionary* now = processRecord([p[@"pid"] intValue]);
  return now && [now isEqual:p];
}
inline bool runtime(NSDictionary* p, NSDictionary* attempt) {
  if (p == (id)NSNull.null) return true;
  if (!keys(p,@[@"wire",@"profile",@"profileInstance",@"profilePathHash",@"instance",@"nonce",@"pid",@"processStartId",@"build",@"contract",@"phase",@"agentSocket",@"managementSocket"])) return false;
  uint64_t pid, wire, contract;
  NSString* id = [attempt[@"profile"] lastPathComponent];
  return uintNumber(p[@"wire"],wire) && wire == 1 && uintNumber(p[@"contract"],contract) && contract == 1 && [p[@"profile"] isEqual:id] &&
    [p[@"profileInstance"] isEqual:attempt[@"profileInstance"]] && [p[@"profilePathHash"] isEqual:attempt[@"profilePathHash"]] &&
    [p[@"build"] isEqual:attempt[@"build"]] && pattern(p[@"instance"],@"^ins_[A-Za-z0-9_-]{22}$") &&
    pattern(p[@"nonce"],@"^[A-Za-z0-9_-]{43}$") && uintNumber(p[@"pid"],pid) && pid > 1 && pid <= INT_MAX &&
    pattern(p[@"processStartId"],@"^[1-9][0-9]{0,19}$") &&
    [@[@"starting",@"ready",@"closing"] containsObject:p[@"phase"]] && path(p[@"agentSocket"]) && path(p[@"managementSocket"]);
}
// Closed structural mapping only: signatures, snapshots and original custody
// remain separate checks at every consumer.
struct PackagedLayout {
  std::string build, buildRoot, guard, bundle, payload, launcher, bootstrap, engine;
  bool installed = false;
};
inline NSString* physicalAccountHome() {
  struct passwd account{}, *record = nullptr;
  char buffer[16384];
  if (getuid() != geteuid() || getpwuid_r(getuid(), &account, buffer, sizeof(buffer), &record) ||
      record != &account || account.pw_uid != geteuid() || !account.pw_dir ||
      !arbol_boundary::canonical(account.pw_dir)) return nil;
  return [NSString stringWithUTF8String:account.pw_dir];
}
inline std::string stableLauncherPath(NSString* home) {
  NSString* component = [home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_BUILDS]
    .stringByDeletingLastPathComponent.stringByDeletingLastPathComponent;
  NSString* path = [component stringByAppendingPathComponent:@"bin/arbol-browser"];
  return path ? path.fileSystemRepresentation : "";
}
inline bool signedIdentity(const std::string& path, NSString* identifier, bool nested = false) {
  if (!arbol_boundary::signature(path, false)) return false;
  NSString* physical = [NSString stringWithUTF8String:path.c_str()];
  SecStaticCodeRef code = nullptr;
  CFDictionaryRef info = nullptr;
  if (!physical || SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:physical], kSecCSDefaultFlags, &code) != errSecSuccess)
    return false;
  bool valid = (!nested || SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckNestedCode, nullptr) == errSecSuccess) &&
    SecCodeCopySigningInformation(code, kSecCSSigningInformation, &info) == errSecSuccess && info &&
    [((__bridge NSDictionary*)info)[(__bridge NSString*)kSecCodeInfoIdentifier] isEqual:identifier];
  if (info) CFRelease(info);
  CFRelease(code);
  return valid;
}
inline constexpr int cliBuildDescriptor = 10, cliCapsuleDescriptor = 11;
inline bool packagedLayout(const std::string& bundle, PackagedLayout& out) {
  NSString* app = [NSString stringWithUTF8String:bundle.c_str()];
  if (!path(app) || ![app.lastPathComponent isEqual:@"ArbolBrowser.app"]) return false;
  NSString* parent = app.stringByDeletingLastPathComponent;
  NSString* root = [parent.lastPathComponent isEqual:@"app"] ? parent.stringByDeletingLastPathComponent : parent;
  NSString* component = root.stringByDeletingLastPathComponent;
  if (!pattern(root.lastPathComponent,@"^[1-9a-f][0-9a-f]{0,15}$") || ![component.lastPathComponent isEqual:@"arbol-browser"]) return false;
  NSString* uses = [component stringByAppendingPathComponent:@".uses"];
  const bool installed = [component hasSuffix:[@"/" stringByAppendingString:@ARBOL_INSTALLATION_STABLE_BUILDS]];
  if (installed) {
    NSString* home = physicalAccountHome();
    if (![component isEqual:[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_BUILDS]] ||
        ![parent.lastPathComponent isEqual:@"app"]) return false;
    uses = [home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_USES];
  }
  out.build = root.lastPathComponent.UTF8String; out.buildRoot = root.UTF8String; out.bundle = bundle;
  out.installed = installed;
  out.guard = [uses stringByAppendingPathComponent:root.lastPathComponent].UTF8String;
  out.payload = bundle + "/Contents/Resources/browser";
  out.launcher = out.payload + "/native/host-launch";
  out.bootstrap = bundle + "/Contents/MacOS/arbol-browser-native";
  out.engine = out.payload + "/runtime/Electron.app/Contents/MacOS/Electron";
  return true;
}
// A signed release binds portable path components. Only this account's
// canonical installed layout supplies the corresponding physical roots.
inline NSString* policyStateRoot(NSDictionary* policy, const PackagedLayout& layout) {
  NSString* build = [NSString stringWithUTF8String:layout.build.c_str()];
  if (![policy[@"build"] isEqual:build]) return nil;
  if (!layout.installed) {
    if (![policy[@"purpose"] isEqual:@"isolated-qualification"] ||
        ![policy[@"buildRoot"] isEqual:[NSString stringWithUTF8String:layout.buildRoot.c_str()]] ||
        !path(policy[@"stateRoot"])) return nil;
    return policy[@"stateRoot"];
  }
  NSString* home = physicalAccountHome();
  NSString* buildPath = [@ARBOL_INSTALLATION_STABLE_BUILDS stringByAppendingPathComponent:build];
  NSString* state = [@ARBOL_INSTALLATION_ROOT stringByAppendingPathComponent:@ARBOL_INSTALLATION_BROWSER];
  if (!home || ![policy[@"purpose"] isEqual:@"production"] ||
      ![policy[@"buildRoot"] isEqual:buildPath] || ![policy[@"stateRoot"] isEqual:state] ||
      ![[home stringByAppendingPathComponent:buildPath] isEqual:[NSString stringWithUTF8String:layout.buildRoot.c_str()]])
    return nil;
  return [home stringByAppendingPathComponent:state];
}
inline bool claimedLayout(NSDictionary* attempt, PackagedLayout& out) {
  NSDictionary* starter = attempt[@"starter"];
  if (!process(starter)) return false;
  std::string executable = [starter[@"executable"] UTF8String];
  const std::string suffix = "/Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron";
  if (executable.size() <= suffix.size() || executable.compare(executable.size()-suffix.size(),suffix.size(),suffix) ||
      !packagedLayout(executable.substr(0,executable.size()-suffix.size()),out) || executable != out.engine ||
      ![attempt[@"build"] isEqual:[NSString stringWithUTF8String:out.build.c_str()]] ||
      ![attempt[@"buildRoot"] isEqual:[NSString stringWithUTF8String:out.buildRoot.c_str()]] ||
      ![attempt[@"buildGuard"] isEqual:[NSString stringWithUTF8String:out.guard.c_str()]]) return false;
  for (NSString* key in @[@"bootstrap",@"engine"]) {
    id actor = attempt[key]; if (actor == NSNull.null) continue;
    const std::string& expected = [key isEqual:@"bootstrap"] ? out.bootstrap : out.engine;
    if (!process(actor) || ![actor[@"executable"] isEqual:[NSString stringWithUTF8String:expected.c_str()]]) return false;
  }
  return true;
}
inline bool record(NSDictionary* p) {
  uint64_t format;
  if (!keys(p,@[@"format",@"request",@"nonce",@"profile",@"profileInstance",@"profilePathHash",@"build",@"buildRoot",@"buildGuard",
    @"sourceDigest",@"productDigest",@"candidateDigest",@"expires",@"starter",@"phase",@"stage",@"bootstrap",@"engine",@"runtime",@"terminal"]) || !uintNumber(p[@"format"],format) || format != 1) return false;
  if (!pattern(p[@"request"],@"^req_[A-Za-z0-9_-]{22}$") || !pattern(p[@"nonce"],@"^[A-Za-z0-9_-]{43}$") ||
      !path(p[@"profile"]) || !pattern(p[@"profileInstance"],@"^prf_[A-Za-z0-9_-]{22}$") ||
      !pattern(p[@"build"],@"^[1-9a-f][0-9a-f]{0,15}$") || !path(p[@"buildRoot"]) || !path(p[@"buildGuard"]) || !process(p[@"starter"])) return false;
  for (NSString* key in @[@"profilePathHash",@"sourceDigest",@"productDigest",@"candidateDigest"])
    if (!pattern(p[key],@"^[0-9a-f]{64}$")) return false;
  if (![p[@"profilePathHash"] isEqual:digest([p[@"profile"] UTF8String])]) return false;
  id expires = p[@"expires"];
  if (![expires isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)expires) == CFBooleanGetTypeID() ||
      !std::isfinite([expires doubleValue]) || [expires doubleValue] <= 0) return false;
  if (![@[@"pending",@"claimed",@"ready",@"closing",@"cancelled",@"closed"] containsObject:p[@"phase"]] ||
      ![@[@"untransferred",@"transferring",@"retained",@"mutation-started",@"marker-bound",@"admitted"] containsObject:p[@"stage"]]) return false;
  if ((p[@"bootstrap"] != NSNull.null && !process(p[@"bootstrap"])) ||
      (p[@"engine"] != NSNull.null && !process(p[@"engine"])) || !runtime(p[@"runtime"],p)) return false;
  NSString* component = [p[@"buildRoot"] stringByDeletingLastPathComponent];
  if (![[component lastPathComponent] isEqual:@"arbol-browser"] || ![[p[@"buildRoot"] lastPathComponent] isEqual:p[@"build"]] ||
      ![p[@"buildGuard"] isEqual:[[component stringByAppendingPathComponent:@".uses"] stringByAppendingPathComponent:p[@"build"]]]) return false;
  if ([p[@"phase"] isEqual:@"pending"] && (p[@"bootstrap"] != NSNull.null || p[@"engine"] != NSNull.null || p[@"runtime"] != NSNull.null || p[@"terminal"] != NSNull.null || ![p[@"stage"] isEqual:@"untransferred"])) return false;
  if (p[@"engine"] != NSNull.null) {
    NSDictionary* a = p[@"bootstrap"], *b = p[@"engine"];
    if (a == (id)NSNull.null || ![a[@"pid"] isEqual:b[@"pid"]] || ![a[@"uid"] isEqual:b[@"uid"]] ||
        ![a[@"startId"] isEqual:b[@"startId"]] || ![a[@"group"] isEqual:b[@"group"]] || ![a[@"session"] isEqual:b[@"session"]]) return false;
  }
  if ([p[@"phase"] isEqual:@"claimed"] && p[@"bootstrap"] == NSNull.null) return false;
  if ([p[@"phase"] isEqual:@"ready"] && (p[@"engine"] == NSNull.null || p[@"runtime"] == NSNull.null ||
      ![p[@"runtime"][@"phase"] isEqual:@"ready"] || ![p[@"stage"] isEqual:@"admitted"])) return false;
  if (p[@"runtime"] != NSNull.null && (p[@"engine"] == NSNull.null ||
      ![p[@"runtime"][@"pid"] isEqual:p[@"engine"][@"pid"]] || ![p[@"runtime"][@"processStartId"] isEqual:p[@"engine"][@"startId"]])) return false;
  if (p[@"terminal"] != NSNull.null && !keys(p[@"terminal"],@[@"path",@"digest"])) return false;
  if (p[@"terminal"] != NSNull.null && (!path(p[@"terminal"][@"path"]) || !pattern(p[@"terminal"][@"digest"],@"^[0-9a-f]{64}$"))) return false;
  PackagedLayout layout; return claimedLayout(p,layout);
}
inline bool immutable(NSDictionary* a, NSDictionary* b) {
  for (NSString* key in @[@"format",@"request",@"nonce",@"profile",@"profileInstance",@"profilePathHash",@"build",@"buildRoot",@"buildGuard",
      @"sourceDigest",@"productDigest",@"candidateDigest",@"expires",@"starter"])
    if (![a[key] isEqual:b[key]]) return false;
  return true;
}
inline bool sameFile(const struct stat& a, const struct stat& b) {
  return a.st_dev == b.st_dev && a.st_ino == b.st_ino && a.st_mode == b.st_mode && a.st_uid == b.st_uid &&
    a.st_nlink == 1 && b.st_nlink == 1 && a.st_size == b.st_size &&
    a.st_mtimespec.tv_sec == b.st_mtimespec.tv_sec && a.st_mtimespec.tv_nsec == b.st_mtimespec.tv_nsec &&
    a.st_ctimespec.tv_sec == b.st_ctimespec.tv_sec && a.st_ctimespec.tv_nsec == b.st_ctimespec.tv_nsec;
}
inline bool privateFile(const struct stat& s) { return S_ISREG(s.st_mode) && s.st_uid == geteuid() && (s.st_mode & 07777) == 0600 && s.st_nlink == 1; }
inline bool readAt(int directory, const std::string& name, std::string& bytes, bool& absent) {
  absent = false; bytes.clear();
  int fd = openat(directory,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
  if (fd < 0) { absent = errno == ENOENT; return absent; }
  struct stat first{}, named{}, last{}, after{};
  bool valid = !fstat(fd,&first) && !fstatat(directory,name.c_str(),&named,AT_SYMLINK_NOFOLLOW) && privateFile(first) && sameFile(first,named) && first.st_size > 0 && first.st_size <= (off_t)limit;
  char data[4096];
  while (valid && bytes.size() <= (size_t)first.st_size) {
    ssize_t n = read(fd,data,std::min(sizeof(data),(size_t)first.st_size+1-bytes.size()));
    if (n > 0) bytes.append(data,(size_t)n); else if (!n) break; else if (errno != EINTR) valid = false;
  }
  valid = valid && bytes.size() == (size_t)first.st_size && !fstat(fd,&last) && !fstatat(directory,name.c_str(),&after,AT_SYMLINK_NOFOLLOW) && sameFile(first,last) && sameFile(last,after);
  if (close(fd)) valid = false; return valid;
}
inline NSDictionary* json(const std::string& bytes) {
  if (bytes.empty() || bytes.size() > limit) return nil;
  NSData* data = [NSData dataWithBytes:bytes.data() length:bytes.size()];
  id object = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
  return [object isKindOfClass:NSDictionary.class] ? object : nil;
}
inline std::string bytes(NSDictionary* object) {
  NSData* data = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingSortedKeys error:nil];
  if (!data || !data.length || data.length >= limit) return {};
  return std::string((const char*)data.bytes,data.length) + "\n";
}
struct Location {
  int directory = -1, lock = -1; struct stat identity{}, lockIdentity{}; std::string path;
  Location() = default; Location(const Location&) = delete; Location& operator=(const Location&) = delete;
  ~Location() { if (directory >= 0) close(directory); } // directory only; never owns the borrowed lock
};
inline bool location(const std::string& lockPath, int lockFd, Location& out) {
  size_t slash = lockPath.rfind('/'); if (slash == std::string::npos || lockPath.substr(slash+1) != "claim.lock") return false;
  std::string lexical = lockPath.substr(0,slash); char physical[PATH_MAX]{};
  if (!realpath(lexical.c_str(),physical)) return false; out.path = physical;
  std::string prefix = "/private/tmp/ab-" + std::to_string(geteuid()) + "/";
  if (out.path.rfind(prefix,0) || out.path.size() != prefix.size()+32) return false;
  for (char ch : out.path.substr(prefix.size())) if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return false;
  if (lexical != out.path && lexical != "/tmp/" + out.path.substr(std::string("/private/tmp/").size())) return false;
  struct stat system{},parent{}; std::string parentPath = out.path.substr(0,out.path.rfind('/'));
  if (lstat("/private/tmp",&system) || !S_ISDIR(system.st_mode) || system.st_uid != 0 || (system.st_mode & 01777) != 01777 ||
      lstat(parentPath.c_str(),&parent) || !S_ISDIR(parent.st_mode) || parent.st_uid != geteuid() || (parent.st_mode & 07777) != 0700) return false;
  out.directory = open(out.path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  if (out.directory < 0) return false;
  struct stat named{};
  bool valid = !fstat(out.directory,&out.identity) && !lstat(out.path.c_str(),&named) && S_ISDIR(out.identity.st_mode) &&
    out.identity.st_uid == geteuid() && (out.identity.st_mode & 07777) == 0700 && out.identity.st_dev == named.st_dev && out.identity.st_ino == named.st_ino;
  struct stat lockNamed{}; char heldPath[PATH_MAX]{};
  valid = valid && lockFd >= 0 && !fstat(lockFd,&out.lockIdentity) && !fstatat(out.directory,"claim.lock",&lockNamed,AT_SYMLINK_NOFOLLOW) &&
    privateFile(out.lockIdentity) && sameFile(out.lockIdentity,lockNamed) && !fcntl(lockFd,F_GETPATH,heldPath) &&
    out.path + "/claim.lock" == heldPath;
  out.lock = lockFd;
  if (!valid) { close(out.directory); out.directory = -1; } return valid;
}
inline bool unchanged(const Location& location) {
  struct stat current{}, held{}, lock{}, lockNamed{};
  return location.directory >= 0 && !fstat(location.directory,&held) && !lstat(location.path.c_str(),&current) &&
    S_ISDIR(current.st_mode) && current.st_dev == location.identity.st_dev && current.st_ino == location.identity.st_ino &&
    held.st_dev == current.st_dev && held.st_ino == current.st_ino && current.st_uid == geteuid() && (current.st_mode & 07777) == 0700 &&
    !fstat(location.lock,&lock) && !fstatat(location.directory,"claim.lock",&lockNamed,AT_SYMLINK_NOFOLLOW) &&
    privateFile(lock) && sameFile(lock,lockNamed) && lock.st_dev == location.lockIdentity.st_dev && lock.st_ino == location.lockIdentity.st_ino;
}
inline bool replace(const Location& at, const std::string& expected, bool absent, const std::string& next) {
  if (!unchanged(at) || !record(json(next))) return false;
  NSString* pathHash = json(next)[@"profilePathHash"];
  if (at.path.substr(at.path.rfind('/')+1) != std::string([pathHash UTF8String]).substr(0,32)) return false;
  bool missing; std::string actual;
  if (!readAt(at.directory,"claim.json",actual,missing) || missing != absent || (!absent && actual != expected)) return false;
  NSString* name = [@".claim-" stringByAppendingString:NSUUID.UUID.UUIDString]; const char* filename = name.UTF8String;
  int fd = openat(at.directory,filename,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC,0600);
  if (fd < 0) return false;
  bool valid = !fchmod(fd,0600); size_t offset = 0;
  while (valid && offset < next.size()) { ssize_t n = write(fd,next.data()+offset,next.size()-offset); if (n > 0) offset += (size_t)n; else if (n < 0 && errno == EINTR) continue; else valid = false; }
  if (valid) valid = !fsync(fd); if (close(fd)) valid = false;
  if (valid) valid = unchanged(at) && readAt(at.directory,"claim.json",actual,missing) && missing == absent && (absent || actual == expected);
  if (valid) valid = !renameat(at.directory,filename,at.directory,"claim.json") && !fsync(at.directory) && unchanged(at);
  if (!valid) (void)unlinkat(at.directory,filename,0);
  return valid;
}
enum class Role { starter, bootstrap, engine, terminal };
inline NSInteger stage(NSDictionary* p) {
  return [@[@"untransferred",@"transferring",@"retained",@"mutation-started",@"marker-bound",@"admitted"] indexOfObject:p[@"stage"]];
}
inline bool sameRuntimeBinding(id old, id next) {
  if (old == NSNull.null) return next == NSNull.null || [next[@"phase"] isEqual:@"starting"];
  if (next == NSNull.null) return false;
  for (NSString* key in @[@"wire",@"profile",@"profileInstance",@"profilePathHash",@"instance",@"nonce",@"pid",@"processStartId",@"build",@"contract",@"agentSocket",@"managementSocket"])
    if (![old[key] isEqual:next[key]]) return false;
  NSInteger a = [@[@"starting",@"ready",@"closing"] indexOfObject:old[@"phase"]];
  NSInteger b = [@[@"starting",@"ready",@"closing"] indexOfObject:next[@"phase"]];
  return b >= a;
}
inline bool transition(NSDictionary* old, NSDictionary* next, Role role) {
  if (!record(next) || (old && !record(old))) return false; double now = arbol_boundary::clockMs();
  NSString* phase = next[@"phase"];
  if (!old || ![old[@"request"] isEqual:next[@"request"]]) {
    bool unused = old && [old[@"phase"] isEqual:@"cancelled"] && [old[@"stage"] isEqual:@"untransferred"] &&
      old[@"bootstrap"] == NSNull.null && old[@"engine"] == NSNull.null && old[@"runtime"] == NSNull.null && old[@"terminal"] == NSNull.null;
    // A serialized label is not independent exit authority. Reuse of a closed
    // claimed family needs the separate native exit verifier, not this generic
    // starter JSON transaction. Unclaimed cancelled intent has no engine.
    if (role != Role::starter || ![phase isEqual:@"pending"] || (old && !unused) ||
        !currentProcess(next[@"starter"],true) || [next[@"expires"] doubleValue] <= now || [next[@"expires"] doubleValue] > now+60000) return false;
    return true;
  }
  if (!immutable(old,next) || [old[@"phase"] isEqual:@"closed"]) return false;
  if ([old[@"phase"] isEqual:@"cancelled"] && ![phase isEqual:@"closed"]) return false;
  if ([phase isEqual:@"cancelled"] && role == Role::starter) {
    if (!currentProcess(old[@"starter"],true) && [old[@"expires"] doubleValue] > now) return false;
    for (NSString* key in @[@"stage",@"bootstrap",@"engine",@"runtime",@"terminal"]) if (![old[key] isEqual:next[key]]) return false;
    return true;
  }
  if (role == Role::bootstrap && [old[@"phase"] isEqual:@"pending"] && [phase isEqual:@"claimed"] &&
      [old[@"expires"] doubleValue] > now && currentProcess(old[@"starter"]) && currentProcess(next[@"bootstrap"],true) &&
      [next[@"stage"] isEqual:@"untransferred"] && next[@"engine"] == NSNull.null && next[@"runtime"] == NSNull.null && next[@"terminal"] == NSNull.null) return true;
  bool enginePhase = ([old[@"phase"] isEqual:@"claimed"] && ([@[@"claimed",@"ready",@"closing"] containsObject:phase])) ||
    ([old[@"phase"] isEqual:@"ready"] && [phase isEqual:@"closing"]);
  if (role == Role::engine && enginePhase &&
      (![old[@"phase"] isEqual:@"claimed"] || [old[@"expires"] doubleValue] > now) &&
      [old[@"bootstrap"] isEqual:next[@"bootstrap"]] && currentProcess(next[@"engine"],true) &&
      (old[@"engine"] == NSNull.null || [old[@"engine"] isEqual:next[@"engine"]]) &&
      sameRuntimeBinding(old[@"runtime"],next[@"runtime"]) && stage(next) >= stage(old) && stage(next) <= stage(old)+1 &&
      next[@"terminal"] == NSNull.null) return true;
  // Only a native custody/exit verifier calls this role after actual evidence.
  return role == Role::terminal && [phase isEqual:@"closed"] && next[@"terminal"] != NSNull.null &&
    [old[@"stage"] isEqual:next[@"stage"]] && [old[@"bootstrap"] isEqual:next[@"bootstrap"]] &&
    [old[@"engine"] isEqual:next[@"engine"]] && [old[@"runtime"] isEqual:next[@"runtime"]];
}
// Short arbitration owned by a native transition. It never borrows startup.lock
// and never creates, unlinks or replaces the stable transition-lock inode.
struct Claim {
  int fd = -1; Location at;
  ~Claim() { if (fd >= 0) close(fd); }
  bool acquire(const std::string& requestPath, double deadline) {
    size_t slash = requestPath.rfind('/'); if (slash == std::string::npos) return false;
    std::string path = requestPath.substr(0,slash) + "/claim.lock";
    fd = open(path.c_str(),O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (fd < 0 || !location(path,fd,at)) return false;
    while (flock(fd,LOCK_EX|LOCK_NB)) {
      if ((errno != EWOULDBLOCK && errno != EAGAIN) || arbol_boundary::clockMs() >= deadline) return false;
      usleep(1000);
    }
    return arbol_boundary::clockMs() < deadline && unchanged(at);
  }
  bool read(std::string& raw, NSDictionary* __strong& value) {
    bool absent;
    if (!readAt(at.directory,"claim.json",raw,absent) || absent || !unchanged(at) || !record(value=json(raw))) return false;
    return at.path.substr(at.path.rfind('/')+1) == std::string([value[@"profilePathHash"] UTF8String]).substr(0,32);
  }
};
inline bool launchRequest(const Claim& claim, const std::string& requestPath, NSDictionary* attempt) {
  std::string filename = "launch-" + std::string([attempt[@"request"] UTF8String]) + ".json";
  if (requestPath != claim.at.path + "/" + filename && requestPath != "/tmp/" + claim.at.path.substr(13) + "/" + filename) return false;
  std::string raw; bool absent;
  if (!readAt(claim.at.directory,filename,raw,absent) || absent) return false;
  NSDictionary* request = json(raw); NSDictionary* selection = request[@"selection"];
  return keys(request,@[@"format",@"request",@"profile",@"profileInstance",@"selection"]) && [request[@"format"] isEqual:@1] &&
    [request[@"request"] isEqual:attempt[@"request"]] && [request[@"profile"] isEqual:attempt[@"profile"]] &&
    [request[@"profileInstance"] isEqual:attempt[@"profileInstance"]] && keys(selection,@[@"build",@"directory",@"guard",@"explicit"]) &&
    CFGetTypeID((__bridge CFTypeRef)selection[@"explicit"]) == CFBooleanGetTypeID() &&
    [selection[@"build"] isEqual:attempt[@"build"]] && [selection[@"directory"] isEqual:attempt[@"buildRoot"]] &&
    [selection[@"guard"] isEqual:attempt[@"buildGuard"]] && unchanged(claim.at);
}
inline bool bundleGuard(const std::string& bundle, std::string& buildRoot, std::string& guard) {
  PackagedLayout layout;
  if (!arbol_boundary::canonical(bundle) || !packagedLayout(bundle,layout)) return false;
  buildRoot = layout.buildRoot; guard = layout.guard;
  NSString* root = [NSString stringWithUTF8String:buildRoot.c_str()];
  NSString* component = root.stringByDeletingLastPathComponent;
  for (const std::string& path : {buildRoot,std::string(component.UTF8String),guard.substr(0,guard.rfind('/'))}) {
    struct stat st{};
    if (!arbol_boundary::canonical(path) || lstat(path.c_str(),&st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode&07777)!=0700) return false;
  }
  return arbol_boundary::privateAncestors(guard);
}
inline bool openBuild(const std::string& bundle, arbol_boundary::Lock& lock) {
  std::string root,path; if (!bundleGuard(bundle,root,path)) return false;
  int fd = open(path.c_str(),O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC); if (fd < 0) return false;
  struct stat st{}; bool valid = !fstat(fd,&st) && privateFile(st) && !flock(fd,LOCK_SH|LOCK_NB);
  lock = {fd,path,(uint64_t)st.st_dev,st.st_ino,st.st_uid,0600,LOCK_SH};
  if (!valid || !arbol_boundary::lockIdentity(lock)) { close(fd); lock.fd=-1; return false; }
  return true;
}
} // namespace arbol_attempt

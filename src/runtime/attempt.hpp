#pragma once
// One native grammar/transaction for the CLI addon and signed fixed-exec outer.
// These are intent records, never watchdog, engine-exit or flush certificates.
#include "../../watchdog/boundary.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <cmath>
#include <pwd.h>
#include <poll.h>
namespace arbol_attempt {
using arbol_boundary::Identity;
constexpr size_t limit = 16384;
#ifndef ARBOL_BROWSER_PROFILE_FORMAT
#define ARBOL_BROWSER_PROFILE_FORMAT 1
#endif
static_assert(ARBOL_BROWSER_PROFILE_FORMAT == 1 || ARBOL_BROWSER_PROFILE_FORMAT == 2);
constexpr int profileFormat = ARBOL_BROWSER_PROFILE_FORMAT;
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
// Shape checks only. Callers must independently authenticate the source and
// hold the installation custody while comparing the observed selection.
inline bool maintenanceSelection(id value) {
  uint64_t format = 0;
  return keys(value, @[@"format", @"build", @"imageSha256"]) &&
    uintNumber(value[@"format"], format) && format == 1 &&
    pattern(value[@"build"], @"^[1-9a-f][0-9a-f]{0,15}$") &&
    pattern(value[@"imageSha256"], @"^[0-9a-f]{64}$");
}
inline bool maintenanceRelease(id value) {
  return keys(value, @[@"selection", @"launcherSha256"]) &&
    maintenanceSelection(value[@"selection"]) && pattern(value[@"launcherSha256"], @"^[0-9a-f]{64}$");
}
inline bool maintenanceJournal(id value) {
  uint64_t format = 0, from = 0, to = 0;
  if (!keys(value, @[@"format", @"aliasBefore", @"before", @"after", @"migration"]) ||
      !uintNumber(value[@"format"], format) || format != 3 ||
      ![value[@"aliasBefore"] isKindOfClass:NSNumber.class] ||
      CFGetTypeID((__bridge CFTypeRef)value[@"aliasBefore"]) != CFBooleanGetTypeID() ||
      !(value[@"before"] == NSNull.null || maintenanceRelease(value[@"before"])) ||
      !maintenanceRelease(value[@"after"]) ||
      !keys(value[@"migration"], @[@"fromProfileFormat", @"toProfileFormat"])) return false;
  return uintNumber(value[@"migration"][@"fromProfileFormat"], from) && from == 1 &&
    uintNumber(value[@"migration"][@"toProfileFormat"], to) && to == 2;
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
  // One layout check derives the installed support guard or isolated .uses,
  // and binds it to the original starter/bootstrap/engine paths.
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
// The caller retains both this directory descriptor and the exclusive
// selection lock. A snapshot is evidence only while those remain held.
struct MaintenanceSelectionSnapshot {
  bool absent = false;
  std::string bytes;
  struct stat directory{}, file{};
};
inline bool maintenanceSelectionSnapshot(int directory, const std::string& directoryPath,
                                         MaintenanceSelectionSnapshot& out) {
  char heldPath[PATH_MAX]{};
  struct stat namedDirectory{}, before{}, after{};
  if (directory < 0 || !arbol_boundary::canonical(directoryPath) ||
      !arbol_boundary::privateAncestors(directoryPath) || fstat(directory, &out.directory) ||
      !S_ISDIR(out.directory.st_mode) || out.directory.st_uid != geteuid() ||
      (out.directory.st_mode & 07777) != 0700 ||
      lstat(directoryPath.c_str(), &namedDirectory) ||
      out.directory.st_dev != namedDirectory.st_dev || out.directory.st_ino != namedDirectory.st_ino ||
      fcntl(directory, F_GETPATH, heldPath) || directoryPath != heldPath) return false;
  errno = 0;
  const bool existed = fstatat(directory, "selected.json", &before, AT_SYMLINK_NOFOLLOW) == 0;
  if (!existed && errno != ENOENT) return false;
  if (!readAt(directory, "selected.json", out.bytes, out.absent) || out.absent == existed) return false;
  if (existed) {
    if (fstatat(directory, "selected.json", &after, AT_SYMLINK_NOFOLLOW) ||
        !privateFile(before) || !sameFile(before, after) || !maintenanceSelection(json(out.bytes))) return false;
    out.file = after;
  } else {
    errno = 0;
    if (!fstatat(directory, "selected.json", &after, AT_SYMLINK_NOFOLLOW) || errno != ENOENT) return false;
  }
  struct stat finalDirectory{}, finalName{};
  return !fstat(directory, &finalDirectory) && !lstat(directoryPath.c_str(), &finalName) &&
    out.directory.st_dev == finalDirectory.st_dev && out.directory.st_ino == finalDirectory.st_ino &&
    out.directory.st_dev == finalName.st_dev && out.directory.st_ino == finalName.st_ino &&
    out.directory.st_uid == finalDirectory.st_uid && out.directory.st_mode == finalDirectory.st_mode &&
    out.directory.st_uid == finalName.st_uid && out.directory.st_mode == finalName.st_mode;
}
inline bool sameMaintenanceSelection(const MaintenanceSelectionSnapshot& a,
                                     const MaintenanceSelectionSnapshot& b) {
  return a.absent == b.absent && a.bytes == b.bytes &&
    a.directory.st_dev == b.directory.st_dev && a.directory.st_ino == b.directory.st_ino &&
    (a.absent || sameFile(a.file, b.file));
}
inline bool maintenanceSelectionMatches(const MaintenanceSelectionSnapshot& actual, id before) {
  if (before == NSNull.null) return actual.absent;
  return maintenanceRelease(before) && !actual.absent && [json(actual.bytes) isEqual:before[@"selection"]];
}
inline std::string bytes(NSDictionary* object) {
  NSData* data = [NSJSONSerialization dataWithJSONObject:object options:NSJSONWritingSortedKeys error:nil];
  if (!data || !data.length || data.length >= limit) return {};
  return std::string((const char*)data.bytes,data.length) + "\n";
}
// Maintenance transport has its own descriptors; ordinary launch capsules do
// not confer maintenance authority. SpawnCopies duplicates above these slots.
inline constexpr int maintenanceSelectionDescriptor = 10, maintenanceOldDescriptor = 11,
  maintenanceNewDescriptor = 12, maintenanceCapsuleDescriptor = 13;
inline constexpr int qualificationStopDescriptor = 14, qualificationEventDescriptor = 15;
inline constexpr int qualificationInstallerStopDescriptor = 3, qualificationInstallerEventDescriptor = 4,
  qualificationPreparationAckDescriptor = 5, qualificationPreparationEventDescriptor = 6,
  qualificationInstallerCapsuleDescriptor = 7;
inline constexpr const char* qualificationFixture = "/Users/msix/Builds/afm9-rollback-plan.49cXVsFk/qualification/fixture";
inline constexpr const char* qualificationNode = "/Users/msix/.nvm/versions/node/v24.22.1/bin/node";
inline constexpr double qualificationMaintenanceMs = 31 * 60 * 1000, qualificationCleanupMs = 30000;

inline bool qualificationStagingPoint(id point) {
  return [@[@"empty-staging",@"partial-staging",@"staged-record",@"staged-marker",@"staged-progress",
    @"marker-rename",@"marker-durable"] containsObject:point];
}
inline bool qualificationNativePublicationPoint(id point) {
  return [@[@"record-rename",@"record-durable",@"claim-retained",@"capture-durable",@"receipt-durable"] containsObject:point];
}
inline bool qualificationProgressPoint(id point) {
  return [@[@"committed-progress",@"completion"] containsObject:point];
}
inline bool qualificationTransactionStartPoint(id point) {
  return [@[@"before-transaction",@"transaction-publication",@"current-publication",@"native-rename-excl"] containsObject:point] ||
    qualificationStagingPoint(point) || qualificationNativePublicationPoint(point) || qualificationProgressPoint(point);
}
inline bool qualificationEnginePoint(id point) {
  return qualificationTransactionStartPoint(point);
}
inline bool enabledQualificationEnginePoint(id point) {
  // Each writer enables only the point it actually implements.
  return qualificationTransactionStartPoint(point);
}
inline bool qualificationDigest(id value) { return pattern(value,@"\\A[0-9a-f]{64}\\z"); }
inline bool qualificationNonce(id value) { return pattern(value,@"\\A[0-9a-f]{32}\\z"); }
inline bool qualificationProducer(NSDictionary* record) {
  return process(record) && [record[@"executable"] isEqual:[NSString stringWithUTF8String:qualificationNode]] &&
    arbol_boundary::canonical(qualificationNode) && currentProcess(record);
}
inline NSDictionary* qualificationActor(NSDictionary* record) {
  return process(record) ? @{@"pid":record[@"pid"],@"startId":record[@"startId"],@"pidVersion":record[@"pidVersion"]} : nil;
}

// Qualification frames contain only objects, strings and unsigned integers.
// Check decoded keys before Foundation can collapse duplicate spellings.
inline NSDictionary* qualificationObject(const std::string& raw, size_t maximum) {
  if (raw.empty() || raw.size() > maximum || raw.back() != '\n' || raw.find('\n') != raw.size()-1 ||
      raw.find('\0') != std::string::npos || raw.compare(0,3,"\xef\xbb\xbf") == 0) return nil;
  size_t at = 0;
  auto space = [&] { while (at < raw.size() && (raw[at]==' ' || raw[at]=='\t' || raw[at]=='\r')) ++at; };
  auto readString = [&]() -> NSString* {
    if (at >= raw.size() || raw[at] != '"') return nil;
    const size_t begin = at++;
    while (at < raw.size()) {
      const unsigned char c = raw[at++];
      if (c < 0x20) return nil;
      if (c == '\\') { if (at >= raw.size()) return nil; ++at; continue; }
      if (c != '"') continue;
      id decoded = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:raw.data()+begin length:at-begin]
        options:NSJSONReadingFragmentsAllowed error:nil];
      if (![decoded isKindOfClass:NSString.class] || ![decoded dataUsingEncoding:NSUTF8StringEncoding allowLossyConversion:NO]) return nil;
      NSString* value=decoded;
      for (NSUInteger i=0; i<value.length; ++i) if (![value characterAtIndex:i]) return nil;
      return value;
    }
    return nil;
  };
  std::function<bool(unsigned)> value = [&](unsigned depth) {
    space(); if (depth > 16 || at >= raw.size()) return false;
    if (raw[at] == '"') return readString() != nil;
    if (raw[at] == '{') {
      ++at; space(); NSMutableSet* names=[NSMutableSet new];
      if (at < raw.size() && raw[at] == '}') { ++at; return true; }
      for (;;) {
        space(); NSString* name=readString();
        if (!name || [names containsObject:name]) return false;
        [names addObject:name]; space();
        if (at >= raw.size() || raw[at++] != ':' || !value(depth+1)) return false;
        space(); if (at >= raw.size()) return false;
        const char next=raw[at++]; if (next == '}') return true; if (next != ',') return false;
      }
    }
    if (raw[at] == '0') { ++at; return true; }
    if (raw[at] < '1' || raw[at] > '9') return false;
    while (at < raw.size() && raw[at] >= '0' && raw[at] <= '9') ++at;
    return true;
  };
  if (!value(0)) return nil;
  space(); return at == raw.size()-1 ? json(raw) : nil;
}

inline NSString* qualificationPipe(int fd, int access, bool prepare = false) {
  struct stat st{};
  const int flags=fcntl(fd,F_GETFL), descriptor=fcntl(fd,F_GETFD);
  if (flags < 0 || descriptor < 0 || (flags & O_ACCMODE) != access || fstat(fd,&st) ||
      !S_ISFIFO(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 0) return nil;
  if (prepare && (fcntl(fd,F_SETFD,descriptor|FD_CLOEXEC) || fcntl(fd,F_SETFL,flags|O_NONBLOCK) ||
      (access==O_WRONLY && fcntl(fd,F_SETNOSIGPIPE,1)))) return nil;
  return [NSString stringWithUTF8String:(std::to_string(uint64_t(st.st_dev))+":"+std::to_string(uint64_t(st.st_ino))).c_str()];
}
inline bool qualificationPipes(int stop, int event, NSDictionary* packet, bool prepare = false) {
  NSString* reader=qualificationPipe(stop,O_RDONLY,prepare), *writer=qualificationPipe(event,O_WRONLY,prepare);
  return reader && writer && ![reader isEqual:writer] && [reader isEqual:packet[@"stopPipe"]] && [writer isEqual:packet[@"eventPipe"]];
}
inline bool qualificationPoll(int fd, short events, double deadline) {
  while (arbol_boundary::clockMs() < deadline) {
    const double left=deadline-arbol_boundary::clockMs(); if (left <= 0) return false;
    pollfd p{fd,events,0}; int n=poll(&p,1,int(std::ceil(std::min(left,double(INT_MAX)))));
    if (n > 0) return !(p.revents&(POLLERR|POLLNVAL)) && (p.revents & (events|(events==POLLIN?POLLHUP:0)));
    if (!n || errno != EINTR) return false;
  }
  return false;
}
inline bool writeQualificationEvent(int fd, NSDictionary* event, double deadline) {
  const std::string raw=bytes(event);
  if (raw.empty() || raw.size()>4096) return false;
  size_t at=0;
  while (at<raw.size() && qualificationPoll(fd,POLLOUT,deadline)) {
    const ssize_t n=write(fd,raw.data()+at,raw.size()-at);
    if (n>0) at+=size_t(n);
    else if (!n || (errno!=EINTR && errno!=EAGAIN && errno!=EWOULDBLOCK)) return false;
  }
  return at==raw.size() && arbol_boundary::clockMs()<deadline;
}
inline std::string readQualificationStop(int fd, double deadline) {
  std::string raw; char block[256];
  while (qualificationPoll(fd,POLLIN,deadline)) {
    const ssize_t n=read(fd,block,sizeof(block));
    if (!n) return arbol_boundary::clockMs()<deadline ? raw : std::string{};
    if (n<0) { if (errno==EINTR || errno==EAGAIN || errno==EWOULDBLOCK) continue; return {}; }
    if (raw.size()+size_t(n)>1024) return {};
    raw.append(block,size_t(n));
  }
  return {};
}
inline bool within(const std::string& child, const std::string& parent) {
  return child.size() > parent.size() && child.compare(0, parent.size(), parent) == 0 && child[parent.size()] == '/';
}
inline bool overlaps(const std::string& a, const std::string& b) { return a == b || within(a,b) || within(b,a); }
inline NSDictionary* maintenanceIdentity(const struct stat& st) {
  return @{ @"device":[NSString stringWithUTF8String:std::to_string(st.st_dev).c_str()],
    @"inode":[NSString stringWithUTF8String:std::to_string(st.st_ino).c_str()], @"uid":@(st.st_uid), @"mode":@(st.st_mode & 07777) };
}
// Retained private directories cannot be redirected by a rename, symlink or
// replacement. Directory mtimes may change when legitimate children change.
struct MaintenanceDirectory {
  int fd = -1; std::string path; struct stat identity{};
  MaintenanceDirectory() = default;
  MaintenanceDirectory(const MaintenanceDirectory&) = delete;
  ~MaintenanceDirectory() { if (fd >= 0) close(fd); }
  bool current() const {
    struct stat held{}, named{}; char actual[PATH_MAX]{};
    return fd >= 0 && arbol_boundary::canonical(path) && arbol_boundary::privateAncestors(path + "/entry") &&
      !fstat(fd,&held) && !lstat(path.c_str(),&named) && !fcntl(fd,F_GETPATH,actual) && path == actual &&
      S_ISDIR(held.st_mode) && S_ISDIR(named.st_mode) && held.st_uid == geteuid() && (held.st_mode & 07777) == 0700 &&
      held.st_dev == identity.st_dev && held.st_ino == identity.st_ino && held.st_mode == identity.st_mode &&
      held.st_dev == named.st_dev && held.st_ino == named.st_ino && held.st_mode == named.st_mode && held.st_uid == named.st_uid;
  }
  bool openPath(const std::string& value, id sealed = nil) {
    if (fd >= 0 || !arbol_boundary::canonical(value)) return false;
    path = value; fd = open(path.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    return fd >= 0 && !fstat(fd,&identity) && current() && (!sealed || [maintenanceIdentity(identity) isEqual:sealed]);
  }
};
struct MaintenanceFile {
  int fd = -1; std::string path, content; struct stat identity{};
  MaintenanceFile() = default;
  MaintenanceFile(const MaintenanceFile&) = delete;
  ~MaintenanceFile() { if (fd >= 0) close(fd); }
  bool current() const {
    struct stat held{}, named{}; char actual[PATH_MAX]{};
    return fd >= 0 && arbol_boundary::canonical(path) && arbol_boundary::privateAncestors(path) &&
      !fstat(fd,&held) && !lstat(path.c_str(),&named) && !fcntl(fd,F_GETPATH,actual) && path == actual &&
      sameFile(identity,held) && sameFile(held,named);
  }
  bool openPath(const std::string& value, mode_t mode, off_t maximum, bool readBytes = false, off_t minimum = 1) {
    if (fd >= 0 || !arbol_boundary::canonical(value)) return false;
    path = value; fd = open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (fd < 0 || fstat(fd,&identity) || !S_ISREG(identity.st_mode) || identity.st_uid != geteuid() ||
        (identity.st_mode & 07777) != mode || identity.st_nlink != 1 || identity.st_size < minimum || identity.st_size > maximum || !current()) return false;
    if (readBytes) {
      content.resize(size_t(identity.st_size)); size_t at = 0;
      while (at < content.size()) {
        ssize_t n = pread(fd,content.data()+at,content.size()-at,off_t(at));
        if (n > 0) at += size_t(n); else if (n != -1 || errno != EINTR) return false;
      }
    }
    return current();
  }
  NSDictionary* record() const { return @{ @"identity":maintenanceIdentity(identity), @"sha256":digest(content) }; }
  NSString* sha256(double deadline) const {
    if (!current()) return nil;
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
    CC_SHA256_CTX hash; CC_SHA256_Init(&hash); char block[65536]; off_t at = 0;
    while (at < identity.st_size && arbol_boundary::clockMs() < deadline) {
      ssize_t n = pread(fd,block,size_t(std::min(off_t(sizeof(block)),identity.st_size-at)),at);
      if (n > 0) { CC_SHA256_Update(&hash,block,CC_LONG(n)); at += n; }
      else if (n != -1 || errno != EINTR) return nil;
    }
    if (at != identity.st_size || arbol_boundary::clockMs() >= deadline || !current()) return nil;
    unsigned char raw[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(raw,&hash);
#pragma clang diagnostic pop
    NSMutableString* result = [NSMutableString new];
    for (unsigned char byte : raw) [result appendFormat:@"%02x",byte]; return result;
  }
};
// Resolve even an absent installed root through its nearest existing ancestor.
// This detects aliases without creating, opening or reading installed data.
inline bool physicalFuturePath(const std::string& value, std::string& out) {
  std::string prefix = value, suffix; char actual[PATH_MAX]{}; struct stat st{};
  for (;;) {
    if (!lstat(prefix.c_str(),&st)) {
      if (!realpath(prefix.c_str(),actual)) return false;
      out = std::string(actual) + suffix; return true;
    }
    if (errno != ENOENT) return false;
    size_t slash = prefix.rfind('/'); if (slash == std::string::npos || slash == 0) return false;
    suffix = prefix.substr(slash) + suffix; prefix.resize(slash);
  }
}
inline bool isolatedFromInstallation(const std::string& fixture) {
  NSString* home = physicalAccountHome(); if (!home) return false;
  for (NSString* component in @[@ARBOL_INSTALLATION_ROOT, @ARBOL_INSTALLATION_BUILDS,
      @ARBOL_INSTALLATION_PAYLOADS, @ARBOL_INSTALLATION_STABLE_BUILDS, @ARBOL_INSTALLATION_STABLE_USES,
      @".local/lib/sylvan-stack/arbol-browser", @"Applications/Arbol Browser"]) {
    std::string installed = [home stringByAppendingPathComponent:component].fileSystemRepresentation, resolved;
    if (!physicalFuturePath(installed,resolved) || overlaps(fixture,installed) || overlaps(fixture,resolved)) return false;
  }
  return true;
}
// Sealed Contents/Resources/maintenance-fixture.json is signed with the
// isolated candidate. Directory identities are allocated before signing. The
// host-policy digest binds product identity without a circular image digest;
// the journal separately pins the complete signed disk image.
inline NSData* maintenanceAppleTool(NSString* program, NSArray<NSString*>* arguments, double deadline) {
  if (arbol_boundary::clockMs() >= deadline) return nil;
  NSPipe* pipe = [NSPipe pipe];
  NSFileHandle* input = pipe.fileHandleForReading;
  const int fd = input.fileDescriptor;
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return nil;
  NSTask* task = [NSTask new];
  task.executableURL = [NSURL fileURLWithPath:program];
  task.arguments = arguments;
  task.environment = @{@"PATH": @"/usr/bin:/bin"};
  task.standardInput = [NSFileHandle fileHandleWithNullDevice];
  task.standardOutput = pipe;
  task.standardError = [NSFileHandle fileHandleWithNullDevice];
  if (![task launchAndReturnError:nil]) return nil;
  NSMutableData* output = [NSMutableData new];
  bool eof = false;
  while (arbol_boundary::clockMs() < deadline && (!eof || task.running)) {
    char bytes[8192];
    ssize_t size = eof ? 0 : read(fd, bytes, sizeof(bytes));
    if (size > 0) {
      [output appendBytes:bytes length:size_t(size)];
      if (output.length > 1048576) break;
    } else if (!size) {
      eof = true;
      if (task.running) usleep(1000);
    } else if (errno == EAGAIN) {
      struct pollfd ready{fd, POLLIN, 0};
      (void)poll(&ready, 1, 20);
    } else if (errno != EINTR) break;
  }
  if (task.running) { [task terminate]; return nil; }
  return eof && arbol_boundary::clockMs() < deadline && output.length <= 1048576 && task.terminationStatus == 0 ? output : nil;
}
inline NSData* diskImageTool(NSArray<NSString*>* arguments, double deadline) {
  return maintenanceAppleTool(@"/usr/bin/hdiutil",arguments,deadline);
}

inline bool mountedImage(const std::string& mount, NSString* image, double deadline) {
  struct statfs fs{};
  if (statfs(mount.c_str(), &fs) || mount != fs.f_mntonname || !(fs.f_flags & MNT_RDONLY) ||
      strcmp(fs.f_fstypename, "apfs")) return false;
  NSData* bytes = diskImageTool(@[@"info", @"-plist"], deadline);
  if (!bytes) return false;
  id info = [NSPropertyListSerialization propertyListWithData:bytes options:NSPropertyListImmutable format:nil error:nil];
  if (![info isKindOfClass:NSDictionary.class] || ![info[@"images"] isKindOfClass:NSArray.class]) return false;
  NSString* point = [NSString stringWithUTF8String:mount.c_str()];
  NSString* device = [NSString stringWithUTF8String:fs.f_mntfromname];
  size_t matches = 0;
  for (NSDictionary* row in info[@"images"]) {
    if (![row isKindOfClass:NSDictionary.class] || ![row[@"system-entities"] isKindOfClass:NSArray.class]) continue;
    for (NSDictionary* entity in row[@"system-entities"]) {
      if (![entity isKindOfClass:NSDictionary.class] || ![entity[@"mount-point"] isEqual:point]) continue;
      if (![entity[@"dev-entry"] isEqual:device] || ![row[@"image-path"] isEqual:image] ||
          ![row[@"owner-uid"] isEqual:@(geteuid())]) return false;
      ++matches;
    }
  }
  return matches == 1;
}
// Disk images are signed data, not executable code: apply the same Developer
// ID requirement as the installer, without requiring Mach-O runtime flags.
inline bool maintenanceImageSignature(const MaintenanceFile& image) {
  if (!image.current()) return false;
  SecStaticCodeRef code = nullptr; SecRequirementRef requirement = nullptr;
  NSURL* url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:image.path.c_str()]];
  bool valid = SecStaticCodeCreateWithPath((__bridge CFURLRef)url,kSecCSDefaultFlags,&code) == errSecSuccess &&
    SecRequirementCreateWithString(CFSTR("anchor apple generic and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"),kSecCSDefaultFlags,&requirement) == errSecSuccess &&
    SecStaticCodeCheckValidity(code,kSecCSStrictValidate|kSecCSCheckAllArchitectures,requirement) == errSecSuccess;
  if (requirement) CFRelease(requirement); if (code) CFRelease(code);
  return valid && image.current();
}
struct MaintenanceBacking {
  Identity helper;
  struct stat executableIdentity{};
  std::vector<int> regularDescriptors;
  static std::string helperPath() { return "/System/Library/PrivateFrameworks/DiskImages.framework/Versions/A/Resources/diskimages-helper"; }
  bool signedHelper() const {
    std::string executable; struct stat named{};
    if (arbol_boundary::current(helper) != 1 || helper.uid != geteuid() || !arbol_boundary::executable(helper,executable) ||
        executable != helperPath() || lstat(executable.c_str(),&named) || !sameFile(executableIdentity,named) ||
        !S_ISREG(named.st_mode) || named.st_uid != 0 || (named.st_mode & 0022) || !(named.st_mode & 0111)) return false;
    SecCodeRef code = nullptr; SecRequirementRef requirement = nullptr;
    NSDictionary* attributes = @{(__bridge NSString*)kSecGuestAttributePid:@(helper.pid)};
    bool valid = SecRequirementCreateWithString(CFSTR("anchor apple"),kSecCSDefaultFlags,&requirement) == errSecSuccess &&
      SecCodeCopyGuestWithAttributes(nullptr,(__bridge CFDictionaryRef)attributes,kSecCSDefaultFlags,&code) == errSecSuccess &&
      SecCodeCheckValidity(code,kSecCSDefaultFlags,requirement) == errSecSuccess;
    if (code) CFRelease(code); if (requirement) CFRelease(requirement);
    return valid && arbol_boundary::current(helper) == 1 && !lstat(executable.c_str(),&named) && sameFile(executableIdentity,named);
  }
  bool descriptors(const MaintenanceFile& image, std::vector<int>& regular) const {
    if (!image.current() || arbol_boundary::current(helper) != 1) return false;
    int needed = proc_pidinfo(helper.pid,PROC_PIDLISTFDS,0,nullptr,0);
    if (needed < 1 || needed % sizeof(struct proc_fdinfo) || needed > int(4096*sizeof(struct proc_fdinfo))) return false;
    std::vector<struct proc_fdinfo> rows(size_t(needed)/sizeof(struct proc_fdinfo)+16);
    int used = proc_pidinfo(helper.pid,PROC_PIDLISTFDS,0,rows.data(),int(rows.size()*sizeof(struct proc_fdinfo)));
    if (used < 1 || used % sizeof(struct proc_fdinfo) || size_t(used) >= rows.size()*sizeof(struct proc_fdinfo)) return false;
    std::set<int> seen;
    for (size_t i = 0; i < size_t(used)/sizeof(struct proc_fdinfo); ++i) {
      const auto& row = rows[i];
      if (row.proc_fd < 0 || !seen.insert(row.proc_fd).second) return false;
      if (row.proc_fdtype != PROX_FDTYPE_VNODE) continue;
      struct vnode_fdinfo file{};
      if (proc_pidfdinfo(helper.pid,row.proc_fd,PROC_PIDFDVNODEINFO,&file,sizeof(file)) != sizeof(file)) return false;
      const auto& vnode = file.pvi.vi_stat;
      if (!S_ISREG(vnode.vst_mode)) continue;
      if ((file.pfi.fi_openflags & (FREAD|FWRITE)) != FREAD || vnode.vst_dev != uint32_t(image.identity.st_dev) ||
          vnode.vst_ino != image.identity.st_ino || vnode.vst_nlink != 1 || vnode.vst_uid != image.identity.st_uid ||
          vnode.vst_size != image.identity.st_size) return false;
      regular.push_back(row.proc_fd);
    }
    std::sort(regular.begin(),regular.end());
    return !regular.empty() && image.current() && arbol_boundary::current(helper) == 1;
  }
  bool current(const MaintenanceFile& image) const {
    std::vector<int> observed;
    return helper.pid > 1 && signedHelper() && descriptors(image,observed) && observed == regularDescriptors && signedHelper();
  }
  bool capture(int pid, const MaintenanceFile& image) {
    if (helper.pid || pid <= 1 || arbol_boundary::observe(pid,helper) != 1 || lstat(helperPath().c_str(),&executableIdentity) ||
        !signedHelper() || !descriptors(image,regularDescriptors)) return false;
    return current(image);
  }
};
inline bool maintenanceMount(const std::string& mount, const MaintenanceFile& image, double deadline, MaintenanceBacking& backing) {
  struct statfs fs{}; struct stat mounted{}, device{};
  if (!image.current() || !arbol_boundary::canonical(mount) || statfs(mount.c_str(),&fs) ||
      mount != fs.f_mntonname || !(fs.f_flags & MNT_RDONLY) || !(fs.f_flags & MNT_LOCAL) || strcmp(fs.f_fstypename,"apfs") ||
      lstat(mount.c_str(),&mounted) || !S_ISDIR(mounted.st_mode) || lstat(fs.f_mntfromname,&device) ||
      !S_ISBLK(device.st_mode) || device.st_rdev != mounted.st_dev) return false;
  NSData* infoBytes = diskImageTool(@[@"info",@"-plist"],deadline);
  NSData* volumeBytes = maintenanceAppleTool(@"/usr/sbin/diskutil",@[@"info",@"-plist",[NSString stringWithUTF8String:fs.f_mntfromname]],deadline);
  if (!infoBytes || !volumeBytes) return false;
  id info = [NSPropertyListSerialization propertyListWithData:infoBytes options:NSPropertyListImmutable format:nil error:nil];
  id volume = [NSPropertyListSerialization propertyListWithData:volumeBytes options:NSPropertyListImmutable format:nil error:nil];
  NSString* point = [NSString stringWithUTF8String:mount.c_str()];
  NSString* node = [NSString stringWithUTF8String:fs.f_mntfromname];
  if (![info isKindOfClass:NSDictionary.class] || ![info[@"images"] isKindOfClass:NSArray.class] ||
      ![volume isKindOfClass:NSDictionary.class] || ![volume[@"MountPoint"] isEqual:point] || ![volume[@"DeviceNode"] isEqual:node] ||
      ![volume[@"FilesystemType"] isEqual:@"apfs"] || ![volume[@"BusProtocol"] isEqual:@"Disk Image"] ||
      ![volume[@"Writable"] isEqual:@NO] || ![volume[@"WritableMedia"] isEqual:@NO] || ![volume[@"WritableVolume"] isEqual:@NO]) return false;
  size_t matches = 0; int helperPid = 0;
  for (id row in info[@"images"]) {
    if (![row isKindOfClass:NSDictionary.class] || ![row[@"system-entities"] isKindOfClass:NSArray.class]) return false;
    for (id entity in row[@"system-entities"]) {
      if (![entity isKindOfClass:NSDictionary.class]) return false;
      if (![entity[@"mount-point"] isEqual:point] && ![entity[@"dev-entry"] isEqual:node]) continue;
      uint64_t pid = 0;
      if (++matches != 1 || ![entity[@"mount-point"] isEqual:point] || ![entity[@"dev-entry"] isEqual:node] ||
          ![row[@"image-path"] isEqual:[NSString stringWithUTF8String:image.path.c_str()]] ||
          ![row[@"owner-uid"] isEqual:@(geteuid())] || ![row[@"image-type"] isEqual:@"UDIF read-only"] ||
          ![row[@"writeable"] isEqual:@NO] || ![row[@"diskimages2"] isEqual:@NO] || ![row[@"image-encrypted"] isEqual:@NO] ||
          !uintNumber(row[@"hdid-pid"],pid) || pid < 1 || pid > INT_MAX) return false;
      helperPid = int(pid);
      for (id key in [row allKeys]) {
        if (![key isKindOfClass:NSString.class] || [key rangeOfString:@"shadow" options:NSCaseInsensitiveSearch].location != NSNotFound ||
            [key rangeOfString:@"overlay" options:NSCaseInsensitiveSearch].location != NSNotFound) return false;
      }
    }
  }
  struct statfs after{};
  return matches == 1 && backing.capture(helperPid,image) && image.current() && !statfs(mount.c_str(),&after) && (after.f_flags & MNT_RDONLY) &&
    !memcmp(&fs.f_fsid,&after.f_fsid,sizeof(fs.f_fsid)) && !strcmp(fs.f_mntfromname,after.f_mntfromname) &&
    !strcmp(fs.f_mntonname,after.f_mntonname);
}
// Retain the actual entry, addon, engine and signed resource descriptions and
// reject every nested mount. All imported code must remain on this immutable
// volume, including targets of sealed symlinks; an overlay cannot supply code.
struct MaintenancePayload {
  int root = -1; std::string mount; struct stat identity{}; struct statfs filesystem{};
  std::vector<std::unique_ptr<MaintenanceFile>> files;
  MaintenancePayload() = default; MaintenancePayload(const MaintenancePayload&) = delete;
  ~MaintenancePayload() { if (root >= 0) close(root); }
  bool sameFilesystem(const struct statfs& now) const {
    return (now.f_flags & MNT_RDONLY) && (now.f_flags & MNT_LOCAL) && !strcmp(now.f_fstypename,"apfs") &&
      !memcmp(&filesystem.f_fsid,&now.f_fsid,sizeof(now.f_fsid)) &&
      !strcmp(filesystem.f_mntonname,now.f_mntonname) && !strcmp(filesystem.f_mntfromname,now.f_mntfromname);
  }
  bool noNestedMounts() const {
    int count = getfsstat(nullptr,0,MNT_NOWAIT); if (count < 1 || count >= 4096) return false;
    std::vector<struct statfs> mounts(size_t(count)+1);
    int read = getfsstat(mounts.data(),int(mounts.size()*sizeof(struct statfs)),MNT_NOWAIT);
    if (read < 1 || size_t(read) >= mounts.size()) return false;
    for (int i = 0; i < read; ++i) if (within(mounts[size_t(i)].f_mntonname,mount)) return false;
    return true;
  }
  bool current() const {
    struct stat held{}, named{}; struct statfs fs{}, actual{};
    if (root < 0 || !arbol_boundary::canonical(mount) || fstat(root,&held) || lstat(mount.c_str(),&named) ||
        held.st_dev != identity.st_dev || held.st_ino != identity.st_ino || held.st_dev != named.st_dev || held.st_ino != named.st_ino ||
        fstatfs(root,&fs) || statfs(mount.c_str(),&actual) || !sameFilesystem(fs) || !sameFilesystem(actual) || !noNestedMounts()) return false;
    for (const auto& file : files) {
      struct statfs byFD{}, byPath{};
      if (!file->current() || file->identity.st_dev != identity.st_dev || fstatfs(file->fd,&byFD) ||
          statfs(file->path.c_str(),&byPath) || !sameFilesystem(byFD) || !sameFilesystem(byPath)) return false;
    }
    return true;
  }
  bool capture(const PackagedLayout& layout, bool isolated, bool inspectTree = true) {
    if (root >= 0) return false;
    mount = layout.buildRoot + "/app";
    root = open(mount.c_str(),O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    if (root < 0 || fstat(root,&identity) || fstatfs(root,&filesystem) || !current()) return false;
    if (inspectTree && !wholeTree(layout.bundle)) return false;
    std::vector<std::string> paths{layout.engine,layout.payload + "/lib/cli/maintenance.js",layout.payload + "/native/platform.node",
      layout.bundle + "/Contents/Resources/host-policy.json",layout.bundle + "/Contents/Resources/native-compatibility.json"};
    if (isolated) paths.push_back(layout.bundle + "/Contents/Resources/maintenance-fixture.json");
    for (const auto& path : paths) {
      struct stat st{}; if (lstat(path.c_str(),&st) || (st.st_mode & 07022) || !within(path,mount)) return false;
      auto file = std::make_unique<MaintenanceFile>();
      if (!file->openPath(path,st.st_mode & 07777,1024LL*1024*1024)) return false;
      files.push_back(std::move(file));
    }
    return current();
  }
private:
  // Check every signed tree entry for another filesystem or an escaping
  // symlink. The signature alone does not impose either path restriction.
  bool wholeTree(const std::string& bundle) const {
    __block bool enumerationFailed = false;
    NSDirectoryEnumerator* entries = [[NSFileManager defaultManager] enumeratorAtURL:
      [NSURL fileURLWithPath:[NSString stringWithUTF8String:bundle.c_str()]] includingPropertiesForKeys:nil
      options:0 errorHandler:^BOOL(NSURL*,NSError*) { enumerationFailed = true; return NO; }];
    if (!entries) return false;
    size_t count = 0;
    for (NSURL* entry in entries) {
      if (++count > 65536) return false;
      std::string path = entry.path.fileSystemRepresentation; struct stat st{}; struct statfs fs{}; char resolved[PATH_MAX]{};
      if (lstat(path.c_str(),&st) || !realpath(path.c_str(),resolved) || !within(resolved,mount) ||
          statfs(path.c_str(),&fs) || !sameFilesystem(fs) || (!S_ISREG(st.st_mode) && !S_ISDIR(st.st_mode) && !S_ISLNK(st.st_mode))) return false;
    }
    return !enumerationFailed;
  }
};

struct IsolatedMaintenance {
  PackagedLayout layout;
  MaintenanceDirectory fixture, support, registry, uses, runtime, stateParent;
  MaintenanceFile policy, hostPolicy, launcher;
  std::string stateRoot, launcherPath;
  NSString* launcherDigest = nil;
  bool current() const {
    return fixture.current() && support.current() && registry.current() && uses.current() && runtime.current() &&
      stateParent.current() && policy.current() && hostPolicy.current() && launcher.current() && isolatedFromInstallation(fixture.path);
  }
  bool admit(const std::string& policyPath, const std::string& runtimePath, const std::string& bundle, double deadline) {
    if (profileFormat != 2 || !packagedLayout(bundle,layout) || layout.installed ||
        bundle != layout.buildRoot + "/app/ArbolBrowser.app" || !arbol_boundary::canonical(bundle) ||
        !signedIdentity(bundle,@"com.sylvan-stack.arbol-browser.native-candidate",true) ||
        policyPath != bundle + "/Contents/Resources/maintenance-fixture.json" ||
        !policy.openPath(policyPath,0600,limit,true) ||
        !hostPolicy.openPath(bundle + "/Contents/Resources/host-policy.json",0600,limit,true)) return false;
    NSDictionary* p = json(policy.content), *host = json(hostPolicy.content); uint64_t format = 0;
    if (!keys(p,@[@"format",@"purpose",@"fixture",@"directories",@"stateRoot",@"runtime",@"registry",@"launcher",@"launcherSha256",@"bundle",@"build",@"hostPolicySha256"]) ||
        !uintNumber(p[@"format"],format) || format != 1 || ![p[@"purpose"] isEqual:@"isolated-qualification"] ||
        !path(p[@"fixture"]) || !keys(p[@"directories"],@[@"fixture",@"support",@"registry",@"uses",@"runtime",@"stateParent"]) ||
        ![p[@"bundle"] isEqual:[NSString stringWithUTF8String:bundle.c_str()]] ||
        ![p[@"build"] isEqual:[NSString stringWithUTF8String:layout.build.c_str()]] ||
        ![p[@"hostPolicySha256"] isEqual:digest(hostPolicy.content)] ||
        ![host[@"purpose"] isEqual:@"isolated-qualification"] || !policyStateRoot(host,layout)) return false;
    const std::string root = [p[@"fixture"] UTF8String];
    const auto exact = [&](NSString* key, const std::string& value) { return [p[key] isEqual:[NSString stringWithUTF8String:value.c_str()]]; };
    stateRoot = root + "/state/browser"; launcherPath = root + "/bin/arbol-browser";
    if (!isolatedFromInstallation(root) || layout.buildRoot != root + "/arbol-browser/" + layout.build ||
        runtimePath != root + "/runtime" || !exact(@"runtime",runtimePath) || !exact(@"registry",root + "/arbol-browser") ||
        !exact(@"stateRoot",stateRoot) || !exact(@"launcher",launcherPath) ||
        ![host[@"stateRoot"] isEqual:p[@"stateRoot"]] || layout.guard != root + "/arbol-browser/.uses/" + layout.build ||
        !fixture.openPath(root,p[@"directories"][@"fixture"]) ||
        !support.openPath(root + "/support",p[@"directories"][@"support"]) ||
        !registry.openPath(root + "/arbol-browser",p[@"directories"][@"registry"]) ||
        !uses.openPath(root + "/arbol-browser/.uses",p[@"directories"][@"uses"]) ||
        !runtime.openPath(runtimePath,p[@"directories"][@"runtime"]) ||
        !stateParent.openPath(root + "/state",p[@"directories"][@"stateParent"]) ||
        !launcher.openPath(launcherPath,0700,1024LL*1024*1024) ||
        !signedIdentity(launcherPath,@"com.sylvan-stack.arbol-browser.isolated-maintenance-launcher")) return false;
    std::set<std::pair<dev_t,ino_t>> identities;
    for (auto* d : {&fixture,&support,&registry,&uses,&runtime,&stateParent})
      if (!identities.insert({d->identity.st_dev,d->identity.st_ino}).second ||
          d->identity.st_dev != fixture.identity.st_dev || (d != &fixture && !within(d->path,root))) return false;
    // The state itself may be absent. This route only checks containment; step
    // 4 observes absence/presence through the retained parent under custody.
    struct stat state{};
    if (!fstatat(stateParent.fd,"browser",&state,AT_SYMLINK_NOFOLLOW)) {
      if (!S_ISDIR(state.st_mode) || state.st_uid != geteuid() || (state.st_mode & 07777) != 0700 ||
          state.st_dev != stateParent.identity.st_dev ||
          !arbol_boundary::canonical(stateRoot)) return false;
    } else if (errno != ENOENT) return false;
    launcherDigest = launcher.sha256(deadline);
    return launcherDigest && [launcherDigest isEqual:p[@"launcherSha256"]] && current() &&
      signedIdentity(bundle,@"com.sylvan-stack.arbol-browser.native-candidate",true) && current();
  }
};
struct MaintenanceGuard {
  arbol_boundary::Lock lock;
  MaintenanceGuard() = default; MaintenanceGuard(const MaintenanceGuard&) = delete;
  ~MaintenanceGuard() { if (lock.fd >= 0) close(lock.fd); } // never LOCK_UN
  bool take(const std::string& path, int inherited = -1, id record = nil) {
    if (lock.fd >= 0 || !arbol_boundary::canonical(path)) return false;
    int fd = inherited >= 0 ? inherited : open(path.c_str(),O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (fd < 0) return false;
    lock.fd = fd; struct stat st{}; int flags = fcntl(fd,F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDWR || fcntl(fd,F_SETFD,FD_CLOEXEC) || fstat(fd,&st)) return false;
    lock = {fd,path,uint64_t(st.st_dev),st.st_ino,st.st_uid,0600,LOCK_EX};
    // Re-lock the original inherited description. Opening its path here would
    // deadlock against the sender or silently lose the original custody.
    return arbol_boundary::lockIdentity(lock) && (!record || [record isEqual:arbol_boundary::capsuleLock(lock)]) &&
      !flock(fd,LOCK_EX|LOCK_NB) && arbol_boundary::lockIdentity(lock);
  }
  bool current() const { return arbol_boundary::lockIdentity(lock); }
};
struct IsolatedMaintenanceAdmission {
  IsolatedMaintenance authority;
  MaintenanceGuard selection, oldBuild, newBuild;
  MaintenanceFile journal, image, oldImage;
  MaintenancePayload payload;
  MaintenanceBacking backing;
  MaintenanceSelectionSnapshot selected;
  NSDictionary* journalObject = nil;
  struct statfs imageMount{};
  bool current() const {
    MaintenanceSelectionSnapshot now; struct statfs mount{};
    return authority.current() && backing.current(image) && payload.current() && payload.sameFilesystem(imageMount) && selection.current() && newBuild.current() &&
      (oldBuild.lock.fd < 0 || (oldBuild.current() && oldImage.current())) && journal.current() && image.current() &&
      maintenanceSelectionSnapshot(authority.support.fd,authority.support.path,now) && sameMaintenanceSelection(selected,now) &&
      maintenanceSelectionMatches(now,journalObject[@"before"]) &&
      !statfs((authority.layout.buildRoot + "/app").c_str(),&mount) && (mount.f_flags & MNT_RDONLY) &&
      !memcmp(&imageMount.f_fsid,&mount.f_fsid,sizeof(mount.f_fsid)) &&
      !strcmp(imageMount.f_mntonname,mount.f_mntonname) && !strcmp(imageMount.f_mntfromname,mount.f_mntfromname);
  }
  bool admit(const std::string& policyPath, const std::string& runtimePath, const std::string& bundle,
             double deadline, NSDictionary* capsule = nil) {
    if (!authority.admit(policyPath,runtimePath,bundle,deadline) ||
        !selection.take(authority.support.path + "/selection.lock",capsule ? maintenanceSelectionDescriptor : -1,
          capsule ? capsule[@"selectionLock"] : nil) ||
        !journal.openPath(authority.support.path + "/install-transaction.json",0600,limit,true)) return false;
    journalObject = json(journal.content);
    if (!maintenanceJournal(journalObject) ||
        ![journalObject[@"after"][@"selection"][@"build"] isEqual:[NSString stringWithUTF8String:authority.layout.build.c_str()]] ||
        ![journalObject[@"after"][@"launcherSha256"] isEqual:authority.launcherDigest] ||
        !maintenanceSelectionSnapshot(authority.support.fd,authority.support.path,selected) ||
        !maintenanceSelectionMatches(selected,journalObject[@"before"])) return false;
    if (capsule && (![capsule[@"journalPath"] isEqual:[NSString stringWithUTF8String:journal.path.c_str()]] ||
        ![capsule[@"journal"] isEqual:journal.record()])) return false;
    if (journalObject[@"before"] != NSNull.null) {
      const std::string old = [journalObject[@"before"][@"selection"][@"build"] UTF8String];
      if (old == authority.layout.build ||
          !oldBuild.take(authority.uses.path + "/" + old,capsule ? maintenanceOldDescriptor : -1,
            capsule ? capsule[@"oldBuildLock"] : nil) ||
          !oldImage.openPath(authority.support.path + "/images/" + old + ".dmg",0600,1024LL*1024*1024) ||
          ![oldImage.sha256(deadline) isEqual:journalObject[@"before"][@"selection"][@"imageSha256"]] ||
          !maintenanceImageSignature(oldImage)) return false;
    } else if (capsule && capsule[@"oldBuildLock"] != NSNull.null) return false;
    if (!newBuild.take(authority.layout.guard,capsule ? maintenanceNewDescriptor : -1,
          capsule ? capsule[@"newBuildLock"] : nil)) return false;
    std::set<std::pair<uint64_t,uint64_t>> guards;
    for (auto* g : {&selection,&oldBuild,&newBuild})
      if (g->lock.fd >= 0 && !guards.insert({g->lock.device,g->lock.inode}).second) return false;
    // Selection was checked BEFORE acquiring any purported old guard. Check
    // it again before accepting the already-mounted qualification image.
    MaintenanceSelectionSnapshot again;
    if (!journal.current() || !maintenanceSelectionSnapshot(authority.support.fd,authority.support.path,again) ||
        !sameMaintenanceSelection(selected,again) ||
        !image.openPath(authority.support.path + "/images/" + authority.layout.build + ".dmg",0600,1024LL*1024*1024) ||
        ![image.sha256(deadline) isEqual:journalObject[@"after"][@"selection"][@"imageSha256"]] ||
        !maintenanceImageSignature(image) || !maintenanceMount(authority.layout.buildRoot + "/app",image,deadline,backing) ||
        statfs((authority.layout.buildRoot + "/app").c_str(),&imageMount) ||
        !(imageMount.f_flags & MNT_RDONLY) || !payload.capture(authority.layout,true)) return false;
    return signedIdentity(bundle,@"com.sylvan-stack.arbol-browser.native-candidate",true) &&
      arbol_boundary::clockMs() < deadline && current();
  }
};
struct InstalledMaintenanceAdmission {
  PackagedLayout layout;
  MaintenanceDirectory support, uses;
  MaintenanceGuard selection, oldBuild, newBuild, mounting;
  MaintenanceFile launcher, journal, release, image, hostPolicy;
  MaintenancePayload payload;
  MaintenanceBacking backing;
  MaintenanceSelectionSnapshot selected;
  NSDictionary* journalObject = nil;
  NSString* launcherDigest = nil;
  struct statfs imageMount{};
  bool current() const {
    MaintenanceSelectionSnapshot now; struct statfs mount{};
    return support.current() && uses.current() && backing.current(image) && payload.current() && payload.sameFilesystem(imageMount) && selection.current() && newBuild.current() &&
      (oldBuild.lock.fd < 0 || oldBuild.current()) && (mounting.lock.fd < 0 || mounting.current()) &&
      launcher.current() && journal.current() && release.current() && image.current() && hostPolicy.current() &&
      maintenanceSelectionSnapshot(support.fd,support.path,now) && sameMaintenanceSelection(selected,now) &&
      maintenanceSelectionMatches(now,journalObject[@"before"]) &&
      !statfs((layout.buildRoot + "/app").c_str(),&mount) && (mount.f_flags & MNT_RDONLY) &&
      !memcmp(&imageMount.f_fsid,&mount.f_fsid,sizeof(mount.f_fsid)) &&
      !strcmp(imageMount.f_mntonname,mount.f_mntonname) && !strcmp(imageMount.f_mntfromname,mount.f_mntfromname);
  }
  bool admit(double deadline, NSDictionary* capsule = nil, bool attach = false) {
    NSString* home = physicalAccountHome();
    NSString* usesPath = [home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_USES];
    if (profileFormat != 2 || !home || !support.openPath(usesPath.stringByDeletingLastPathComponent.fileSystemRepresentation) ||
        !uses.openPath(usesPath.fileSystemRepresentation) ||
        !launcher.openPath(stableLauncherPath(home),0755,1024LL*1024*1024) ||
        !signedIdentity(launcher.path,@"com.sylvan-stack.arbol-browser.launcher") ||
        !selection.take(support.path + "/selection.lock",capsule ? maintenanceSelectionDescriptor : -1,
          capsule ? capsule[@"selectionLock"] : nil) ||
        !journal.openPath(support.path + "/install-transaction.json",0600,limit,true)) return false;
    journalObject = json(journal.content); launcherDigest = launcher.sha256(deadline);
    if (!maintenanceJournal(journalObject) || !launcherDigest || ![journalObject[@"after"][@"launcherSha256"] isEqual:launcherDigest] ||
        !maintenanceSelectionSnapshot(support.fd,support.path,selected) ||
        !maintenanceSelectionMatches(selected,journalObject[@"before"])) return false;
    NSString* build = journalObject[@"after"][@"selection"][@"build"];
    std::string root = [[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_BUILDS] stringByAppendingPathComponent:build].fileSystemRepresentation;
    if (!packagedLayout(root + "/app/ArbolBrowser.app",layout) || !layout.installed ||
        !release.openPath(support.path + "/releases/" + layout.build + ".json",0600,limit,true)) return false;
    NSDictionary* receipt = json(release.content);
    if (!keys(receipt,@[@"format",@"build",@"imageSha256",@"source",@"payloadDigest",@"launcherSha256"]) ||
        ![receipt[@"format"] isEqual:@1] || ![receipt[@"build"] isEqual:build] ||
        ![receipt[@"imageSha256"] isEqual:journalObject[@"after"][@"selection"][@"imageSha256"]] ||
        ![receipt[@"launcherSha256"] isEqual:launcherDigest] || !pattern(receipt[@"payloadDigest"],@"^[0-9a-f]{64}$") ||
        !pattern(receipt[@"source"],@"^[0-9a-f]{40}$")) return false;
    if (capsule && (![capsule[@"journalPath"] isEqual:[NSString stringWithUTF8String:journal.path.c_str()]] ||
        ![capsule[@"journal"] isEqual:journal.record()] ||
        ![capsule[@"bundle"] isEqual:[NSString stringWithUTF8String:layout.bundle.c_str()]])) return false;
    if (journalObject[@"before"] != NSNull.null) {
      const std::string old = [journalObject[@"before"][@"selection"][@"build"] UTF8String];
      if (old == layout.build || !oldBuild.take(uses.path + "/" + old,capsule ? maintenanceOldDescriptor : -1,
          capsule ? capsule[@"oldBuildLock"] : nil)) return false;
    } else if (capsule && capsule[@"oldBuildLock"] != NSNull.null) return false;
    if (!newBuild.take(layout.guard,capsule ? maintenanceNewDescriptor : -1,capsule ? capsule[@"newBuildLock"] : nil)) return false;
    std::set<std::pair<uint64_t,uint64_t>> guards;
    for (auto* g : {&selection,&oldBuild,&newBuild})
      if (g->lock.fd >= 0 && !guards.insert({g->lock.device,g->lock.inode}).second) return false;
    MaintenanceSelectionSnapshot again;
    if (!journal.current() || !maintenanceSelectionSnapshot(support.fd,support.path,again) || !sameMaintenanceSelection(selected,again) ||
        !image.openPath(support.path + "/images/" + layout.build + ".dmg",0600,1024LL*1024*1024) ||
        ![image.sha256(deadline) isEqual:receipt[@"imageSha256"]] || !maintenanceImageSignature(image)) return false;
    const std::string mount = root + "/app";
    if (!arbol_boundary::canonical(mount) || !arbol_boundary::privateAncestors(mount)) return false;
    if (attach) {
      if (capsule || !mounting.take(layout.guard + ".mount")) return false;
      struct statfs fs{}; if (statfs(mount.c_str(),&fs)) return false;
      if (mount != fs.f_mntonname) {
        NSString* point = [NSString stringWithUTF8String:mount.c_str()];
        NSArray* entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:point error:nil];
        if (!entries || entries.count || !diskImageTool(@[@"attach",[NSString stringWithUTF8String:image.path.c_str()],
            @"-readonly",@"-nokernel",@"-mountpoint",point,@"-noautoopen",@"-nobrowse",@"-plist"],deadline)) return false;
      }
    }
    if (!maintenanceMount(mount,image,deadline,backing) || statfs(mount.c_str(),&imageMount) ||
        !arbol_boundary::canonical(layout.bundle) || !signedIdentity(layout.bundle,@"com.sylvan-stack.arbol-browser",true) ||
        !hostPolicy.openPath(layout.bundle + "/Contents/Resources/host-policy.json",0600,limit,true) ||
        !policyStateRoot(json(hostPolicy.content),layout) || !payload.capture(layout,false)) return false;
    return arbol_boundary::clockMs() < deadline && current();
  }
};
inline std::string readAnonymousMaintenanceCapsule(int fd) {
  struct stat before{}, after{};
  const int flags = fcntl(fd,F_GETFL);
  if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY || fcntl(fd,F_SETFD,FD_CLOEXEC) ||
      fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_uid != geteuid() || before.st_nlink != 0 ||
      (before.st_mode & 07777) != 0600 || before.st_size < 1 || before.st_size > off_t(limit)) return {};
  std::string raw(size_t(before.st_size),'\0'); size_t at = 0;
  while (at < raw.size()) {
    ssize_t n = pread(fd,raw.data()+at,raw.size()-at,off_t(at));
    if (n > 0) at += size_t(n); else if (n != -1 || errno != EINTR) return {};
  }
  if (fstat(fd,&after) || after.st_nlink != 0 || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
      before.st_mode != after.st_mode || before.st_uid != after.st_uid || before.st_size != after.st_size ||
      before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec ||
      before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec || close(fd)) return {};
  return raw;
}
inline bool qualificationInterruptionPacket(NSDictionary* p) {
  uint64_t schema=0, cutoff=0;
  if (!keys(p,@[@"schema",@"kind",@"parent",@"requestSha256",@"nonce",@"point",@"stopPipe",@"eventPipe",@"journal",@"build",@"imageSha256",@"deadline"]) ||
      !uintNumber(p[@"schema"],schema) || schema!=1 || ![p[@"kind"] isEqual:@"qualification-interrupt"] ||
      !process(p[@"parent"]) || !qualificationEnginePoint(p[@"point"]) ||
      !qualificationDigest(p[@"requestSha256"]) || !qualificationNonce(p[@"nonce"]) ||
      !pattern(p[@"stopPipe"],@"\\A[0-9]{1,20}:[0-9]{1,20}\\z") || !pattern(p[@"eventPipe"],@"\\A[0-9]{1,20}:[0-9]{1,20}\\z") ||
      [p[@"stopPipe"] isEqual:p[@"eventPipe"]] || !pattern(p[@"build"],@"\\A[1-9a-f][0-9a-f]{0,15}\\z") || [p[@"build"] isEqual:@"1"] ||
      !qualificationDigest(p[@"imageSha256"]) || !uintNumber(p[@"deadline"],cutoff) ||
      !keys(p[@"journal"],@[@"identity",@"sha256"]) || !qualificationDigest(p[@"journal"][@"sha256"])) return false;
  NSDictionary* identity=p[@"journal"][@"identity"]; uint64_t uid=0,mode=0;
  const double remaining=double(cutoff)-arbol_boundary::clockMs();
  return remaining>0 && remaining<=qualificationMaintenanceMs && keys(identity,@[@"device",@"inode",@"uid",@"mode"]) &&
    pattern(identity[@"device"],@"\\A[0-9]{1,20}\\z") && pattern(identity[@"inode"],@"\\A[0-9]{1,20}\\z") &&
    uintNumber(identity[@"uid"],uid) && uid==geteuid() && uintNumber(identity[@"mode"],mode) && mode==0600;
}
inline bool qualificationInterruptionBinding(NSDictionary* packet, const IsolatedMaintenanceAdmission& admission) {
  NSDictionary* journal=admission.journalObject;
  return admission.authority.fixture.path==qualificationFixture && admission.oldBuild.lock.fd>=0 &&
    [journal[@"before"][@"selection"][@"build"] isEqual:@"1"] &&
    [packet[@"journal"] isEqual:admission.journal.record()] &&
    [packet[@"build"] isEqual:journal[@"after"][@"selection"][@"build"]] &&
    [packet[@"imageSha256"] isEqual:journal[@"after"][@"selection"][@"imageSha256"]] && admission.current();
}
inline NSDictionary* readQualificationInstallerCapsule() {
  NSDictionary* p=qualificationObject(readAnonymousMaintenanceCapsule(qualificationInstallerCapsuleDescriptor),limit);
  return qualificationInterruptionPacket(p) ? p : nil;
}
inline NSDictionary* readMaintenanceCapsule(bool isolated = false) {
  const std::string raw=readAnonymousMaintenanceCapsule(maintenanceCapsuleDescriptor);
  NSDictionary* p=json(raw); uint64_t format=0;
  if (!uintNumber(p[@"format"],format) || !process(p[@"parent"]) ||
      ![p[@"deadline"] isKindOfClass:NSNumber.class] || CFGetTypeID((__bridge CFTypeRef)p[@"deadline"]) == CFBooleanGetTypeID()) return nil;
  const double remaining = [p[@"deadline"] doubleValue] - arbol_boundary::clockMs();
  if (!std::isfinite(remaining) || remaining<=0 || remaining>60000) return nil;
  NSArray* ordinary=@[@"format",@"kind",@"parent",@"deadline",@"selectionLock",@"oldBuildLock",@"newBuildLock",@"journalPath",@"journal",@"bundle"];
  if (format==1) return keys(p,ordinary) && [p[@"kind"] isEqual:@"maintenance"] ? p : nil;
  NSDictionary* control=p[@"qualification"];
  return isolated && format==2 && [p[@"kind"] isEqual:@"qualification-maintenance"] &&
    keys(p,[ordinary arrayByAddingObject:@"qualification"]) && bytes(p)==raw && qualificationInterruptionPacket(control) &&
    [p[@"deadline"] doubleValue]<=[control[@"deadline"] doubleValue] ? p : nil;
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

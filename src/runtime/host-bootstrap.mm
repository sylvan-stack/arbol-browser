// Separately signed outer bootstrap: source-pinned publisher, no live-learned
// trust or inherited engine arguments. This code never loads an input addon.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include "../../watchdog/boundary.hpp"
#include "attempt.hpp"
#include "startup-proof.hpp"
#include "../../watchdog/exit.hpp"
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <cstring>
#include <string>
#include <pwd.h>
static NSString* const team = @"7V372XL59S";
static NSString* const bundleID = @"com.sylvan-stack.arbol-browser.native-candidate";
static NSString* const publisher = @"anchor apple generic and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";
static double expiry=0;
static bool inTime() { return expiry>0 && arbol_boundary::clockMs()<expiry; }
static bool safeDirectory(NSString* path, bool privateMode) {
  if(!arbol_attempt::path(path) || !arbol_boundary::canonical(path.fileSystemRepresentation)) return false;
  NSString* current=path;
  while(![current isEqual:@"/"]) {
    struct stat st{};
    if(!inTime() || lstat(current.fileSystemRepresentation,&st) || !S_ISDIR(st.st_mode) || (st.st_mode&0022) ||
       (st.st_uid!=0 && st.st_uid!=geteuid()) ||
       (privateMode && (st.st_uid!=geteuid() || (st.st_mode&07777)!=0700))) return false;
    privateMode=false; current=current.stringByDeletingLastPathComponent;
  }
  return true;
}
static NSString* protectedPath(NSString* path) {
  NSMutableArray* suffix=[NSMutableArray new]; NSString* current=path;
  for(;;) {
    if(!inTime()) return nil; struct stat st{};
    if(!lstat(current.fileSystemRepresentation,&st)) break;
    if(errno!=ENOENT || [current isEqual:@"/"]) return nil;
    [suffix insertObject:current.lastPathComponent atIndex:0]; current=current.stringByDeletingLastPathComponent;
  }
  char physical[PATH_MAX]{}; if(!realpath(current.fileSystemRepresentation,physical)) return nil;
  current=[NSString stringWithUTF8String:physical]; for(NSString* name in suffix) current=[current stringByAppendingPathComponent:name]; return current;
}
static bool overlaps(NSString* a,NSString* b) {
  return [a isEqual:@"/"] || [b isEqual:@"/"] || [a isEqual:b] ||
    [a hasPrefix:[b stringByAppendingString:@"/"]] || [b hasPrefix:[a stringByAppendingString:@"/"]];
}
static bool isolated(NSString* buildRoot,NSString* state) {
  if(!safeDirectory(buildRoot,true)||!safeDirectory(buildRoot.stringByDeletingLastPathComponent,true)||!safeDirectory(state,true)||overlaps(buildRoot,state)) return false;
  struct passwd record{},*account=nullptr; char buffer[16384];
  if(getuid()!=geteuid() || getpwuid_r(geteuid(),&record,buffer,sizeof(buffer),&account) || !account || account->pw_uid!=geteuid()) return false;
  NSString* home=protectedPath([NSString stringWithUTF8String:account->pw_dir]); if(!home) return false;
  NSString* installation=[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_ROOT];
  for(NSString* path in @[[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_BUILDS],
                          [home stringByAppendingPathComponent:@ARBOL_INSTALLATION_PAYLOADS],
                          [installation stringByAppendingPathComponent:@ARBOL_INSTALLATION_BROWSER]]) {
    NSString* protectedRoot=protectedPath(path);
    if(!protectedRoot || overlaps(buildRoot,protectedRoot)||overlaps(state,protectedRoot)) return false;
  }
  return inTime();
}
static bool signature(NSString* path, bool outer, bool jit, bool installed = false) {
  if(!inTime()) return false;
  SecStaticCodeRef code = nullptr; SecRequirementRef requirement = nullptr; CFDictionaryRef information = nullptr;
  NSString* anchor = installed ? @ARBOL_PRODUCTION_PUBLISHER_REQUIREMENT : publisher;
  NSString* identifier = installed ? @ARBOL_PRODUCTION_BUNDLE_ID : bundleID;
  NSString* expectedTeam = installed ? @ARBOL_PRODUCTION_PUBLISHER_TEAM : team;
  NSString* text = outer ? [anchor stringByAppendingFormat:@" and identifier \"%@\"", identifier] : anchor;
  if (SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path], kSecCSDefaultFlags, &code) != errSecSuccess) return false;
  OSStatus result = SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags, &requirement);
  if (result == errSecSuccess) result = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement);
  if (result == errSecSuccess) result = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
  bool valid = false;
  if (result == errSecSuccess && information) {
    NSDictionary* info = (__bridge NSDictionary*)information;
    NSDictionary* entitlements = info[(__bridge NSString*)kSecCodeInfoEntitlementsDict];
    valid = ([info[(__bridge NSString*)kSecCodeInfoFlags] unsignedIntValue] & kSecCodeSignatureRuntime) &&
      [info[(__bridge NSString*)kSecCodeInfoTeamIdentifier] isEqual:expectedTeam] &&
      [info[(__bridge NSString*)kSecCodeInfoTimestamp] isKindOfClass:[NSDate class]];
    for (NSString* key in entitlements) if (![key isEqualToString:@"com.apple.security.cs.allow-jit"] || !jit || ![entitlements[key] isEqual:@YES]) valid = false;
  }
  if (information) CFRelease(information);
  if (requirement) CFRelease(requirement);
  CFRelease(code);
  return valid && inTime();
}
static id json(NSString* path) {
  if(!inTime()) return nil;
  int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); struct stat stat{}, named{},last{},after{};
  if (fd < 0) return nil;
  if (fstat(fd, &stat) || lstat(path.fileSystemRepresentation,&named) || !S_ISREG(stat.st_mode) ||
      (stat.st_mode&0022) || !arbol_attempt::sameFile(stat,named) || stat.st_size < 1 || stat.st_size > 1048576) { close(fd); return nil; }
  NSMutableData* bytes = [NSMutableData dataWithLength:(NSUInteger)stat.st_size+1]; size_t offset = 0;
  while (offset < bytes.length) { if(!inTime()) { close(fd); return nil; } ssize_t n = read(fd, (char*)bytes.mutableBytes + offset, bytes.length - offset); if (n < 0 && errno==EINTR) continue; if (n < 0) { close(fd); return nil; } if(!n) break; offset += (size_t)n; }
  bool valid = offset==(size_t)stat.st_size && !fstat(fd,&last) && !lstat(path.fileSystemRepresentation,&after) &&
    arbol_attempt::sameFile(stat,last) && arbol_attempt::sameFile(last,after);
  if(close(fd)) valid=false; if(!valid) return nil; bytes.length=offset;
  NSError* error = nil; id value = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:&error];
  return error || ![value isKindOfClass:NSDictionary.class] ? nil : value;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static NSString* digest(NSString* path, bool symlink, uint32_t& magic) {
  if(!inTime()) return nil; magic=0;
  CC_SHA256_CTX context; CC_SHA256_Init(&context);
  if (symlink) {
    struct stat before{},after{}; if(lstat(path.fileSystemRepresentation,&before) || !S_ISLNK(before.st_mode)) return nil;
    char link[PATH_MAX]; ssize_t length = readlink(path.fileSystemRepresentation, link, sizeof(link));
    char again[PATH_MAX]; ssize_t repeated=readlink(path.fileSystemRepresentation,again,sizeof(again));
    if (length <= 0 || length == sizeof(link) || repeated!=length || memcmp(link,again,length) ||
        lstat(path.fileSystemRepresentation,&after) || before.st_dev!=after.st_dev || before.st_ino!=after.st_ino ||
        before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec || before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec ||
        before.st_ctimespec.tv_sec!=after.st_ctimespec.tv_sec || before.st_ctimespec.tv_nsec!=after.st_ctimespec.tv_nsec) return nil;
    const char prefix[] = "symlink"; CC_SHA256_Update(&context, prefix, sizeof(prefix)); CC_SHA256_Update(&context, link, (CC_LONG)length);
  } else {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); if (fd < 0) return nil;
    struct stat first{},named{},last{},after{};
    bool valid=!fstat(fd,&first)&&!lstat(path.fileSystemRepresentation,&named)&&S_ISREG(first.st_mode)&&
      !(first.st_mode&0022)&&first.st_size>=0&&arbol_attempt::sameFile(first,named);
    char bytes[65536]; size_t offset=0;
    while(valid && offset<=(size_t)first.st_size) {
      if(!inTime()) { valid=false; break; }
      ssize_t n=read(fd,bytes,std::min(sizeof(bytes),(size_t)first.st_size+1-offset));
      if(n>0) { if(!offset && n>=4) memcpy(&magic,bytes,4); CC_SHA256_Update(&context,bytes,(CC_LONG)n); offset+=(size_t)n; }
      else if(n<0&&errno==EINTR) continue; else if(n<0) valid=false; else break;
    }
    valid=valid&&offset==(size_t)first.st_size&&!fstat(fd,&last)&&!lstat(path.fileSystemRepresentation,&after)&&
      arbol_attempt::sameFile(first,last)&&arbol_attempt::sameFile(last,after);
    if(close(fd)) valid=false; if(!valid) return nil;
  }
  unsigned char bytes[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(bytes, &context);
  NSMutableString* result = [NSMutableString new]; for (unsigned char byte : bytes) [result appendFormat:@"%02x", byte]; return result;
}
#pragma clang diagnostic pop
static bool payload(NSString* bundle, NSDictionary* manifest) {
  arbol_attempt::PackagedLayout layout;
  if (!arbol_attempt::packagedLayout(bundle.fileSystemRepresentation,layout)) return false;
  NSDictionary* files = manifest[@"files"]; if (![files isKindOfClass:[NSDictionary class]] || files.count < 3 || files.count > 4096) return false;
  NSString* root = [NSString stringWithUTF8String:layout.payload.c_str()];
  NSString* prefix = [bundle stringByAppendingString:@"/"];
  NSDirectoryEnumerator* walk = [[NSFileManager defaultManager] enumeratorAtPath:root]; NSMutableDictionary* actual = [NSMutableDictionary new];
  if (!walk) return false;
  for (NSString* relative in walk) {
    if(!inTime()) return false;
    NSString* path = [root stringByAppendingPathComponent:relative]; struct stat stat{};
    if (lstat(path.fileSystemRepresentation, &stat)) return false;
    bool link = S_ISLNK(stat.st_mode);
    if (link) { if (![[path stringByResolvingSymlinksInPath] hasPrefix:prefix]) return false; }
    else if (S_ISDIR(stat.st_mode)) continue;
    else if (!S_ISREG(stat.st_mode)) return false;
    uint32_t magic=0; NSString* hash = digest(path, link,magic); if (!hash) return false;
    actual[[@"Contents/Resources/browser/" stringByAppendingString:relative]] = hash;
    if (actual.count > 4096) return false;
    if (!link) {
      if (magic == MH_MAGIC || magic == MH_CIGAM || magic == MH_MAGIC_64 || magic == MH_CIGAM_64 ||
          magic == FAT_MAGIC || magic == FAT_CIGAM || magic == FAT_MAGIC_64 || magic == FAT_CIGAM_64) {
        bool jit = [relative hasPrefix:@"runtime/Electron.app/"] && [relative containsString:@"/Contents/MacOS/"];
        if (!signature(path, false, jit, layout.installed)) return false;
      }
    }
  }
  return [actual isEqual:files];
}

class RetainedStartupPackage {
  arbol_startup_proof::Descriptor root_;
  arbol_attempt::MaintenanceFile image_;
  arbol_attempt::MaintenancePayload mount_;
  NSDictionary* appProof_ = nil;
  std::string bundle_;
public:
  static std::string imagePath(const arbol_attempt::PackagedLayout& layout) {
    NSString* home = arbol_attempt::physicalAccountHome();
    if (!home) return {};
    NSString* support = [home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_USES].stringByDeletingLastPathComponent;
    return [[support stringByAppendingPathComponent:@"images"]
      stringByAppendingPathComponent:[NSString stringWithFormat:@"%s.dmg", layout.build.c_str()]].fileSystemRepresentation;
  }
  bool current() const {
    return root_.get() >= 0 && image_.current() &&
      (appProof_ ? arbol_startup_proof::currentCache(appProof_, bundle_, root_.get(), image_.fd, mount_) : mount_.current());
  }
  bool authenticate(const arbol_attempt::PackagedLayout& layout, NSDictionary* attempt) {
    if (!layout.installed || !arbol_attempt::record(attempt) || !inTime()) return false;
    arbol_attempt::PackagedLayout claimed;
    if (!arbol_attempt::claimedLayout(attempt, claimed) || claimed.bundle != layout.bundle ||
        claimed.guard != layout.guard || !image_.openPath(imagePath(layout), 0600, 1024LL * 1024 * 1024)) return false;
    bundle_ = layout.bundle;
    root_.reset(open(layout.bundle.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (root_.get() < 0 || !mount_.capture(layout, false)) return false;
    if (arbol_startup_proof::fromStarter(attempt, layout.bundle, root_.get(), image_.fd,
        std::min(expiry, arbol_boundary::clockMs() + 60))) return current();
    appProof_ = arbol_startup_proof::cached(layout.bundle, root_.get(), image_.fd, expiry, nil, attempt[@"candidateDigest"]);
    return appProof_ && current();
  }
};

// This invocation only verifies the installed package. It never reads a
// profile, takes ownership or admits a Browser process.
static int verifyInstalledPackage(const arbol_attempt::PackagedLayout& layout, NSString* bundle,
                                  const char* helper, const char* requestPath) {
  // Wait until the stock broker has authenticated this live process against
  // the original executable's exact CodeDirectory and Publisher.
  struct pollfd gate{STDIN_FILENO, POLLIN, 0};
  char approval = 0;
  if (!inTime() || poll(&gate, 1, int(std::min(5000.0, expiry - arbol_boundary::clockMs()))) != 1 ||
      !(gate.revents & POLLIN) || read(STDIN_FILENO, &approval, 1) != 1 || approval != '1' || !inTime()) return 4;
  NSString* helperText = [NSString stringWithUTF8String:helper];
  if (!layout.installed || !arbol_attempt::pattern(helperText, @"^[1-9][0-9]{0,9}$") ||
      helperText.longLongValue <= 1 || helperText.longLongValue > INT_MAX) return 4;
  arbol_boundary::Identity self;
  std::string executable;
  if (arbol_boundary::observe(getpid(), self) != 1 || !arbol_boundary::executable(self, executable) ||
      executable != layout.bootstrap) return 4;
  const std::string imagePath = RetainedStartupPackage::imagePath(layout);
  arbol_attempt::MaintenanceFile image;
  arbol_attempt::MaintenanceBacking backing;
  arbol_attempt::MaintenancePayload immutable;
  // The verifier must see the same directory and backing file that the caller
  // retained before consulting the system's mounted-image inventory.
  struct stat callerBundle{}, namedBundle{}, callerImage{};
  const auto sameBundle = [&]() {
    return !lstat(layout.bundle.c_str(), &namedBundle) &&
      callerBundle.st_dev == namedBundle.st_dev && callerBundle.st_ino == namedBundle.st_ino &&
      callerBundle.st_mode == namedBundle.st_mode && callerBundle.st_uid == namedBundle.st_uid &&
      callerBundle.st_nlink == namedBundle.st_nlink && callerBundle.st_size == namedBundle.st_size &&
      !memcmp(&callerBundle.st_mtimespec, &namedBundle.st_mtimespec, sizeof(timespec)) &&
      !memcmp(&callerBundle.st_ctimespec, &namedBundle.st_ctimespec, sizeof(timespec));
  };
  if (fstat(STDOUT_FILENO, &callerBundle) || !S_ISDIR(callerBundle.st_mode) || !sameBundle() ||
      fstat(STDERR_FILENO, &callerImage) || (fcntl(STDERR_FILENO, F_GETFL) & O_ACCMODE) != O_RDONLY ||
      !image.openPath(imagePath, 0600, 1024LL * 1024 * 1024) ||
      !arbol_attempt::sameFile(callerImage, image.identity) ||
      !backing.capture(helperText.intValue, image)) return 4;
  if (requestPath) {
    NSDictionary* attempt = nil;
    {
      arbol_attempt::Claim claim;
      std::string raw;
      if (!claim.acquire(requestPath, std::min(expiry, arbol_boundary::clockMs() + 60)) ||
          !claim.read(raw, attempt) || ![attempt[@"phase"] isEqual:@"claimed"] ||
          !arbol_attempt::launchRequest(claim, requestPath, attempt)) attempt = nil;
    }
    RetainedStartupPackage relayed;
    if (relayed.authenticate(layout, attempt) && backing.current(image) && sameBundle() && inTime()) {
      os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "arbol-browser startup used launcher package proof");
      return 0;
    }
  }
  NSDictionary* appProof = arbol_startup_proof::cached(layout.bundle, STDOUT_FILENO, image.fd, expiry);
  if (appProof && immutable.capture(layout, false) && backing.current(image) && sameBundle() &&
      arbol_startup_proof::currentCache(appProof, layout.bundle, STDOUT_FILENO, image.fd, immutable) && inTime()) {
    os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "arbol-browser verifier used App package proof");
    return 0;
  }
  if (!immutable.capture(layout, false) || !signature(bundle, true, false, true)) return 4;
  NSDictionary* manifest = json([bundle stringByAppendingPathComponent:@"Contents/Resources/native-compatibility.json"]);
  if (!payload(bundle, manifest) || !immutable.current() || !backing.current(image) ||
      !sameBundle() || !inTime()) return 4;
  return 0;
}

// LaunchServices supplies a new independent process. The fixed signed shim
// still owns selection, profile-instance checks and ordinary open admission.
static int openInstalledProfile(const arbol_attempt::PackagedLayout& layout, NSString* bundle, const char* profile, const char* instance) {
  NSString* id = [NSString stringWithUTF8String:profile];
  NSString* key = [NSString stringWithUTF8String:instance];
  struct statfs volume{};
  if (!layout.installed || !arbol_attempt::pattern(id, @"^[a-z]([a-z0-9-]{0,62}[a-z0-9])?$") ||
      !arbol_attempt::pattern(key, @"^prf_[A-Za-z0-9_-]{22}$") ||
      !safeDirectory(bundle, false) || statfs(bundle.fileSystemRepresentation, &volume) ||
      !(volume.f_flags & MNT_RDONLY) || strcmp(volume.f_fstypename, "apfs") || layout.buildRoot + "/app" != volume.f_mntonname ||
      !signature(bundle, true, false, true)) return 4;
  NSString* home = arbol_attempt::physicalAccountHome();
  if (!home) return 4;
  std::string launcher = arbol_attempt::stableLauncherPath(home);
  NSString* path = [NSString stringWithUTF8String:launcher.c_str()];
  struct stat file{};
  if (!safeDirectory(path.stringByDeletingLastPathComponent, false) ||
      !arbol_boundary::canonical(launcher) || lstat(launcher.c_str(), &file) || !S_ISREG(file.st_mode) ||
      file.st_uid != geteuid() || (file.st_mode & 07777) != 0755 || file.st_nlink != 1 ||
      !arbol_attempt::signedIdentity(launcher, @"com.sylvan-stack.arbol-browser.launcher") || !inTime()) return 4;
  const char* arguments[] = {launcher.c_str(), "open", "--profile", profile, "--profile-instance", instance, nullptr};
  std::string homeEnvironment = "HOME=" + std::string(home.fileSystemRepresentation);
  const char* environment[] = {homeEnvironment.c_str(), "PATH=/usr/bin:/bin", "TMPDIR=/private/tmp", nullptr};
  execve(launcher.c_str(), const_cast<char* const*>(arguments), const_cast<char* const*>(environment));
  return 4;
}
int main(int argc, const char* argv[]) {
  @autoreleasepool {
    arbol_exit::NoUseOriginal noUse;
    try { @try {
      expiry=arbol_boundary::clockMs()+60000;
      if ((argc == 3 || argc == 4) && !strcmp(argv[1], "--arbol-verify-installed-package")) {
        expiry=arbol_boundary::clockMs()+5000;
        NSString* bundle = NSBundle.mainBundle.bundlePath;
        arbol_attempt::PackagedLayout layout;
        if (!arbol_attempt::packagedLayout(bundle.fileSystemRepresentation, layout)) return 4;
        return verifyInstalledPackage(layout, bundle, argv[2], argc == 4 ? argv[3] : nullptr);
      }
      const bool profileOpen = argc == 4 && !strcmp(argv[1], "--arbol-profile-open");
      if ((!profileOpen && (argc != 3 || strcmp(argv[1], "--arbol-host-request") || argv[2][0] != '/')) ||
          getppid() != 1 || setpgid(0, 0) || getpgrp() != getpid()) return 4;
      NSOperatingSystemVersion os = NSProcessInfo.processInfo.operatingSystemVersion;
      if (os.majorVersion != 27 || os.minorVersion != 0 || os.patchVersion != 1 || sizeof(void*) != 8) return 4;
      NSString* bundle = NSBundle.mainBundle.bundlePath;
      arbol_attempt::PackagedLayout layout;
      if (!arbol_attempt::packagedLayout(bundle.fileSystemRepresentation,layout)) return 4;
      arbol_boundary::Lock build;
      if (!arbol_attempt::openBuild(bundle.fileSystemRepresentation,build)) return 4;
      if (profileOpen) return openInstalledProfile(layout, bundle, argv[2], argv[3]);
      // Read only authenticated private control metadata here, release the
      // short lock during signature work, then compare the exact version again.
      std::string initialRaw; NSDictionary* initial=nil; arbol_attempt::PackagedLayout initialLayout;
      { arbol_attempt::Claim early;
        if(!early.acquire(argv[2],std::min(expiry,arbol_boundary::clockMs()+2000)) || !early.read(initialRaw,initial) ||
           !arbol_attempt::launchRequest(early,argv[2],initial) ||
           !arbol_attempt::claimedLayout(initial,initialLayout) || initialLayout.bundle!=layout.bundle || initialLayout.guard!=build.path || ![initial[@"phase"] isEqual:@"pending"]) return 4;
        expiry=std::min(expiry,[initial[@"expires"] doubleValue]); if(!inTime()) return 4;
      }
      arbol_boundary::Identity original; std::string originalPath;
      if(arbol_boundary::observe(getpid(),original)!=1 || original.group!=(uint32_t)getpid() || getsid(0)<=0 ||
          !arbol_boundary::executable(original,originalPath) || originalPath!=layout.bootstrap) return 4;
      RetainedStartupPackage relayed;
      const bool alreadyVerified = relayed.authenticate(layout, initial);
      if (alreadyVerified) os_log_with_type(OS_LOG_DEFAULT, OS_LOG_TYPE_DEFAULT, "arbol-browser outer startup used launcher package proof");
      if (!alreadyVerified && !signature(bundle, true, false, layout.installed)) return 4;
      NSString* expectedTeam = layout.installed ? @ARBOL_PRODUCTION_PUBLISHER_TEAM : team;
      NSString* expectedBundle = layout.installed ? @ARBOL_PRODUCTION_BUNDLE_ID : bundleID;
      NSString* expectedPublisher = layout.installed ? @ARBOL_PRODUCTION_PUBLISHER_REQUIREMENT : publisher;
      NSDictionary* policy = json([bundle stringByAppendingPathComponent:@"Contents/Resources/publisher-requirement.json"]);
      if (![policy isEqual:@{@"team": expectedTeam, @"bundleIdentifier": expectedBundle, @"requirement": expectedPublisher}]) return 4;
      NSDictionary* manifest = json([bundle stringByAppendingPathComponent:@"Contents/Resources/native-compatibility.json"]);
      NSDictionary* runtime = @{@"electron": @"45.3.2", @"chromium": @"156.0.8078.100", @"node": @"24.22.2", @"napi": @"10", @"modules": @"150", @"platform": @"darwin", @"arch": @"arm64", @"macOS": @"27.0.1"};
      NSDictionary* features = @{@"sitePerProcess": @YES, @"disabledFeatures": @[@"MacAccessibilityTextOperation"], @"extraChromiumArguments": @[]};
      if (![manifest[@"runtime"] isEqual:runtime] || ![manifest[@"featureConfiguration"] isEqual:features] ||
          ![manifest[@"publisherTeam"] isEqual:expectedTeam] || ![manifest[@"bundleIdentifier"] isEqual:expectedBundle] ||
          (alreadyVerified ? !relayed.current() : !payload(bundle, manifest) || !signature(bundle, true, false, layout.installed))) return 4;
      NSString* root = [NSString stringWithUTF8String:layout.payload.c_str()];
      NSDictionary* hostPolicy=json([bundle stringByAppendingPathComponent:@"Contents/Resources/host-policy.json"]);
      NSDictionary* metadata=json([root stringByAppendingPathComponent:@"metadata.json"]);
      NSString* stateRoot = arbol_attempt::policyStateRoot(hostPolicy, layout);
      NSString* buildRoot = [NSString stringWithUTF8String:layout.buildRoot.c_str()];
      if (!stateRoot ||
          ![metadata[@"component"][@"build"] isEqual:hostPolicy[@"build"]] ||
          ![metadata[@"sourceDigest"] isEqual:hostPolicy[@"sourceDigest"]] || ![metadata[@"host"][@"productDigest"] isEqual:hostPolicy[@"productDigest"]]) return 4;
      if (layout.installed) {
        struct statfs volume{};
        if (!safeDirectory(buildRoot, false) || !safeDirectory(stateRoot, true) ||
            statfs(bundle.fileSystemRepresentation, &volume) || !(volume.f_flags & MNT_RDONLY) ||
            strcmp(volume.f_fstypename, "apfs") || layout.buildRoot + "/app" != volume.f_mntonname) return 4;
      } else if (!isolated(buildRoot, stateRoot)) return 4;
      // No owner lock, marker, session or engine resource is touched by a stale,
      // cancelled or already claimed LaunchServices delivery.
      arbol_attempt::Claim claim; std::string prior; NSDictionary* attempt=nil;
      if (!claim.acquire(argv[2],std::min(expiry,arbol_boundary::clockMs()+2000)) || !claim.read(prior,attempt) || prior!=initialRaw ||
          !arbol_attempt::launchRequest(claim,argv[2],attempt) ||
          ![attempt[@"buildRoot"] isEqual:buildRoot] || ![attempt[@"build"] isEqual:hostPolicy[@"build"]] ||
          ![attempt[@"buildGuard"] isEqual:[NSString stringWithUTF8String:build.path.c_str()]] ||
          !arbol_attempt::pattern([attempt[@"profile"] lastPathComponent],@"^[a-z](?:[a-z0-9-]{0,62}[a-z0-9])?$") ||
          ![attempt[@"profile"] isEqual:[[stateRoot stringByAppendingPathComponent:@"profiles"] stringByAppendingPathComponent:[attempt[@"profile"] lastPathComponent]]] ||
          ![attempt[@"starter"][@"executable"] isEqual:[NSString stringWithUTF8String:layout.engine.c_str()]] ||
          ![attempt[@"sourceDigest"] isEqual:hostPolicy[@"sourceDigest"]] || ![attempt[@"productDigest"] isEqual:hostPolicy[@"productDigest"]]) return 4;
      NSMutableDictionary* claimed=[attempt mutableCopy]; claimed[@"phase"]=@"claimed"; claimed[@"bootstrap"]=arbol_attempt::processRecord(getpid());
      std::string claimedRaw=arbol_attempt::bytes(claimed);
      if(!arbol_attempt::transition(attempt,claimed,arbol_attempt::Role::bootstrap)) return 4;
      // Capture before the actual write attempt, including an ambiguously
      // failed replacement. The one native terminal guard covers every later
      // return and both C++/Objective-C exceptions without inventing an Owner.
      noUse.capture(argv[2],bundle.fileSystemRepresentation,build,claimed,@"outer",prior);
      if(!arbol_attempt::replace(claim.at,prior,false,claimedRaw)) {
        (void)noUse.confirmUnclaimed(claim,prior); // exact actual still-held Claim
        return 4;
      }
      if(!arbol_boundary::lockIdentity(build)) return 4;
      NSDictionary* transport=@{@"format":@1,@"kind":@"host-build",@"requestPath":[NSString stringWithUTF8String:argv[2]],
        @"claimDigest":arbol_attempt::digest(claimedRaw),@"bootstrap":claimed[@"bootstrap"],@"guard":arbol_boundary::capsuleLock(build),@"descriptor":@(build.fd)};
      int capsule=arbol_boundary::capsuleDescriptor(arbol_attempt::bytes(transport));
      if(capsule<0 || fcntl(capsule,F_SETFD,0) || fcntl(build.fd,F_SETFD,0)) return 4;
      // End the short transition before exec. Only the original Build OFD and
      // unlinked read-only transport survive. Its bytes alone grant no trust.
      if(close(claim.fd)) return 4; claim.fd=-1;
      NSString* engine = [NSString stringWithUTF8String:layout.engine.c_str()];
      NSString* entry = [root stringByAppendingPathComponent:@"lib/host/main.mjs"];
      std::string home = "HOME=" + std::string(NSHomeDirectory().fileSystemRepresentation), user = "USER=" + std::string(NSUserName().UTF8String);
      // PID version changes across exec; record stable original identity here and
      // let preloaded process support capture the running engine's actual version.
      std::string custody="ARBOL_BROWSER_BOOTSTRAP=1:"+std::to_string(original.pid)+":"+std::to_string(original.start)+":"+std::to_string(original.group)+":"+std::to_string(getsid(0))+":"+std::to_string(original.uid);
      std::string inherited="ARBOL_BROWSER_BUILD_CAPSULE="+std::to_string(capsule);
      char* environment[] = {home.data(), user.data(), custody.data(), inherited.data(), (char*)"PATH=/usr/bin:/bin", (char*)"TMPDIR=/private/tmp", nullptr};
      char* args[] = {(char*)engine.fileSystemRepresentation, (char*)"--site-per-process", (char*)"--disable-features=MacAccessibilityTextOperation", (char*)entry.fileSystemRepresentation, (char*)"--arbol-host-request", (char*)argv[2], nullptr};
      if(!inTime() || !arbol_boundary::lockIdentity(build) || (alreadyVerified && !relayed.current())) return 4;
      noUse.beforeExec();
      execve(engine.fileSystemRepresentation, args, environment);
      int failure=errno; noUse.returnedExecFailure(failure); return 4;
    } @catch (NSException*) { return 4; } } catch(...) { return 4; }
  }
}

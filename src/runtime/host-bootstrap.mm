// Separately signed outer bootstrap: source-pinned publisher, no live-learned
// trust or inherited engine arguments. This code never loads an input addon.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <cstring>
#include <string>
static NSString* const team = @"7V372XL59S";
static NSString* const bundleID = @"com.sylvan-stack.arbol-browser.native-candidate";
static NSString* const publisher = @"anchor apple generic and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists";
static bool signature(NSString* path, bool outer, bool jit) {
  SecStaticCodeRef code = nullptr; SecRequirementRef requirement = nullptr; CFDictionaryRef information = nullptr;
  NSString* text = outer ? [publisher stringByAppendingFormat:@" and identifier \"%@\"", bundleID] : publisher;
  if (SecStaticCodeCreateWithPath((__bridge CFURLRef)[NSURL fileURLWithPath:path], kSecCSDefaultFlags, &code) != errSecSuccess) return false;
  OSStatus result = SecRequirementCreateWithString((__bridge CFStringRef)text, kSecCSDefaultFlags, &requirement);
  if (result == errSecSuccess) result = SecStaticCodeCheckValidity(code, kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode, requirement);
  if (result == errSecSuccess) result = SecCodeCopySigningInformation(code, kSecCSSigningInformation, &information);
  bool valid = false;
  if (result == errSecSuccess && information) {
    NSDictionary* info = (__bridge NSDictionary*)information;
    NSDictionary* entitlements = info[(__bridge NSString*)kSecCodeInfoEntitlementsDict];
    valid = ([info[(__bridge NSString*)kSecCodeInfoFlags] unsignedIntValue] & kSecCodeSignatureRuntime) &&
      [info[(__bridge NSString*)kSecCodeInfoTeamIdentifier] isEqual:team];
    for (NSString* key in entitlements) if (![key isEqualToString:@"com.apple.security.cs.allow-jit"] || !jit || ![entitlements[key] isEqual:@YES]) valid = false;
  }
  if (information) CFRelease(information);
  if (requirement) CFRelease(requirement);
  CFRelease(code);
  return valid;
}
static id json(NSString* path) {
  int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat stat{};
  if (fd < 0) return nil;
  if (fstat(fd, &stat) || !S_ISREG(stat.st_mode) || stat.st_size < 1 || stat.st_size > 1048576) { close(fd); return nil; }
  NSMutableData* bytes = [NSMutableData dataWithLength:(NSUInteger)stat.st_size]; size_t offset = 0;
  while (offset < bytes.length) { ssize_t n = read(fd, (char*)bytes.mutableBytes + offset, bytes.length - offset); if (n <= 0) { close(fd); return nil; } offset += (size_t)n; }
  close(fd); NSError* error = nil; id value = [NSJSONSerialization JSONObjectWithData:bytes options:0 error:&error]; return error ? nil : value;
}
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static NSString* digest(NSString* path, bool symlink) {
  CC_SHA256_CTX context; CC_SHA256_Init(&context);
  if (symlink) {
    char link[PATH_MAX]; ssize_t length = readlink(path.fileSystemRepresentation, link, sizeof(link));
    if (length <= 0 || length == sizeof(link)) return nil;
    const char prefix[] = "symlink"; CC_SHA256_Update(&context, prefix, sizeof(prefix)); CC_SHA256_Update(&context, link, (CC_LONG)length);
  } else {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); if (fd < 0) return nil;
    char bytes[65536]; ssize_t n; while ((n = read(fd, bytes, sizeof(bytes))) > 0) CC_SHA256_Update(&context, bytes, (CC_LONG)n);
    close(fd); if (n < 0) return nil;
  }
  unsigned char bytes[CC_SHA256_DIGEST_LENGTH]; CC_SHA256_Final(bytes, &context);
  NSMutableString* result = [NSMutableString new]; for (unsigned char byte : bytes) [result appendFormat:@"%02x", byte]; return result;
}
#pragma clang diagnostic pop
static bool payload(NSString* bundle, NSDictionary* manifest) {
  NSDictionary* files = manifest[@"files"]; if (![files isKindOfClass:[NSDictionary class]] || files.count < 3 || files.count > 4096) return false;
  NSString* root = [bundle stringByAppendingPathComponent:@"Contents/Resources/browser"];
  NSString* prefix = [bundle stringByAppendingString:@"/"];
  NSDirectoryEnumerator* walk = [[NSFileManager defaultManager] enumeratorAtPath:root]; NSMutableDictionary* actual = [NSMutableDictionary new];
  if (!walk) return false;
  for (NSString* relative in walk) {
    NSString* path = [root stringByAppendingPathComponent:relative]; struct stat stat{};
    if (lstat(path.fileSystemRepresentation, &stat)) return false;
    bool link = S_ISLNK(stat.st_mode);
    if (link) { [walk skipDescendants]; if (![[path stringByResolvingSymlinksInPath] hasPrefix:prefix]) return false; }
    else if (S_ISDIR(stat.st_mode)) continue;
    else if (!S_ISREG(stat.st_mode)) return false;
    NSString* hash = digest(path, link); if (!hash) return false;
    actual[[@"Contents/Resources/browser/" stringByAppendingString:relative]] = hash;
    if (actual.count > 4096) return false;
    if (!link) {
      int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); uint32_t magic = 0;
      if (fd < 0) return false; ssize_t n = read(fd, &magic, sizeof(magic)); close(fd);
      if (n == sizeof(magic) && (magic == MH_MAGIC_64 || magic == MH_CIGAM_64 || magic == FAT_MAGIC || magic == FAT_CIGAM)) {
        bool jit = [relative hasPrefix:@"runtime/Electron.app/"] && [relative containsString:@"/Contents/MacOS/"];
        if (!signature(path, false, jit)) return false;
      }
    }
  }
  return [actual isEqual:files];
}
int main(int argc, const char* argv[]) {
  @autoreleasepool {
    @try {
      if (argc != 3 || strcmp(argv[1], "--arbol-host-request") || argv[2][0] != '/' || getppid() != 1 || setpgid(0, 0) || getpgrp() != getpid()) return 4;
      NSOperatingSystemVersion os = NSProcessInfo.processInfo.operatingSystemVersion;
      if (os.majorVersion != 27 || os.minorVersion != 0 || os.patchVersion != 1 || sizeof(void*) != 8) return 4;
      NSString* bundle = NSBundle.mainBundle.bundlePath;
      if (!signature(bundle, true, false)) return 4;
      NSDictionary* policy = json([bundle stringByAppendingPathComponent:@"Contents/Resources/publisher-requirement.json"]);
      if (![policy isEqual:@{@"team": team, @"bundleIdentifier": bundleID, @"requirement": publisher}]) return 4;
      NSDictionary* manifest = json([bundle stringByAppendingPathComponent:@"Contents/Resources/native-compatibility.json"]);
      NSDictionary* runtime = @{@"electron": @"45.3.2", @"chromium": @"156.0.8078.100", @"node": @"24.22.2", @"napi": @"10", @"modules": @"150", @"platform": @"darwin", @"arch": @"arm64", @"macOS": @"27.0.1"};
      NSDictionary* features = @{@"sitePerProcess": @YES, @"disabledFeatures": @[@"MacAccessibilityTextOperation"], @"extraChromiumArguments": @[]};
      if (![manifest[@"runtime"] isEqual:runtime] || ![manifest[@"featureConfiguration"] isEqual:features] || ![manifest[@"publisherTeam"] isEqual:team] || ![manifest[@"bundleIdentifier"] isEqual:bundleID] || !payload(bundle, manifest) || !signature(bundle, true, false)) return 4;
      int fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC); struct stat stat{};
      if (fd < 0) return 4;
      bool request = !fstat(fd, &stat) && S_ISREG(stat.st_mode) && stat.st_uid == geteuid() && (stat.st_mode & 07777) == 0600 && stat.st_nlink == 1 && stat.st_size > 0 && stat.st_size <= 16384; close(fd); if (!request) return 4;
      NSString* root = [bundle stringByAppendingPathComponent:@"Contents/Resources/browser"];
      NSString* engine = [root stringByAppendingPathComponent:@"runtime/Electron.app/Contents/MacOS/Electron"];
      NSString* entry = [root stringByAppendingPathComponent:@"lib/host/main.mjs"];
      std::string home = "HOME=" + std::string(NSHomeDirectory().fileSystemRepresentation), user = "USER=" + std::string(NSUserName().UTF8String);
      char* environment[] = {home.data(), user.data(), (char*)"PATH=/usr/bin:/bin", (char*)"TMPDIR=/private/tmp", nullptr};
      char* args[] = {(char*)engine.fileSystemRepresentation, (char*)"--site-per-process", (char*)"--disable-features=MacAccessibilityTextOperation", (char*)entry.fileSystemRepresentation, (char*)"--arbol-host-request", (char*)argv[2], nullptr};
      execve(engine.fileSystemRepresentation, args, environment); return 4;
    } @catch (NSException*) { return 4; }
  }
}

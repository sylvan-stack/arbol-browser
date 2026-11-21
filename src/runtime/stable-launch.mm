// Installed Browser entry. It uses only the account's installed image and guard.
#include "attempt.hpp"
#include <poll.h>

namespace {
using arbol_boundary::clockMs;
using arbol_attempt::PackagedLayout;

class FD {
  int value_;
public:
  explicit FD(int value) : value_(value) {}
  FD(const FD&) = delete;
  ~FD() { if (value_ >= 0) close(value_); }
  int get() const { return value_; }
};

int openInstalledFile(const std::string& path) {
  if (!arbol_boundary::canonical(path) || !arbol_boundary::privateAncestors(path)) return -1;
  return open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
}

bool fileIdentity(int fd, const std::string& path, const struct stat& original) {
  struct stat held{}, named{};
  return !fstat(fd, &held) && !lstat(path.c_str(), &named) && arbol_attempt::privateFile(held) &&
    arbol_attempt::sameFile(original, held) && arbol_attempt::sameFile(held, named);
}

std::string readSelection(const std::string& path) {
  FD file(openInstalledFile(path));
  struct stat before{};
  if (file.get() < 0 || fstat(file.get(), &before) || !arbol_attempt::privateFile(before) ||
      before.st_size < 1 || before.st_size > 4096) return {};
  std::string contents(size_t(before.st_size), '\0');
  size_t offset = 0;
  while (offset < contents.size()) {
    ssize_t size = read(file.get(), contents.data() + offset, contents.size() - offset);
    if (size > 0) offset += size_t(size);
    else if (size != -1 || errno != EINTR) return {};
  }
  return fileIdentity(file.get(), path, before) ? contents : std::string();
}

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
NSString* imageDigest(int fd, const std::string& path, const struct stat& image, double deadline) {
  if (!arbol_attempt::privateFile(image) || image.st_size < 1 || image.st_size > 1024LL * 1024 * 1024)
    return nil;
  CC_SHA256_CTX hash;
  CC_SHA256_Init(&hash);
  char bytes[65536];
  off_t remaining = image.st_size;
  while (remaining > 0 && clockMs() < deadline) {
    ssize_t size = read(fd, bytes, size_t(std::min(remaining, off_t(sizeof(bytes)))));
    if (size > 0) { CC_SHA256_Update(&hash, bytes, CC_LONG(size)); remaining -= size; }
    else if (size != -1 || errno != EINTR) return nil;
  }
  if (remaining || clockMs() >= deadline || !fileIdentity(fd, path, image)) return nil;
  unsigned char raw[CC_SHA256_DIGEST_LENGTH];
  CC_SHA256_Final(raw, &hash);
  NSMutableString* digest = [NSMutableString new];
  for (unsigned char byte : raw) [digest appendFormat:@"%02x", byte];
  return digest;
}
#pragma clang diagnostic pop

NSData* diskImageTool(NSArray<NSString*>* arguments, double deadline) {
  if (clockMs() >= deadline) return nil;
  NSPipe* pipe = [NSPipe pipe];
  NSFileHandle* input = pipe.fileHandleForReading;
  const int fd = input.fileDescriptor;
  const int flags = fcntl(fd, F_GETFL);
  if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK)) return nil;
  NSTask* task = [NSTask new];
  task.executableURL = [NSURL fileURLWithPath:@"/usr/bin/hdiutil"];
  task.arguments = arguments;
  task.environment = @{@"PATH": @"/usr/bin:/bin"};
  task.standardInput = [NSFileHandle fileHandleWithNullDevice];
  task.standardOutput = pipe;
  task.standardError = [NSFileHandle fileHandleWithNullDevice];
  if (![task launchAndReturnError:nil]) return nil;
  NSMutableData* output = [NSMutableData new];
  bool eof = false;
  while (clockMs() < deadline && (!eof || task.running)) {
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
  return eof && clockMs() < deadline && output.length <= 1048576 && task.terminationStatus == 0 ? output : nil;
}

bool mountedImage(const std::string& mount, NSString* image, double deadline) {
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

int launch(int argc, const char* argv[], double deadline) {
  NSString* home = arbol_attempt::physicalAccountHome();
  const std::string launcher = arbol_attempt::stableLauncherPath(home);
  arbol_boundary::Identity self;
  std::string executable;
  if (!home || launcher.empty() || arbol_boundary::observe(getpid(), self) != 1 ||
      !arbol_boundary::executable(self, executable) || executable != launcher ||
      !arbol_attempt::signedIdentity(launcher, @"com.sylvan-stack.arbol-browser.launcher")) return 4;
  NSString* uses = [home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_USES];
  NSString* support = uses.stringByDeletingLastPathComponent;
  const std::string selectionPath = [support stringByAppendingPathComponent:@"selected.json"].fileSystemRepresentation;
  const std::string selected = readSelection(selectionPath);
  NSDictionary* receipt = arbol_attempt::json(selected);
  NSString* build = receipt[@"build"];
  if (!arbol_attempt::keys(receipt, @[@"format", @"build", @"imageSha256"]) ||
      ![receipt[@"format"] isEqual:@1] || !arbol_attempt::pattern(build, @"^[1-9a-f][0-9a-f]{0,15}$") ||
      !arbol_attempt::pattern(receipt[@"imageSha256"], @"^[0-9a-f]{64}$")) return 4;
  int first = 1;
  if (argc > 1 && !strcmp(argv[1], "-v")) {
    if (argc < 4 || strcmp(argv[2], build.UTF8String)) return 4;
    first = 3;
  }
  NSString* root = [[home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_BUILDS] stringByAppendingPathComponent:build];
  const std::string mount = [root stringByAppendingPathComponent:@"app"].fileSystemRepresentation;
  const std::string bundle = mount + "/ArbolBrowser.app";
  PackagedLayout layout;
  if (!arbol_attempt::packagedLayout(bundle, layout) || !layout.installed) return 4;
  FD guard(open(layout.guard.c_str(), O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC));
  struct stat held{};
  if (guard.get() < 0 || fstat(guard.get(), &held) || !arbol_attempt::privateFile(held) ||
      flock(guard.get(), LOCK_SH | LOCK_NB)) return 4;
  arbol_boundary::Lock lock{guard.get(), layout.guard, uint64_t(held.st_dev), held.st_ino, held.st_uid, 0600, LOCK_SH};
  if (!arbol_boundary::lockIdentity(lock) || readSelection(selectionPath) != selected ||
      !arbol_boundary::canonical(mount) || !arbol_boundary::privateAncestors(mount)) return 4;
  NSString* image = [[support stringByAppendingPathComponent:@"images"] stringByAppendingPathComponent:[build stringByAppendingString:@".dmg"]];
  const std::string imagePath = image.fileSystemRepresentation;
  FD backing(openInstalledFile(imagePath));
  struct stat imageStat{};
  if (backing.get() < 0 || fstat(backing.get(), &imageStat) ||
      ![imageDigest(backing.get(), imagePath, imageStat, deadline) isEqual:receipt[@"imageSha256"]]) return 4;

  struct statfs fs{};
  if (statfs(mount.c_str(), &fs)) return 4;
  if (mount != fs.f_mntonname) {
    NSString* point = [NSString stringWithUTF8String:mount.c_str()];
    NSArray* entries = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:point error:nil];
    if (!entries || entries.count || !diskImageTool(@[@"attach", image, @"-readonly", @"-nokernel",
        @"-mountpoint", point, @"-noautoopen", @"-nobrowse", @"-plist"], deadline)) return 4;
  }
  if (!mountedImage(mount, image, deadline) || !fileIdentity(backing.get(), imagePath, imageStat) ||
      !arbol_boundary::canonical(bundle) || !arbol_attempt::signedIdentity(bundle, @ARBOL_PRODUCTION_BUNDLE_ID, true) ||
      !arbol_boundary::lockIdentity(lock) || readSelection(selectionPath) != selected || clockMs() >= deadline) return 4;

  NSDictionary* parent = arbol_attempt::processRecord(getpid());
  if (!parent) return 4;
  FD capsule(arbol_boundary::capsuleDescriptor(arbol_attempt::bytes(@{@"format":@1, @"parent":parent,
    @"deadline":@(deadline), @"guard":arbol_boundary::capsuleLock(lock),
    @"bundle":[NSString stringWithUTF8String:bundle.c_str()]})));
  posix_spawn_file_actions_t actions;
  if (capsule.get() < 0 || posix_spawn_file_actions_init(&actions)) return 4;
  arbol_boundary::SpawnCopies copies;
  if (!copies.map(actions, guard.get(), arbol_attempt::cliBuildDescriptor) ||
      !copies.map(actions, capsule.get(), arbol_attempt::cliCapsuleDescriptor)) {
    posix_spawn_file_actions_destroy(&actions); return 4;
  }
  const std::string entry = layout.payload + "/lib/cli/main.mjs";
  std::string homeEnv = "HOME=" + std::string(home.fileSystemRepresentation);
  std::string buildEnv = "ARBOL_BROWSER_SELECTION=" + arbol_attempt::bytes(@{@"format":@1, @"build":build,
    @"directory":root, @"guard":[NSString stringWithUTF8String:layout.guard.c_str()], @"explicit":@(first != 1)});
  char* environment[] = {homeEnv.data(), buildEnv.data(), (char*)"PATH=/usr/bin:/bin",
    (char*)"ELECTRON_RUN_AS_NODE=1", (char*)"TMPDIR=/private/tmp", nullptr};
  std::vector<char*> args{(char*)layout.engine.c_str(), (char*)entry.c_str()};
  for (int index = first; index < argc; ++index) args.push_back((char*)argv[index]);
  args.push_back(nullptr);
  pid_t child = 0;
  const int result = clockMs() < deadline ?
    posix_spawn(&child, layout.engine.c_str(), &actions, nullptr, args.data(), environment) : ETIMEDOUT;
  posix_spawn_file_actions_destroy(&actions);
  copies.closeCopies();
  if (result) return 4;
  int status = 0;
  pid_t waited;
  do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  if (waited != child) return 4;
  return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
}
}

int main(int argc, const char* argv[]) {
  @autoreleasepool { @try {
    return launch(argc, argv, clockMs() + 60000);
  } @catch (NSException*) { return 4; } }
}

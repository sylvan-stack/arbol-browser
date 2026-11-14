// LaunchServices-owned native app entry. Isolate before stock Electron or any
// helper exists. No inherited lock FD handoff to Electron is assumed.
#import <Foundation/Foundation.h>
#import <Security/Security.h>
#include <mach-o/dyld.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <limits.h>
#include <cstring>
#include <string>

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    if (argc != 3 || std::strcmp(argv[1], "--arbol-host-request") != 0 || argv[2][0] != '/') return 4;
    // Refuse any invocation still parented by a Driver/app-server or shell.
    // LaunchServices' launchd parent is the only accepted bootstrap parent.
    if (getppid() != 1 || setpgid(0, 0) != 0 || getpgrp() != getpid()) return 4;
    SecCodeRef self = nullptr;
    OSStatus signature = SecCodeCopySelf(kSecCSDefaultFlags, &self);
    if (signature != errSecSuccess || !self) return 4;
    signature = SecCodeCheckValidity(self, kSecCSStrictValidate, nullptr);
    CFRelease(self);
    if (signature != errSecSuccess) return 4;
    // Structural seal only. The later trusted support provider must enforce
    // Developer ID/team/manifest identity before engine data or page admission.
    int fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat st{};
    if (fd < 0) return 4;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 07777) != 0600 || st.st_nlink != 1 || st.st_size <= 0 || st.st_size > 16384) { close(fd); return 4; }
    close(fd);
    char executable[PATH_MAX]{}; uint32_t length = sizeof(executable);
    if (_NSGetExecutablePath(executable, &length) != 0) return 4;
    NSString* path = [[NSString stringWithUTF8String:executable] stringByResolvingSymlinksInPath];
    NSString* root = path;
    for (int i = 0; i < 5; ++i) root = [root stringByDeletingLastPathComponent];
    NSString* engine = [root stringByAppendingPathComponent:@"runtime/Electron.app/Contents/MacOS/Electron"];
    NSString* entry = [root stringByAppendingPathComponent:@"lib/host/main.mjs"];
    // Replace rather than filter an open-ended environment. No runtime install,
    // remote debugging flag, provider option or native-addon override exists.
    NSString* home = NSHomeDirectory();
    std::string homeEnv = "HOME=" + std::string(home.fileSystemRepresentation);
    std::string userEnv = "USER=" + std::string(NSUserName().UTF8String);
    char* environment[] = { homeEnv.data(), userEnv.data(), (char*)"PATH=/usr/bin:/bin", (char*)"TMPDIR=/private/tmp", nullptr };
    char* args[] = { (char*)engine.fileSystemRepresentation, (char*)entry.fileSystemRepresentation,
      (char*)"--arbol-host-request", (char*)argv[2], nullptr };
    execve(engine.fileSystemRepresentation, args, environment);
    return 4;
  }
}

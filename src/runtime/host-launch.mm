// One-shot LaunchServices request. This process never becomes the browser's
// parent or a resident broker. Arguments name only a private request file.
#import <AppKit/AppKit.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <chrono>

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    if (argc != 3) return 4;
    NSString* application = [NSString stringWithUTF8String:argv[1]];
    NSString* request = [NSString stringWithUTF8String:argv[2]];
    if (!application.isAbsolutePath || !request.isAbsolutePath) return 4;
    struct stat st{};
    if (lstat(argv[2], &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() ||
        (st.st_mode & 07777) != 0600 || st.st_nlink != 1 || st.st_size > 16384) return 4;
    NSWorkspaceOpenConfiguration* configuration = [NSWorkspaceOpenConfiguration configuration];
    configuration.createsNewApplicationInstance = YES;
    configuration.activates = YES;
    configuration.addsToRecentItems = NO;
    configuration.arguments = @[ @"--arbol-host-request", request ];
    // A closed environment is supplied; bootstrap also replaces the complete
    // inherited environment before exec. No caller flags or Node/DYLD options.
    configuration.environment = @{};
    __block BOOL completed = NO;
    __block int status = 4;
    [[NSWorkspace sharedWorkspace] openApplicationAtURL:[NSURL fileURLWithPath:application]
      configuration:configuration completionHandler:^(NSRunningApplication* app, NSError* error) {
        if (!error && app && app.processIdentifier > 0) {
          std::printf("%d\n", app.processIdentifier); std::fflush(stdout); status = 0;
        }
        completed = YES;
      }];
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(28);
    while (!completed && std::chrono::steady_clock::now() < deadline)
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.025]];
    return completed ? status : 4;
  }
}

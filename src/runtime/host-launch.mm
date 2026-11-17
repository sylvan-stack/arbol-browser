// One-shot LaunchServices request. This process never becomes the browser's
// parent or a resident broker. Arguments name only a private request file.
#import <AppKit/AppKit.h>
#include "attempt.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    if (argc != 3) return 4;
    NSString* application = [NSString stringWithUTF8String:argv[1]];
    NSString* request = [NSString stringWithUTF8String:argv[2]];
    if (!application.isAbsolutePath || !request.isAbsolutePath) return 4;
    double deadline=arbol_boundary::clockMs()+28000;
    { arbol_attempt::Claim claim; std::string raw; NSDictionary* attempt=nil;
      if(!claim.acquire(argv[2],std::min(deadline,arbol_boundary::clockMs()+2000)) || !claim.read(raw,attempt) ||
         !arbol_attempt::launchRequest(claim,argv[2],attempt) || ![attempt[@"phase"] isEqual:@"pending"] ||
         !arbol_attempt::currentProcess(attempt[@"starter"]) ||
         ![application isEqual:[attempt[@"buildRoot"] stringByAppendingPathComponent:@"ArbolBrowser.app"]] ||
         !arbol_boundary::canonical(application.fileSystemRepresentation)) return 4;
      deadline=std::min(deadline,[attempt[@"expires"] doubleValue]);
    }
    if(arbol_boundary::clockMs()>=deadline) return 4;
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
        if (!error && app && app.processIdentifier > 0 && arbol_boundary::clockMs()<deadline &&
            [[app.bundleURL.path stringByResolvingSymlinksInPath] isEqual:application]) {
          std::printf("%d\n", app.processIdentifier); std::fflush(stdout); status = 0;
        }
        completed = YES;
      }];
    while (!completed && arbol_boundary::clockMs() < deadline)
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.025]];
    return completed ? status : 4;
  }
}

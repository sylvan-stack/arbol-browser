// One-shot LaunchServices request. This process never becomes the browser's
// parent or a resident broker. Arguments name only a private request file.
#import <AppKit/AppKit.h>
#import <os/log.h>
#include "attempt.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <memory>
#include <mutex>

namespace {
enum class Outcome { pending, refused, accepted, timedOut };
struct Reply {
  std::mutex mutex;
  Outcome outcome = Outcome::pending;
  bool callbackStarted = false;
  int pid = 0;
};

// This authenticates only the fixed exec's PID hint. The caller still requires
// its independent attempts.launched proof and all normal readiness/owner gates.
bool reexecuted(NSString* application, const std::string& requestPath,
    NSDictionary* pending, const std::string& requestRaw, int pid,
    double deadline, unsigned& phase) {
  arbol_attempt::Claim claim; std::string raw; NSDictionary* current = nil;
  if (!claim.acquire(requestPath,std::min(deadline,arbol_boundary::clockMs()+2000)) ||
      !claim.read(raw,current)) return false;
  phase = 2;
  std::string liveRequest; bool absent;
  if (!arbol_attempt::immutable(pending,current) ||
      ![@[@"claimed",@"ready"] containsObject:current[@"phase"]] ||
      current[@"terminal"] != NSNull.null || [current[@"expires"] doubleValue] <= arbol_boundary::clockMs() ||
      !arbol_attempt::currentProcess(pending[@"starter"]) ||
      !arbol_attempt::launchRequest(claim,requestPath,current) ||
      !arbol_attempt::readAt(claim.at.directory,requestPath.substr(requestPath.rfind('/')+1),liveRequest,absent) ||
      absent || liveRequest != requestRaw) return false;
  phase = 3;
  NSDictionary* original = current[@"bootstrap"];
  if (!arbol_attempt::process(original) || [original[@"pid"] intValue] != pid ||
      [original[@"group"] intValue] != pid ||
      ![original[@"executable"] isEqual:[application stringByAppendingPathComponent:@"Contents/MacOS/arbol-browser-native"]] ||
      !arbol_boundary::canonical([original[@"executable"] fileSystemRepresentation])) return false;
  NSString* engine = [application stringByAppendingPathComponent:@"Contents/Resources/browser/runtime/Electron.app/Contents/MacOS/Electron"];
  NSDictionary* live = arbol_attempt::processRecord(pid);
  if (!arbol_attempt::process(live) || ![live[@"executable"] isEqual:engine] ||
      !arbol_boundary::canonical(engine.fileSystemRepresentation) ||
      [live[@"pidVersion"] isEqual:original[@"pidVersion"]]) return false;
  for (NSString* key in @[@"pid",@"uid",@"startId",@"group",@"session",@"parentStartId",@"parentPidVersion"])
    if (![live[key] isEqual:original[key]]) return false;
  if (current[@"engine"] != NSNull.null && ![current[@"engine"] isEqual:live]) return false;
  phase = 4;
  std::string after, afterRequest; NSDictionary* reread = nil;
  // Keep the same short Claim lock through the fresh kernel and exact file
  // rechecks. No transition, admission or new authority is published here.
  if (!arbol_attempt::currentProcess(live) || !claim.read(after,reread) || after != raw ||
      !arbol_attempt::launchRequest(claim,requestPath,reread) ||
      !arbol_attempt::readAt(claim.at.directory,requestPath.substr(requestPath.rfind('/')+1),afterRequest,absent) ||
      absent || afterRequest != requestRaw || !arbol_attempt::unchanged(claim.at) ||
      arbol_boundary::clockMs() >= deadline) return false;
  phase = 5;
  return true;
}
}

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    if (argc != 3) return 4;
    NSString* application = [NSString stringWithUTF8String:argv[1]];
    NSString* request = [NSString stringWithUTF8String:argv[2]];
    if (!application.isAbsolutePath || !request.isAbsolutePath) return 4;
    double deadline=arbol_boundary::clockMs()+28000;
    NSDictionary* pending = nil; std::string requestRaw;
    { arbol_attempt::Claim claim; std::string raw; NSDictionary* attempt=nil;
      if(!claim.acquire(argv[2],std::min(deadline,arbol_boundary::clockMs()+2000)) || !claim.read(raw,attempt) ||
         !arbol_attempt::launchRequest(claim,argv[2],attempt) || ![attempt[@"phase"] isEqual:@"pending"] ||
         !arbol_attempt::currentProcess(attempt[@"starter"]) ||
         ![application isEqual:[attempt[@"buildRoot"] stringByAppendingPathComponent:@"ArbolBrowser.app"]] ||
         !arbol_boundary::canonical(application.fileSystemRepresentation)) return 4;
      bool absent; std::string checkedRequest;
      const std::string name = request.lastPathComponent.UTF8String;
      if (!arbol_attempt::readAt(claim.at.directory,name,requestRaw,absent) || absent ||
          !arbol_attempt::launchRequest(claim,argv[2],attempt) ||
          !arbol_attempt::readAt(claim.at.directory,name,checkedRequest,absent) || absent ||
          checkedRequest != requestRaw || !arbol_attempt::unchanged(claim.at)) return 4;
      pending = [attempt copy];
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
    const std::string requestPath = argv[2];
    const auto reply = std::make_shared<Reply>();
    [[NSWorkspace sharedWorkspace] openApplicationAtURL:[NSURL fileURLWithPath:application]
      configuration:configuration completionHandler:^(NSRunningApplication* app, NSError* error) {
        bool open;
        { std::lock_guard<std::mutex> held(reply->mutex);
          if (reply->callbackStarted) return;
          reply->callbackStarted = true;
          open = reply->outcome == Outcome::pending;
        }
        bool accepted = false; int pid = 0; unsigned branch = 0, phase = 0;
        try { @try {
          if (open && !error && app && app.processIdentifier > 1 && arbol_boundary::clockMs()<deadline) {
            pid = app.processIdentifier;
            NSString* reported = app.bundleURL.path;
            NSString* nested = [application stringByAppendingPathComponent:@"Contents/Resources/browser/runtime/Electron.app"];
            if ([[reported stringByResolvingSymlinksInPath] isEqual:application]) {
              branch = 1; accepted = true;
            } else if ([reported isEqual:nested] && arbol_boundary::canonical(nested.fileSystemRepresentation)) {
              branch = 2; phase = 1;
              accepted = reexecuted(application,requestPath,pending,requestRaw,pid,deadline,phase);
            }
          }
        } @catch (NSException*) { accepted = false; } } catch (...) { accepted = false; }
        Outcome outcome;
        { std::lock_guard<std::mutex> held(reply->mutex);
          if (reply->outcome == Outcome::pending) {
            if (arbol_boundary::clockMs() >= deadline) reply->outcome = Outcome::timedOut;
            else {
              reply->outcome = accepted ? Outcome::accepted : Outcome::refused;
              if (accepted) reply->pid = pid;
            }
          }
          outcome = reply->outcome;
        }
        // One fixed-size private diagnostic from the genuine callback. No PID,
        // paths, request/profile bytes, result tokens or raw errors are logged.
        os_log_with_type(OS_LOG_DEFAULT,OS_LOG_TYPE_DEFAULT,
          "host-launch callback error=%{private}d app=%{private}d branch=%{private}u phase=%{private}u outcome=%{private}u",
          error != nil,app != nil,branch,phase,(unsigned)outcome);
      }];
    while (arbol_boundary::clockMs() < deadline) {
      { std::lock_guard<std::mutex> held(reply->mutex);
        if (reply->outcome != Outcome::pending) break;
      }
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.025]];
    }
    std::lock_guard<std::mutex> held(reply->mutex);
    if (arbol_boundary::clockMs() >= deadline) {
      if (reply->outcome == Outcome::pending) reply->outcome = Outcome::timedOut;
      return 4;
    }
    if (reply->outcome != Outcome::accepted || reply->pid <= 1) return 4;
    std::printf("%d\n",reply->pid); std::fflush(stdout);
    return 0;
  }
}

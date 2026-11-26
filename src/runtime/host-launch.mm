// One-shot LaunchServices request. This process never becomes the browser's
// parent or a resident broker. Arguments name only a private request file.
#import <AppKit/AppKit.h>
#import <os/log.h>
#include "attempt.hpp"
#include "startup-proof.hpp"
#include <sys/stat.h>
#include <unistd.h>
#include <cstdio>
#include <cstdint>
#include <memory>
#include <mutex>

namespace {
enum class Outcome { pending, refused, accepted, timedOut };
enum class ErrorDomain { noneOrUnknown, cocoa, posix, osStatus, other };
struct Reply {
  std::mutex mutex;
  Outcome outcome = Outcome::pending;
  bool callback = false;
  int callbackPid = 0;
  bool error = false, app = false;
  ErrorDomain errorDomain = ErrorDomain::noneOrUnknown;
  int64_t errorCode = 0;
};

enum class Observation { refused, waiting, proved };
struct Baseline {
  int requestFd = -1;
  struct stat directory{}, lock{}, request{};
  ~Baseline() { if (requestFd >= 0) close(requestFd); }
};
bool stable(const arbol_attempt::Claim& claim, const Baseline& baseline,
    const std::string& name) {
  struct stat request{}, held{};
  return claim.at.identity.st_dev == baseline.directory.st_dev &&
    claim.at.identity.st_ino == baseline.directory.st_ino &&
    arbol_attempt::sameFile(claim.at.lockIdentity,baseline.lock) &&
    baseline.requestFd >= 0 && !fstat(baseline.requestFd,&held) &&
    arbol_attempt::sameFile(held,baseline.request) &&
    !fstatat(claim.at.directory,name.c_str(),&request,AT_SYMLINK_NOFOLLOW) &&
    arbol_attempt::sameFile(request,baseline.request) && arbol_attempt::unchanged(claim.at);
}

bool readRequest(const arbol_attempt::Claim& claim, const Baseline& baseline,
    const std::string& name, double deadline, std::string& bytes) {
  bytes.clear();
  if (baseline.request.st_size <= 0 || baseline.request.st_size > (off_t)arbol_attempt::limit ||
      !stable(claim,baseline,name)) return false;
  char buffer[4096];
  while (bytes.size() <= (size_t)baseline.request.st_size) {
    if (arbol_boundary::clockMs() >= deadline) return false;
    ssize_t n = pread(baseline.requestFd,buffer,
      std::min(sizeof(buffer),(size_t)baseline.request.st_size+1-bytes.size()),(off_t)bytes.size());
    if (n > 0) bytes.append(buffer,(size_t)n);
    else if (!n) break;
    else if (errno != EINTR) return false;
  }
  return bytes.size() == (size_t)baseline.request.st_size && stable(claim,baseline,name) &&
    arbol_boundary::clockMs() < deadline;
}

bool lineage(const arbol_boundary::Identity& id, const arbol_boundary::Info& info,
    int session, NSDictionary* original) {
  return id.pid == [original[@"pid"] intValue] && id.uid == [original[@"uid"] unsignedIntValue] &&
    std::to_string(id.start) == [original[@"startId"] UTF8String] &&
    id.group == [original[@"group"] unsignedIntValue] && session == [original[@"session"] intValue] &&
    std::to_string(info.unique.parent) == [original[@"parentStartId"] UTF8String] &&
    info.unique.originalParentVersion == [original[@"parentPidVersion"] intValue] &&
    !(info.bsd.pbi_flags & PROC_FLAG_INEXIT);
}

// An audit-token image query can straddle the one fixed exec. Only a verified
// unchanged original birth/lineage on BOTH sides permits another observation.
// A later complete coherent sample, never that inconclusive query, proves PID.
Observation sample(NSString* application, NSDictionary* original,
    NSDictionary* __strong& live, unsigned& branch) {
  arbol_attempt::PackagedLayout layout;
  if (!arbol_attempt::packagedLayout(application.fileSystemRepresentation,layout)) return Observation::refused;
  int pid = [original[@"pid"] intValue];
  arbol_boundary::Identity first, last; arbol_boundary::Info before{}, after{};
  if (arbol_boundary::observe(pid,first,&before) != 1 ||
      !lineage(first,before,getsid(pid),original)) return Observation::refused;
  std::string image;
  bool found = arbol_boundary::executable(first,image);
  if (arbol_boundary::observe(pid,last,&after) != 1 ||
      !lineage(last,after,getsid(pid),original)) return Observation::refused;
  int version = [original[@"pidVersion"] intValue];
  NSString* outer = [NSString stringWithUTF8String:layout.bootstrap.c_str()];
  NSString* engine = [NSString stringWithUTF8String:layout.engine.c_str()];
  if (found && image != outer.fileSystemRepresentation && image != engine.fileSystemRepresentation)
    return Observation::refused;
  if (first.version != last.version)
    return first.version == version && last.version != version ? Observation::waiting : Observation::refused;
  if (!found) return Observation::refused;
  branch = first.version == version ? 1 : 2;
  NSString* expected = branch == 1 ? outer : engine;
  if (image != expected.fileSystemRepresentation || !arbol_boundary::canonical(expected.fileSystemRepresentation))
    return Observation::refused;
  live = @{@"pid":@(last.pid),@"uid":@(last.uid),@"startId":original[@"startId"],
    @"pidVersion":@(last.version),@"group":@(last.group),@"session":original[@"session"],
    @"parentStartId":original[@"parentStartId"],@"parentPidVersion":original[@"parentPidVersion"],@"executable":expected};
  return Observation::proved;
}

// Read-only classification under a temporary short Claim. The main loop owns
// it only until this observation/reply ends, never across a polling wait.
Observation inspect(arbol_attempt::Claim& claim, NSString* application, const std::string& requestPath,
    NSDictionary* pending, const std::string& requestRaw, const Baseline& baseline,
    NSDictionary* offered, double deadline, int& pid, unsigned& branch, unsigned& phase) {
  std::string raw; NSDictionary* current = nil;
  const std::string name = requestPath.substr(requestPath.rfind('/')+1);
  if (!claim.acquire(requestPath,std::min(deadline,arbol_boundary::clockMs()+2000)) ||
      !claim.read(raw,current) || !stable(claim,baseline,name)) return Observation::refused;
  arbol_attempt::PackagedLayout layout;
  if (!arbol_attempt::claimedLayout(current,layout) || layout.bundle!=application.fileSystemRepresentation) return Observation::refused;
  phase = 1;
  std::string liveRequest;
  if (!arbol_attempt::immutable(pending,current) ||
      current[@"terminal"] != NSNull.null || [current[@"expires"] doubleValue] <= arbol_boundary::clockMs() ||
      !arbol_attempt::currentProcess(pending[@"starter"]) ||
      !arbol_attempt::launchRequest(claim,requestPath,current) ||
      !readRequest(claim,baseline,name,deadline,liveRequest) ||
      liveRequest != requestRaw || !stable(claim,baseline,name) ||
      arbol_boundary::clockMs() >= deadline) return Observation::refused;
  phase = 2;
  if ([current[@"phase"] isEqual:@"pending"]) return Observation::waiting;
  if (![@[@"claimed",@"ready"] containsObject:current[@"phase"]]) return Observation::refused;
  NSDictionary* original = current[@"bootstrap"];
  if (!arbol_attempt::process(original) || [original[@"group"] intValue] != [original[@"pid"] intValue] ||
      (offered && ![original isEqual:offered]) ||
      ![original[@"executable"] isEqual:[NSString stringWithUTF8String:layout.bootstrap.c_str()]] ||
      !arbol_boundary::canonical([original[@"executable"] fileSystemRepresentation])) return Observation::refused;
  phase = 3;
  NSDictionary* live = nil;
  Observation result = sample(application,original,live,branch);
  if (result != Observation::proved) return result;
  if (current[@"engine"] != NSNull.null && ![current[@"engine"] isEqual:live]) return Observation::refused;
  phase = 4;
  std::string after, afterRequest; NSDictionary* reread = nil;
  if (!claim.read(after,reread) || after != raw ||
      !arbol_attempt::launchRequest(claim,requestPath,reread) ||
      !readRequest(claim,baseline,name,deadline,afterRequest) ||
      afterRequest != requestRaw || !stable(claim,baseline,name) ||
      !arbol_attempt::currentProcess(pending[@"starter"]) || arbol_boundary::clockMs() >= deadline)
    return Observation::refused;
  NSDictionary* fresh = nil;
  result = sample(application,original,fresh,branch);
  if (result != Observation::proved) return result;
  if (![fresh isEqual:live]) {
    // Two coherent samples on opposite sides of the same fixed exec are also
    // inconclusive for this reply. Reclassify with the Claim released.
    return [live[@"pidVersion"] isEqual:original[@"pidVersion"]] &&
      ![fresh[@"pidVersion"] isEqual:original[@"pidVersion"]] && current[@"engine"] == NSNull.null ?
      Observation::waiting : Observation::refused;
  }
  if (arbol_boundary::clockMs() >= deadline) return Observation::refused;
  pid = [fresh[@"pid"] intValue];
  phase = 5;
  return Observation::proved;
}

void diagnostic(const Reply& reply, unsigned branch, unsigned phase) {
  os_log_with_type(OS_LOG_DEFAULT,OS_LOG_TYPE_DEFAULT,
    "host-launch reply callback=%{public}d error=%{public}d app=%{public}d branch=%{public}u phase=%{public}u outcome=%{public}u errorDomain=%{public}u errorCode=%{public}lld",
    reply.callback,reply.error,reply.app,branch,phase,(unsigned)reply.outcome,
    (unsigned)reply.errorDomain,(long long)reply.errorCode);
}
}

int main(int argc, const char* argv[]) {
  @autoreleasepool {
    const bool prepared = argc == 4 && !strcmp(argv[3], "--wait-for-reservation");
    if (argc != 3 && !prepared) return 4;
    NSString* application = [NSString stringWithUTF8String:argv[1]];
    NSString* request = [NSString stringWithUTF8String:argv[2]];
    if (!application.isAbsolutePath || !request.isAbsolutePath) return 4;
    arbol_attempt::PackagedLayout packaged;
    if (!arbol_attempt::packagedLayout(application.fileSystemRepresentation,packaged)) return 4;
    const double preparationDeadline=arbol_boundary::clockMs()+60000;
    arbol_startup_proof::RetainedAppPackage package;
    arbol_boundary::Lock packageGuard;
    arbol_startup_proof::ProvisionalClaimOffer offer;
    const bool provisional = prepared && packaged.installed &&
      package.capture(packaged,std::min(preparationDeadline,arbol_boundary::clockMs()+250)) && package.witnessed() &&
      offer.listenFor(argv[2]) && arbol_attempt::openBuild(packaged.bundle,packageGuard);
    arbol_startup_proof::Descriptor originalGuard(packageGuard.fd);
    const auto waitForReservation = [&](const std::shared_ptr<Reply>& reply) -> char {
      struct stat gate{};
      if (fstat(STDIN_FILENO,&gate) || (!S_ISFIFO(gate.st_mode) && !S_ISSOCK(gate.st_mode))) return false;
      while (arbol_boundary::clockMs()<preparationDeadline) {
        if (reply) { std::lock_guard<std::mutex> held(reply->mutex); if (reply->error) return false; }
        pollfd readable{STDIN_FILENO,POLLIN,0};
        const int available=poll(&readable,1,0);
        if (available>0) {
          char approved=0;
          if ((readable.revents&POLLIN) && read(STDIN_FILENO,&approved,1)==1 && (approved=='1'||approved=='2')) return approved;
          return 0;
        }
        if (available<0 && errno!=EINTR) return false;
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
        usleep(1000);
      }
      return false;
    };
    double deadline=arbol_boundary::clockMs()+28000;
    NSDictionary* pending = nil; std::string pendingRaw, requestRaw; Baseline baseline;
    const auto loadPending = [&]() {
      arbol_attempt::Claim claim; NSDictionary* attempt=nil; arbol_attempt::PackagedLayout layout;
      if(!claim.acquire(argv[2],std::min(deadline,arbol_boundary::clockMs()+2000)) || !claim.read(pendingRaw,attempt) ||
         !arbol_attempt::launchRequest(claim,argv[2],attempt) || ![attempt[@"phase"] isEqual:@"pending"] ||
         !arbol_attempt::currentProcess(attempt[@"starter"]) ||
         !arbol_attempt::claimedLayout(attempt,layout) || layout.bundle!=application.fileSystemRepresentation ||
         !arbol_boundary::canonical(application.fileSystemRepresentation)) return false;
      std::string checkedRequest;
      const std::string name = request.lastPathComponent.UTF8String;
      baseline.requestFd = openat(claim.at.directory,name.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
      baseline.directory = claim.at.identity; baseline.lock = claim.at.lockIdentity;
      if (baseline.requestFd < 0 || fstat(baseline.requestFd,&baseline.request) ||
          !arbol_attempt::privateFile(baseline.request) ||
          !readRequest(claim,baseline,name,deadline,requestRaw) ||
          !arbol_attempt::launchRequest(claim,argv[2],attempt) ||
          !readRequest(claim,baseline,name,deadline,checkedRequest) ||
          checkedRequest != requestRaw || !stable(claim,baseline,name)) return false;
      pending = [attempt copy];
      deadline=std::min(deadline,[attempt[@"expires"] doubleValue]);
      return arbol_boundary::clockMs()<deadline;
    };
    if (!provisional) {
      if (prepared && !waitForReservation({})) return 4;
      deadline=arbol_boundary::clockMs()+28000;
      if (!loadPending()) return 4;
    }
    NSWorkspaceOpenConfiguration* configuration = [NSWorkspaceOpenConfiguration configuration];
    configuration.createsNewApplicationInstance = YES;
    configuration.activates = NO;
    configuration.addsToRecentItems = NO;
    configuration.arguments = @[ provisional ? @"--arbol-host-preflight" : @"--arbol-host-request", request ];
    // A closed environment is supplied; bootstrap also replaces the complete
    // inherited environment before exec. No caller flags or Node/DYLD options.
    configuration.environment = @{};
    const std::string requestPath = argv[2];
    const auto reply = std::make_shared<Reply>();
    if (provisional && (!package.current() || !arbol_boundary::lockIdentity(packageGuard))) return 4;
    try { @try {
      [[NSWorkspace sharedWorkspace] openApplicationAtURL:[NSURL fileURLWithPath:application]
      configuration:configuration completionHandler:^(NSRunningApplication* app, NSError* error) {
        { std::lock_guard<std::mutex> held(reply->mutex);
          if (reply->callback || reply->outcome != Outcome::pending) return;
          reply->callback = true; reply->error = error != nil; reply->app = app != nil;
        }
        if (error) {
          // The authoritative error flag is already visible. Optional getters
          // cannot hold its mutex or delay the main loop's original cutoff.
          ErrorDomain domain = ErrorDomain::noneOrUnknown; int64_t code = 0;
          try { @try {
            NSString* value = error.domain;
            static_assert(sizeof(NSInteger) == sizeof(int64_t));
            const int64_t number = error.code;
            const ErrorDomain category = [value isEqual:NSCocoaErrorDomain] ? ErrorDomain::cocoa :
              [value isEqual:NSPOSIXErrorDomain] ? ErrorDomain::posix :
              [value isEqual:NSOSStatusErrorDomain] ? ErrorDomain::osStatus :
              value ? ErrorDomain::other : ErrorDomain::noneOrUnknown;
            domain = category; code = number;
          } @catch (NSException*) {} } catch (...) {}
          { std::lock_guard<std::mutex> held(reply->mutex);
            reply->errorDomain = domain; reply->errorCode = code;
          }
          return;
        }
        // Optional metadata can veto a contrary positive PID, never authorize
        // this launch. Its getter cannot hold main past the original cutoff.
        int callbackPid = 0;
        try { @try {
          if (app) callbackPid = app.processIdentifier;
        } @catch (NSException*) {} } catch (...) {}
        { std::lock_guard<std::mutex> held(reply->mutex);
          if (reply->outcome == Outcome::pending) reply->callbackPid = callbackPid;
        }
      }];
    } @catch (NSException*) { std::lock_guard<std::mutex> held(reply->mutex); reply->error = true; }
    } catch (...) { std::lock_guard<std::mutex> held(reply->mutex); reply->error = true; }
    NSDictionary* offered = nil;
    if (provisional) {
      const char approval=waitForReservation(reply);
      if (!approval) return 4;
      deadline=std::min(preparationDeadline,arbol_boundary::clockMs()+28000);
      if (!loadPending()) return 4;
      if (!package.matches(packaged,pending[@"candidateDigest"]) || !package.current() ||
          !arbol_boundary::lockIdentity(packageGuard)) return 4;
      NSString* digest=arbol_attempt::digest(pendingRaw);
      const auto approve = [&](int pid,const auto& deliver) {
        std::lock_guard<std::mutex> held(reply->mutex);
        if (reply->error) return -1;
        if (reply->callbackPid>0 && reply->callbackPid!=pid) return 0;
        return deliver() ? 1 : -1;
      };
      while (arbol_boundary::clockMs()<deadline) {
        { std::lock_guard<std::mutex> held(reply->mutex); if (reply->error) return 4; }
        const int result=offer.offer(packaged,digest,approval=='2',deadline,approve,offered);
        if (result<0) return 4;
        if (result>0) break;
        [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
        usleep(1000);
      }
      if (!offered) return 4;
    }
    unsigned branch = 0, phase = 0;
    while (arbol_boundary::clockMs() < deadline) {
      { std::lock_guard<std::mutex> held(reply->mutex);
        if (reply->error) { reply->outcome = Outcome::refused; break; }
      }
      {
        arbol_attempt::Claim claim; int pid = 0;
        Observation result = Observation::refused;
        try { @try {
          result = inspect(claim,application,requestPath,pending,requestRaw,baseline,offered,deadline,pid,branch,phase);
        } @catch (NSException*) {} } catch (...) {}
        std::lock_guard<std::mutex> held(reply->mutex);
        if (reply->error || result == Observation::refused ||
            (result == Observation::proved && reply->callbackPid > 0 && reply->callbackPid != pid)) {
          reply->outcome = Outcome::refused; break;
        }
        if (result == Observation::proved) {
          reply->outcome = Outcome::accepted;
          if (arbol_boundary::clockMs() >= deadline) reply->outcome = Outcome::timedOut;
          diagnostic(*reply,branch,phase);
          if (reply->outcome != Outcome::accepted || pid <= 1 || arbol_boundary::clockMs() >= deadline) return 4;
          // Claim and callback serialization remain held through the sole
          // reply. No cancellation or settled callback error can race output.
          std::printf("%d\n",pid); std::fflush(stdout);
          return 0;
        }
      }
      // The temporary Claim is closed before AppKit or the outer can run.
      [[NSRunLoop currentRunLoop] runMode:NSDefaultRunLoopMode beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.025]];
    }
    { std::lock_guard<std::mutex> held(reply->mutex);
      if (reply->outcome == Outcome::pending) reply->outcome = Outcome::timedOut;
      diagnostic(*reply,branch,phase);
    }
    return 4;
  }
}

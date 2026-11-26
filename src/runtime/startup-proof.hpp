#pragma once

#include "attempt.hpp"
#include <os/log.h>

namespace arbol_startup_proof {
inline constexpr int writerDescriptor = 12;
inline constexpr size_t packetLimit = 4096;

class Descriptor {
  int value_;
public:
  explicit Descriptor(int value = -1) : value_(value) {}
  Descriptor(const Descriptor&) = delete;
  ~Descriptor() { reset(); }
  int get() const { return value_; }
  void reset(int value = -1) { if (value_ >= 0) close(value_); value_ = value; }
};

inline NSString* decimal(long long value) {
  return [NSString stringWithUTF8String:std::to_string(value).c_str()];
}
inline NSString* nanos(timespec value) {
  if (!value.tv_sec) return decimal(value.tv_nsec);
  return [NSString stringWithFormat:@"%lld%09ld", static_cast<long long>(value.tv_sec), value.tv_nsec];
}
inline NSArray* stamp(const struct stat& value) {
  return @[decimal(value.st_dev), decimal(value.st_ino), decimal(value.st_mode), decimal(value.st_uid),
    decimal(value.st_gid), decimal(value.st_nlink), decimal(value.st_size), nanos(value.st_mtimespec),
    nanos(value.st_ctimespec), nanos(value.st_birthtimespec)];
}

inline std::string endpoint(NSDictionary* starter) {
  if (!arbol_attempt::process(starter)) return {};
  const auto home = arbol_boundary::appHome();
  if (home.empty()) return {};
  return home + "/.arbol/app/browser-proof-" + [starter[@"startId"] UTF8String] + ".sock";
}

inline bool address(const std::string& path, sockaddr_un& value) {
  if (path.empty() || path.size() >= sizeof(value.sun_path) ||
      !arbol_boundary::privateAncestors(path)) return false;
  value.sun_family = AF_UNIX;
  memcpy(value.sun_path, path.c_str(), path.size() + 1);
  value.sun_len = SUN_LEN(&value);
  return true;
}

inline bool peerToken(int socket, audit_token_t& token) {
  socklen_t size = sizeof(token);
  return !getsockopt(socket, SOL_LOCAL, LOCAL_PEERTOKEN, &token, &size) &&
    size == sizeof(token) && audit_token_to_euid(token) == geteuid() && audit_token_to_pid(token) > 1;
}

inline bool signedLauncher(const audit_token_t& token, NSDictionary* starter) {
  NSDictionary* launcher = arbol_attempt::processRecord(audit_token_to_pid(token));
  std::string executable = arbol_attempt::stableLauncherPath(arbol_attempt::physicalAccountHome());
  NSString* expected = [NSString stringWithUTF8String:executable.c_str()];
  if (executable.empty() || !launcher || ![launcher[@"executable"] isEqual:expected] ||
      [launcher[@"pidVersion"] intValue] != audit_token_to_pidversion(token) ||
      ![launcher[@"startId"] isEqual:starter[@"parentStartId"]] ||
      ![launcher[@"pidVersion"] isEqual:starter[@"parentPidVersion"]]) return false;
  SecCodeRef code = nullptr; SecRequirementRef requirement = nullptr;
  NSDictionary* attributes = @{(__bridge NSString*)kSecGuestAttributeAudit:[NSData dataWithBytes:&token length:sizeof(token)]};
  bool valid = SecCodeCopyGuestWithAttributes(nullptr, (__bridge CFDictionaryRef)attributes, kSecCSDefaultFlags, &code) == errSecSuccess &&
    SecRequirementCreateWithString(CFSTR("anchor apple generic and identifier \"com.sylvan-stack.arbol-browser.launcher\" and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"),
      kSecCSDefaultFlags, &requirement) == errSecSuccess &&
    SecCodeCheckValidity(code, kSecCSDefaultFlags, requirement) == errSecSuccess;
  if (code) CFRelease(code);
  if (requirement) CFRelease(requirement);
  return valid && arbol_attempt::currentProcess(launcher) && arbol_attempt::currentProcess(starter);
}

inline std::string provisionalEndpoint(const std::string& requestPath) {
  NSString* path = [NSString stringWithUTF8String:requestPath.c_str()];
  NSString* name = path.lastPathComponent;
  const auto home = arbol_boundary::appHome();
  if (home.empty() || !arbol_attempt::path(path) ||
      !arbol_attempt::pattern(name, @"^launch-req_[A-Za-z0-9_-]{22}\\.json$")) return {};
  return home + "/.arbol/app/browser-start-" + [name.stringByDeletingPathExtension UTF8String] + ".sock";
}

inline NSDictionary* signedProvisionalPeer(int fd, const std::string& executable, NSString* identifier) {
  audit_token_t token{};
  if (!peerToken(fd,token)) return nil;
  NSDictionary* process = arbol_attempt::processRecord(audit_token_to_pid(token));
  if (!process || [process[@"pidVersion"] intValue] != audit_token_to_pidversion(token) ||
      ![process[@"executable"] isEqual:[NSString stringWithUTF8String:executable.c_str()]]) return nil;
  NSString* anchor = [NSString stringWithFormat:@"anchor apple generic and identifier \"%@\" and certificate leaf[subject.OU] = \"7V372XL59S\" and certificate leaf[field.1.2.840.113635.100.6.1.13] exists",identifier];
  NSDictionary* attributes = @{(__bridge NSString*)kSecGuestAttributeAudit:[NSData dataWithBytes:&token length:sizeof(token)]};
  SecCodeRef code = nullptr;
  SecRequirementRef requirement = nullptr;
  const bool valid = SecCodeCopyGuestWithAttributes(nullptr,(__bridge CFDictionaryRef)attributes,kSecCSDefaultFlags,&code)==errSecSuccess &&
    SecRequirementCreateWithString((__bridge CFStringRef)anchor,kSecCSDefaultFlags,&requirement)==errSecSuccess &&
    SecCodeCheckValidity(code,kSecCSDefaultFlags,requirement)==errSecSuccess;
  if (requirement) CFRelease(requirement);
  if (code) CFRelease(code);
  return valid && arbol_attempt::currentProcess(process) ? process : nil;
}

class ProvisionalClaimOffer {
  Descriptor listener_;
  std::string path_;
  struct stat original_{};
  bool owns_ = false;
public:
  ProvisionalClaimOffer() = default;
  ProvisionalClaimOffer(const ProvisionalClaimOffer&) = delete;
  ~ProvisionalClaimOffer() {
    struct stat named{};
    if (owns_ && !lstat(path_.c_str(),&named) && S_ISSOCK(named.st_mode) &&
        original_.st_dev==named.st_dev && original_.st_ino==named.st_ino) (void)unlink(path_.c_str());
  }
  bool listenFor(const std::string& requestPath) {
    path_ = provisionalEndpoint(requestPath);
    sockaddr_un addr{};
    if (!address(path_,addr)) return false;
    listener_.reset(socket(AF_UNIX,SOCK_STREAM,0));
    const int fd = listener_.get();
    if (fd<0 || fcntl(fd,F_SETFD,FD_CLOEXEC) || fcntl(fd,F_SETFL,O_NONBLOCK) ||
        bind(fd,reinterpret_cast<sockaddr*>(&addr),addr.sun_len) || lstat(path_.c_str(),&original_) ||
        !S_ISSOCK(original_.st_mode) || original_.st_uid!=geteuid()) return false;
    owns_ = true;
    return !chmod(path_.c_str(),0600) && !listen(fd,4);
  }
  template<typename Approve>
  int offer(const arbol_attempt::PackagedLayout& layout, NSString* digest, bool showEmptyWhenReady, double deadline,
            Approve approve, NSDictionary* __strong& offered) {
    if (!arbol_attempt::pattern(digest,@"^[0-9a-f]{64}$")) return -1;
    Descriptor peer(accept(listener_.get(),nullptr,nullptr));
    if (peer.get()<0) return errno==EAGAIN || errno==EWOULDBLOCK || errno==EINTR ? 0 : -1;
    NSDictionary* process = signedProvisionalPeer(peer.get(),layout.bootstrap,@"com.sylvan-stack.arbol-browser");
    const int actual = [process[@"pid"] intValue];
    if (!process || actual<=1 || [process[@"group"] intValue]!=actual) return 0;
    int noSignal = 1;
    if (fcntl(peer.get(),F_SETFL,O_NONBLOCK) || setsockopt(peer.get(),SOL_SOCKET,SO_NOSIGPIPE,&noSignal,sizeof(noSignal)) ||
        !arbol_attempt::currentProcess(process)) return -1;
    char frame[65];
    memcpy(frame,digest.UTF8String,64);
    frame[64]=showEmptyWhenReady?'2':'1';
    const auto deliver = [&]() {
      return arbol_boundary::clockMs()<deadline && send(peer.get(),frame,sizeof(frame),0)==ssize_t(sizeof(frame));
    };
    const int result = approve(actual,deliver);
    if (result>0) offered=process;
    return result;
  }
};

inline NSString* awaitProvisionalClaim(const std::string& requestPath, const arbol_attempt::PackagedLayout& layout,
                                       double deadline, NSDictionary* __strong& helper, bool& showEmptyWhenReady) {
  const auto endpoint = provisionalEndpoint(requestPath);
  sockaddr_un addr{};
  struct stat named{};
  if (!address(endpoint,addr) || !arbol_boundary::canonical(endpoint) || lstat(endpoint.c_str(),&named) ||
      !S_ISSOCK(named.st_mode) || named.st_uid!=geteuid() || (named.st_mode&07777)!=0600) return nil;
  Descriptor peer(socket(AF_UNIX,SOCK_STREAM,0));
  const int fd = peer.get();
  if (fd<0 || fcntl(fd,F_SETFD,FD_CLOEXEC) || fcntl(fd,F_SETFL,O_NONBLOCK) ||
      connect(fd,reinterpret_cast<sockaddr*>(&addr),addr.sun_len)) return nil;
  NSDictionary* process = signedProvisionalPeer(fd,layout.launcher,@"host-launch");
  if (!process) return nil;
  char bytes[65]; size_t used=0;
  while (used<sizeof(bytes) && arbol_boundary::clockMs()<deadline) {
    pollfd ready{fd,POLLIN,0};
    const int available = poll(&ready,1,25);
    if (available==0 || (available<0 && errno==EINTR)) continue;
    if (available<0 || !(ready.revents&POLLIN)) return nil;
    const ssize_t count = read(fd,bytes+used,sizeof(bytes)-used);
    if (count<=0) return nil;
    used+=size_t(count);
  }
  if (used!=sizeof(bytes) || arbol_boundary::clockMs()>=deadline || !arbol_attempt::currentProcess(process)) return nil;
  NSString* digest = [[NSString alloc] initWithBytes:bytes length:64 encoding:NSASCIIStringEncoding];
  if (!arbol_attempt::pattern(digest,@"^[0-9a-f]{64}$") || (bytes[64]!='1' && bytes[64]!='2')) return nil;
  helper=process;
  showEmptyWhenReady=bytes[64]=='2';
  return digest;
}

inline bool helperForStarter(NSDictionary* helper, NSDictionary* starter) {
  return arbol_attempt::currentProcess(helper) && arbol_attempt::currentProcess(starter) &&
    [helper[@"parentStartId"] isEqual:starter[@"startId"]] &&
    [helper[@"parentPidVersion"] isEqual:starter[@"pidVersion"]];
}

inline bool packet(NSDictionary* value) {
  return arbol_attempt::keys(value, @[@"format", @"bundle", @"root", @"backing", @"snapshot"]) &&
    [value[@"format"] isEqual:@1] && arbol_attempt::path(value[@"bundle"]) &&
    [value[@"root"] isKindOfClass:NSArray.class] && [value[@"backing"] isKindOfClass:NSArray.class] &&
    arbol_attempt::pattern(value[@"snapshot"], @"^[0-9a-f]{64}$");
}

inline bool descriptors(NSDictionary* value, const std::string& bundle, int root, int image) {
  struct stat held{}, named{}, backing{};
  return packet(value) && [value[@"bundle"] isEqual:[NSString stringWithUTF8String:bundle.c_str()]] &&
    !fstat(root, &held) && S_ISDIR(held.st_mode) && !lstat(bundle.c_str(), &named) &&
    [stamp(held) isEqual:value[@"root"]] && [stamp(named) isEqual:value[@"root"]] &&
    !fstat(image, &backing) && arbol_attempt::privateFile(backing) && [stamp(backing) isEqual:value[@"backing"]];
}

inline bool connectAppCache(Descriptor& connection) {
  const auto home = arbol_boundary::appHome();
  if (home.empty()) return false;
  const auto endpoint = home + "/.arbol/app/browser-package-proof-v1.sock";
  sockaddr_un addr{};
  struct stat node{};
  if (!address(endpoint, addr) || !arbol_boundary::canonical(endpoint) ||
      lstat(endpoint.c_str(), &node) || !S_ISSOCK(node.st_mode) || node.st_uid != geteuid() ||
      (node.st_mode & 07777) != 0600) return false;
  connection.reset(socket(AF_UNIX, SOCK_STREAM, 0));
  const int fd = connection.get();
  audit_token_t token{};
  int suppressSignal = 1;
  if (fd < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK) ||
      setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &suppressSignal, sizeof(suppressSignal)) ||
      connect(fd, reinterpret_cast<sockaddr*>(&addr), addr.sun_len) || !peerToken(fd, token)) return false;
  arbol_boundary::Identity process;
  std::string executable;
  if (arbol_boundary::observe(audit_token_to_pid(token), process) != 1 ||
      process.version != audit_token_to_pidversion(token) ||
      !arbol_boundary::executable(process, executable) || executable != arbol_boundary::supervisorExecutable()) return false;
  NSDictionary* attributes = @{(__bridge NSString*)kSecGuestAttributeAudit:[NSData dataWithBytes:&token length:sizeof(token)]};
  return arbol_boundary::liveApplicationCode(attributes) && arbol_boundary::current(process) == 1;
}

inline NSArray* volumeIdentity(const arbol_attempt::MaintenancePayload& mount) {
  return @[decimal(mount.filesystem.f_fsid.val[0]), decimal(mount.filesystem.f_fsid.val[1])];
}
inline NSArray* helperIdentity(const arbol_attempt::MaintenanceBacking& backing) {
  return @[decimal(backing.helper.pid), [NSString stringWithUTF8String:std::to_string(backing.helper.start).c_str()],
    decimal(backing.helper.version)];
}

struct AppImageWitness {
  NSArray* volume = nil;
  NSArray* helper = nil;
  bool present() const { return volume && helper; }
  bool bind(NSDictionary* record) {
    id observedVolume = record[@"volume"], observedHelper = record[@"helper"];
    if (![observedVolume isKindOfClass:NSArray.class] || [observedVolume count] != 2 ||
        ![observedHelper isKindOfClass:NSArray.class] || [observedHelper count] != 3) return false;
    for (id field in observedVolume) if (!arbol_attempt::pattern(field, @"^-?[0-9]{1,10}$")) return false;
    if (!arbol_attempt::pattern(observedHelper[0], @"^[1-9][0-9]{0,9}$") ||
        [observedHelper[0] longLongValue] < 2 || [observedHelper[0] longLongValue] > INT_MAX ||
        !arbol_attempt::pattern(observedHelper[1], @"^[1-9][0-9]{0,19}$") ||
        !arbol_attempt::pattern(observedHelper[2], @"^-?[0-9]{1,10}$")) return false;
    volume = observedVolume;
    helper = observedHelper;
    return true;
  }
};

inline std::string appProofResponse(const std::string& query, double deadline) {
  Descriptor connection;
  if (query.size()>packetLimit || arbol_boundary::clockMs()>=deadline || !connectAppCache(connection)) return {};
  const int fd = connection.get();
  if (send(fd,query.data(),query.size(),0)!=ssize_t(query.size()) || shutdown(fd,SHUT_WR)) return {};
  std::string data;
  while (arbol_boundary::clockMs() < deadline && data.size() <= packetLimit) {
    pollfd ready{fd, POLLIN, 0};
    if (poll(&ready, 1, 25) < 1 || !(ready.revents & (POLLIN | POLLHUP))) return {};
    char buffer[packetLimit];
    const ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count < 0) return {};
    if (count == 0) return data;
    data.append(buffer, size_t(count));
  }
  return {};
}

inline NSDictionary* cached(const std::string& bundle, int root, int image, double cutoff,
                            NSString* expectedImage = nil, NSString* expectedSnapshot = nil,
                            AppImageWitness* witness = nullptr) {
  const double deadline = std::min(cutoff, arbol_boundary::clockMs() + 150);
  std::string data = appProofResponse("B" + bundle,deadline);
  if (data.empty()) data=appProofResponse("Q",deadline); // Earlier installed Apps expose only Q.
  NSDictionary* cachedProof = arbol_attempt::json(data);
  NSString* digest = cachedProof[@"imageSha256"];
  if (!arbol_attempt::pattern(digest, @"^[0-9a-f]{64}$") ||
      (expectedImage && ![expectedImage isEqual:digest]) ||
      (expectedSnapshot && ![expectedSnapshot isEqual:cachedProof[@"snapshot"]])) return nil;
  NSMutableDictionary* physicalProof = [cachedProof mutableCopy];
  [physicalProof removeObjectForKey:@"imageSha256"];
  if ([physicalProof[@"format"] isEqual:@2]) {
    AppImageWitness witnessed;
    if (!witnessed.bind(physicalProof)) return nil;
    [physicalProof removeObjectsForKeys:@[@"volume", @"helper"]];
    physicalProof[@"format"] = @1;
    if (witness) *witness = witnessed;
  }
  return descriptors(physicalProof,bundle,root,image) && arbol_boundary::clockMs()<deadline ? physicalProof : nil;
}

inline bool currentCache(NSDictionary* proof, const std::string& bundle, int root, int image,
                         const arbol_attempt::MaintenancePayload& mount) {
  struct statfs filesystem{};
  return descriptors(proof, bundle, root, image) && !fstatfs(root, &filesystem) &&
    mount.sameFilesystem(filesystem) && mount.current() && descriptors(proof, bundle, root, image);
}

inline std::string installedImagePath(const arbol_attempt::PackagedLayout& layout) {
  NSString* home = arbol_attempt::physicalAccountHome();
  if (!home) return {};
  NSString* support = [home stringByAppendingPathComponent:@ARBOL_INSTALLATION_STABLE_USES].stringByDeletingLastPathComponent;
  return [[support stringByAppendingPathComponent:@"images"]
    stringByAppendingPathComponent:[NSString stringWithFormat:@"%s.dmg", layout.build.c_str()]].fileSystemRepresentation;
}

class RetainedAppPackage {
  Descriptor root_;
  arbol_attempt::MaintenanceFile image_;
  arbol_attempt::MaintenanceBacking backing_;
  arbol_attempt::MaintenancePayload mount_;
  NSDictionary* proof_ = nil;
  std::string bundle_;
  bool witnessed_ = false;
public:
  bool capture(const arbol_attempt::PackagedLayout& layout, double deadline, NSString* snapshot = nil,
               NSString* archive = nil) {
    if (!layout.installed || root_.get() >= 0 ||
        !image_.openPath(installedImagePath(layout), 0600, 1024LL * 1024 * 1024)) return false;
    bundle_ = layout.bundle;
    root_.reset(open(bundle_.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC));
    if (root_.get() < 0) return false;
    AppImageWitness witness;
    proof_ = cached(bundle_, root_.get(), image_.fd, deadline, archive, snapshot, &witness);
    if (!proof_ || !mount_.capture(layout, false, !witness.present())) return false;
    if (witness.present()) {
      // The signed launcher recorded this exact read-only filesystem and
      // already checked every tree entry while the same helper held its image.
      if (![witness.volume isEqual:volumeIdentity(mount_)] ||
          !backing_.capture([witness.helper[0] intValue], image_) ||
          ![witness.helper isEqual:helperIdentity(backing_)]) return false;
      witnessed_ = true;
    } else if (!arbol_attempt::maintenanceMount(mount_.mount, image_, deadline, backing_)) return false;
    return current() && arbol_boundary::clockMs() < deadline;
  }
  bool current() const {
    return proof_ && currentCache(proof_, bundle_, root_.get(), image_.fd, mount_) &&
      backing_.current(image_) && currentCache(proof_, bundle_, root_.get(), image_.fd, mount_);
  }
  bool matchesOriginal(int root, const struct stat& image) const {
    return matchesBacking(image) && descriptors(proof_, bundle_, root, image_.fd);
  }
  bool matchesBacking(const struct stat& image) const { return arbol_attempt::sameFile(image, image_.identity); }
  bool matchesRoot(int fd) const {
    struct stat held{};
    struct statfs filesystem{};
    return proof_ && !fstat(fd,&held) && S_ISDIR(held.st_mode) && [stamp(held) isEqual:proof_[@"root"]] &&
      !fstatfs(fd,&filesystem) && mount_.sameFilesystem(filesystem);
  }
  bool matches(const arbol_attempt::PackagedLayout& layout, NSString* snapshot) const {
    return proof_ && bundle_ == layout.bundle && [proof_[@"snapshot"] isEqual:snapshot];
  }
  NSString* witnessedSnapshot() const { return witnessed_ ? proof_[@"snapshot"] : nil; }
  bool witnessed() const { return witnessed_; }
};

inline void publishToApp(NSDictionary* verified, const std::string& bundle, int root, int image,
                         NSString* imageDigest, double deadline) {
  if (arbol_boundary::clockMs() >= deadline || !packet(verified) ||
      !arbol_attempt::pattern(imageDigest, @"^[0-9a-f]{64}$")) return;
  NSMutableDictionary* proof = [verified mutableCopy];
  proof[@"imageSha256"] = imageDigest;
  arbol_attempt::PackagedLayout layout;
  arbol_attempt::MaintenanceFile file;
  arbol_attempt::MaintenancePayload mount;
  arbol_attempt::MaintenanceBacking helper;
  struct stat original{};
  if (arbol_attempt::packagedLayout(bundle, layout) && layout.installed && !fstat(image, &original) &&
      file.openPath(installedImagePath(layout), 0600, 1024LL * 1024 * 1024) &&
      arbol_attempt::sameFile(original, file.identity) && mount.capture(layout, false) &&
      arbol_attempt::maintenanceMount(mount.mount, file, deadline, helper) &&
      currentCache(verified, bundle, root, image, mount) && helper.current(file)) {
    proof[@"format"] = @2;
    proof[@"volume"] = volumeIdentity(mount);
    proof[@"helper"] = helperIdentity(helper);
  }
  if (arbol_boundary::clockMs() >= deadline || !descriptors(verified, bundle, root, image)) return;

  Descriptor connection;
  if (!connectAppCache(connection)) {
    os_log_info(OS_LOG_DEFAULT, "arbol-browser App package proof publisher could not authenticate the App");
    return;
  }
  const std::string frame = "P" + arbol_attempt::bytes(proof);
  const int fd = connection.get();
  if (frame.size() > packetLimit || send(fd, frame.data(), frame.size(), 0) != ssize_t(frame.size()) ||
      shutdown(fd, SHUT_WR)) return;

  // Keep our kernel identity available to the App through its validation.
  const int wait = int(std::clamp(deadline - arbol_boundary::clockMs(), 0.0, 100.0));
  pollfd ready{fd, POLLIN, 0};
  char acknowledgement = 0;
  if (poll(&ready, 1, wait) > 0 && (ready.revents & POLLIN) &&
      recv(fd, &acknowledgement, sizeof(acknowledgement), 0) == 1 && acknowledgement == 1) {
    os_log_info(OS_LOG_DEFAULT, "arbol-browser App package proof publication acknowledged");
  } else {
    os_log_info(OS_LOG_DEFAULT, "arbol-browser App package proof publication was not acknowledged");
  }
}

// The native parent and the Node command share an anonymous write pipe.
// Only the verified command can nominate the exact original package.
class Relay {
  Descriptor listener_, input_;
  std::string socketPath_;
  struct stat socketIdentity_{};
  NSDictionary* starter_ = nil;
  NSDictionary* verified_ = nil;
  std::string raw_;
  bool ownsSocket_ = false;
  bool alreadyWitnessed_;
public:
  Relay(int reader, bool alreadyWitnessed) : input_(reader), alreadyWitnessed_(alreadyWitnessed) {}
  Relay(const Relay&) = delete;
  ~Relay() {
    struct stat current{};
    if (ownsSocket_ && !lstat(socketPath_.c_str(), &current) && S_ISSOCK(current.st_mode) &&
        current.st_dev == socketIdentity_.st_dev && current.st_ino == socketIdentity_.st_ino)
      (void)unlink(socketPath_.c_str());
  }
  bool listenFor(NSDictionary* starter) {
    sockaddr_un addr{};
    socketPath_ = endpoint(starter);
    if (input_.get() < 0 || !address(socketPath_, addr)) return false;
    listener_.reset(socket(AF_UNIX, SOCK_STREAM, 0));
    int s = listener_.get();
    if (s < 0 || fcntl(s, F_SETFD, FD_CLOEXEC) || fcntl(s, F_SETFL, O_NONBLOCK) ||
        bind(s, reinterpret_cast<sockaddr*>(&addr), addr.sun_len) ||
        lstat(socketPath_.c_str(), &socketIdentity_) || !S_ISSOCK(socketIdentity_.st_mode) ||
        socketIdentity_.st_uid != geteuid()) return false;
    ownsSocket_ = true;
    if (chmod(socketPath_.c_str(), 0600) || listen(s, 4) || fcntl(input_.get(), F_SETFL, O_NONBLOCK)) return false;
    starter_ = starter;
    return true;
  }
  void advance(const std::string& bundle, int root, int backing, NSString* imageDigest, double deadline,
               bool completedInfo = false) {
    if (arbol_boundary::clockMs() >= deadline) return;
    if (input_.get() >= 0) {
      char bytes[packetLimit];
      const ssize_t count = read(input_.get(), bytes, sizeof(bytes));
      if (count > 0) {
        raw_.append(bytes, size_t(count));
        if (raw_.size() > packetLimit) input_.reset();
      } else if (!count) {
        NSDictionary* candidate = arbol_attempt::json(raw_);
        if ((completedInfo || arbol_attempt::currentProcess(starter_)) && descriptors(candidate, bundle, root, backing)) {
          verified_ = candidate;
          if (!alreadyWitnessed_) publishToApp(verified_, bundle, root, backing, imageDigest, deadline);
        }
        input_.reset();
      }
    }
    Descriptor peer(accept(listener_.get(), nullptr, nullptr));
    if (peer.get() < 0 || !verified_ || !arbol_attempt::currentProcess(starter_) ||
        !descriptors(verified_, bundle, root, backing)) return;
    audit_token_t token{};
    int enabled = 1;
    if (!peerToken(peer.get(), token) || fcntl(peer.get(), F_SETFL, O_NONBLOCK) ||
        setsockopt(peer.get(), SOL_SOCKET, SO_NOSIGPIPE, &enabled, sizeof(enabled))) return;
    (void)send(peer.get(), raw_.data(), raw_.size(), 0);
  }
};

inline bool fromStarter(NSDictionary* attempt, const std::string& bundle, int root, int image, double deadline) {
  NSDictionary* starter = attempt[@"starter"];
  const std::string path = endpoint(starter);
  sockaddr_un addr{};
  struct stat node{};
  if (!address(path, addr) || !arbol_boundary::canonical(path) || !arbol_attempt::currentProcess(starter) ||
      lstat(path.c_str(), &node) || !S_ISSOCK(node.st_mode) || node.st_uid != geteuid() ||
      (node.st_mode & 07777) != 0600) return false;
  Descriptor peer(socket(AF_UNIX, SOCK_STREAM, 0));
  const int fd = peer.get();
  audit_token_t token{};
  if (fd < 0 || fcntl(fd, F_SETFD, FD_CLOEXEC) || fcntl(fd, F_SETFL, O_NONBLOCK) ||
      connect(fd, reinterpret_cast<sockaddr*>(&addr), addr.sun_len) || !peerToken(fd, token) ||
      !signedLauncher(token, starter)) return false;
  std::string bytes;
  while (arbol_boundary::clockMs() < deadline && bytes.size() <= packetLimit) {
    pollfd ready{fd, POLLIN, 0};
    if (poll(&ready, 1, 25) < 1 || !(ready.revents & (POLLIN | POLLHUP))) return false;
    char buffer[packetLimit];
    ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count < 0) return false;
    if (count == 0) {
      NSDictionary* value = arbol_attempt::json(bytes);
      return descriptors(value, bundle, root, image) && [value[@"snapshot"] isEqual:attempt[@"candidateDigest"]] &&
        arbol_attempt::currentProcess(starter) && arbol_boundary::clockMs() < deadline;
    }
    bytes.append(buffer, size_t(count));
  }
  return false;
}
}

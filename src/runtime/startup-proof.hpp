#pragma once

#include "attempt.hpp"

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

inline NSDictionary* cached(const std::string& bundle, int root, int image, double cutoff,
                            NSString* expectedImage = nil, NSString* expectedSnapshot = nil) {
  Descriptor connection;
  const double deadline = std::min(cutoff, arbol_boundary::clockMs() + 150);
  if (!connectAppCache(connection)) return nil;
  const int fd = connection.get();
  const char query = 'Q';
  if (send(fd, &query, 1, 0) != 1 || shutdown(fd, SHUT_WR)) return nil;
  std::string data;
  while (arbol_boundary::clockMs() < deadline && data.size() <= packetLimit) {
    pollfd ready{fd, POLLIN, 0};
    if (poll(&ready, 1, 25) < 1 || !(ready.revents & (POLLIN | POLLHUP))) return nil;
    char buffer[packetLimit];
    const ssize_t count = read(fd, buffer, sizeof(buffer));
    if (count < 0) return nil;
    if (count == 0) {
      NSDictionary* cachedProof = arbol_attempt::json(data);
      NSString* digest = cachedProof[@"imageSha256"];
      if (!arbol_attempt::pattern(digest, @"^[0-9a-f]{64}$") ||
          (expectedImage && ![expectedImage isEqual:digest]) ||
          (expectedSnapshot && ![expectedSnapshot isEqual:cachedProof[@"snapshot"]])) return nil;
      NSMutableDictionary* physicalProof = [cachedProof mutableCopy];
      [physicalProof removeObjectForKey:@"imageSha256"];
      return descriptors(physicalProof, bundle, root, image) && arbol_boundary::clockMs() < deadline ? physicalProof : nil;
    }
    data.append(buffer, size_t(count));
  }
  return nil;
}

inline bool currentCache(NSDictionary* proof, const std::string& bundle, int root, int image,
                         const arbol_attempt::MaintenancePayload& mount) {
  struct statfs filesystem{};
  return descriptors(proof, bundle, root, image) && !fstatfs(root, &filesystem) &&
    mount.sameFilesystem(filesystem) && mount.current() && descriptors(proof, bundle, root, image);
}

inline void publishToApp(NSDictionary* verified, NSString* imageDigest, double deadline) {
  if (arbol_boundary::clockMs() >= deadline || !packet(verified) ||
      !arbol_attempt::pattern(imageDigest, @"^[0-9a-f]{64}$")) return;
  Descriptor connection;
  if (!connectAppCache(connection)) return;
  NSMutableDictionary* proof = [verified mutableCopy];
  proof[@"imageSha256"] = imageDigest;
  const std::string frame = "P" + arbol_attempt::bytes(proof);
  if (frame.size() <= packetLimit) (void)send(connection.get(), frame.data(), frame.size(), 0);
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
public:
  explicit Relay(int reader) : input_(reader) {}
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
          publishToApp(verified_, imageDigest, deadline);
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

#import "keys.hpp"
#include <cmath>
#include <cstring>
#include <limits>
@implementation ArbolPagePolicy
@end
namespace arbol_native {
NSMutableArray<ArbolPagePolicy*>* policies = [NSMutableArray new];
bool creating = false;
thread_local unsigned callbackDepth = 0;
static char policyKey;
static __weak NSView* creationRoot;
static __weak NSWindow* creationWindow;
static NSArray<NSView*>* creationBefore;
static uint32_t creationContents = 0;
static uint64_t nextIdentifier = 0;
static void scanPages(NSView* view, NSMutableArray<NSView*>* found, std::set<void*>& seen, unsigned depth) {
  if (!view || depth > 128 || seen.size() >= 1000000 || !seen.insert((__bridge void*)view).second) throw std::runtime_error("native_view_tree_bound");
  if ([NSStringFromClass(view.class) isEqualToString:@"WebContentsViewCocoa"]) [found addObject:view];
  for (NSView* child in view.subviews) scanPages(child, found, seen, depth + 1);
}
NSArray<NSView*>* pageViews(NSView* root) {
  NSMutableArray<NSView*>* found = [NSMutableArray new]; std::set<void*> seen;
  scanPages(root, found, seen, 0); return found;
}
ArbolPagePolicy* viewPolicy(NSView* view) {
  if (![NSThread isMainThread]) return nil;
  for (unsigned depth = 0; view && depth < 128; ++depth, view = view.superview) {
    ArbolPagePolicy* policy = objc_getAssociatedObject(view, &policyKey);
    if (policy) return policy;
  }
  return nil;
}
NSDictionary* bindingObject(ArbolPagePolicy* policy) {
  return @{ @"id": @(policy.identifier), @"nonce": policy.nonce, @"webContentsId": @(policy.webContentsId),
    @"revision": @(policy.revision), @"blocked": @(policy.blocked), @"retired": @(policy.retired) };
}
// All registry and Objective-C access stays on the main thread. Off-main
// callbacks examine only the atomic phase before refusing.
bool policyLive(ArbolPagePolicy* policy) {
  if (![NSThread isMainThread] || !policy || policy.retired) return false;
  NSView* view = policy.view; NSWindow* window = policy.window;
  if (!view || !window || view.window != window || viewPolicy(view) != policy) return false;
  NSView* ancestor = view;
  for (unsigned depth = 0; ancestor && depth < 128; ++depth, ancestor = ancestor.superview)
    if (ancestor == window.contentView) return true;
  return false;
}
void advanceRevision(ArbolPagePolicy* policy) {
  if (policy.revision == UINT32_MAX) { poison("native_revision_exhausted"); throw std::runtime_error("native_restart_required"); }
  ++policy.revision;
}
static void sealBindings() {
  if (![NSThread isMainThread]) return; // Atomic non-ready phase already denies all callbacks.
  creating = false; creationBefore = nil; creationRoot = nil; creationWindow = nil; creationContents = 0;
  for (ArbolPagePolicy* policy in policies) { policy.blocked = YES; policy.retired = YES; policy.view = nil; policy.window = nil; }
  liveBindings = 0;
}
static bool auditBindings() {
  if (![NSThread isMainThread]) return false;
  @try {
    if (policies.count != policyObjects || policies.count != nextIdentifier || policies.count > 1000000) return false;
    size_t live = 0;
    for (NSUInteger index = 0; index < policies.count; ++index) {
      ArbolPagePolicy* policy = policies[index];
      if (policy.identifier != index || !policy.webContentsId || !policy.nonce || ![[[NSUUID alloc] initWithUUIDString:policy.nonce].UUIDString.lowercaseString isEqualToString:policy.nonce]) return false;
      if (policy.retired) { if (!policy.blocked || policy.view || policy.window) return false; }
      else { if (!policyLive(policy)) return false; ++live; }
    }
    return live == liveBindings;
  } @catch (NSException*) { return false; }
}
void initializeBindings() {
  if (![NSThread isMainThread] || phase.load() != Phase::Planning || bindingAudit || bindingSeal || policies.count) throw std::runtime_error("native_binding_initialization");
  bindingAudit = auditBindings; bindingSeal = sealBindings;
}
static napi_value bindingFailure(napi_env env) {
  if ([NSThread isMainThread]) poison("native_binding_failed");
  else phase.store(Phase::Poisoned, std::memory_order_release);
  napi_throw_error(env, nullptr, "native_binding_failed"); return nullptr;
}
static uint32_t contentsArgument(napi_env env, napi_value value) {
  double number;
  if (napi_get_value_double(env, value, &number) != napi_ok || !std::isfinite(number) || std::floor(number) != number || number < 1 || number > UINT32_MAX)
    throw std::runtime_error("native_contents_identity");
  return static_cast<uint32_t>(number);
}
napi_value beginBinding(napi_env env, napi_callback_info info) {
  napi_value args[2]; if (!mainCall(env, info, 2, args)) return bindingFailure(env);
  @try { try {
    if (!integrity() || creating) throw std::runtime_error("native_creation_unavailable");
    bool buffer = false; void* bytes = nullptr; size_t size = 0;
    if (napi_is_buffer(env, args[0], &buffer) != napi_ok || !buffer || napi_get_buffer_info(env, args[0], &bytes, &size) != napi_ok || size != sizeof(void*))
      throw std::runtime_error("native_window_handle");
    void* pointer = nullptr; std::memcpy(&pointer, bytes, sizeof(pointer));
    NSWindow* window = nil;
    for (NSWindow* candidate in NSApp.windows) if ((__bridge void*)candidate.contentView == pointer) {
      if (window) throw std::runtime_error("native_ambiguous_window"); window = candidate;
    }
    if (!window || !window.contentView || window.contentView.window != window) throw std::runtime_error("native_unknown_window");
    uint32_t contents = contentsArgument(env, args[1]);
    for (ArbolPagePolicy* policy in policies) if (policy.webContentsId == contents) throw std::runtime_error("native_contents_reused");
    NSArray<NSView*>* before = pageViews(window.contentView);
    creationWindow = window; creationRoot = window.contentView; creationContents = contents; creationBefore = before; creating = true;
    napi_value result; napi_get_undefined(env, &result); return result;
  } catch (const std::exception&) { return bindingFailure(env); } } @catch (NSException*) { return bindingFailure(env); }
}
napi_value finishBinding(napi_env env, napi_callback_info info) {
  if (!mainCall(env, info, 0)) return bindingFailure(env);
  @try { try {
    if (!integrity() || !creating) throw std::runtime_error("native_creation_unavailable");
    NSWindow* window = creationWindow; NSView* root = creationRoot;
    if (!window || !root || window.contentView != root || root.window != window || ![NSApp.windows containsObject:window]) throw std::runtime_error("native_creation_window_changed");
    NSArray<NSView*>* after = pageViews(root); NSMutableArray<NSView*>* added = [NSMutableArray new];
    for (NSView* old in creationBefore) if (![after containsObject:old]) throw std::runtime_error("native_creation_interleaved");
    for (NSView* view in after) if (![creationBefore containsObject:view]) [added addObject:view];
    if (added.count != 1) throw std::runtime_error("native_ambiguous_creation");
    NSView* view = added[0];
    if (view.window != window || viewPolicy(view)) throw std::runtime_error("native_view_reused");
    if (nextIdentifier > UINT32_MAX || policies.count >= 1000000) throw std::runtime_error("native_binding_exhausted");
    ArbolPagePolicy* policy = [ArbolPagePolicy new]; policy.identifier = static_cast<uint32_t>(nextIdentifier++);
    policy.webContentsId = creationContents; policy.nonce = NSUUID.UUID.UUIDString.lowercaseString; policy.blocked = YES;
    policy.view = view; policy.window = window;
    [policies addObject:policy]; ++liveBindings; ++policyObjects;
    objc_setAssociatedObject(view, &policyKey, policy, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    creating = false; creationBefore = nil; creationRoot = nil; creationWindow = nil; creationContents = 0;
    return jsonReply(env, bindingObject(policy));
  } catch (const std::exception&) { return bindingFailure(env); } } @catch (NSException*) { return bindingFailure(env); }
}
static uint32_t keyNumber(id value, bool positive = false) {
  if (![value isKindOfClass:[NSNumber class]] || CFGetTypeID((__bridge CFTypeRef)value) == CFBooleanGetTypeID()) throw std::runtime_error("native_key_number");
  double number = [value doubleValue];
  if (!std::isfinite(number) || std::floor(number) != number || number < (positive ? 1 : 0) || number > UINT32_MAX) throw std::runtime_error("native_key_number");
  return static_cast<uint32_t>(number);
}
ArbolPagePolicy* keyPolicy(napi_env env, napi_value value) {
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok || !length || length > kStructuredLimit) throw std::runtime_error("native_key_bound");
  std::vector<char> bytes(length + 1); size_t written = 0;
  if (napi_get_value_string_utf8(env, value, bytes.data(), bytes.size(), &written) != napi_ok || written != length) throw std::runtime_error("native_key_encoding");
  NSError* error = nil;
  id key = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes.data() length:length] options:0 error:&error];
  NSSet* names = [NSSet setWithArray:@[@"id", @"nonce", @"webContentsId", @"revision"]];
  if (error || ![key isKindOfClass:[NSDictionary class]] || ![[NSSet setWithArray:[key allKeys]] isEqualToSet:names]) throw std::runtime_error("native_key_shape");
  uint32_t identifier = keyNumber(key[@"id"]), contents = keyNumber(key[@"webContentsId"], true), revision = keyNumber(key[@"revision"]);
  if (identifier >= policies.count || ![key[@"nonce"] isKindOfClass:[NSString class]]) throw std::runtime_error("native_key_identity");
  ArbolPagePolicy* policy = policies[identifier];
  if (!policyLive(policy) || policy.identifier != identifier || policy.webContentsId != contents || policy.revision != revision || ![policy.nonce isEqualToString:key[@"nonce"]])
    throw std::runtime_error("native_key_stale");
  return policy;
}
template <typename Function> static napi_value keyCall(napi_env env, napi_callback_info info, size_t count, Function operation) {
  napi_value args[2]; if (!mainCall(env, info, count, args)) return bindingFailure(env);
  @try { try {
    if (!integrity() || creating || callbackDepth) throw std::runtime_error("native_policy_unavailable");
    ArbolPagePolicy* policy = keyPolicy(env, args[0]); CallbackScope scope;
    operation(policy, args); return jsonReply(env, bindingObject(policy));
  } catch (const std::exception&) { return bindingFailure(env); } } @catch (NSException*) { return bindingFailure(env); }
}
napi_value bindingInfo(napi_env env, napi_callback_info info) {
  return keyCall(env, info, 1, [](ArbolPagePolicy*, napi_value*) {});
}
napi_value mark(napi_env env, napi_callback_info info) {
  return keyCall(env, info, 2, [env](ArbolPagePolicy* policy, napi_value* args) {
    bool blocked;
    if (napi_get_value_bool(env, args[1], &blocked) != napi_ok) throw std::runtime_error("native_block_boolean");
    advanceRevision(policy); policy.blocked = blocked;
  });
}
napi_value restore(napi_env env, napi_callback_info info) {
  return keyCall(env, info, 1, [](ArbolPagePolicy* policy, napi_value*) {
    NSView* view = policy.view; view.hidden = NO;
    for (NSView* child in view.subviews) child.hidden = NO;
    [view setNeedsDisplay:YES]; // Presentation only; never native focus or a policy change.
  });
}
napi_value retire(napi_env env, napi_callback_info info) {
  return keyCall(env, info, 1, [](ArbolPagePolicy* policy, napi_value*) {
    advanceRevision(policy); policy.blocked = YES; policy.retired = YES;
    policy.view = nil; policy.window = nil; --liveBindings;
  });
}

}

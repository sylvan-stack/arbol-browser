#import "keys.hpp"
#include <cmath>
#include <cstring>
#include <limits>
@implementation ArbolPagePolicy
@end
namespace arbol_native {
NSMutableArray<ArbolPagePolicy*>* policies = [NSMutableArray new];
bool creating = false;
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
static napi_value bindingFailure(napi_env env) {
  poison("native_binding_failed"); napi_throw_error(env, nullptr, "native_binding_failed"); return nullptr;
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
}

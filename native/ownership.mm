#import "inventory.hpp"
#include <dlfcn.h>
#include <limits.h>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
namespace arbol_native {
std::atomic<Phase> phase{Phase::New};
std::vector<Hook> hooks;
BindingAudit bindingAudit = nullptr;
BindingSeal bindingSeal = nullptr;
size_t liveBindings = 0, policyObjects = 0;
static std::string reason;
void poison(const char* why) {
  Phase current = phase.load(std::memory_order_acquire);
  if (current != Phase::Closing) phase.store(Phase::Poisoned, std::memory_order_release);
  reason = why;
  if (bindingSeal) bindingSeal();
}
bool mainCall(napi_env env, napi_callback_info info, size_t expected, napi_value* arguments) {
  if (![NSThread isMainThread]) { napi_throw_error(env, nullptr, "native_main_thread_only"); return false; }
  // Read one extra argument to distinguish exact arity from truncation.
  napi_value values[3]; size_t count = 3;
  if (expected > 2 || napi_get_cb_info(env, info, &count, values, nullptr, nullptr) != napi_ok || count != expected) {
    napi_throw_error(env, nullptr, "native_argument_shape"); return false;
  }
  for (size_t i = 0; i < expected; ++i) arguments[i] = values[i];
  return true;
}
napi_value jsonReply(napi_env env, id value) {
  NSError* error = nil;
  NSData* bytes = [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:&error];
  if (!bytes || error || bytes.length > kStructuredLimit) { poison("native_reply_bound"); napi_throw_error(env, nullptr, "native_reply_bound"); return nullptr; }
  napi_value result;
  if (napi_create_string_utf8(env, (const char*)bytes.bytes, bytes.length, &result) != napi_ok) { poison("native_reply_failed"); return nullptr; }
  return result;
}
NSString* providerOf(IMP implementation) {
  Dl_info image{}; Dl_info addon{};
  if (!dladdr((void*)implementation, &image) || !image.dli_fname || !dladdr((void*)&providerOf, &addon) || !addon.dli_fname) return @"<unknown>";
  NSString* actual = [[NSString stringWithUTF8String:image.dli_fname] stringByResolvingSymlinksInPath];
  NSString* expected;
  if ([actual.lastPathComponent isEqualToString:@"AppKit"]) expected = @"/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit";
  else {
    NSString* native = [[NSString stringWithUTF8String:addon.dli_fname] stringByDeletingLastPathComponent];
    expected = [[native stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"runtime/Electron.app/Contents/Frameworks/Electron Framework.framework/Versions/A/Electron Framework"];
  }
  if (![actual isEqualToString:[expected stringByResolvingSymlinksInPath]]) return @"<unexpected-provider>";
  return actual.lastPathComponent;
}
static void initializeSelectors() {
  // Chromium installs generated editing selectors in +initialize. Trigger this
  // before observing any target, never synthesize expected methods ourselves.
  Class widget = NSClassFromString(@"RenderWidgetHostViewCocoa");
  if (widget) [(id)widget class];
}
NSDictionary* liveInventory() {
  initializeSelectors();
  NSMutableDictionary* methods = [NSMutableDictionary new];
  for (const auto& target : targets) {
    Class cls = objc_getClass(target.cls); SEL sel = sel_registerName(target.selector);
    Method method = cls ? class_getInstanceMethod(cls, sel) : nullptr;
    NSString* key = [NSString stringWithFormat:@"%s#%s", target.cls, target.selector];
    methods[key] = method ? (id)@{@"encoding": @(method_getTypeEncoding(method)), @"provider": providerOf(method_getImplementation(method))} : (id)@"<absent>";
  }
  return @{@"abi": @1, @"compiledNapi": @(NAPI_VERSION), @"pointerBytes": @(sizeof(void*)), @"rangeBytes": @(sizeof(NSRange)), @"pointBytes": @(sizeof(NSPoint)), @"methods": methods};
}
NSDictionary* pinnedInventory() {
  NSMutableDictionary* methods = [NSMutableDictionary new];
  for (const auto& target : targets) {
    NSString* key = [NSString stringWithFormat:@"%s#%s", target.cls, target.selector];
    methods[key] = strcmp(target.encoding, "<absent>") ? (id)@{@"encoding": @(target.encoding), @"provider": @(target.provider)} : (id)@"<absent>";
  }
  return @{@"abi": @1, @"compiledNapi": @8, @"pointerBytes": @8, @"rangeBytes": @16, @"pointBytes": @16, @"methods": methods};
}
NSDictionary* statusObject() {
  const char* names[] = {"new", "planning", "ready", "rejected", "poisoned", "closing"};
  size_t applied = 0;
  for (const auto& hook : hooks) {
    Method method = class_getInstanceMethod(hook.cls, hook.selector);
    if (method && method_getImplementation(method) == hook.guard) ++applied;
  }
  return @{@"abi": @1, @"phase": @(names[(unsigned)phase.load(std::memory_order_acquire)]), @"reason": @(reason.c_str()),
    @"hooks": @(hooks.size()), @"appliedHooks": @(applied), @"liveBindings": @(liveBindings), @"policyObjects": @(policyObjects)};
}
static napi_value getABI(napi_env env, napi_callback_info info) { if (!mainCall(env, info, 0)) return nullptr; return jsonReply(env, liveInventory()); }
static napi_value status(napi_env env, napi_callback_info info) { if (!mainCall(env, info, 0)) return nullptr; return jsonReply(env, statusObject()); }
static void environmentClosing(void*) { phase.store(Phase::Closing, std::memory_order_release); if (bindingSeal) bindingSeal(); }
}
NAPI_MODULE_INIT() {
  using namespace arbol_native;
  if (![NSThread isMainThread]) { napi_throw_error(env, nullptr, "native_main_thread_only"); return nullptr; }
  napi_add_env_cleanup_hook(env, environmentClosing, nullptr);
  napi_property_descriptor exportsList[] = {
    {"getABI", nullptr, getABI, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"status", nullptr, status, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, sizeof(exportsList) / sizeof(exportsList[0]), exportsList) != napi_ok) return nullptr;
  return exports;
}

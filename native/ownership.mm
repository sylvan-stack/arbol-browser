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

// Conservative first-stage guards intentionally deny all page routes. ABR-6
// supplies ownership-aware bodies; this stage exposes no binding/admission API.
static void denyObject(id, SEL, id) {}
static void denySelector(id, SEL, SEL) {}
static void denyVoid(id, SEL) {}
static BOOL denyBool(id, SEL) { return NO; }
static BOOL denyBoolObject(id, SEL, id) { return NO; }
static id denyGetter(id, SEL) { return nil; }
static NSUInteger denyOperation(id, SEL, id) { return 0; }
static void denyObjects(id, SEL, id, id) {}
static void denyBoolean(id, SEL, BOOL) {}
static void denyRange(id, SEL, NSRange) {}
static void denyObjectRange(id, SEL, id, NSRange) {}
static void denyMarked(id, SEL, id, NSRange, NSRange) {}
static void denyPoint(id, SEL, id, NSPoint) {}
static void denyDragEnd(id, SEL, id, NSPoint, NSUInteger) {}
static IMP conservativeGuard(const char* encoding) {
  struct Shape { const char* encoding; IMP guard; };
  const Shape shapes[] = {
    {"v@:@", (IMP)denyObject}, {"v24@0:8@16", (IMP)denyObject}, {"v24@0:8:16", (IMP)denySelector},
    {"v16@0:8", (IMP)denyVoid}, {"B16@0:8", (IMP)denyBool}, {"B24@0:8@16", (IMP)denyBoolObject},
    {"@16@0:8", (IMP)denyGetter}, {"Q24@0:8@16", (IMP)denyOperation}, {"v32@0:8@16@24", (IMP)denyObjects},
    {"v20@0:8B16", (IMP)denyBoolean}, {"v32@0:8{_NSRange=QQ}16", (IMP)denyRange},
    {"v40@0:8@16{_NSRange=QQ}24", (IMP)denyObjectRange},
    {"v56@0:8@16{_NSRange=QQ}24{_NSRange=QQ}40", (IMP)denyMarked},
    {"v40@0:8@16{CGPoint=dd}24", (IMP)denyPoint}, {"v48@0:8@16{CGPoint=dd}24Q40", (IMP)denyDragEnd},
  };
  for (const auto& shape : shapes) if (!strcmp(shape.encoding, encoding)) return shape.guard;
  throw std::runtime_error("unqualified_method_encoding");
}
void stageGuard(Class cls, SEL selector, IMP guard, const char* encoding) {
  if (phase.load() != Phase::Planning || !cls || !guard || !encoding || hooks.size() >= kMaxTargets) throw std::runtime_error("invalid_hook_plan");
  for (const auto& hook : hooks) if (hook.cls == cls && hook.selector == selector) throw std::runtime_error("duplicate_hook_plan");
  Method method = class_getInstanceMethod(cls, selector);
  if (!method || strcmp(method_getTypeEncoding(method), encoding)) throw std::runtime_error("hook_encoding_changed");
  NSString* provider = providerOf(method_getImplementation(method));
  hooks.push_back({cls, selector, method_getImplementation(method), guard, encoding, provider.UTF8String, false});
}
static bool originalIntact(const Hook& hook) {
  Method method = class_getInstanceMethod(hook.cls, hook.selector);
  return method && method_getImplementation(method) == hook.before && !strcmp(method_getTypeEncoding(method), hook.encoding.c_str()) &&
    [providerOf(hook.before) isEqualToString:@(hook.provider.c_str())];
}
static void planOwnershipGuards() {
  for (const auto& target : targets) {
    if (!strcmp(target.encoding, "<absent>")) continue;
    stageGuard(objc_getClass(target.cls), sel_registerName(target.selector), conservativeGuard(target.encoding), target.encoding);
  }
}
static napi_value install(napi_env env, napi_callback_info info) {
  napi_value argument;
  if (!mainCall(env, info, 1, &argument)) { phase.store(Phase::Poisoned); return nullptr; }
  if (phase.load() != Phase::New) { napi_throw_error(env, nullptr, "native_install_not_repeatable"); return nullptr; }
  phase.store(Phase::Planning, std::memory_order_release);
  @try {
    try {
      size_t length = 0;
      if (napi_get_value_string_utf8(env, argument, nullptr, 0, &length) != napi_ok || !length || length > kStructuredLimit) throw std::runtime_error("native_inventory_bound");
      std::vector<char> bytes(length + 1);
      size_t written = 0;
      if (napi_get_value_string_utf8(env, argument, bytes.data(), bytes.size(), &written) != napi_ok || written != length) throw std::runtime_error("native_inventory_encoding");
      NSError* error = nil;
      id expected = [NSJSONSerialization JSONObjectWithData:[NSData dataWithBytes:bytes.data() length:length] options:0 error:&error];
      if (error || ![expected isKindOfClass:[NSDictionary class]] || ![expected isEqual:pinnedInventory()] || ![expected isEqual:liveInventory()]) throw std::runtime_error("native_inventory_mismatch");
      planOwnershipGuards();
      if (hooks.empty()) throw std::runtime_error("native_empty_plan");
      // Complete preflight before the first mutation, then recheck each commit.
      for (const auto& hook : hooks) if (!originalIntact(hook)) throw std::runtime_error("native_plan_changed");
      for (auto& hook : hooks) {
        if (!originalIntact(hook)) throw std::runtime_error("native_commit_changed");
        class_replaceMethod(hook.cls, hook.selector, hook.guard, hook.encoding.c_str());
        hook.applied = true;
        Method method = class_getInstanceMethod(hook.cls, hook.selector);
        if (!method || method_getImplementation(method) != hook.guard || strcmp(method_getTypeEncoding(method), hook.encoding.c_str())) throw std::runtime_error("native_guard_commit_failed");
      }
      for (const auto& hook : hooks) if (method_getImplementation(class_getInstanceMethod(hook.cls, hook.selector)) != hook.guard) throw std::runtime_error("native_installed_guard_changed");
      phase.store(Phase::Ready, std::memory_order_release);
      return jsonReply(env, statusObject());
    } catch (const std::exception&) {
      bool restored = true;
      for (auto it = hooks.rbegin(); it != hooks.rend(); ++it) if (it->applied) {
        class_replaceMethod(it->cls, it->selector, it->before, it->encoding.c_str());
        restored = originalIntact(*it) && restored;
      }
      poison(restored ? "native_install_failed" : "native_rollback_failed");
      napi_throw_error(env, nullptr, "native_install_failed");
      return nullptr;
    }
  } @catch (NSException*) {
    // Objective-C uncertainty never permits retry or unsafe unhook.
    poison("native_install_exception"); napi_throw_error(env, nullptr, "native_install_failed"); return nullptr;
  }
}
static napi_value checkIntegrity(napi_env env, napi_callback_info info) {
  if (!mainCall(env, info, 0)) return nullptr;
  if (!integrity()) { napi_throw_error(env, nullptr, "native_integrity_failed"); return nullptr; }
  return jsonReply(env, statusObject());
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
    {"checkIntegrity", nullptr, checkIntegrity, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"install", nullptr, install, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"getABI", nullptr, getABI, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"status", nullptr, status, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, sizeof(exportsList) / sizeof(exportsList[0]), exportsList) != napi_ok) return nullptr;
  return exports;
}

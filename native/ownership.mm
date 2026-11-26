#import "keys.hpp"
#include <dlfcn.h>
#include <limits.h>
#include <cstdlib>
#include <cstring>
#include <map>
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
static NSString* resolveProvider(const Dl_info& image) {
  Dl_info addon{};
  if (!dladdr((void*)&providerOf, &addon) || !addon.dli_fname) return @"<unknown>";
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
NSString* providerOf(IMP implementation) {
  Dl_info image{};
  if (!dladdr((void*)implementation, &image) || !image.dli_fname) return @"<unknown>";
  return resolveProvider(image);
}
// Darwin's header lookup resolves the current mapping without symbol lookup.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
static const mach_header* loadedImage(const void* address) {
  return _dyld_get_image_header_containing_address(address);
}
#pragma clang diagnostic pop
static void pinHookProviders() {
  static std::map<const mach_header*, void*> pinned;
  for (auto& hook : hooks) {
    const auto* implementation = reinterpret_cast<const void*>(hook.before);
    Dl_info image{};
    if (!dladdr(implementation, &image) || !image.dli_fname ||
        ![resolveProvider(image) isEqualToString:@(hook.provider.c_str())])
      throw std::runtime_error("native_provider_changed");
    const auto* header = loadedImage(implementation);
    if (!header || header != image.dli_fbase) throw std::runtime_error("native_provider_header_changed");
    if (!pinned.count(header)) {
      // Keep one loader reference per verified mapping for the process lifetime.
      void* handle = dlopen(image.dli_fname, RTLD_NOLOAD | RTLD_NOW | RTLD_LOCAL);
      if (!handle) throw std::runtime_error("native_provider_pin_failed");
      if (_dyld_get_dlopen_image_header(handle) != header) {
        dlclose(handle);
        throw std::runtime_error("native_provider_pin_changed");
      }
      pinned.emplace(header, handle);
    }
    if (loadedImage(implementation) != header)
      throw std::runtime_error("native_provider_header_changed");
    hook.providerImage = header;
  }
}
bool installedHooksIntact() {
  for (const auto& hook : hooks) {
    Method method = class_getInstanceMethod(hook.cls, hook.selector);
    if (!hook.applied || !method || method_getImplementation(method) != hook.guard ||
        strcmp(method_getTypeEncoding(method), hook.encoding.c_str()) || !hook.providerImage ||
        loadedImage(reinterpret_cast<const void*>(hook.before)) != hook.providerImage)
      return false;
  }
  return true;
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
void planAccessibility();
void planTextInput();
void planResponder();
void planInteraction();
static void planOwnershipGuards() {
  initializeBindings();
  planAccessibility(); planTextInput(); planResponder(); planInteraction();
  size_t required = 0;
  for (const auto& target : targets) if (strcmp(target.encoding, "<absent>")) {
    ++required; bool planned = false;
    const Class cls = objc_getClass(target.cls);
    const SEL selector = sel_registerName(target.selector);
    for (const auto& hook : hooks) {
      if (hook.cls == cls && hook.selector == selector) {
        if (hook.provider != target.provider) throw std::runtime_error("native_route_provider_mismatch");
        planned = true;
        break;
      }
    }
    if (!planned) throw std::runtime_error("native_route_not_planned");
  }
  if (hooks.size() != required) throw std::runtime_error("native_route_coverage_mismatch");
}
static napi_value install(napi_env env, napi_callback_info info) {
  napi_value argument;
  if (!mainCall(env, info, 1, &argument)) { if (phase.load() != Phase::Closing) phase.store(Phase::Poisoned); return nullptr; }
  if (phase.load() != Phase::New) { poison("native_install_not_repeatable"); napi_throw_error(env, nullptr, "native_install_not_repeatable"); return nullptr; }
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
      pinHookProviders();
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
extern bool closingIntegrity();
static napi_value seal(napi_env env, napi_callback_info info) {
  if (!mainCall(env, info, 0)) return nullptr;
  // Publish exclusion first. Reentrant callbacks see closing even if teardown
  // or audit throws. No path transitions this process back to ready.
  phase.exchange(Phase::Closing, std::memory_order_acq_rel);
  @try {
    if (bindingSeal) bindingSeal();
    if (!closingIntegrity()) { napi_throw_error(env, nullptr, "native_seal_unconfirmed"); return nullptr; }
    return jsonReply(env, statusObject());
  } @catch (NSException*) { napi_throw_error(env, nullptr, "native_seal_unconfirmed"); return nullptr; }
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
    {"beginBinding", nullptr, beginBinding, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"finishBinding", nullptr, finishBinding, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"bindingInfo", nullptr, bindingInfo, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"mark", nullptr, mark, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"restore", nullptr, restore, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"retire", nullptr, retire, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"interactionState", nullptr, interactionState, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"seal", nullptr, seal, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"checkIntegrity", nullptr, checkIntegrity, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"install", nullptr, install, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"getABI", nullptr, getABI, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"status", nullptr, status, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, sizeof(exportsList) / sizeof(exportsList[0]), exportsList) != napi_ok) return nullptr;
  return exports;
}

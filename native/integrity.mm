#import "inventory.hpp"
#include <cstring>
namespace arbol_native {
// Every reachable target remains closed: absence, original provider identity,
// method encoding and our exact installed IMP, plus ABR-6's binding audit.
bool integrity() {
  if (![NSThread isMainThread] || phase.load(std::memory_order_acquire) != Phase::Ready) return false;
  if (hooks.empty() || hooks.size() > kMaxTargets || liveBindings > 1000000 || policyObjects > 1000000) { poison("native_state_bound"); return false; }
  for (const auto& target : targets) {
    Method method = class_getInstanceMethod(objc_getClass(target.cls), sel_registerName(target.selector));
    if (!strcmp(target.encoding, "<absent>")) {
      if (method) { poison("native_absence_changed"); return false; }
    } else if (!method || strcmp(method_getTypeEncoding(method), target.encoding)) { poison("native_encoding_changed"); return false; }
  }
  for (const auto& hook : hooks) {
    Method method = class_getInstanceMethod(hook.cls, hook.selector);
    if (!hook.applied || !method || method_getImplementation(method) != hook.guard || strcmp(method_getTypeEncoding(method), hook.encoding.c_str()) ||
        ![providerOf(hook.before) isEqualToString:@(hook.provider.c_str())]) { poison("native_guard_integrity_changed"); return false; }
  }
  if ((!bindingAudit && (liveBindings || policyObjects)) || (bindingAudit && !bindingAudit())) { poison("native_binding_integrity_changed"); return false; }
  return phase.load(std::memory_order_acquire) == Phase::Ready;
}
bool closingIntegrity() {
  if (phase.load(std::memory_order_acquire) != Phase::Closing || liveBindings != 0) return false;
  // Tombstones and callable guards remain resident. A missing guard cannot be
  // reported as successful exclusion; ABR-7's watchdog owns uncertain teardown.
  for (const auto& hook : hooks) {
    Method method = class_getInstanceMethod(hook.cls, hook.selector);
    if (!method || method_getImplementation(method) != hook.guard || strcmp(method_getTypeEncoding(method), hook.encoding.c_str())) return false;
  }
  return !bindingAudit || bindingAudit();
}

}

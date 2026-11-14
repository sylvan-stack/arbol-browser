#import "keys.hpp"
#include <cstring>
namespace arbol_native {
static char accessibilityPolicyKey;
IMP originalFor(id object, SEL selector) {
  for (const auto& hook : hooks) if (hook.selector == selector && [object isKindOfClass:hook.cls]) return hook.before;
  throw std::runtime_error("native_original_missing");
}
void stageRoute(const Target& target, IMP implementation) {
  stageGuard(objc_getClass(target.cls), sel_registerName(target.selector), implementation, target.encoding);
}
ArbolPagePolicy* ownerPolicy(id object) {
  if (![NSThread isMainThread] || phase.load(std::memory_order_acquire) != Phase::Ready || callbackDepth || creating) return nil;
  CallbackScope scope; std::set<void*> seen;
  for (unsigned depth = 0; object && depth < 128; ++depth) {
    if (!seen.insert((__bridge void*)object).second) return nil;
    ArbolPagePolicy* cached = objc_getAssociatedObject(object, &accessibilityPolicyKey);
    if (cached) return cached;
    if ([object isKindOfClass:[NSView class]]) return viewPolicy(object);
    if (![object respondsToSelector:@selector(accessibilityParent)]) return nil;
    object = ((id(*)(id, SEL))objc_msgSend)(object, @selector(accessibilityParent));
  }
  return nil;
}
bool callbackAllowed(ArbolPagePolicy* policy) {
  return [NSThread isMainThread] && phase.load(std::memory_order_acquire) == Phase::Ready && !callbackDepth && !creating &&
    policyLive(policy) && !policy.blocked && ![policy.view isHiddenOrHasHiddenAncestor];
}
static id widgetRoots(NSView* widget) {
  ArbolPagePolicy* policy = viewPolicy(widget);
  if (![NSThread isMainThread] || phase.load() != Phase::Ready || callbackDepth || creating || !policyLive(policy)) return @[];
  CallbackScope scope;
  id roots = ((id(*)(id, SEL))originalFor(widget, @selector(accessibilityChildren)))(widget, @selector(accessibilityChildren));
  if (!roots) return @[];
  if (![roots isKindOfClass:[NSArray class]] || [roots count] > 4096) throw std::runtime_error("native_accessibility_roots_bound");
  for (id root in roots) {
    ArbolPagePolicy* old = objc_getAssociatedObject(root, &accessibilityPolicyKey);
    if (old && old != policy) throw std::runtime_error("native_accessibility_root_reused");
    objc_setAssociatedObject(root, &accessibilityPolicyKey, policy, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  }
  return roots;
}
static void primeView(NSView* view, unsigned depth, size_t& count) {
  if (depth > 128 || ++count > 1000000) throw std::runtime_error("native_accessibility_tree_bound");
  if ([NSStringFromClass(view.class) isEqualToString:@"RenderWidgetHostViewCocoa"]) widgetRoots(view);
  for (NSView* child in view.subviews) primeView(child, depth + 1, count);
}
void primeAccessibility(ArbolPagePolicy* policy) {
  if (!policyLive(policy)) throw std::runtime_error("native_accessibility_binding_missing");
  size_t count = 0; primeView(policy.view, 0, count);
}
template <typename Function> static void mutate(id object, Function operation) {
  if (![NSThread isMainThread]) return;
  @try { try { if (!callbackAllowed(ownerPolicy(object))) return; CallbackScope scope; operation(); }
    catch (const std::exception&) { poison("native_accessibility_failed"); } }
  @catch (NSException*) { poison("native_accessibility_failed"); }
}
static BOOL axActivate(id self, SEL selector) {
  if (![NSThread isMainThread]) return NO;
  @try { try { if (!callbackAllowed(ownerPolicy(self))) return NO; CallbackScope scope;
    return ((BOOL(*)(id, SEL))originalFor(self, selector))(self, selector);
  } catch (const std::exception&) { poison("native_accessibility_failed"); } } @catch (NSException*) { poison("native_accessibility_failed"); }
  return NO;
}
static void axObject(id self, SEL selector, id value) { mutate(self, [&] { ((void(*)(id, SEL, id))originalFor(self, selector))(self, selector, value); }); }
static void axObjects(id self, SEL selector, id value, id attribute) { mutate(self, [&] { ((void(*)(id, SEL, id, id))originalFor(self, selector))(self, selector, value, attribute); }); }
static void axBoolean(id self, SEL selector, BOOL value) { mutate(self, [&] { ((void(*)(id, SEL, BOOL))originalFor(self, selector))(self, selector, value); }); }
static void axRange(id self, SEL selector, NSRange value) { mutate(self, [&] { ((void(*)(id, SEL, NSRange))originalFor(self, selector))(self, selector, value); }); }
static id axChildren(id self, SEL) {
  if (![NSThread isMainThread]) return @[];
  @try { try { return widgetRoots(self); } catch (const std::exception&) { poison("native_accessibility_failed"); } } @catch (NSException*) { poison("native_accessibility_failed"); }
  return @[];
}
static id axCustomActions(id self, SEL selector) {
  if (![NSThread isMainThread]) return nil;
  @try { try {
    ArbolPagePolicy* policy = ownerPolicy(self);
    if (!policyLive(policy) || callbackDepth || creating || phase.load() != Phase::Ready) return nil;
    CallbackScope scope;
    id actions = ((id(*)(id, SEL))originalFor(self, selector))(self, selector);
    if (!actions) return nil;
    if (![actions isKindOfClass:[NSArray class]] || [actions count] > 4096) throw std::runtime_error("native_custom_action_bound");
    NSMutableArray* wrapped = [NSMutableArray new];
    for (NSAccessibilityCustomAction* action in actions) {
      if (![action isKindOfClass:[NSAccessibilityCustomAction class]] || !action.handler) throw std::runtime_error("native_custom_action_shape");
      BOOL (^handler)(void) = [action.handler copy]; __weak id element = self;
      // Wrap a new object, never rewrite or repeatedly nest a cached provider action.
      [wrapped addObject:[[NSAccessibilityCustomAction alloc] initWithName:action.name handler:^BOOL {
        if (![NSThread isMainThread]) return NO;
        @try { try { id current = element;
          if (!current || ownerPolicy(current) != policy || !callbackAllowed(policy)) return NO;
          CallbackScope callback; return handler();
        } catch (const std::exception&) { poison("native_custom_action_failed"); } } @catch (NSException*) { poison("native_custom_action_failed"); }
        return NO;
      }]];
    }
    return wrapped;
  } catch (const std::exception&) { poison("native_accessibility_failed"); } } @catch (NSException*) { poison("native_accessibility_failed"); }
  return nil;
}
void planAccessibility() {
  for (const auto& target : targets) {
    if (!strcmp(target.cls, "RenderWidgetHostViewCocoa") && !strcmp(target.selector, "accessibilityChildren")) { stageRoute(target, (IMP)axChildren); continue; }
    if (strcmp(target.cls, "BrowserAccessibilityCocoa") || !strcmp(target.encoding, "<absent>")) continue;
    IMP guard = nullptr;
    if (!strcmp(target.selector, "accessibilityCustomActions")) guard = (IMP)axCustomActions;
    else if (!strcmp(target.encoding, "B16@0:8")) guard = (IMP)axActivate;
    else if (!strcmp(target.encoding, "v24@0:8@16")) guard = (IMP)axObject;
    else if (!strcmp(target.encoding, "v32@0:8@16@24")) guard = (IMP)axObjects;
    else if (!strcmp(target.encoding, "v20@0:8B16")) guard = (IMP)axBoolean;
    else if (!strcmp(target.encoding, "v32@0:8{_NSRange=QQ}16")) guard = (IMP)axRange;
    if (!guard) throw std::runtime_error("native_unplanned_accessibility_shape");
    stageRoute(target, guard);
  }
}
}

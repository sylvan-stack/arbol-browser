#import "keys.hpp"
#include <cstring>
namespace arbol_native {
static __weak NSView* expectedResponder;
static ArbolPagePolicy* expectedPolicy;
static unsigned expectedDepth;
static bool pageResponder(NSView* view) {
  for (unsigned depth = 0; view && depth < 128; ++depth, view = view.superview)
    if ([NSStringFromClass(view.class) isEqualToString:@"WebContentsViewCocoa"] || [NSStringFromClass(view.class) isEqualToString:@"RenderWidgetHostViewCocoa"]) return true;
  return view != nil; // An unbounded ancestry is unknown, never shell authority.
}
static bool visibleUser(ArbolPagePolicy* policy) {
  return phase.load() == Phase::Ready && !creating && policyLive(policy) && !policy.blocked &&
    ![policy.view isHiddenOrHasHiddenAncestor] && policy.window.isKeyWindow;
}
struct ResponderContinuation {
  ResponderContinuation(NSView* view, ArbolPagePolicy* policy) { expectedResponder = view; expectedPolicy = policy; expectedDepth = callbackDepth + 1; }
  ~ResponderContinuation() { expectedResponder = nil; expectedPolicy = nil; expectedDepth = 0; }
};
static BOOL makeResponder(NSWindow* self, SEL selector, id candidate) {
  if (![NSThread isMainThread]) return NO;
  @try { try {
    if (candidate && ![candidate isKindOfClass:[NSView class]]) return NO;
    NSView* view = candidate;
    if (callbackDepth && !pointerFocusContinuation(self, view)) return NO;
    if (view && view.window != self) return NO;
    ArbolPagePolicy* policy = view ? viewPolicy(view) : nil;
    if (view && (pageResponder(view) || policy)) {
      if (!visibleUser(policy)) return NO;
      // AppKit synchronously calls this exact candidate's becomeFirstResponder.
      // Permit that one verified continuation; unrelated reentrancy still denies.
      ResponderContinuation continuation(view, policy); CallbackScope scope;
      return ((BOOL(*)(id, SEL, id))originalFor(self, selector))(self, selector, candidate);
    }
    if (!view && [self.firstResponder isKindOfClass:[NSView class]]) {
      NSView* old = (NSView*)self.firstResponder;
      if (pageResponder(old) && !visibleUser(viewPolicy(old))) return NO;
    }
    // Native trusted shell controls have no page ancestor. No global AX/focus lock.
    CallbackScope scope;
    return ((BOOL(*)(id, SEL, id))originalFor(self, selector))(self, selector, candidate);
  } catch (const std::exception&) { poison("native_responder_failed"); } } @catch (NSException*) { poison("native_responder_failed"); }
  return NO;
}
static BOOL becomeResponder(NSView* self, SEL selector) {
  if (![NSThread isMainThread]) return NO;
  @try { try {
    ArbolPagePolicy* policy = viewPolicy(self);
    if (!visibleUser(policy)) return NO;
    if (callbackDepth && !(callbackDepth == expectedDepth && expectedResponder == self && expectedPolicy == policy) && routePolicy(self, selector) != policy) return NO;
    CallbackScope scope;
    return ((BOOL(*)(id, SEL))originalFor(self, selector))(self, selector);
  } catch (const std::exception&) { poison("native_responder_failed"); } } @catch (NSException*) { poison("native_responder_failed"); }
  return NO;
}
void planResponder() {
  for (const auto& target : targets) {
    if (!strcmp(target.cls, "NSWindow") && !strcmp(target.selector, "makeFirstResponder:")) stageRoute(target, (IMP)makeResponder);
    else if (!strcmp(target.cls, "RenderWidgetHostViewCocoa") && !strcmp(target.selector, "becomeFirstResponder")) stageRoute(target, (IMP)becomeResponder);
  }
}
}

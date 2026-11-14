#import "keys.hpp"
#include <cstring>
namespace arbol_native {
static char interactionKey;
constexpr uint64_t maxSafeInteger = 9007199254740991ULL;
static NSMutableDictionary* interaction(ArbolPagePolicy* policy) {
  if (!policyLive(policy)) throw std::runtime_error("native_interaction_owner_missing");
  NSMutableDictionary* state = objc_getAssociatedObject(policy, &interactionKey);
  if (!state) {
    state = [@{@"buttons": @0, @"wheel": @NO, @"momentum": @NO, @"htmlSource": @NO, @"htmlTarget": @NO,
      @"drops": @0, @"uncertain": @NO} mutableCopy];
    objc_setAssociatedObject(policy, &interactionKey, state, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
  }
  return state;
}
template <typename Result, typename Function> static Result inputResult(id object, Result denied, Function operation) {
  if (![NSThread isMainThread]) return denied;
  @try { try {
    ArbolPagePolicy* policy = ownerPolicy(object);
    if (!callbackAllowed(policy)) return denied;
    NSMutableDictionary* state = interaction(policy); CallbackScope scope; return operation(state);
  } catch (const std::exception&) { poison("native_interaction_failed"); } } @catch (NSException*) { poison("native_interaction_failed"); }
  return denied;
}
static void mouseEvent(id self, SEL selector, NSEvent* event) {
  inputResult(self, false, [&](NSMutableDictionary* state) {
    if (![event isKindOfClass:[NSEvent class]]) { state[@"uncertain"] = @YES; return false; }
    uint32_t buttons = [state[@"buttons"] unsignedIntValue];
    switch (event.type) {
      case NSEventTypeLeftMouseDown: case NSEventTypeRightMouseDown: case NSEventTypeOtherMouseDown:
      case NSEventTypeLeftMouseUp: case NSEventTypeRightMouseUp: case NSEventTypeOtherMouseUp: {
        if (event.buttonNumber < 0 || event.buttonNumber >= 32) { state[@"uncertain"] = @YES; return false; }
        uint32_t bit = uint32_t{1} << event.buttonNumber;
        if (event.type == NSEventTypeLeftMouseDown || event.type == NSEventTypeRightMouseDown || event.type == NSEventTypeOtherMouseDown) buttons |= bit;
        else buttons &= ~bit;
        break;
      }
      case NSEventTypeLeftMouseDragged: case NSEventTypeRightMouseDragged: case NSEventTypeOtherMouseDragged:
        if (!buttons) { state[@"uncertain"] = @YES; return false; } break;
      case NSEventTypeMouseMoved: case NSEventTypeMouseEntered: case NSEventTypeMouseExited: break;
      default: state[@"uncertain"] = @YES; return false;
    }
    state[@"buttons"] = @(buttons);
    ((void(*)(id, SEL, id))originalFor(self, selector))(self, selector, event); return true;
  });
}
static void wheelEvent(id self, SEL selector, NSEvent* event) {
  inputResult(self, false, [&](NSMutableDictionary* state) {
    if (![event isKindOfClass:[NSEvent class]] || event.type != NSEventTypeScrollWheel) { state[@"uncertain"] = @YES; return false; }
    constexpr NSUInteger active = NSEventPhaseMayBegin | NSEventPhaseBegan | NSEventPhaseChanged | NSEventPhaseStationary;
    constexpr NSUInteger ended = NSEventPhaseEnded | NSEventPhaseCancelled;
    if ((event.phase | event.momentumPhase) & ~(active | ended)) { state[@"uncertain"] = @YES; return false; }
    if (event.phase & active) state[@"wheel"] = @YES;
    if (event.phase & ended) state[@"wheel"] = @NO;
    if (event.momentumPhase & active) state[@"momentum"] = @YES;
    if (event.momentumPhase & ended) state[@"momentum"] = @NO;
    ((void(*)(id, SEL, id))originalFor(self, selector))(self, selector, event); return true;
  });
}
static NSUInteger dragTarget(id self, SEL selector, id sender) {
  return inputResult(self, NSUInteger{NSDragOperationNone}, [&](NSMutableDictionary* state) {
    if (![sender conformsToProtocol:@protocol(NSDraggingInfo)]) { state[@"uncertain"] = @YES; return NSUInteger{NSDragOperationNone}; }
    state[@"htmlTarget"] = @YES;
    return ((NSUInteger(*)(id, SEL, id))originalFor(self, selector))(self, selector, sender);
  });
}
static void dragExited(id self, SEL selector, id sender) {
  inputResult(self, false, [&](NSMutableDictionary* state) {
    if (![sender conformsToProtocol:@protocol(NSDraggingInfo)]) { state[@"uncertain"] = @YES; return false; }
    ((void(*)(id, SEL, id))originalFor(self, selector))(self, selector, sender);
    state[@"htmlTarget"] = @NO; return true;
  });
}
static BOOL dragDrop(id self, SEL selector, id sender) {
  return inputResult(self, BOOL{NO}, [&](NSMutableDictionary* state) {
    if (![sender conformsToProtocol:@protocol(NSDraggingInfo)] || ![state[@"htmlTarget"] boolValue]) { state[@"uncertain"] = @YES; return BOOL{NO}; }
    uint64_t drops = [state[@"drops"] unsignedLongLongValue];
    if (drops == maxSafeInteger) throw std::runtime_error("native_drop_count_exhausted");
    BOOL accepted = ((BOOL(*)(id, SEL, id))originalFor(self, selector))(self, selector, sender);
    if (accepted) state[@"drops"] = @(drops + 1);
    state[@"htmlTarget"] = @NO; return accepted;
  });
}
static void dragSource(id self, SEL selector, id session, NSPoint point) {
  if (![NSThread isMainThread]) return;
  @try { try {
    ArbolPagePolicy* policy = ownerPolicy(self);
    if (!callbackAllowed(policy)) {
      // An unexpected OS source session cannot be safely cancelled by inventing
      // mouse-up/drop. Keep exclusion and invoke the profile-fatal boundary.
      if (policyLive(policy) && policy.blocked) poison("native_blocked_drag_source");
      return;
    }
    NSMutableDictionary* state = interaction(policy); state[@"htmlSource"] = @YES; CallbackScope scope;
    ((void(*)(id, SEL, id, NSPoint))originalFor(self, selector))(self, selector, session, point);
  } catch (const std::exception&) { poison("native_interaction_failed"); } } @catch (NSException*) { poison("native_interaction_failed"); }
}
static void dragEnded(id self, SEL selector, id session, NSPoint point, NSUInteger operation) {
  inputResult(self, false, [&](NSMutableDictionary* state) {
    if (![state[@"htmlSource"] boolValue] || operation > maxSafeInteger) { state[@"uncertain"] = @YES; return false; }
    ((void(*)(id, SEL, id, NSPoint, NSUInteger))originalFor(self, selector))(self, selector, session, point, operation);
    state[@"htmlSource"] = @NO; state[@"buttons"] = @0; state[@"lastDragOperation"] = @(operation); return true;
  });
}
static void markedState(NSView* view, bool& marked, bool& found, size_t& count, unsigned depth) {
  if (++count > 1000000 || depth > 128) throw std::runtime_error("native_widget_tree_bound");
  if ([NSStringFromClass(view.class) isEqualToString:@"RenderWidgetHostViewCocoa"]) {
    if (![view conformsToProtocol:@protocol(NSTextInputClient)] || ![view respondsToSelector:@selector(hasMarkedText)]) throw std::runtime_error("native_text_state_unknown");
    found = true; marked = [(id<NSTextInputClient>)view hasMarkedText] || marked;
  }
  for (NSView* child in view.subviews) markedState(child, marked, found, count, depth + 1);
}
napi_value interactionState(napi_env env, napi_callback_info info) {
  napi_value argument;
  if (!mainCall(env, info, 1, &argument)) return nullptr;
  @try { try {
    if (!integrity() || creating || callbackDepth) throw std::runtime_error("native_interaction_unavailable");
    ArbolPagePolicy* policy = keyPolicy(env, argument); NSMutableDictionary* state = interaction(policy);
    CallbackScope scope; bool marked = false, found = false; size_t count = 0;
    markedState(policy.view, marked, found, count, 0);
    bool busy = !found || marked || [state[@"uncertain"] boolValue] || [state[@"buttons"] unsignedIntValue] || [state[@"wheel"] boolValue] ||
      [state[@"momentum"] boolValue] || [state[@"htmlSource"] boolValue] || [state[@"htmlTarget"] boolValue];
    NSMutableDictionary* reply = [state mutableCopy]; [reply removeObjectForKey:@"uncertain"];
    reply[@"marked"] = @(marked); reply[@"busy"] = @(busy);
    // Per-page capture/held-button accounting. A profile-wide hardware mask is
    // neither substituted for this state nor allowed to clear a missing release.
    reply[@"pressedButtons"] = state[@"buttons"];
    return jsonReply(env, reply);
  } catch (const std::exception&) { poison("native_interaction_failed"); } } @catch (NSException*) { poison("native_interaction_failed"); }
  napi_throw_error(env, nullptr, "native_interaction_failed"); return nullptr;
}
void planInteraction() {
  for (const auto& target : targets) {
    IMP guard = nullptr;
    if (!strcmp(target.cls, "RenderWidgetHostViewCocoa")) {
      if (!strcmp(target.selector, "mouseEvent:")) guard = (IMP)mouseEvent;
      if (!strcmp(target.selector, "scrollWheel:")) guard = (IMP)wheelEvent;
    } else if (!strcmp(target.cls, "WebContentsViewCocoa")) {
      if (!strcmp(target.selector, "draggingEntered:") || !strcmp(target.selector, "draggingUpdated:")) guard = (IMP)dragTarget;
      if (!strcmp(target.selector, "draggingExited:")) guard = (IMP)dragExited;
      if (!strcmp(target.selector, "performDragOperation:")) guard = (IMP)dragDrop;
      if (!strcmp(target.selector, "draggingSession:willBeginAtPoint:")) guard = (IMP)dragSource;
      if (!strcmp(target.selector, "draggingSession:endedAtPoint:operation:")) guard = (IMP)dragEnded;
    }
    if (guard) stageRoute(target, guard);
  }
}
}

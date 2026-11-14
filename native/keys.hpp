#pragma once
#import "inventory.hpp"
#import <objc/message.h>
#include <cstdint>
#include <set>
#include <stdexcept>
// Policies outlive their weak native views. Cached native clients retain the
// same policy object; an association is never rebound to a replacement page.
@interface ArbolPagePolicy : NSObject
@property uint32_t identifier;
@property uint32_t webContentsId;
@property uint32_t revision;
@property(copy) NSString* nonce;
@property BOOL blocked;
@property BOOL retired;
@property(weak) NSView* view;
@property(weak) NSWindow* window;
@end
namespace arbol_native {
extern NSMutableArray<ArbolPagePolicy*>* policies;
extern bool creating;
void initializeBindings();
bool policyLive(ArbolPagePolicy* policy);
void advanceRevision(ArbolPagePolicy* policy);
ArbolPagePolicy* ownerPolicy(id object);
bool callbackAllowed(ArbolPagePolicy* policy);
extern thread_local unsigned callbackDepth;
struct CallbackScope { CallbackScope() { ++callbackDepth; } ~CallbackScope() { --callbackDepth; } };
IMP originalFor(id object, SEL selector);
void stageRoute(const Target& target, IMP implementation);
void primeAccessibility(ArbolPagePolicy* policy);
napi_value bindingInfo(napi_env env, napi_callback_info info);
napi_value mark(napi_env env, napi_callback_info info);
napi_value restore(napi_env env, napi_callback_info info);
napi_value retire(napi_env env, napi_callback_info info);
napi_value interactionState(napi_env env, napi_callback_info info);
ArbolPagePolicy* keyPolicy(napi_env env, napi_value value);
NSArray<NSView*>* pageViews(NSView* root);
NSDictionary* bindingObject(ArbolPagePolicy* policy);
ArbolPagePolicy* viewPolicy(NSView* view);
napi_value beginBinding(napi_env env, napi_callback_info info);
napi_value finishBinding(napi_env env, napi_callback_info info);
}

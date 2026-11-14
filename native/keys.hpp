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
NSArray<NSView*>* pageViews(NSView* root);
NSDictionary* bindingObject(ArbolPagePolicy* policy);
ArbolPagePolicy* viewPolicy(NSView* view);
napi_value beginBinding(napi_env env, napi_callback_info info);
napi_value finishBinding(napi_env env, napi_callback_info info);
}

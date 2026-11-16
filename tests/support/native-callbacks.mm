// Testing-only callback bridge, independently compiled/signed outside the app.
// The pass-through control observes one Foundation resolver in its own process.
#import <Cocoa/Cocoa.h>
#import <objc/message.h>
#include <node_api.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <atomic>
#include <cstring>
#include <pthread.h>
#include <set>
@interface QualificationRoutes : NSObject
@property(nonatomic,weak) NSView* root;
@property(nonatomic,weak) NSView* widget;
@property(nonatomic,strong) id button;
@property(nonatomic,strong) id field;
@property(nonatomic,copy) BOOL (^action)(void);
@end
@implementation QualificationRoutes
@end
static NSMutableDictionary<NSString*,QualificationRoutes*>* routes;
static napi_value fail(napi_env env,const char* reason) { napi_throw_error(env,nullptr,reason); return nullptr; }
static bool args(napi_env env,napi_callback_info info,size_t expected,napi_value* values) {
  size_t count=3; napi_value actual[3];
  if(![NSThread isMainThread]||expected>2||napi_get_cb_info(env,info,&count,actual,nullptr,nullptr)!=napi_ok||count!=expected) { fail(env,"fixture_main_or_arity"); return false; }
  for(size_t i=0;i<expected;++i) values[i]=actual[i]; return true;
}
static NSString* string(napi_env env,napi_value value) {
  char text[128]{}; size_t length=0;
  if(napi_get_value_string_utf8(env,value,text,sizeof(text),&length)!=napi_ok||!length||length>=sizeof(text)) return nil;
  return [[NSString alloc] initWithBytes:text length:length encoding:NSUTF8StringEncoding];
}
static napi_value reply(napi_env env,id value) {
  NSData* bytes=[NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:nil];
  if(!bytes||bytes.length>1048576) return fail(env,"fixture_reply_bound");
  napi_value result; if(napi_create_string_utf8(env,(const char*)bytes.bytes,bytes.length,&result)!=napi_ok) return nullptr; return result;
}
static void views(NSView* view,NSString* name,NSMutableArray* found,unsigned depth=0) {
  if(!view||depth>64||found.count>128) return;
  if([NSStringFromClass(view.class) isEqualToString:name]) [found addObject:view];
  for(NSView* child in view.subviews) views(child,name,found,depth+1);
}
static void accessibility(id element,NSMutableArray* found,std::set<void*>& seen,unsigned depth=0) {
  if(!element||depth>64||seen.size()>=2048||!seen.insert((__bridge void*)element).second) return;
  [found addObject:element];
  if([element respondsToSelector:@selector(accessibilityChildren)])
    for(id child in [element accessibilityChildren]) accessibility(child,found,seen,depth+1);
}
static napi_value capture(napi_env env,napi_callback_info info) {
  napi_value value; if(!args(env,info,1,&value)) return nullptr;
  @try {
    bool buffer=false;void* bytes=nullptr;size_t size=0;
    if(napi_is_buffer(env,value,&buffer)!=napi_ok||!buffer||napi_get_buffer_info(env,value,&bytes,&size)!=napi_ok||size!=sizeof(void*)) return fail(env,"fixture_window_handle");
    void* pointer=nullptr;std::memcpy(&pointer,bytes,size);NSWindow* window=nil;
    for(NSWindow* candidate in NSApp.windows) if((__bridge void*)candidate.contentView==pointer) { if(window) return fail(env,"fixture_ambiguous_window");window=candidate; }
    if(!window) return fail(env,"fixture_unknown_window");
    NSMutableArray* roots=[NSMutableArray new];views(window.contentView,@"WebContentsViewCocoa",roots);
    if(roots.count!=1) return fail(env,"fixture_requires_one_actual_page");
    NSView* root=roots[0];NSMutableArray* widgets=[NSMutableArray new];views(root,@"RenderWidgetHostViewCocoa",widgets);
    if(widgets.count!=1) return fail(env,"fixture_requires_one_actual_widget");
    QualificationRoutes* row=[QualificationRoutes new];row.root=root;row.widget=widgets[0];
    NSMutableArray* elements=[NSMutableArray new];std::set<void*> seen;accessibility(row.widget,elements,seen);
    for(id element in elements) {
      NSString* role=[element respondsToSelector:@selector(accessibilityRole)]?[element accessibilityRole]:@"";
      if([role isEqualToString:@"AXButton"]&&!row.button) row.button=element;
      if([role isEqualToString:@"AXTextField"]&&!row.field) row.field=element;
      if(!row.action&&[element respondsToSelector:@selector(accessibilityCustomActions)]) {
        for(NSAccessibilityCustomAction* action in [element accessibilityCustomActions]) if(action.handler) { row.action=action.handler;break; }
      }
    }
    if(!routes) routes=[NSMutableDictionary new];NSString* token=NSUUID.UUID.UUIDString.lowercaseString;routes[token]=row;
    return reply(env,@{@"token":token,@"root":[NSString stringWithFormat:@"%p",root],@"widget":[NSString stringWithFormat:@"%p",row.widget],
      @"axNodes":@(elements.count),@"button":@(row.button!=nil),@"field":@(row.field!=nil),@"cachedHandler":@(row.action!=nil)});
  } @catch(NSException*) { return fail(env,"fixture_capture_exception"); }
}
static napi_value state(napi_env env,napi_callback_info info) {
  napi_value value;if(!args(env,info,1,&value)) return nullptr;QualificationRoutes* row=routes[string(env,value)];
  if(!row) return fail(env,"fixture_unknown_token");NSView* root=row.root;NSView* widget=row.widget;
  return reply(env,@{@"weakRootAlive":@(root!=nil),@"weakWidgetAlive":@(widget!=nil),@"attached":@(root&&root.superview!=nil),
    @"firstResponder":@(widget&&widget.window.firstResponder==widget),@"cachedButton":@(row.button!=nil),@"cachedHandler":@(row.action!=nil)});
}
// Drop only clients retained by this testing fixture; weak page witnesses remain.
static napi_value releaseClients(napi_env env,napi_callback_info info) {
  napi_value value;if(!args(env,info,1,&value)) return nullptr;NSString* token=string(env,value);
  if(!token||!routes[token]) return fail(env,"fixture_unknown_token");
  QualificationRoutes* row=routes[token];row.button=nil;row.field=nil;row.action=nil;
  return reply(env,@{@"token":token,@"fixtureClientsReleased":@YES});
}
static napi_value invoke(napi_env env,napi_callback_info info) {
  napi_value values[2];if(!args(env,info,2,values)) return nullptr;QualificationRoutes* row=routes[string(env,values[0])];NSString* route=string(env,values[1]);
  if(!row||!route) return fail(env,"fixture_unknown_token_or_route");
  @try {
    NSView* widget=row.widget;BOOL result=YES;
    if([route isEqualToString:@"press"]) { if(!row.button) return fail(env,"fixture_missing_button");result=((BOOL(*)(id,SEL))objc_msgSend)(row.button,@selector(accessibilityPerformPress)); }
    else if([route isEqualToString:@"custom"]) { if(!row.action) return fail(env,"fixture_missing_handler");result=row.action(); }
    else {
      if(!widget) return fail(env,"fixture_weak_widget_gone");
      if([route isEqualToString:@"text"]) ((void(*)(id,SEL,id,NSRange))objc_msgSend)(widget,@selector(insertText:replacementRange:),@"N",NSMakeRange(NSNotFound,0));
      else if([route isEqualToString:@"mark"]) ((void(*)(id,SEL,id,NSRange,NSRange))objc_msgSend)(widget,@selector(setMarkedText:selectedRange:replacementRange:),@"M",NSMakeRange(1,0),NSMakeRange(NSNotFound,0));
      else if([route isEqualToString:@"unmark"]) ((void(*)(id,SEL))objc_msgSend)(widget,@selector(unmarkText));
      else if([route isEqualToString:@"delete"]) ((void(*)(id,SEL,SEL))objc_msgSend)(widget,@selector(doCommandBySelector:),@selector(deleteBackward:));
      else if([route isEqualToString:@"directDelete"]) ((void(*)(id,SEL,id))objc_msgSend)(widget,@selector(deleteBackward:),nil);
      else if([route isEqualToString:@"selectAll"]) ((void(*)(id,SEL,id))objc_msgSend)(widget,@selector(selectAll:),nil);
      else if([route isEqualToString:@"focus"]) result=[widget.window makeFirstResponder:widget];
      else if([route isEqualToString:@"resignFocus"]) result=[widget.window makeFirstResponder:nil];
      else return fail(env,"fixture_unknown_route");
    }
    return reply(env,@{@"route":route,@"returned":@(result)});
  } @catch(NSException*) { return fail(env,"fixture_callback_exception"); }
}
static napi_value descriptor(napi_env env,napi_callback_info info) {
  napi_value value;int32_t fd=0;if(!args(env,info,1,&value)||napi_get_value_int32(env,value,&fd)!=napi_ok||fd<3) return fail(env,"fixture_descriptor_argument");
  struct stat st{};int flags=fcntl(fd,F_GETFL);if(flags<0||fstat(fd,&st)) return fail(env,"fixture_descriptor_unavailable");
  NSMutableDictionary* record=[@{@"fd":@(fd),@"device":[NSString stringWithFormat:@"%llu",(uint64_t)st.st_dev],@"inode":[NSString stringWithFormat:@"%llu",st.st_ino],
    @"uid":@(st.st_uid),@"mode":@(st.st_mode&07777),@"links":@(st.st_nlink),@"accessMode":@(flags&O_ACCMODE),@"size":@(st.st_size)} mutableCopy];
  // pread observes the actual anonymous capsule without changing shared offset.
  if(S_ISREG(st.st_mode)&&st.st_nlink==0&&(flags&O_ACCMODE)==O_RDONLY&&st.st_size>0&&st.st_size<=16384) {
    NSMutableData* bytes=[NSMutableData dataWithLength:(NSUInteger)st.st_size];
    if(pread(fd,bytes.mutableBytes,bytes.length,0)!=(ssize_t)bytes.length) return fail(env,"fixture_capsule_read");
    id capsule=[NSJSONSerialization JSONObjectWithData:bytes options:0 error:nil];if(![capsule isKindOfClass:NSDictionary.class]) return fail(env,"fixture_capsule_shape");record[@"capsule"]=capsule;
  }
  return reply(env,record);
}
static napi_value block(napi_env env,napi_callback_info info) {
  napi_value value;int32_t ms=0;if(!args(env,info,1,&value)||napi_get_value_int32(env,value,&ms)!=napi_ok||ms<1||ms>8000) return fail(env,"fixture_block_bound");
  [NSThread sleepForTimeInterval:(double)ms/1000.0];return reply(env,@{@"returnedAfterMs":@(ms)});
}
static NSString* imagePath(IMP implementation) {
  Dl_info image{};
  return implementation && dladdr((void*)implementation,&image) && image.dli_fname ? @(image.dli_fname) : nil;
}
static Method declaredResolver() {
  Method declared=nullptr;
  unsigned count=0;
  Method* methods=class_copyMethodList(NSString.class,&count);
  for(unsigned index=0;index<count;++index) {
    if(method_getName(methods[index])==@selector(stringByResolvingSymlinksInPath)) { declared=methods[index];break; }
  }
  free(methods);
  return declared;
}
static NSDictionary* resolverReceivers(Method declared) {
  SEL resolver=method_getName(declared);
  IMP original=method_getImplementation(declared);
  NSMutableDictionary* observations=[NSMutableDictionary new];
  for(NSString* name in @[@"NSWindow",@"BrowserAccessibilityCocoa"]) {
    Class cls=objc_getClass(name.UTF8String);
    SEL selector=[name isEqualToString:@"NSWindow"] ? @selector(makeFirstResponder:) : @selector(accessibilityPerformPress);
    Method method=cls ? class_getInstanceMethod(cls,selector) : nullptr;
    NSString* path=method ? imagePath(method_getImplementation(method)) : nil;
    if(!path) return nil;
    Class concrete=object_getClass(path);
    Method resolved=class_getInstanceMethod(concrete,resolver);
    IMP implementation=resolved ? method_getImplementation(resolved) : nullptr;
    observations[name]=@{ @"providerPath":path,@"receiverClass":NSStringFromClass(concrete),
      @"sameMethod":@(resolved==declared),@"sameImplementation":@(implementation==original),
      @"resolverImage":imagePath(implementation) ?: @"<unknown>" };
  }
  return observations;
}
static napi_value resolverDispatch(napi_env env,napi_callback_info info) {
  if(!args(env,info,0,nullptr)) return nullptr;
  Method declared=declaredResolver();
  if(!declared) return fail(env,"fixture_resolver_not_declared");
  IMP original=method_getImplementation(declared);
  NSDictionary* observations=resolverReceivers(declared);
  if(!observations) return fail(env,"fixture_provider_image_unavailable");
  return reply(env,@{ @"declaredEncoding":@(method_getTypeEncoding(declared)),@"declaredImage":imagePath(original) ?: @"<unknown>",
    @"receivers":observations });
}
static napi_value auditMethods(napi_env env,napi_callback_info info) {
  napi_value argument;
  if(!args(env,info,1,&argument)) return nullptr;
  uint32_t count=0;
  if(napi_get_array_length(env,argument,&count)!=napi_ok||!count||count>256) return fail(env,"fixture_inventory_bound");
  NSMutableDictionary* result=[NSMutableDictionary new];
  for(uint32_t index=0;index<count;++index) {
    napi_value value;
    if(napi_get_element(env,argument,index,&value)!=napi_ok) return fail(env,"fixture_inventory_key");
    NSString* key=string(env,value);
    NSArray<NSString*>* parts=[key componentsSeparatedByString:@"#"];
    if(parts.count!=2||!parts[0].length||!parts[1].length||result[key]) return fail(env,"fixture_inventory_key");
    Class cls=objc_getClass(parts[0].UTF8String);
    Method method=cls ? class_getInstanceMethod(cls,sel_registerName(parts[1].UTF8String)) : nullptr;
    if(!method) { result[key]=@"<absent>";continue; }
    IMP implementation=method_getImplementation(method);
    result[key]=@{ @"implementation":[NSString stringWithFormat:@"%p",(void*)implementation],
      @"encoding":@(method_getTypeEncoding(method)),@"image":imagePath(implementation) ?: @"<unknown>" };
  }
  return reply(env,result);
}
static std::atomic<IMP> resolverOriginal{nullptr};
static Method controlledResolver;
static char ownershipImage[PATH_MAX], providerPaths[2][PATH_MAX];
static unsigned resolverCalls[2];
static bool resolverActive;
static thread_local bool resolving;
static id observeResolver(id receiver, SEL selector) {
  auto original=reinterpret_cast<id(*)(id,SEL)>(resolverOriginal.load(std::memory_order_acquire));
  if(!pthread_main_np()||!resolverActive||resolving) return original(receiver,selector);
  resolving=true;
  @try {
    Dl_info caller{};
    char receiverPath[PATH_MAX];
    if(dladdr(__builtin_return_address(0),&caller)&&caller.dli_fname&&!strcmp(caller.dli_fname,ownershipImage)&&
        CFStringGetCString((__bridge CFStringRef)receiver,receiverPath,sizeof(receiverPath),kCFStringEncodingUTF8)) {
      for(unsigned index=0;index<2;++index) if(!strcmp(receiverPath,providerPaths[index])) ++resolverCalls[index];
    }
    return original(receiver,selector);
  } @finally { resolving=false; }
}
static napi_value startResolverControl(napi_env env,napi_callback_info info) {
  napi_value argument;
  if(!args(env,info,1,&argument)) return nullptr;
  size_t length=0;
  if(resolverOriginal.load()||napi_get_value_string_utf8(env,argument,ownershipImage,sizeof(ownershipImage),&length)!=napi_ok||
      !length||length>=sizeof(ownershipImage)-1||ownershipImage[0]!='/') return fail(env,"fixture_resolver_context");
  Method declared=declaredResolver();
  if(!declared||strcmp(method_getTypeEncoding(declared),"@16@0:8")) return fail(env,"fixture_resolver_abi");
  IMP original=method_getImplementation(declared);
  if(![imagePath(original) isEqualToString:@"/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation"])
    return fail(env,"fixture_resolver_provider");
  NSDictionary* observations=resolverReceivers(declared);
  if(!observations) return fail(env,"fixture_resolver_provider_paths");
  unsigned index=0;
  for(NSString* name in @[@"NSWindow",@"BrowserAccessibilityCocoa"]) {
    NSDictionary* row=observations[name];
    NSString* path=row[@"providerPath"];
    if(![row[@"sameMethod"] boolValue]||![row[@"sameImplementation"] boolValue]||
        ![path getCString:providerPaths[index] maxLength:sizeof(providerPaths[index]) encoding:NSUTF8StringEncoding])
      return fail(env,"fixture_resolver_dispatch_unavailable");
    ++index;
  }
  controlledResolver=declared;
  resolverOriginal.store(original,std::memory_order_release);
  resolverActive=true;
  IMP control=(IMP)&observeResolver;
  if(method_setImplementation(declared,control)!=original||method_getImplementation(declared)!=control)
    return fail(env,"fixture_resolver_control_unconfirmed");
  return reply(env,@{ @"active":@YES });
}
static napi_value resolverControlObservation(napi_env env,napi_callback_info info) {
  if(!args(env,info,0,nullptr)) return nullptr;
  return reply(env,@{ @"appKit":@(resolverCalls[0]),@"electron":@(resolverCalls[1]) });
}
static napi_value stopResolverControl(napi_env env,napi_callback_info info) {
  if(!args(env,info,0,nullptr)) return nullptr;
  IMP control=(IMP)&observeResolver;
  if(!resolverActive||method_getImplementation(controlledResolver)!=control) return fail(env,"fixture_resolver_control_unconfirmed");
  resolverActive=false;
  IMP original=resolverOriginal.load();
  if(method_setImplementation(controlledResolver,original)!=control||method_getImplementation(controlledResolver)!=original)
    return fail(env,"fixture_resolver_restore_unconfirmed");
  return resolverControlObservation(env,info);
}
NAPI_MODULE_INIT() {
  if(![NSThread isMainThread]) return fail(env,"fixture_main_thread_only");
  napi_property_descriptor exportsList[]={
    {"capture",nullptr,capture,nullptr,nullptr,nullptr,napi_default,nullptr},{"state",nullptr,state,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"invoke",nullptr,invoke,nullptr,nullptr,nullptr,napi_default,nullptr},{"descriptor",nullptr,descriptor,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"block",nullptr,block,nullptr,nullptr,nullptr,napi_default,nullptr},{"releaseClients",nullptr,releaseClients,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"resolverDispatch",nullptr,resolverDispatch,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"auditMethods",nullptr,auditMethods,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"startResolverControl",nullptr,startResolverControl,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"resolverControlObservation",nullptr,resolverControlObservation,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"stopResolverControl",nullptr,stopResolverControl,nullptr,nullptr,nullptr,napi_default,nullptr}};
  if(napi_define_properties(env,exports,sizeof(exportsList)/sizeof(exportsList[0]),exportsList)!=napi_ok) return nullptr;return exports;
}

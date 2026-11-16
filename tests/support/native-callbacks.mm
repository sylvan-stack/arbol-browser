// Testing-only callback bridge, independently compiled/signed outside the app.
// The pass-through control observes one Foundation resolver in its own process.
#import <Cocoa/Cocoa.h>
#import <objc/message.h>
#include <node_api.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <atomic>
#include <cstring>
#include <pthread.h>
#include <set>
#include <thread>
@interface QualificationRoutes : NSObject
@property(nonatomic,weak) NSView* root;
@property(nonatomic,weak) NSView* widget;
@property(nonatomic,strong) id button;
@property(nonatomic,strong) id field;
@property(nonatomic,copy) BOOL (^action)(void);
@end
@implementation QualificationRoutes
@end
@interface QualificationAXParent : NSObject
@property(nonatomic,strong) id client;
@property(nonatomic) NSUInteger nestedCalls;
@property(nonatomic) BOOL nestedResult;
@end
@implementation QualificationAXParent
- (id)accessibilityParent {
  ++_nestedCalls;
  _nestedResult=((BOOL(*)(id,SEL))objc_msgSend)(_client,@selector(accessibilityPerformPress));
  return nil;
}
@end
// Supplies only fictional data to the native destination callbacks.
// This is a destination probe, with no OS drag source session.
@interface QualificationDrop : NSObject<NSDraggingInfo>
@property(nonatomic,weak) NSWindow* draggingDestinationWindow;
@property(nonatomic,strong) NSPasteboard* draggingPasteboard;
@property(nonatomic) NSPoint draggingLocation;
@property NSDraggingFormation draggingFormation;
@property BOOL animatesToDestination;
@property NSInteger numberOfValidItemsForDrop;
@end
@implementation QualificationDrop
- (NSDragOperation)draggingSourceOperationMask { return NSDragOperationCopy; }
- (NSPoint)draggedImageLocation { return self.draggingLocation; }
- (NSImage*)draggedImage { return nil; }
- (id)draggingSource { return nil; }
- (NSInteger)draggingSequenceNumber { return 1; }
- (void)slideDraggedImageTo:(NSPoint)point { (void)point; }
- (NSArray<NSString*>*)namesOfPromisedFilesDroppedAtDestination:(NSURL*)destination { (void)destination; return nil; }
- (void)enumerateDraggingItemsWithOptions:(NSDraggingItemEnumerationOptions)options forView:(NSView*)view
  classes:(NSArray<Class>*)classes searchOptions:(NSDictionary<NSPasteboardReadingOptionKey,id>*)searchOptions
  usingBlock:(void (^)(NSDraggingItem*,NSInteger,BOOL*))block {
  (void)options; (void)view; (void)classes; (void)searchOptions; (void)block;
}
- (NSSpringLoadingHighlight)springLoadingHighlight { return NSSpringLoadingHighlightNone; }
- (void)resetSpringLoading {}
@end
static NSMutableDictionary<NSString*,QualificationRoutes*>* routes;
static QualificationDrop* destinationDrag;
static __weak NSView* dragRoot;
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
static NSWindow* findWindow(napi_env env,napi_value value) {
  bool buffer=false;void* bytes=nullptr;size_t size=0;
  if(napi_is_buffer(env,value,&buffer)!=napi_ok||!buffer||napi_get_buffer_info(env,value,&bytes,&size)!=napi_ok||size!=sizeof(void*)) return nil;
  void* pointer=nullptr;std::memcpy(&pointer,bytes,size);NSWindow* window=nil;
  for(NSWindow* candidate in NSApp.windows) if((__bridge void*)candidate.contentView==pointer) {
    if(window) return nil;
    window=candidate;
  }
  return window;
}
static napi_value windowPages(napi_env env,napi_callback_info info) {
  napi_value value;if(!args(env,info,1,&value)) return nullptr;
  NSWindow* window=findWindow(env,value);
  if(!window) return fail(env,"fixture_unknown_window");
  NSMutableArray* roots=[NSMutableArray new];views(window.contentView,@"WebContentsViewCocoa",roots);
  NSMutableArray* identities=[NSMutableArray new];
  for(NSView* root in roots) [identities addObject:[NSString stringWithFormat:@"%p",root]];
  return reply(env,identities);
}
static napi_value capturePage(napi_env env,napi_value handle,NSString* identity) {
  @try {
    NSWindow* window=findWindow(env,handle);
    if(!window) return fail(env,"fixture_unknown_window");
    NSMutableArray* roots=[NSMutableArray new];views(window.contentView,@"WebContentsViewCocoa",roots);
    if(identity) {
      NSIndexSet* other=[roots indexesOfObjectsPassingTest:^BOOL(NSView* root, NSUInteger, BOOL*) {
        return ![[NSString stringWithFormat:@"%p",root] isEqualToString:identity];
      }];
      [roots removeObjectsAtIndexes:other];
    }
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
      @"buttonIdentity":[NSString stringWithFormat:@"%p",row.button],
      @"axNodes":@(elements.count),@"button":@(row.button!=nil),@"field":@(row.field!=nil),@"cachedHandler":@(row.action!=nil)});
  } @catch(NSException*) { return fail(env,"fixture_capture_exception"); }
}
static napi_value capture(napi_env env,napi_callback_info info) {
  napi_value value;if(!args(env,info,1,&value)) return nullptr;
  return capturePage(env,value,nil);
}
static napi_value captureRoot(napi_env env,napi_callback_info info) {
  napi_value values[2];if(!args(env,info,2,values)) return nullptr;
  NSString* identity=string(env,values[1]);
  if(!identity) return fail(env,"fixture_root_identity_required");
  return capturePage(env,values[0],identity);
}
static napi_value state(napi_env env,napi_callback_info info) {
  napi_value value;if(!args(env,info,1,&value)) return nullptr;QualificationRoutes* row=routes[string(env,value)];
  if(!row) return fail(env,"fixture_unknown_token");NSView* root=row.root;NSView* widget=row.widget;
  return reply(env,@{@"weakRootAlive":@(root!=nil),@"weakWidgetAlive":@(widget!=nil),@"attached":@(root&&root.superview!=nil),
    @"rootHidden":@(root&&[root isHiddenOrHasHiddenAncestor]),@"widgetHidden":@(widget&&[widget isHiddenOrHasHiddenAncestor]),
    @"windowVisible":@(widget.window.isVisible),@"windowKey":@(widget.window.isKeyWindow),
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
    else if([route isEqualToString:@"axValue"]) {
      if(!row.field||![row.field respondsToSelector:@selector(setAccessibilityValue:)]) return fail(env,"fixture_missing_ax_value");
      ((void(*)(id,SEL,id))objc_msgSend)(row.field,@selector(setAccessibilityValue:),@"AX fixture edit");
    }
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
// Deliver only closed, fictional events to the fixture window through AppKit.
// Keyboard delivery uses the current responder, so an unintended focus change
// cannot be concealed by addressing the expected widget directly.
static napi_value windowInput(napi_env env,napi_callback_info info) {
  napi_value values[2];if(!args(env,info,2,values)) return nullptr;
  QualificationRoutes* row=routes[string(env,values[0])];
  NSString* action=string(env,values[1]);
  NSView* widget=row.widget;
  NSWindow* window=widget.window;
  if(!window.isKeyWindow||!window.isVisible||[widget isHiddenOrHasHiddenAncestor]) return fail(env,"fixture_input_window_unavailable");
  @try {
    NSResponder* before=window.firstResponder;
    if([action isEqualToString:@"b"]||[action isEqualToString:@"z"]) {
      unsigned short code=[action isEqualToString:@"b"] ? 11 : 6;
      for(NSEventType type : {NSEventTypeKeyDown,NSEventTypeKeyUp}) {
        NSEvent* ev=[NSEvent keyEventWithType:type location:NSZeroPoint modifierFlags:0 timestamp:NSProcessInfo.processInfo.systemUptime
          windowNumber:window.windowNumber context:nil characters:action charactersIgnoringModifiers:action isARepeat:NO keyCode:code];
        if(!ev) return fail(env,"fixture_key_event_unavailable");
        [window sendEvent:ev];
      }
    } else if([action isEqualToString:@"down"]||[action isEqualToString:@"up"]) {
      NSEventType type=[action isEqualToString:@"down"] ? NSEventTypeLeftMouseDown : NSEventTypeLeftMouseUp;
      NSPoint local=NSMakePoint(24,widget.isFlipped ? 110 : NSHeight(widget.bounds)-110);
      NSEvent* ev=[NSEvent mouseEventWithType:type location:[widget convertPoint:local toView:nil] modifierFlags:0
        timestamp:NSProcessInfo.processInfo.systemUptime windowNumber:window.windowNumber context:nil eventNumber:0 clickCount:1
        pressure:type==NSEventTypeLeftMouseDown ? 1.0 : 0.0];
      if(!ev) return fail(env,"fixture_pointer_event_unavailable");
      [window sendEvent:ev];
    } else return fail(env,"fixture_unknown_input");
    return reply(env,@{@"action":action,@"windowNumber":@(window.windowNumber),@"firstResponderBefore":@(before==widget),
      @"firstResponderAfter":@(window.firstResponder==widget)});
  } @catch(NSException*) { return fail(env,"fixture_window_input_exception"); }
}
static napi_value destinationInput(napi_env env,napi_callback_info info) {
  napi_value values[2];if(!args(env,info,2,values)) return nullptr;
  NSView* root=routes[string(env,values[0])].root;
  NSString* action=string(env,values[1]);
  if(!root.window.isKeyWindow||[root isHiddenOrHasHiddenAncestor]) return fail(env,"fixture_drop_window_unavailable");
  @try {
    if([action isEqualToString:@"enter"] && !destinationDrag) {
      QualificationDrop* drag=[QualificationDrop new];
      drag.draggingDestinationWindow=root.window;
      drag.draggingLocation=[root convertPoint:NSMakePoint(24,root.isFlipped ? 180 : NSHeight(root.bounds)-180) toView:nil];
      drag.draggingPasteboard=[NSPasteboard pasteboardWithUniqueName];
      [drag.draggingPasteboard declareTypes:@[NSPasteboardTypeString] owner:nil];
      if(![drag.draggingPasteboard setString:@"fixture drag" forType:NSPasteboardTypeString]) {
        [drag.draggingPasteboard releaseGlobally];
        return fail(env,"fixture_drag_pasteboard_unavailable");
      }
      destinationDrag=drag; dragRoot=root;
      NSDragOperation operation=((NSDragOperation(*)(id,SEL,id))objc_msgSend)(root,@selector(draggingEntered:),drag);
      return reply(env,@{@"action":action,@"operation":@(operation)});
    }
    if([action isEqualToString:@"exit"] && destinationDrag && dragRoot==root) {
      ((void(*)(id,SEL,id))objc_msgSend)(root,@selector(draggingExited:),destinationDrag);
      [destinationDrag.draggingPasteboard releaseGlobally];
      destinationDrag=nil; dragRoot=nil;
      return reply(env,@{@"action":action});
    }
    return fail(env,"fixture_destination_drag_sequence");
  } @catch(NSException*) { return fail(env,"fixture_destination_drag_exception"); }
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
static napi_value monotonicNanos(napi_env env,napi_callback_info info) {
  if(!args(env,info,0,nullptr)) return nullptr;
  return reply(env,@{@"nanos":[NSString stringWithFormat:@"%llu",clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)]});
}
static NSString* imagePath(IMP implementation) {
  Dl_info image{};
  return implementation && dladdr((void*)implementation,&image) && image.dli_fname ? @(image.dli_fname) : nil;
}
static napi_value invokePressContext(napi_env env,napi_callback_info info) {
  napi_value values[2];if(!args(env,info,2,values)) return nullptr;
  id client=routes[string(env,values[0])].button;
  NSString* context=string(env,values[1]);
  if(!client||!context) return fail(env,"fixture_missing_button_or_context");
  SEL selector=@selector(accessibilityPerformPress);
  Method method=class_getInstanceMethod(object_getClass(client),selector);
  IMP implementation=method ? method_getImplementation(method) : nullptr;
  NSString* image=imagePath(implementation);
  if(![image.lastPathComponent isEqualToString:@"ownership.node"]) return fail(env,"fixture_expected_native_guard");
  auto press=reinterpret_cast<BOOL(*)(id,SEL)>(implementation);
  if([context isEqualToString:@"off-main"]) {
    BOOL mainThread=YES,result=YES,threw=NO;
    std::thread worker([&] {
      @autoreleasepool {
        mainThread=pthread_main_np()!=0;
        @try { result=press(client,selector); } @catch(NSException*) { threw=YES; }
      }
    });
    worker.join();
    return reply(env,@{ @"context":context,@"image":image,@"mainThread":@(mainThread),@"returned":@(result),@"threw":@(threw) });
  }
  if([context isEqualToString:@"unknown"]) {
    BOOL result=press([NSObject new],selector);
    return reply(env,@{ @"context":context,@"image":image,@"returned":@(result) });
  }
  if([context isEqualToString:@"reentrant"]) {
    // Owner resolution calls accessibilityParent inside the actual guard's
    // callback scope. The probe has no owner and can only reenter this client.
    QualificationAXParent* parent=[QualificationAXParent new];parent.client=client;
    BOOL result=press(parent,selector);
    return reply(env,@{ @"context":context,@"image":image,@"returned":@(result),
      @"nestedCalls":@(parent.nestedCalls),@"nestedResult":@(parent.nestedResult) });
  }
  return fail(env,"fixture_unknown_press_context");
}
static Method declaredMethod(Class cls,SEL selector) {
  Method declared=nullptr;
  unsigned count=0;
  Method* methods=class_copyMethodList(cls,&count);
  for(unsigned index=0;index<count;++index) {
    if(method_getName(methods[index])==selector) { declared=methods[index];break; }
  }
  free(methods);
  return declared;
}
static Method declaredResolver() {
  return declaredMethod(NSString.class,@selector(stringByResolvingSymlinksInPath));
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

enum class PoisonScenario { None, Restored, Unconfirmed };
static PoisonScenario poisonScenario=PoisonScenario::None;
struct MethodWitness {
  const char* selector;
  const char* encoding;
  SEL target;
  IMP original;
};
static MethodWitness witnesses[]={
  {"accessibilityCustomActions","@16@0:8",nullptr,nullptr},
  {"accessibilityPerformAction:","v24@0:8@16",nullptr,nullptr},
  {"accessibilityPerformDecrement","B16@0:8",nullptr,nullptr},
  {"accessibilityPerformIncrement","B16@0:8",nullptr,nullptr},
  {"accessibilityPerformPress","B16@0:8",nullptr,nullptr}
};
static IMP commitBefore[5],commitAfter[5],rollbackBefore[5],rollbackAfter[5];
static Class witnessClass;
static Method observedDecrementGuard;
static unsigned observedGuardMasks;
static bool driftApplied, confirmationFault, journalUncertain;

static BOOL fixturePress(id,SEL) { return NO; }
static bool fromImage(IMP implementation,const char* path) {
  Dl_info image{};
  return implementation&&dladdr((void*)implementation,&image)&&image.dli_fname&&!strcmp(image.dli_fname,path);
}
static Method liveWitness(unsigned index) {
  return class_getInstanceMethod(witnessClass,witnesses[index].target);
}
static void readWitnesses(IMP (&current)[5]) {
  for(unsigned index=0;index<5;++index) {
    Method method=liveWitness(index);
    current[index]=method ? method_getImplementation(method) : nullptr;
  }
}
static bool productGuard(unsigned index, IMP implementation) {
  return implementation!=witnesses[index].original&&fromImage(implementation,ownershipImage);
}
static bool observeInstallTransaction() {
  if(poisonScenario==PoisonScenario::None||journalUncertain||confirmationFault) return false;
  IMP current[5];readWitnesses(current);
  unsigned mask=0;
  for(unsigned index=0;index<5;++index) if(productGuard(index,current[index])) mask|=1u<<index;
  observedGuardMasks|=1u<<mask;
  if(!driftApplied&&mask==7&&
      current[3]==witnesses[3].original&&current[4]==witnesses[4].original) {
    std::memcpy(commitBefore,current,sizeof(current));
    observedDecrementGuard=liveWitness(2);
    IMP previous=method_setImplementation(liveWitness(4),(IMP)&fixturePress);
    readWitnesses(commitAfter);
    driftApplied=commitAfter[4]==(IMP)&fixturePress;
    journalUncertain=!driftApplied||previous!=witnesses[4].original;
  } else if(driftApplied&&poisonScenario==PoisonScenario::Unconfirmed&&current[0]==commitBefore[0]&&current[1]==commitBefore[1]&&
      current[2]==witnesses[2].original&&current[3]==witnesses[3].original&&current[4]==(IMP)&fixturePress&&liveWitness(2)==observedDecrementGuard) {
    std::memcpy(rollbackBefore,current,sizeof(current));
    IMP previous=method_setImplementation(liveWitness(2),commitBefore[2]);
    readWitnesses(rollbackAfter);
    confirmationFault=previous==witnesses[2].original&&rollbackAfter[2]==commitBefore[2];
    journalUncertain=!confirmationFault;
    return confirmationFault;
  }
  return false;
}
static id observeResolver(id receiver, SEL selector) {
  auto original=reinterpret_cast<id(*)(id,SEL)>(resolverOriginal.load(std::memory_order_acquire));
  if(!pthread_main_np()||!resolverActive||resolving) return original(receiver,selector);
  resolving=true;
  @try {
    Dl_info caller{};
    char receiverPath[PATH_MAX];
    bool rejectConfirmation=false;
    if(dladdr(__builtin_return_address(0),&caller)&&caller.dli_fname&&!strcmp(caller.dli_fname,ownershipImage)&&
        CFStringGetCString((__bridge CFStringRef)receiver,receiverPath,sizeof(receiverPath),kCFStringEncodingUTF8)) {
      for(unsigned index=0;index<2;++index) if(!strcmp(receiverPath,providerPaths[index])) ++resolverCalls[index];
      if(!strcmp(receiverPath,providerPaths[1])) rejectConfirmation=observeInstallTransaction();
    }
    id path=original(receiver,selector);
    return rejectConfirmation ? @"/arbol-browser-qualification/invalid-provider" : path;
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
static napi_value armInstallPoison(napi_env env,napi_callback_info info) {
  napi_value argument;
  if(!args(env,info,1,&argument)) return nullptr;
  NSString* scenario=string(env,argument);
  if(!resolverActive||poisonScenario!=PoisonScenario::None) return fail(env,"fixture_poison_state");
  const bool unconfirmed=[scenario isEqualToString:@"rollback-unconfirmed"];
  if(!unconfirmed&&![scenario isEqualToString:@"rollback-confirmed"]) return fail(env,"fixture_poison_scenario");
  witnessClass=objc_getClass("BrowserAccessibilityCocoa");
  if(!witnessClass) return fail(env,"fixture_poison_class");
  for(auto& witness:witnesses) {
    witness.target=sel_registerName(witness.selector);
    Method method=class_getInstanceMethod(witnessClass,witness.target);
    if(!method||strcmp(method_getTypeEncoding(method),witness.encoding)) return fail(env,"fixture_poison_abi");
    witness.original=method_getImplementation(method);
    if(!fromImage(witness.original,providerPaths[1])) return fail(env,"fixture_poison_provider");
  }
  if(declaredMethod(witnessClass,witnesses[4].target)!=liveWitness(4)) return fail(env,"fixture_poison_press_not_declared");
  poisonScenario=unconfirmed ? PoisonScenario::Unconfirmed : PoisonScenario::Restored;
  return reply(env,@{ @"armed":@YES });
}
static NSArray* witnessSnapshot(const IMP (&snapshot)[5]) {
  NSMutableArray* result=[NSMutableArray new];
  for(IMP implementation:snapshot) [result addObject:[NSString stringWithFormat:@"%p",(void*)implementation]];
  return result;
}
static napi_value finishInstallPoison(napi_env env,napi_callback_info info) {
  if(!args(env,info,0,nullptr)) return nullptr;
  if(resolverActive||poisonScenario==PoisonScenario::None) return fail(env,"fixture_poison_state");
  bool externalRestored=!driftApplied;
  Method press=liveWitness(4);
  if(driftApplied&&press&&method_getImplementation(press)==(IMP)&fixturePress) {
    IMP previous=method_setImplementation(press,witnesses[4].original);
    externalRestored=previous==(IMP)&fixturePress&&method_getImplementation(press)==witnesses[4].original;
  }
  return reply(env,@{ @"driftApplied":@(driftApplied),@"confirmationFault":@(confirmationFault),
    @"uncertain":@(journalUncertain),@"externalRestored":@(externalRestored),@"observedGuardMasks":@(observedGuardMasks),
    @"appKitCalls":@(resolverCalls[0]),@"electronCalls":@(resolverCalls[1]),
    @"commitBefore":witnessSnapshot(commitBefore),@"commitAfter":witnessSnapshot(commitAfter),
    @"rollbackBefore":witnessSnapshot(rollbackBefore),@"rollbackAfter":witnessSnapshot(rollbackAfter) });
}
NAPI_MODULE_INIT() {
  if(![NSThread isMainThread]) return fail(env,"fixture_main_thread_only");
  napi_property_descriptor exportsList[]={
    {"capture",nullptr,capture,nullptr,nullptr,nullptr,napi_default,nullptr},{"state",nullptr,state,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"invoke",nullptr,invoke,nullptr,nullptr,nullptr,napi_default,nullptr},{"descriptor",nullptr,descriptor,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"block",nullptr,block,nullptr,nullptr,nullptr,napi_default,nullptr},{"releaseClients",nullptr,releaseClients,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"monotonicNanos",nullptr,monotonicNanos,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"resolverDispatch",nullptr,resolverDispatch,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"auditMethods",nullptr,auditMethods,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"startResolverControl",nullptr,startResolverControl,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"resolverControlObservation",nullptr,resolverControlObservation,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"stopResolverControl",nullptr,stopResolverControl,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"armInstallPoison",nullptr,armInstallPoison,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"finishInstallPoison",nullptr,finishInstallPoison,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"windowPages",nullptr,windowPages,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"invokePressContext",nullptr,invokePressContext,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"captureRoot",nullptr,captureRoot,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"destinationInput",nullptr,destinationInput,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"windowInput",nullptr,windowInput,nullptr,nullptr,nullptr,napi_default,nullptr}};
  if(napi_define_properties(env,exports,sizeof(exportsList)/sizeof(exportsList[0]),exportsList)!=napi_ok) return nullptr;return exports;
}

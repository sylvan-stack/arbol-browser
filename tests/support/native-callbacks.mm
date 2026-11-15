// Testing-only callback bridge, independently compiled/signed outside the app.
// It neither links production boundary code nor installs/replaces any method.
#import <Cocoa/Cocoa.h>
#import <objc/message.h>
#include <node_api.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
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
NAPI_MODULE_INIT() {
  if(![NSThread isMainThread]) return fail(env,"fixture_main_thread_only");
  napi_property_descriptor exportsList[]={
    {"capture",nullptr,capture,nullptr,nullptr,nullptr,napi_default,nullptr},{"state",nullptr,state,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"invoke",nullptr,invoke,nullptr,nullptr,nullptr,napi_default,nullptr},{"descriptor",nullptr,descriptor,nullptr,nullptr,nullptr,napi_default,nullptr},
    {"block",nullptr,block,nullptr,nullptr,nullptr,napi_default,nullptr}};
  if(napi_define_properties(env,exports,sizeof(exportsList)/sizeof(exportsList[0]),exportsList)!=napi_ok) return nullptr;return exports;
}

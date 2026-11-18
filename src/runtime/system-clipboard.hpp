#pragma once
#import <AppKit/NSPasteboard.h>
#import <AppKit/NSApplication.h>
#import <CommonCrypto/CommonDigest.h>
#include <objc/runtime.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <atomic>
#include <mutex>
#include <thread>
#include <vector>
#include <string>
#include <array>
#include <cstring>
#include <algorithm>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

// Exact accepted BRW-D36 producer. No content, type, filename or item lookup.
// Objects, originals and the guard itself live until this process exits.
namespace arbol_clipboard {
static constexpr const char* appkitPath="/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit";
static constexpr std::array<unsigned char,16> appkitUUID={0x3b,0x92,0x00,0x39,0x6c,0xc0,0x34,0xe8,0x85,0x98,0xdd,0x01,0x39,0x65,0xbc,0xac};
static constexpr std::array<unsigned char,16> frameworkUUID={0x4c,0x4c,0x44,0x35,0x55,0x55,0x31,0x44,0xa1,0xab,0x10,0x79,0xe5,0xcf,0x28,0x1e};
static constexpr off_t signedCodeEnd=205923376;
static constexpr const char* stockCodeDigest="31d2f1c6ae224fdeacb118cc965fb7430aad360ed277e44a7e51619ba5aea602";

inline bool sameFile(const struct stat& a,const struct stat& b) {
  return S_ISREG(a.st_mode)&&S_ISREG(b.st_mode)&&a.st_dev==b.st_dev&&a.st_ino==b.st_ino&&a.st_uid==b.st_uid&&
    a.st_mode==b.st_mode&&a.st_nlink==1&&b.st_nlink==1&&a.st_size==b.st_size&&
    a.st_mtimespec.tv_sec==b.st_mtimespec.tv_sec&&a.st_mtimespec.tv_nsec==b.st_mtimespec.tv_nsec&&
    a.st_ctimespec.tv_sec==b.st_ctimespec.tv_sec&&a.st_ctimespec.tv_nsec==b.st_ctimespec.tv_nsec;
}
inline bool imageUUID(const void* address,const std::array<unsigned char,16>& expected) {
  const auto* header=static_cast<const mach_header_64*>(address);
  if(!header||header->magic!=MH_MAGIC_64||header->cputype!=CPU_TYPE_ARM64||header->ncmds>4096||header->sizeofcmds>1048576) return false;
  const char* begin=reinterpret_cast<const char*>(header)+sizeof(*header),*end=begin+header->sizeofcmds,*p=begin;
  bool found=false;
  for(uint32_t i=0;i<header->ncmds;++i) {
    if(p+sizeof(load_command)>end) return false; const auto* command=reinterpret_cast<const load_command*>(p);
    if(command->cmdsize<sizeof(*command)||command->cmdsize>static_cast<size_t>(end-p)) return false;
    if(command->cmd==LC_UUID) {
      if(found||command->cmdsize!=sizeof(uuid_command)||memcmp(reinterpret_cast<const uuid_command*>(p)->uuid,expected.data(),16)) return false;
      found=true;
    }
    p+=command->cmdsize;
  }
  return found&&p==end;
}
inline bool appkitImplementation(IMP imp) {
  Dl_info image{};
  return imp&&dladdr(reinterpret_cast<const void*>(imp),&image)&&image.dli_fname&&
    !strcmp(image.dli_fname,appkitPath)&&imageUUID(image.dli_fbase,appkitUUID);
}
inline const mach_header* frameworkLoaded(const std::string& path) {
  const mach_header* found=nullptr;
  for(uint32_t i=0;i<_dyld_image_count();++i) {
    const char* name=_dyld_get_image_name(i); char canonical[PATH_MAX]{};
    if(name&&realpath(name,canonical)&&path==canonical) {
      if(found||!imageUUID(_dyld_get_image_header(i),frameworkUUID)) return nullptr; found=_dyld_get_image_header(i);
    }
  }
  return found;
}

// Hash the entire pinned stock Mach-O except the signature blob, normalizing
// only LC_CODE_SIGNATURE and __LINKEDIT sizes changed by supported re-signing.
// Code, imports, Objective-C data and every other byte remain in the identity.
// A native worker does this finite read before any AppKit installation.
struct Source {
  std::string path; int fd=-1; struct stat identity{};
  const mach_header* loaded=nullptr; void* retainedImage=nullptr;
  std::atomic<int> result{0}; std::thread* worker=nullptr;
  explicit Source(std::string value):path(std::move(value)) {}
  bool pinLoaded() {
    loaded=frameworkLoaded(path); if(!loaded) return false;
    retainedImage=dlopen(path.c_str(),RTLD_NOW|RTLD_NOLOAD|RTLD_NODELETE);
    return retainedImage&&imageUUID(loaded,frameworkUUID);
  }
  bool loadedIntact() const { return retainedImage&&imageUUID(loaded,frameworkUUID); }
  bool unchanged() const {
    struct stat held{},named{};
    return fd>=3&&!fstat(fd,&held)&&!lstat(path.c_str(),&named)&&sameFile(identity,held)&&sameFile(held,named);
  }
  bool verifyStockCode(double deadline) {
    fd=open(path.c_str(),O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if(fd<3||fstat(fd,&identity)||!S_ISREG(identity.st_mode)||identity.st_uid!=geteuid()||identity.st_nlink!=1||
       identity.st_size<=signedCodeEnd||identity.st_size>268435456||!unchanged()) return false;
    alignas(mach_header_64) std::array<unsigned char,16384> header{};
    if(pread(fd,header.data(),header.size(),0)!=(ssize_t)header.size()) return false;
    const auto* mh=reinterpret_cast<const mach_header_64*>(header.data());
    if(mh->magic!=MH_MAGIC_64||mh->cputype!=CPU_TYPE_ARM64||mh->sizeofcmds>header.size()-sizeof(*mh)||
       !imageUUID(header.data(),frameworkUUID)) return false;
    size_t offset=sizeof(*mh); unsigned signatures=0,linkedit=0;
    for(uint32_t i=0;i<mh->ncmds;++i) {
      const auto* command=reinterpret_cast<const load_command*>(header.data()+offset);
      if(command->cmd==LC_CODE_SIGNATURE) {
        const auto* signature=reinterpret_cast<const linkedit_data_command*>(command);
        if(command->cmdsize!=sizeof(*signature)||signature->dataoff!=signedCodeEnd||
           (uint64_t)signature->dataoff+signature->datasize!=(uint64_t)identity.st_size||offset+8!=10600) return false;
        memset(header.data()+offset+8,0,8); ++signatures;
      }
      if(command->cmd==LC_SEGMENT_64) {
        const auto* segment=reinterpret_cast<const segment_command_64*>(command);
        if(command->cmdsize<sizeof(*segment)) return false;
        if(!strncmp(segment->segname,"__LINKEDIT",16)) {
          if(offset+32!=3712||offset+48!=3728) return false;
          memset(header.data()+offset+32,0,8); memset(header.data()+offset+48,0,8); ++linkedit;
        }
      }
      offset+=command->cmdsize;
    }
    if(signatures!=1||linkedit!=1) return false;
    CC_SHA256_CTX digest; if(CC_SHA256_Init(&digest)!=1) return false;
    if(CC_SHA256_Update(&digest,header.data(),(CC_LONG)header.size())!=1) return false;
    std::array<unsigned char,65536> buffer{}; off_t position=header.size();
    while(position<signedCodeEnd) {
      if(arbol_boundary::clockMs()>=deadline) return false;
      size_t count=std::min(buffer.size(),(size_t)(signedCodeEnd-position));
      ssize_t got=pread(fd,buffer.data(),count,position);
      if(got<0&&errno==EINTR) continue;
      if(got<=0||CC_SHA256_Update(&digest,buffer.data(),(CC_LONG)got)!=1) return false;
      position+=got;
    }
    unsigned char bytes[CC_SHA256_DIGEST_LENGTH]; if(CC_SHA256_Final(bytes,&digest)!=1) return false;
    char encoded[65]{}; for(unsigned i=0;i<sizeof(bytes);++i) snprintf(encoded+2*i,3,"%02x",bytes[i]);
    return !strcmp(encoded,stockCodeDigest)&&unchanged()&&arbol_boundary::clockMs()<deadline;
  }
  bool verify(double deadline) {
    return verifyStockCode(deadline)&&arbol_boundary::signature(path,false)&&
      unchanged()&&arbol_boundary::clockMs()<deadline;
  }
  void start(double deadline) {
    worker=new std::thread([this,deadline] {
      bool ok=false; @autoreleasepool { try { @try { ok=verify(deadline); } @catch(NSException*) {} } catch(...) {} }
      result.store(ok?1:-1,std::memory_order_release);
    });
  }
};

struct Entry {
  Class cls=nullptr; SEL selector=nullptr; Method method=nullptr; IMP original=nullptr,replacement=nullptr;
  std::string encoding; bool (*provider)(IMP)=appkitImplementation;
};
struct CatalogMethod { Method method; IMP original; std::string encoding; };
struct Catalog { Class cls; std::vector<CatalogMethod> methods; };
struct Guard;
struct SystemCatalogPolicy {
  unsigned classLimit;
  bool (*registerEntries)(Guard&);
};
struct Guard {
  std::recursive_mutex mutex; bool attempted=false,protected_=false,failed=false;
  Source* source=nullptr; void* owner=nullptr;
  bool (*current)(void*)=nullptr; void (*fatal)(void*)=nullptr;
  Class board=nullptr,inert=nullptr,filter=nullptr,item=nullptr,meta=nullptr;
  Class additionalItem=nullptr;
  const SystemCatalogPolicy* systemCatalog=nullptr;
  NSPasteboard* general=nil;
  std::vector<Entry> entries;
  std::vector<Catalog> catalogs;
  static Guard& instance() { static Guard* value=new Guard; return *value; }
  void seal() {
    if(!failed) { failed=true; protected_=false; if(fatal) fatal(owner); }
  }
  void fail() { std::lock_guard<std::recursive_mutex> lock(mutex); seal(); }
  bool entryIntact(const Entry& e,bool installed) const {
    return class_getInstanceMethod(e.cls,e.selector)==e.method&&
      !strcmp(method_getTypeEncoding(e.method),e.encoding.c_str())&&
      method_getImplementation(e.method)==(installed&&e.replacement?e.replacement:e.original)&&e.provider(e.original);
  }
  // Every observed loaded subclass must be in the exact accepted family.
  // This is continuous integrity for the pinned producer, not arbitrary new
  // native-code/plugin coverage. Such a provider remains unsupported.
  bool family() const {
    unsigned count=0; Class* classes=objc_copyClassList(&count);
    bool ok=classes&&count<=(systemCatalog?systemCatalog->classLimit:50000);
    for(unsigned i=0;ok&&i<count;++i) {
      Class c=classes[i],base=c; unsigned depth=0;
      while(base&&base!=board&&base!=item&&++depth<=128) base=class_getSuperclass(base);
      if(depth>128||(base==board&&c!=board&&c!=inert&&c!=filter)||(base==item&&c!=item&&c!=additionalItem)) ok=false;
    }
    free(classes); return ok;
  }
  bool intact(bool installed) const {
    if(failed||!source||!source->unchanged()||!current||!current(owner)||!source->loadedIntact()||!family()) return false;
    for(const auto& e:entries) if(!entryIntact(e,installed)) return false;
    for(const auto& catalog:catalogs) {
      unsigned count=0; Method* methods=class_copyMethodList(catalog.cls,&count);
      bool ok=count==catalog.methods.size()&&count<=512;
      for(unsigned i=0;ok&&i<count;++i) {
        const CatalogMethod* before=nullptr;
        for(const auto& m:catalog.methods) if(m.method==methods[i]) { before=&m; break; }
        if(!before||strcmp(method_getTypeEncoding(methods[i]),before->encoding.c_str())) { ok=false; break; }
        IMP expected=before->original;
        if(installed) for(const auto& e:entries) if(e.method==methods[i]&&e.replacement) { expected=e.replacement; break; }
        if(method_getImplementation(methods[i])!=expected) ok=false;
      }
      free(methods); if(!ok) return false;
    }
    return true;
  }
  bool captureCatalog(Class cls, int expectedCount=-1) {
    unsigned count=0; Method* methods=class_copyMethodList(cls,&count);
    if(count>512||(!methods&&count)||(expectedCount>=0&&count!=(unsigned)expectedCount)) { free(methods); return false; }
    Catalog catalog{cls,{}}; bool ok=true;
    for(unsigned i=0;i<count;++i) {
      IMP imp=method_getImplementation(methods[i]); const char* encoding=method_getTypeEncoding(methods[i]);
      if(!encoding||(!appkitImplementation(imp)&&(!systemCatalog||
         std::none_of(entries.begin(),entries.end(),[&](const Entry& e) {
           return e.cls==cls&&e.method==methods[i]&&e.original==imp&&entryIntact(e,false);
         })))) { ok=false; break; }
      catalog.methods.push_back({methods[i],imp,encoding});
    }
    free(methods);
    if(ok&&systemCatalog) ok=std::all_of(entries.begin(),entries.end(),[&](const Entry& e) {
      return e.cls!=cls||e.provider==appkitImplementation||
        std::any_of(catalog.methods.begin(),catalog.methods.end(),[&](const CatalogMethod& method) {
          return method.method==e.method&&method.original==e.original;
        });
    });
    if(ok) catalogs.push_back(std::move(catalog)); return ok;
  }
  const Entry* lookup(Class cls,SEL selector) const {
    for(const auto& e:entries) if(e.cls==cls&&e.selector==selector) return &e;
    return nullptr;
  }
  IMP original(SEL selector) const { const auto* e=lookup(board,selector); return e?e->original:nullptr; }
  bool healthy() {
    if(!protected_||failed||!source||!source->unchanged()||!source->loadedIntact()||!current||!current(owner)) { seal(); return false; }
    return true;
  }
  bool hot(Class receiver,SEL selector) {
    if(!healthy()) return false;
    const auto* e=lookup(board,selector),*n=lookup(receiver,sel_registerName("name"));
    if(!e||!n||!entryIntact(*e,true)||!entryIntact(*n,true)) { seal(); return false; }
    return true;
  }
  // Namespace identity only. Never inspect contents, formats, items or args.
  // Unknown receivers cannot fall through to an unverified original.
  bool classify(id object,SEL selector,IMP& action,Class& cls,bool& named) {
    IMP getter=nullptr; SEL name=sel_registerName("name");
    {
      std::lock_guard<std::recursive_mutex> lock(mutex); cls=object?object_getClass(object):nullptr;
      if((cls!=board&&cls!=inert&&cls!=filter)||(object==general&&cls!=board)||!hot(cls,selector)) { seal(); return false; }
      getter=lookup(cls,name)->original; action=original(selector);
    }
    // Exact read-only AppKit namespace getter, outside our lock too. Never
    // hold a guard mutex across a provider/drag callback in another thread.
    id value=((id(*)(id,SEL))getter)(object,name);
    bool valid=value&&[value isKindOfClass:NSString.class]&&[(NSString*)value length]>0;
    bool system=valid&&[(NSString*)value isEqualToString:NSPasteboardNameGeneral];
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if(!valid||object_getClass(object)!=cls||!hot(cls,selector)||(object==general&&!system)||(system&&cls!=board)) { seal(); return false; }
    // A retained original can never be authorized by a changed named flag.
    named=object!=general&&!system; return true;
  }
  NSInteger unchangedCount(id object) {
    IMP getter=nullptr; SEL selector=sel_registerName("changeCount");
    {
      std::lock_guard<std::recursive_mutex> lock(mutex);
      if(object_getClass(object)!=board||!hot(board,selector)) return -1;
      getter=original(selector);
    }
    NSInteger count=((NSInteger(*)(id,SEL))getter)(object,selector);
    std::lock_guard<std::recursive_mutex> lock(mutex);
    if(object_getClass(object)!=board||!hot(board,selector)) { seal(); return -1; } return count;
  }
  bool aliases() {
    const auto* a=lookup(meta,sel_registerName("generalPasteboard"));
    const auto* b=lookup(meta,sel_registerName("pasteboardWithName:"));
    if(!a||!b) return false;
    id x=((id(*)(id,SEL))a->original)(board,a->selector);
    id y=((id(*)(id,SEL,id))b->original)(board,b->selector,NSPasteboardNameGeneral);
    const auto* n=lookup(board,sel_registerName("name"));
    return x&&x==y&&object_getClass(x)==board&&(!general||general==x)&&n&&
      [((id(*)(id,SEL))n->original)(x,n->selector) isEqualToString:NSPasteboardNameGeneral];
  }
  bool check(void* actual) {
    try { @try {
      { std::lock_guard<std::recursive_mutex> lock(mutex);
        if(actual!=owner||!protected_||!intact(true)) { seal(); return false; } }
      bool bound=aliases();
      std::lock_guard<std::recursive_mutex> lock(mutex);
      if(!bound||!intact(true)) { seal(); return false; } return true;
    } @catch(NSException*) { fail(); return false; } }
    catch(...) { fail(); return false; }
  }
  bool add(Class cls,const char* name,const char* encoding,IMP replacement=nullptr,
           bool (*provider)(IMP)=appkitImplementation) {
    if(!cls||entries.size()>=96) return false;
    SEL selector=sel_registerName(name); Method method=class_getInstanceMethod(cls,selector);
    if(!method||strcmp(method_getTypeEncoding(method),encoding)||!provider(method_getImplementation(method))) return false;
    entries.push_back({cls,selector,method,method_getImplementation(method),replacement,encoding,provider}); return true;
  }
  bool install(Source* input,void* actual,bool(*isCurrent)(void*),void(*onFatal)(void*),
               const SystemCatalogPolicy* additional=nullptr);
};

// Validate/capture each exact pair under the guard. The named-board original
// always runs outside it; a provider can synchronously cross threads.
template<typename R,typename F> inline R mutation(id self,SEL selector,R denied,F invoke) {
  auto& g=Guard::instance();
  try { @try {
    IMP before=nullptr; Class cls=nullptr; bool named=false;
    if(!g.classify(self,selector,before,cls,named)||!named) return denied;
    R value=invoke(before);
    std::lock_guard<std::recursive_mutex> lock(g.mutex);
    if(object_getClass(self)!=cls||!g.hot(cls,selector)) { g.seal(); return denied; } return value;
  } @catch(NSException*) { g.fail(); return denied; } }
  catch(...) { g.fail(); return denied; }
}
inline BOOL boolObject(id self,SEL sel,id a) { return mutation<BOOL>(self,sel,NO,[&](IMP f){return ((BOOL(*)(id,SEL,id))f)(self,sel,a);}); }
inline BOOL boolObjects(id self,SEL sel,id a,id b) { return mutation<BOOL>(self,sel,NO,[&](IMP f){return ((BOOL(*)(id,SEL,id,id))f)(self,sel,a,b);}); }
inline BOOL boolFlag(id self,SEL sel,BOOL a) { return mutation<BOOL>(self,sel,NO,[&](IMP f){return ((BOOL(*)(id,SEL,BOOL))f)(self,sel,a);}); }
inline BOOL data(id self,SEL sel,id a,id b,NSUInteger index,BOOL types) {
  return mutation<BOOL>(self,sel,NO,[&](IMP f){return ((BOOL(*)(id,SEL,id,id,NSUInteger,BOOL))f)(self,sel,a,b,index,types);});
}
template<typename F> inline NSInteger generation(id self,SEL selector,F invoke) {
  auto& g=Guard::instance();
  try { @try {
    IMP f=nullptr; Class cls=nullptr; bool named=false;
    if(!g.classify(self,selector,f,cls,named)) return -1;
    if(!named) return g.unchangedCount(self);
    NSInteger value=invoke(f);
    std::lock_guard<std::recursive_mutex> lock(g.mutex);
    if(object_getClass(self)!=cls||!g.hot(cls,selector)) { g.seal(); return -1; } return value;
  } @catch(NSException*) { g.fail(); return -1; } }
  catch(...) { g.fail(); return -1; }
}
inline NSInteger clear(id self,SEL sel) { return generation(self,sel,[&](IMP f){return ((NSInteger(*)(id,SEL))f)(self,sel);}); }
inline NSInteger prepare(id self,SEL sel,NSUInteger options) { return generation(self,sel,[&](IMP f){return ((NSInteger(*)(id,SEL,NSUInteger))f)(self,sel,options);}); }
inline NSInteger types(id self,SEL sel,id a,id b) { return generation(self,sel,[&](IMP f){return ((NSInteger(*)(id,SEL,id,id))f)(self,sel,a,b);}); }
inline NSInteger owner(id self,SEL sel,id a,id b,NSUInteger index,SEL provider,BOOL usesTypes) {
  return generation(self,sel,[&](IMP f){return ((NSInteger(*)(id,SEL,id,id,NSUInteger,SEL,BOOL))f)(self,sel,a,b,index,provider,usesTypes);});
}
inline void release(id self,SEL sel) {
  auto& g=Guard::instance();
  try { @try {
    IMP f=nullptr; Class cls=nullptr; bool named=false;
    if(!g.classify(self,sel,f,cls,named)||!named) return;
    ((void(*)(id,SEL))f)(self,sel);
    std::lock_guard<std::recursive_mutex> lock(g.mutex);
    if(object_getClass(self)!=cls||!g.hot(cls,sel)) g.seal();
  } @catch(NSException*) { g.fail(); } }
  catch(...) { g.fail(); }
}
inline id refuseShunt(id cls,SEL selector) {
  auto& g=Guard::instance(); std::lock_guard<std::recursive_mutex> lock(g.mutex);
  @try { const auto* e=g.lookup(g.meta,selector);
    if(cls!=g.board||!g.healthy()||!e||!g.entryIntact(*e,true)) g.seal(); } @catch(NSException*) { g.seal(); }
  // Exact inspected AppKit failure result. No receiver rearrangement or start.
  return nil;
}
inline void refuseUnshunt(id cls,SEL selector) {
  auto& g=Guard::instance(); std::lock_guard<std::recursive_mutex> lock(g.mutex);
  @try { const auto* e=g.lookup(g.meta,selector);
    if(cls!=g.board||!g.healthy()||!e||!g.entryIntact(*e,true)) g.seal(); } @catch(NSException*) { g.seal(); }
  // This provider has denied every start; never invoke a global stop.
}
inline bool Guard::install(Source* input,void* actual,bool(*isCurrent)(void*),void(*onFatal)(void*),
                           const SystemCatalogPolicy* additional) {
  std::lock_guard<std::recursive_mutex> lock(mutex);
  if(attempted) return false; attempted=true; source=input; owner=actual; current=isCurrent; fatal=onFatal;
  systemCatalog=additional;
  @try {
    if(![NSThread isMainThread]||!input||input->result.load(std::memory_order_acquire)!=1||!input->unchanged()||
       !current||!current(owner)||!input->pinLoaded()) { seal(); return false; }
    board=objc_getClass("NSPasteboard"); inert=objc_getClass("NSInertPasteboard");
    filter=objc_getClass("NSFilterServicesPasteboard"); item=objc_getClass("NSPasteboardItem");
    if(!board||!inert||!filter||!item||class_getSuperclass(inert)!=board||class_getSuperclass(filter)!=board) { seal(); return false; }
    for(Class cls:{board,inert,filter,item}) {
      const char* image=class_getImageName(cls);
      if(!image||strcmp(image,appkitPath)) { seal(); return false; } [(id)cls class];
    }
    meta=object_getClass(board);
    bool ok=add(meta,"generalPasteboard","@16@0:8")&&add(meta,"pasteboardWithName:","@24@0:8@16")&&
      add(board,"name","@16@0:8")&&add(inert,"name","@16@0:8")&&add(filter,"name","@16@0:8")&&
      add(board,"changeCount","q16@0:8")&&
      add(board,"prepareForNewContentsWithOptions:","q24@0:8Q16",(IMP)prepare)&&add(board,"clearContents","q16@0:8",(IMP)clear)&&
      add(board,"declareTypes:owner:","q32@0:8@16@24",(IMP)types)&&add(board,"addTypes:owner:","q32@0:8@16@24",(IMP)types)&&
      add(board,"_setData:forType:index:usesPboardTypes:","B44@0:8@16@24Q32B40",(IMP)data)&&
      add(board,"_setOwner:forTypes:atIndex:selector:usesPboardTypes:","q52@0:8@16@24Q32:40B48",(IMP)arbol_clipboard::owner)&&
      add(board,"_setExpirationDate:","B24@0:8@16",(IMP)boolObject)&&add(board,"_setShouldExcludeFromHistory:","B20@0:8B16",(IMP)boolFlag)&&
      add(board,"writeObjects:","B24@0:8@16",(IMP)boolObject)&&add(board,"setData:forType:","B32@0:8@16@24",(IMP)boolObjects)&&
      add(board,"setString:forType:","B32@0:8@16@24",(IMP)boolObjects)&&add(board,"setPropertyList:forType:","B32@0:8@16@24",(IMP)boolObjects)&&
      add(board,"setDataProvider:forTypes:","B32@0:8@16@24",(IMP)boolObjects)&&add(board,"attemptOverwrite:","B24@0:8@16",(IMP)boolObject)&&
      add(board,"writeFileContents:","B24@0:8@16",(IMP)boolObject)&&add(board,"writeFileWrapper:","B24@0:8@16",(IMP)boolObject)&&
      add(board,"releaseGlobally","Vv16@0:8",(IMP)release)&&
      add(item,"setData:forType:","B32@0:8@16@24")&&add(item,"setString:forType:","B32@0:8@16@24")&&
      add(item,"setPropertyList:forType:","B32@0:8@16@24")&&add(item,"setDataProvider:forTypes:","B32@0:8@16@24")&&
      add(meta,"_startShuntingGeneralPasteboardForIntelligence","@16@0:8",(IMP)refuseShunt)&&
      add(meta,"_stopShuntingGeneralPasteboardForIntelligence","v16@0:8",(IMP)refuseUnshunt);
    // Verify the exact non-general family overrides too, without mutating
    // their behavior. Inherited Method records are deduplicated below.
    if(ok) {
      const size_t baseCount=entries.size();
      for(Class cls:{inert,filter}) for(size_t i=0;i<baseCount;++i) {
        const Entry e=entries[i]; if(e.cls!=board||!e.replacement) continue;
        Method m=class_getInstanceMethod(cls,e.selector);
        if(!m||strcmp(method_getTypeEncoding(m),e.encoding.c_str())||!appkitImplementation(method_getImplementation(m))) { ok=false; break; }
        if(m!=e.method) entries.push_back({cls,e.selector,m,method_getImplementation(m),nullptr,e.encoding});
      }
    }
    if(ok&&systemCatalog) ok=systemCatalog->registerEntries(*this);
    if(ok) for(Class cls:{board,inert,filter,item,meta,object_getClass(inert),object_getClass(filter)})
      if(!captureCatalog(cls)) { ok=false; break; }
    if(ok&&additionalItem) ok=captureCatalog(additionalItem,4)&&captureCatalog(object_getClass(additionalItem),0);
    if(!ok||!intact(false)||!aliases()) { seal(); return false; }
    const auto* factory=lookup(meta,sel_registerName("generalPasteboard"));
    general=((id(*)(id,SEL))factory->original)(board,factory->selector);
    if(!general||!intact(false)||!aliases()) { seal(); return false; }
    // Startup is still closed by genuine native custody. Never roll a partial
    // installation back to permissive originals or mint a partial receipt.
    for(const auto& e:entries) if(e.replacement) {
      if(!entryIntact(e,false)||method_setImplementation(e.method,e.replacement)!=e.original) { seal(); return false; }
    }
    if(!intact(true)||!aliases()) { seal(); return false; }
    protected_=true; return true;
  } @catch(NSException*) { seal(); return false; }
}
} // namespace arbol_clipboard

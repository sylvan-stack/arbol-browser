#include <node_api.h>
#include "../../watchdog/boundary.hpp"
#include "../runtime/system-clipboard.hpp"

namespace {
arbol_clipboard::Source* source = nullptr;
pid_t originalProcess = 0;

struct SystemImage {
  const char* path;
  std::array<unsigned char,16> uuid;
};
constexpr SystemImage webKit{
  "/System/Library/Frameworks/WebKit.framework/Versions/A/Frameworks/WebKitLegacy.framework/Versions/A/WebKitLegacy",
  {0x4d,0x59,0xe3,0xa4,0x29,0xcf,0x3f,0xde,0x9d,0x6c,0x61,0x3a,0x1e,0x3f,0x57,0x9b}
};
constexpr SystemImage annotations{
  "/System/Library/PrivateFrameworks/AnnotationKit.framework/Versions/A/AnnotationKit",
  {0xa2,0x9d,0x03,0xbf,0x3d,0xc0,0x37,0x75,0xb2,0x10,0x0e,0xd0,0x16,0x29,0x02,0x2a}
};
constexpr SystemImage authentication{
  "/System/Library/Frameworks/AuthenticationServices.framework/Versions/A/AuthenticationServices",
  {0x2e,0x9f,0x57,0x5e,0xb8,0xe5,0x37,0x73,0x93,0x43,0x28,0x7a,0x71,0xaf,0x30,0x6b}
};
constexpr SystemImage swiftUI{
  "/System/Library/Frameworks/SwiftUI.framework/Versions/A/SwiftUI",
  {0xe9,0x64,0x67,0x5c,0x54,0x53,0x37,0xa7,0x8e,0x48,0x48,0x80,0x62,0x15,0xf9,0x81}
};

bool fromImage(const void* address, const SystemImage& expected) {
  Dl_info image{};
  return address && dladdr(address, &image) && image.dli_fname &&
    !strcmp(image.dli_fname, expected.path) && arbol_clipboard::imageUUID(image.dli_fbase, expected.uuid);
}

template<const SystemImage& expected> bool providedBy(IMP implementation) {
  return fromImage(reinterpret_cast<const void*>(implementation), expected);
}

void denyClear(id, SEL) {}
void denyObject(id, SEL, id) {}
void denyObjectFlag(id, SEL, id, BOOL) {}
void denyThreeObjects(id, SEL, id, id, id) {}
id denyDragImage(id, SEL, id, id, id, id, id) { return nil; }
void denyImage(id, SEL, id, id, id, id, id, id, id) {}
int denyFind(id, SEL, id, id) { return -1; }
BOOL denyProvider(id, SEL, id, id) { return NO; }

bool registerSystemCatalog(arbol_clipboard::Guard& guard) {
  const Class item = objc_getClass("_TtC7SwiftUIP33_0BC2519238CC4854E8BA774CC855AC9A14PasteboardItem");
  const char* itemImage = item ? class_getImageName(item) : nullptr;
  if (!itemImage || strcmp(itemImage, swiftUI.path) || class_getSuperclass(item) != guard.item ||
      !fromImage((__bridge const void*)item, swiftUI)) return false;
  guard.additionalItem = item;
  struct MethodBinding {
    Class owner;
    const char* selector;
    const char* encoding;
    IMP replacement;
    bool (*provider)(IMP);
  };
  const MethodBinding methods[] = {
    {guard.board, "_web_bestURL", "@16@0:8", nullptr, providedBy<webKit>},
    {guard.board, "_web_declareAndWriteDragImageForElement:URL:title:archive:source:", "@56@0:8@16@24@32@40@48", (IMP)denyDragImage, providedBy<webKit>},
    {guard.board, "_web_writeFileWrapperAsRTFDAttachment:", "v24@0:8@16", (IMP)denyObject, providedBy<webKit>},
    {guard.board, "_web_writeImage:element:URL:title:archive:types:source:", "v72@0:8@16@24@32@40@48@56@64", (IMP)denyImage, providedBy<webKit>},
    {guard.board, "_web_writePromisedRTFDFromArchive:containsImage:", "v28@0:8@16B24", (IMP)denyObjectFlag, providedBy<webKit>},
    {guard.board, "_web_writeURL:andTitle:types:", "v40@0:8@16@24@32", (IMP)denyThreeObjects, providedBy<webKit>},
    {guard.meta, "_web_dragTypesForURL", "@16@0:8", nullptr, providedBy<webKit>},
    {guard.meta, "_web_setFindPasteboardString:withOwner:", "i32@0:8@16@24", (IMP)denyFind, providedBy<webKit>},
    {guard.meta, "_web_writableTypesForImageIncludingArchive:", "@20@0:8B16", nullptr, providedBy<webKit>},
    {guard.meta, "_web_writableTypesForURL", "@16@0:8", nullptr, providedBy<webKit>},
    {guard.board, "akClearContents", "v16@0:8", (IMP)denyClear, providedBy<annotations>},
    {guard.board, "akPasteboardContainsAnnotations", "B16@0:8", nullptr, providedBy<annotations>},
    {guard.board, "akPasteboardAnnotations", "@16@0:8", nullptr, providedBy<annotations>},
    {guard.board, "akPasteboardSetAnnotations:", "v24@0:8@16", (IMP)denyObject, providedBy<annotations>},
    {guard.board, "as_writeString:isSensitive:", "v28@0:8@16B24", (IMP)denyObjectFlag, providedBy<authentication>},
    {item, "init", "@16@0:8", nullptr, providedBy<swiftUI>},
    {item, ".cxx_destruct", "v16@0:8", nullptr, providedBy<swiftUI>},
    {item, "initWithPasteboardPropertyList:ofType:", "@32@0:8@16@24", nullptr, providedBy<swiftUI>},
    {item, "setDataProvider:forTypes:", "B32@0:8@16@24", (IMP)denyProvider, providedBy<swiftUI>},
  };
  for (const auto& method : methods) {
    if (!guard.add(method.owner, method.selector, method.encoding, method.replacement, method.provider)) return false;
  }
  return true;
}
constexpr arbol_clipboard::SystemCatalogPolicy catalog{100000, registerSystemCatalog};

bool current(void* value) {
  return source && value == source && originalProcess == getpid();
}

[[noreturn]] void fatal(void*) {
  constexpr char message[] = "Arbol Browser preview stopped. Native clipboard protection is unavailable.\n";
  (void)write(STDERR_FILENO, message, sizeof(message) - 1);
  _exit(70);
}

napi_value install(napi_env env, napi_callback_info info) {
  napi_value argument;
  size_t count = 1;
  char path[PATH_MAX];
  size_t length = 0;
  if (source || ![NSThread isMainThread] ||
      napi_get_cb_info(env, info, &count, &argument, nullptr, nullptr) != napi_ok || count != 1 ||
      napi_get_value_string_utf8(env, argument, nullptr, 0, &length) != napi_ok || !length || length >= sizeof(path) ||
      napi_get_value_string_utf8(env, argument, path, sizeof(path), &length) != napi_ok ||
      length != strlen(path) || !arbol_boundary::canonical(path) ||
      !arbol_boundary::retainNativeImage()) fatal(nullptr);
  originalProcess = getpid();
  source = new arbol_clipboard::Source(path);
  @autoreleasepool {
    @try {
      if (!source->verifyStockCode(arbol_boundary::clockMs() + 5000)) fatal(nullptr);
      source->result.store(1, std::memory_order_release);
      if (!arbol_clipboard::Guard::instance().install(source, source, current, fatal, &catalog) ||
          !source->unchanged()) fatal(nullptr);
    } @catch (NSException*) { fatal(nullptr); }
  }
  napi_value out;
  if (napi_get_undefined(env, &out) != napi_ok) fatal(nullptr);
  return out;
}

napi_value check(napi_env env, napi_callback_info) {
  if (!source || ![NSThread isMainThread] || !arbol_clipboard::Guard::instance().check(source)) fatal(nullptr);
  napi_value out;
  if (napi_get_undefined(env, &out) != napi_ok) fatal(nullptr);
  return out;
}
}

NAPI_MODULE_INIT() {
  const napi_property_descriptor operations[] = {
    {"install", nullptr, install, nullptr, nullptr, nullptr, napi_default, nullptr},
    {"check", nullptr, check, nullptr, nullptr, nullptr, napi_default, nullptr},
  };
  if (napi_define_properties(env, exports, 2, operations) != napi_ok) fatal(nullptr);
  return exports;
}

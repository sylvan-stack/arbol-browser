#include <node_api.h>
#include "../../watchdog/boundary.hpp"
#include "../runtime/system-clipboard.hpp"

namespace {
arbol_clipboard::Source* source = nullptr;
pid_t originalProcess = 0;

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
      if (!arbol_clipboard::Guard::instance().install(source, source, current, fatal) ||
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

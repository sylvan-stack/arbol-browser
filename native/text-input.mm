#import "keys.hpp"
#include "edit-selectors.hpp"
#include <cstring>
namespace arbol_native {
template <typename Function> static void textMutation(id object, SEL selector, Function operation) {
  if (![NSThread isMainThread]) return;
  @try { try { ArbolPagePolicy* policy = routePolicy(object, selector); if (!policy) return; OriginalRoute scope(policy, object, selector); operation(); }
    catch (const std::exception&) { poison("native_text_failed"); } }
  @catch (NSException*) { poison("native_text_failed"); }
}
static bool writesGeneralClipboard(SEL selector) {
  return selector == sel_registerName("copy:") || selector == sel_registerName("cut:");
}
static void editObject(id self, SEL selector, id argument) {
  textMutation(self, selector, [&] {
    if (!writesGeneralClipboard(selector)) ((void(*)(id, SEL, id))originalFor(self, selector))(self, selector, argument);
  });
}
static void textFinish(id self, SEL selector) {
  textMutation(self, selector, [&] { ((void(*)(id, SEL))originalFor(self, selector))(self, selector); });
}
static bool knownCommand(SEL command) {
  for (const char* name : editingSelectors) if (command == sel_registerName(name)) return true;
  for (const char* name : {"undo:", "redo:", "paste:", "pasteAndMatchStyle:"}) if (command == sel_registerName(name)) return true;
  return false;
}
static void textCommand(id self, SEL selector, SEL command) {
  textMutation(self, selector, [&] {
    if (knownCommand(command) && !writesGeneralClipboard(command)) ((void(*)(id, SEL, SEL))originalFor(self, selector))(self, selector, command);
  });
}
static void textInsert(id self, SEL selector, id text, NSRange replacement) {
  textMutation(self, selector, [&] { ((void(*)(id, SEL, id, NSRange))originalFor(self, selector))(self, selector, text, replacement); });
}
static void textMarked(id self, SEL selector, id text, NSRange selected, NSRange replacement) {
  textMutation(self, selector, [&] { ((void(*)(id, SEL, id, NSRange, NSRange))originalFor(self, selector))(self, selector, text, selected, replacement); });
}
void planTextInput() {
  size_t generated = 0;
  for (const auto& target : targets) {
    if (strcmp(target.cls, "RenderWidgetHostViewCocoa")) continue;
    IMP guard = nullptr;
    for (const char* name : editingSelectors) if (!strcmp(name, target.selector)) { guard = (IMP)editObject; ++generated; break; }
    if (!guard) {
      for (const char* name : {"insertText:", "undo:", "redo:", "paste:", "pasteAndMatchStyle:"}) if (!strcmp(name, target.selector)) guard = (IMP)editObject;
      if (!strcmp(target.selector, "unmarkText") || !strcmp(target.selector, "finishComposingText")) guard = (IMP)textFinish;
      if (!strcmp(target.selector, "doCommandBySelector:")) guard = (IMP)textCommand;
      if (!strcmp(target.selector, "insertText:replacementRange:")) guard = (IMP)textInsert;
      if (!strcmp(target.selector, "setMarkedText:selectedRange:replacementRange:")) guard = (IMP)textMarked;
    }
    if (guard) stageRoute(target, guard);
  }
  if (generated != 88) throw std::runtime_error("native_edit_inventory_incomplete");
}
}

#pragma once
// Closed target/encoding/provider table from the retained signed prototype,
// abi-inspection.json; production qualification is separate. No runtime discovery.
#import <Cocoa/Cocoa.h>
#import <objc/runtime.h>
#include <node_api.h>
#include <atomic>
#include <string>
#include <vector>
namespace arbol_native {
constexpr size_t kStructuredLimit = 1048576, kMaxTargets = 4096;
enum class Phase { New, Planning, Ready, Rejected, Poisoned, Closing };
extern std::atomic<Phase> phase;
struct Target { const char* cls; const char* selector; const char* encoding; const char* provider; };
inline const Target targets[] = {
  {"BrowserAccessibilityCocoa", "accessibilityCustomActions", "@16@0:8", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "accessibilityPerformAction:", "v24@0:8@16", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "accessibilityPerformDecrement", "B16@0:8", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "accessibilityPerformIncrement", "B16@0:8", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "accessibilityPerformPress", "B16@0:8", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "accessibilityPerformShowMenu", "B16@0:8", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "accessibilitySetValue:forAttribute:", "v32@0:8@16@24", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "setAccessibilityFocused:", "v20@0:8B16", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "setAccessibilitySelectedText:", "v24@0:8@16", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "setAccessibilitySelectedTextRange:", "v32@0:8{_NSRange=QQ}16", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "setAccessibilityValue:", "v24@0:8@16", "Electron Framework"},
  {"BrowserAccessibilityCocoa", "setSelectedTextMarkerRange:", "<absent>", "<absent>"},
  {"NSWindow", "makeFirstResponder:", "B24@0:8@16", "AppKit"},
  {"RenderWidgetHostViewCocoa", "accessibilityChildren", "@16@0:8", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "alignCenter:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "alignJustified:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "alignLeft:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "alignRight:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "becomeFirstResponder", "B16@0:8", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "copy:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "cut:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "delete:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteBackward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteBackwardByDecomposingPreviousCharacter:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteForward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteToBeginningOfLine:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteToBeginningOfParagraph:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteToEndOfLine:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteToEndOfParagraph:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteToMark:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteWordBackward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "deleteWordForward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "doCommandBySelector:", "v24@0:8:16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "finishComposingText", "v16@0:8", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "ignoreSpelling:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "indent:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertBacktab:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertLineBreak:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertNewline:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertNewlineIgnoringFieldEditor:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertParagraphSeparator:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertTab:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertTabIgnoringFieldEditor:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertText:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "insertText:replacementRange:", "v40@0:8@16{_NSRange=QQ}24", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "makeTextWritingDirectionLeftToRight:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "makeTextWritingDirectionNatural:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "makeTextWritingDirectionRightToLeft:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "mouseEvent:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveBackward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveBackwardAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveDown:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveDownAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveForward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveForwardAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveLeft:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveLeftAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveParagraphBackwardAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveParagraphForwardAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveRight:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveRightAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfDocument:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfDocumentAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfLine:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfLineAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfParagraph:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfParagraphAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfSentence:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToBeginningOfSentenceAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfDocument:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfDocumentAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfLine:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfLineAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfParagraph:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfParagraphAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfSentence:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveToEndOfSentenceAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveUp:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveUpAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordBackward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordBackwardAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordForward:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordForwardAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordLeft:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordLeftAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordRight:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "moveWordRightAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "outdent:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "pageDown:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "pageDownAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "pageUp:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "pageUpAndModifySelection:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "paste:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "pasteAndMatchStyle:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "redo:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "scrollWheel:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "selectAll:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "selectLine:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "selectParagraph:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "selectSentence:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "selectToMark:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "selectWord:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "setMark:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "setMarkedText:selectedRange:replacementRange:", "v56@0:8@16{_NSRange=QQ}24{_NSRange=QQ}40", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "showGuessPanel:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "subscript:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "superscript:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "swapWithMark:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "transpose:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "underline:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "undo:", "v24@0:8@16", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "unmarkText", "v16@0:8", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "unscript:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "yank:", "v@:@", "Electron Framework"},
  {"RenderWidgetHostViewCocoa", "yankAndSelect:", "v@:@", "Electron Framework"},
  {"WebContentsViewCocoa", "draggingEntered:", "Q24@0:8@16", "Electron Framework"},
  {"WebContentsViewCocoa", "draggingExited:", "v24@0:8@16", "Electron Framework"},
  {"WebContentsViewCocoa", "draggingSession:endedAtPoint:operation:", "v48@0:8@16{CGPoint=dd}24Q40", "Electron Framework"},
  {"WebContentsViewCocoa", "draggingSession:willBeginAtPoint:", "v40@0:8@16{CGPoint=dd}24", "Electron Framework"},
  {"WebContentsViewCocoa", "draggingUpdated:", "Q24@0:8@16", "Electron Framework"},
  {"WebContentsViewCocoa", "performDragOperation:", "B24@0:8@16", "Electron Framework"},
};
struct Hook { Class cls; SEL selector; IMP before; IMP guard; std::string encoding; std::string provider; bool applied; };
extern std::vector<Hook> hooks;
// ABR-6 binds these internal seams to weak-view/tombstone policy. They are not
// JavaScript exports and may be installed only during the one planning phase.
using BindingAudit = bool (*)();
using BindingSeal = void (*)();
extern BindingAudit bindingAudit;
extern BindingSeal bindingSeal;
extern size_t liveBindings, policyObjects;
void poison(const char* reason);
bool integrity();
NSString* providerOf(IMP implementation);
bool installedHooksIntact();
NSDictionary* liveInventory();
NSDictionary* pinnedInventory();
NSDictionary* statusObject();
napi_value jsonReply(napi_env env, id value);
bool mainCall(napi_env env, napi_callback_info info, size_t expected, napi_value* arguments = nullptr);
void stageGuard(Class cls, SEL selector, IMP guard, const char* encoding);
}

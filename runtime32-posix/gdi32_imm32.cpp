// gdi32, imm32 and dbghelp: what the reference asks of them answered without them. GDI draws nothing
// (the reference draws through Direct3D; its GDI calls are a crash dialog's and a font's metrics),
// the input method is off (no IME on the host's side yet), and no minidump is written (the
// runtime's own crash report is in the log).
#include <atomic>

#include "Runtime.h"

using namespace rh;

namespace {
// a GDI object: a handle that names it, never drawn with
uint32_t Gdi() {
    static std::atomic<uint32_t> next{0x00040000};
    return next += 4;
}
uint32_t g_selected = 0;
}  // namespace

static uint32_t CreateDCA_(uint32_t, uint32_t, uint32_t, uint32_t) { return Gdi(); }
RH_REG(GDI32, CreateDCA, CreateDCA_)
static uint32_t DeleteDC_(uint32_t) { return 1; }
RH_REG(GDI32, DeleteDC, DeleteDC_)
static uint32_t CreateFontIndirectA_(uint32_t) { return Gdi(); }
RH_REG(GDI32, CreateFontIndirectA, CreateFontIndirectA_)
static uint32_t CreatePen_(uint32_t, uint32_t, uint32_t) { return Gdi(); }
RH_REG(GDI32, CreatePen, CreatePen_)
static uint32_t GetStockObject_(uint32_t k) { return 0x00030000 + k * 4; }
RH_REG(GDI32, GetStockObject, GetStockObject_)
static uint32_t SelectObject_(uint32_t, uint32_t obj) {
    uint32_t old = g_selected;
    g_selected = obj;
    return old ? old : GetStockObject_(13);   // (SYSTEM_FONT, the DC's first)
}
RH_REG(GDI32, SelectObject, SelectObject_)
static uint32_t DeleteObject_(uint32_t) { return 1; }
RH_REG(GDI32, DeleteObject, DeleteObject_)
static uint32_t TextOutA_(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(GDI32, TextOutA, TextOutA_)
static uint32_t MoveToEx_(uint32_t, uint32_t, uint32_t, uint32_t old) {
    if (old) memset(At(old), 0, 8);
    return 1;
}
RH_REG(GDI32, MoveToEx, MoveToEx_)
static uint32_t LineTo_(uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(GDI32, LineTo, LineTo_)
static uint32_t Ellipse_(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(GDI32, Ellipse, Ellipse_)
// a fixed 8x16 font's extent
static uint32_t GetTextExtentPoint32A_(uint32_t, uint32_t, uint32_t n, uint32_t size) {
    *At<int32_t>(size) = static_cast<int32_t>(n * 8);
    *At<int32_t>(size + 4) = 16;
    return 1;
}
RH_REG(GDI32, GetTextExtentPoint32A, GetTextExtentPoint32A_)
// ExtEscape: a driver's escape (NVIDIA's queries through it): not supported, 0
static uint32_t ExtEscape_(uint32_t, uint32_t, uint32_t, uint32_t, uint32_t, uint32_t) { return 0; }
RH_REG(GDI32, ExtEscape, ExtEscape_)

// ---- imm32: no input method; the context a handle, closed, in alphanumeric mode -------------------
static uint32_t ImmGetContext_(uint32_t) { return 0x00050000; }
RH_REG(IMM32, ImmGetContext, ImmGetContext_)
static uint32_t ImmReleaseContext_(uint32_t, uint32_t) { return 1; }
RH_REG(IMM32, ImmReleaseContext, ImmReleaseContext_)
static uint32_t ImmAssociateContext_(uint32_t, uint32_t) { return 0x00050000; }
RH_REG(IMM32, ImmAssociateContext, ImmAssociateContext_)
static uint32_t ImmDisableTextFrameService_(uint32_t) { return 1; }
RH_REG(IMM32, ImmDisableTextFrameService, ImmDisableTextFrameService_)
static uint32_t ImmGetCandidateListW_(uint32_t, uint32_t, uint32_t, uint32_t) { return 0; }
RH_REG(IMM32, ImmGetCandidateListW, ImmGetCandidateListW_)
static uint32_t ImmGetCompositionStringW_(uint32_t, uint32_t, uint32_t, uint32_t) { return 0; }
RH_REG(IMM32, ImmGetCompositionStringW, ImmGetCompositionStringW_)
static uint32_t ImmGetConversionStatus_(uint32_t, uint32_t conv, uint32_t sent) {
    if (conv) *At<uint32_t>(conv) = 0;   // IME_CMODE_ALPHANUMERIC
    if (sent) *At<uint32_t>(sent) = 0;
    return 1;
}
RH_REG(IMM32, ImmGetConversionStatus, ImmGetConversionStatus_)
static uint32_t ImmSetConversionStatus_(uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(IMM32, ImmSetConversionStatus, ImmSetConversionStatus_)
static uint32_t ImmGetOpenStatus_(uint32_t) { return 0; }
RH_REG(IMM32, ImmGetOpenStatus, ImmGetOpenStatus_)
static uint32_t ImmSetOpenStatus_(uint32_t, uint32_t) { return 1; }
RH_REG(IMM32, ImmSetOpenStatus, ImmSetOpenStatus_)
static uint32_t ImmGetVirtualKey_(uint32_t) { return 0; }   // (VK_PROCESSKEY never: no IME)
RH_REG(IMM32, ImmGetVirtualKey, ImmGetVirtualKey_)
static uint32_t ImmNotifyIME_(uint32_t, uint32_t, uint32_t, uint32_t) { return 1; }
RH_REG(IMM32, ImmNotifyIME, ImmNotifyIME_)

// ---- dbghelp ----------------------------------------------------------------------------------------
RH_STUB(dbghelp, MiniDumpWriteDump, 7, 0, win::ERROR_CALL_NOT_IMPLEMENTED)

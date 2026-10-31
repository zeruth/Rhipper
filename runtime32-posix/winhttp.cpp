// winhttp: not here yet. WinHttpOpen fails (ERROR_WINHTTP_INTERNAL_ERROR, logged) and so does every
// call after it, as on a machine whose HTTP stack is broken: the reference takes its no-network
// path for what it fetched over HTTP (news, a patch list). A real one would go over the host's
// (Java's HttpURLConnection or a bundled client): its handles, a session's thread for the
// asynchronous callbacks (WinHttpSetStatusCallback's, on a low thread).
#include "Runtime.h"

namespace {
constexpr uint32_t ERROR_WINHTTP_INTERNAL_ERROR = 12004, ERROR_WINHTTP_INVALID_HANDLE = 12017;
}

static uint32_t WinHttpOpen_(uint32_t agent, uint32_t, uint32_t, uint32_t, uint32_t) {
    rh::Log("WinHttpOpen(%s): no HTTP here yet, failed", agent ? rh::Narrow(rh::At<char16_t>(agent)).c_str() : "-");
    rh::SetLastError(ERROR_WINHTTP_INTERNAL_ERROR);
    return 0;
}
RH_REG(WINHTTP, WinHttpOpen, WinHttpOpen_)
RH_STUB(WINHTTP, WinHttpConnect, 4, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpOpenRequest, 7, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpSendRequest, 7, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpReceiveResponse, 2, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpQueryHeaders, 6, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpReadData, 4, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpSetOption, 4, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpSetTimeouts, 5, 0, ERROR_WINHTTP_INVALID_HANDLE)
RH_STUB(WINHTTP, WinHttpCloseHandle, 1, 1, 0)
// WinHttpSetStatusCallback returns the previous callback, or WINHTTP_INVALID_STATUS_CALLBACK (-1)
RH_STUB(WINHTTP, WinHttpSetStatusCallback, 4, 0xFFFFFFFFu, ERROR_WINHTTP_INVALID_HANDLE)

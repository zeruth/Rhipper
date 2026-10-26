// The DxDiag bridge's messages (DxDiag32.cpp, the 32-bit helper; DxDiagBridge.cpp, the port's side).
// The port asks, the helper makes the call on its own 32-bit DxDiag objects and answers: one
// request, one reply, over the helper's standard input and output.
//
// A request: Op, then two words (a, b), then two strings (the container's path, a name). A reply: the
// HRESULT, a word (a count), the VARIANT's type and 8 bytes of its value, then a string (a name, a
// BSTR's text). A string is its length in UTF-16 units, then the units.
// A container is named by its path from the root: the names GetChildContainer was given on the way
// down, joined with '\x01' (a name may hold dots of its own: DxDiag takes "A.B" as A's child B).
#pragma once
#include <cstdint>

namespace dxdiagwire {

enum Op : uint32_t {
    kInitialize = 1,        // a: header version, b: WHQL checks
    kChild = 2,             // GetRootContainer (path "" and no name) or GetChildContainer(name)
    kNumChildren = 3,
    kEnumChild = 4,         // a: index, b: the buffer's length
    kNumProps = 5,
    kEnumProp = 6,          // a: index, b: the buffer's length
    kGetProp = 7,
};

const wchar_t kSep = L'\x01';

}  // namespace dxdiagwire

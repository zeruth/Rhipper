"""The 32-bit faces of the COM objects a 32-bit reference is handed (runtime32/Com32Gen.cpp).

An x86 reference calls a COM method through a 4-byte vtable slot, `this` and its arguments 4 bytes
each on the stack; the x64 object Windows makes has 8-byte slots and takes x64 arguments. The port
gives the reference a proxy in the object's place (runtime32/Com32.h): a 4-byte vtable whose slots
are this file's thunks, one per method, each taking the reference's 32-bit words, converting them
(an interface the reference holds is a proxy, unwrapped; one it is handed back is wrapped; a handle
sign-extended; a float read from the double the translation passes), and calling the native method
by its vtable index. A method whose arguments hold structures laid out differently on x64 (a
pointer or handle inside) is one of runtime32/Com32.cpp's, by name (SPECIAL).

The methods come from the DirectX SDK's headers (DECLARE_INTERFACE_ / STDMETHOD), the generated
file includes none: the SDK's own xaudio2.h is 2.9's, not the 2.7 the reference uses.

    python com32gen.py [--sdk "C:/Program Files (x86)/Microsoft DirectX SDK (August 2009)/Include"]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
OUT = HERE / "runtime32" / "Com32Gen.cpp"
SDK = Path(r"C:\Program Files (x86)\Microsoft DirectX SDK (August 2009)\Include")

# the interfaces given proxies, by header; and those the headers do not declare
HEADERS = {
    "d3d9.h": ["IDirect3D9", "IDirect3DDevice9", "IDirect3DStateBlock9", "IDirect3DSwapChain9",
               "IDirect3DResource9", "IDirect3DVertexDeclaration9", "IDirect3DVertexShader9",
               "IDirect3DPixelShader9", "IDirect3DBaseTexture9", "IDirect3DTexture9",
               "IDirect3DVolumeTexture9", "IDirect3DCubeTexture9", "IDirect3DVertexBuffer9",
               "IDirect3DIndexBuffer9", "IDirect3DSurface9", "IDirect3DVolume9", "IDirect3DQuery9"],
    "dinput.h": ["IDirectInput8A", "IDirectInputDevice8A", "IDirectInputEffect"],
    "XAudio2.h": ["IXAudio2", "IXAudio2Voice", "IXAudio2SourceVoice", "IXAudio2SubmixVoice",
                  "IXAudio2MasteringVoice"],
    # (DirectX's system information, which a client reads at startup: its COM calls pump the
    # thread's messages, and the window procedure runs inside them)
    "dxdiag.h": ["IDxDiagProvider", "IDxDiagContainer"],
}
EXTRA = """
DECLARE_INTERFACE(IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObj) PURE;
    STDMETHOD_(ULONG,AddRef)(THIS) PURE;
    STDMETHOD_(ULONG,Release)(THIS) PURE;
};
DECLARE_INTERFACE_(IClassFactory, IUnknown) {
    STDMETHOD(QueryInterface)(THIS_ REFIID riid, void** ppvObj) PURE;
    STDMETHOD_(ULONG,AddRef)(THIS) PURE;
    STDMETHOD_(ULONG,Release)(THIS) PURE;
    STDMETHOD(CreateInstance)(THIS_ IUnknown* pUnkOuter, REFIID riid, void** ppvObject) PURE;
    STDMETHOD(LockServer)(THIS_ BOOL fLock) PURE;
};
"""
EXTRA_IIDS = {
    "IUnknown": "00000000-0000-0000-C000-000000000046",
    "IClassFactory": "00000001-0000-0000-C000-000000000046",
}

# methods whose arguments hold a pointer or handle inside a structure: Com32.cpp's S_<iface>_<method>
SPECIAL = {
    ("IDirect3D9", "CreateDevice"), ("IDirect3DDevice9", "Reset"),
    ("IDirect3DDevice9", "CreateAdditionalSwapChain"), ("IDirect3DDevice9", "GetCreationParameters"),
    ("IDirect3DSwapChain9", "GetPresentParameters"), ("IDirect3DSwapChain9", "Present"),
    ("IDirect3DTexture9", "LockRect"), ("IDirect3DCubeTexture9", "LockRect"),
    ("IDirect3DSurface9", "LockRect"), ("IDirect3DVolumeTexture9", "LockBox"),
    ("IDirect3DVolume9", "LockBox"),
    ("IDirectInput8A", "EnumDevices"),
    ("IDirectInputDevice8A", "EnumObjects"), ("IDirectInputDevice8A", "SetDataFormat"),
    ("IDirectInputDevice8A", "GetDeviceData"),
    ("IXAudio2", "RegisterForCallbacks"), ("IXAudio2", "UnregisterForCallbacks"),
    ("IXAudio2", "CreateSourceVoice"), ("IXAudio2", "CreateSubmixVoice"),
    ("IXAudio2", "CreateMasteringVoice"),
    ("IXAudio2Voice", "SetOutputVoices"), ("IXAudio2Voice", "SetEffectChain"),
    ("IXAudio2SourceVoice", "SubmitSourceBuffer"), ("IXAudio2SourceVoice", "GetState"),
    ("IDxDiagProvider", "Initialize"), ("IDxDiagContainer", "GetProp"),
}
# methods not given to the reference yet (structures with pointers inside: force feedback, action
# maps, effect files): logged, E_NOTIMPL
UNSUPPORTED = {
    ("IDirectInput8A", "EnumDevicesBySemantics"), ("IDirectInput8A", "ConfigureDevices"),
    ("IDirectInputDevice8A", "CreateEffect"), ("IDirectInputDevice8A", "EnumEffects"),
    ("IDirectInputDevice8A", "EnumCreatedEffectObjects"), ("IDirectInputDevice8A", "Escape"),
    ("IDirectInputDevice8A", "SendDeviceData"), ("IDirectInputDevice8A", "EnumEffectsInFile"),
    ("IDirectInputDevice8A", "WriteEffectToFile"), ("IDirectInputDevice8A", "BuildActionMap"),
    ("IDirectInputDevice8A", "SetActionMap"), ("IDirectInputDevice8A", "GetImageInfo"),
    ("IDirectInputEffect", "GetParameters"), ("IDirectInputEffect", "SetParameters"),
    ("IDirectInputEffect", "Escape"),
}
# structures laid out differently on x64: a method passing one must be SPECIAL or UNSUPPORTED
NONFLAT = {"D3DPRESENT_PARAMETERS", "D3DDEVICE_CREATION_PARAMETERS", "D3DLOCKED_RECT", "D3DLOCKED_BOX",
           "DIDATAFORMAT", "DIDEVICEOBJECTDATA", "DIEFFECT", "DIACTIONFORMATA", "DIEFFESCAPE",
           "DIFILEEFFECT", "DICONFIGUREDEVICESPARAMSA", "DIDEVICEIMAGEINFOHEADERA",
           "XAUDIO2_VOICE_SENDS", "XAUDIO2_EFFECT_CHAIN", "XAUDIO2_BUFFER", "XAUDIO2_BUFFER_WMA",
           "XAUDIO2_VOICE_STATE", "IXAudio2EngineCallback", "IXAudio2VoiceCallback",
           "DXDIAG_INIT_PARAMS", "VARIANT"}

FLOATS = {"float", "FLOAT"}
HANDLES = {"HWND", "HANDLE", "HDC", "HMONITOR", "HICON", "HMENU", "HKEY"}
BASIC_PTRS = {"LPVOID": "void", "LPCVOID": "void", "PVOID": "void", "LPDWORD": "DWORD",
              "LPUNKNOWN": "IUnknown", "LPGUID": "GUID", "LPCGUID": "GUID", "LPRECT": "RECT",
              "LPCRECT": "RECT", "LPCSTR": "CHAR", "LPSTR": "CHAR", "LPCWSTR": "WCHAR",
              "LPWSTR": "WCHAR", "LPCTSTR": "CHAR", "LPTSTR": "CHAR", "LPLONG": "LONG",
              "REFIID": "IID", "REFGUID": "GUID", "REFCLSID": "GUID"}
MODIFIERS = {"const", "CONST", "struct", "FAR", "unsigned", "signed", "volatile"}


def clean(text):
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.S)
    text = re.sub(r"//[^\n]*", " ", text)
    text = text.replace("\\\n", " ")
    text = re.sub(r"\b__(?:in|out|inout|deref|ecount|bcount|opt|out_ecount|in_ecount|in_bcount|out_bcount|"
                  r"deref_out|in_opt|out_opt|inout_opt|deref_out_opt|out_ecount_opt|in_ecount_opt|"
                  r"in_bcount_opt|out_bcount_opt|out_ecount_part|out_bcount_part|reserved)\w*"
                  r"(?:\([^()]*\))?", " ", text)
    text = re.sub(r"\b_(?:In|Out|Inout|Outptr|Reserved)\w*_(?:\([^()]*\))?", " ", text)
    text = re.sub(r"X2DEFAULT\([^()]*\)", " ", text)
    return text


METHOD = re.compile(r"STDMETHOD(?:_\(\s*([^,()]+?)\s*,\s*(\w+)\s*\)|\(\s*(\w+)\s*\))\s*\(([^;]*?)\)\s*PURE")


def methods_of(body, owner, macros):
    """[(owner, ret, name, [(type, stars)])] in vtable order; a Declare_*_Methods() expanded with
    the interface it is named for as the owner"""
    out = []
    pos = 0
    pat = re.compile(r"(Declare_(\w+)_Methods)\(\)|" + METHOD.pattern)
    for m in pat.finditer(body):
        if m.group(1):
            out += methods_of(macros[m.group(1)], m.group(2), macros)
            continue
        ret, name = (m.group(3), m.group(4)) if m.group(4) else ("HRESULT", m.group(5))
        args = re.sub(r"\bTHIS_?\b", "", m.group(6)).strip()
        params = []
        for a in [x.strip() for x in args.split(",") if x.strip()]:
            toks = a.replace("*", " * ").split()
            if toks == ["void"]:
                continue
            idents = [t for t in toks if t != "*" and t not in MODIFIERS]
            # the last identifier is a name when a type comes before it
            if len(idents) > 1 and toks[-1] != "*":
                toks = toks[:-1]
            stars = toks.count("*")
            base = [t for t in toks if t != "*" and t not in MODIFIERS][-1]
            params.append((base, stars))
        out.append((owner, ret.strip(), name, params))
    return out


def parse(sdk):
    ifaces, iids, typedefs, callbacks = {}, dict(EXTRA_IIDS), {}, set()
    texts = [clean(EXTRA)] + [clean((sdk / h).read_text(encoding="latin-1")) for h in HEADERS]
    for text in texts:
        macros = {m.group(1): m.group(2) for m in re.finditer(r"#define\s+(Declare_\w+_Methods)\(\)(.*)", text)}
        for m in re.finditer(r"DECLARE_INTERFACE(?:_\(\s*(\w+)\s*,\s*(\w+)\s*\)|\(\s*(\w+)\s*\))\s*\{(.*?)\}\s*;",
                             text, flags=re.S):
            name, base = (m.group(1), m.group(2)) if m.group(1) else (m.group(3), None)
            # (each method once: XAudio2 2.7's voice macro expanded in each branch of the header's
            # #ifdefs made IXAudio2Voice 57 methods for its 19, and every source voice method's
            # slot 57 too far. No COM interface here overloads a name)
            seen, ms = set(), []
            for meth in methods_of(m.group(4), name, macros):
                if meth[2] not in seen:
                    seen.add(meth[2])
                    ms.append(meth)
            ifaces.setdefault(name, (base, ms))
        for m in re.finditer(r"DEFINE_GUID\(\s*IID_(\w+)\s*,([^)]*)\)", text):
            iids.setdefault(m.group(1), guid(m.group(2)))
        for m in re.finditer(r"DEFINE_IID\(\s*(\w+)\s*,([^)]*)\)", text):
            iids.setdefault(m.group(1), guid(m.group(2)))
        for m in re.finditer(r"typedef\s+(?:const\s+|CONST\s+)?(?:struct\s+)?(\w+)\s+(?:FAR\s+)?\*\s*(?:FAR\s+)?(\w+)\s*[;,]", text):
            typedefs.setdefault(m.group(2), m.group(1))
        for m in re.finditer(r"\}\s*(\w+)\s*,\s*(?:FAR\s*)?\*\s*(?:FAR\s*)?(LP\w+)", text):
            typedefs.setdefault(m.group(2), m.group(1))
        for m in re.finditer(r"typedef\s+const\s+(\w+)\s+(?:FAR\s+)?\*\s*(LPC\w+)", text):
            typedefs.setdefault(m.group(2), m.group(1))
        for m in re.finditer(r"typedef\s+\w+\s*\(\s*(?:FAR\s+)?(?:PASCAL|CALLBACK|WINAPI)\s*\*\s*(\w+)\s*\)", text):
            callbacks.add(m.group(1))
    return ifaces, iids, typedefs, callbacks


def guid(args):
    p = [int(x.strip(), 16) for x in args.split(",")]
    return f"{p[0]:08X}-{p[1]:04X}-{p[2]:04X}-{p[3]:02X}{p[4]:02X}-" + "".join(f"{x:02X}" for x in p[5:11])


def full_methods(name, ifaces):
    base, ms = ifaces[name]
    # (d3d9.h and dinput.h list every method of an interface, IUnknown's too; XAudio2.h's voices
    # list only their own after the base's macro)
    if ms and ms[0][2] == "QueryInterface" or base is None or base not in ifaces:
        return ms
    # (nor one whose list already begins with its base's, the base's Declare_..._Methods() macro
    # expanded in place: counted twice, IXAudio2SourceVoice's own methods sat 57 slots past its
    # vtable's end, SetFrequencyRatio at 83 for 26, and a sound voice's update called through
    # garbage, 2026-10-28)
    bm = full_methods(base, ifaces)
    if [m[2] for m in ms[:len(bm)]] == [m[2] for m in bm]:
        return ms
    return bm + ms


def resolve(t, stars, typedefs):
    """(base type, pointer depth) with LPxxx typedefs taken apart"""
    for _ in range(4):
        if t in BASIC_PTRS:
            t, stars = BASIC_PTRS[t], stars + 1
        elif t in typedefs and t not in HANDLES:
            t, stars = typedefs[t], stars + 1
        else:
            break
    return t, stars


def generate(ifaces, iids, typedefs, callbacks):
    known = set(ifaces)
    wanted = [n for hs in HEADERS.values() for n in hs] + ["IUnknown", "IClassFactory"]
    lines = ["// Generated by com32gen.py from the DirectX SDK's headers: do not edit. The 32-bit",
             "// vtables of the COM proxies (Com32.h), one thunk per method.",
             '#include "Com32.h"', "", "namespace com32 {", ""]
    flat_ptrs = set()
    decls = []
    emitted = set()
    for iface in wanted:
        ms = full_methods(iface, ifaces)
        names = []
        for k, (owner, ret, mname, params) in enumerate(ms):
            # (a method an interface inherits by its base's macro is the base's thunk: the same slot)
            key = (owner, mname)
            fn = f"S_{owner}_{mname}" if key in SPECIAL else f"T_{owner}_{mname}"
            if fn in emitted:
                names.append(fn)
                continue
            emitted.add(fn)
            kinds = []
            for t, stars in params:
                bt, st = resolve(t, stars, typedefs)
                kinds.append((t, bt, st))
            uses_nonflat = any(bt in NONFLAT for _, bt, _ in kinds) or any(t in callbacks for t, _, _ in kinds)
            if key in SPECIAL:
                decls.append(fn)
                names.append(fn)
                continue
            if key in UNSUPPORTED:
                lines.append(f"static unsigned int {fn}(...) {{ return Unsupported(\"{owner}::{mname}\"); }}")
                names.append(fn)
                continue
            if uses_nonflat:
                sys.exit(f"com32gen: {owner}::{mname} passes a structure laid out differently on x64 "
                         f"({[t for t, _, _ in kinds]}): add it to SPECIAL or UNSUPPORTED")
            sig, pre, call, post = ["uint32_t self"], [], ["n"], []
            ntypes = ["void*"]
            for i, (t, bt, st) in enumerate(kinds):
                a = f"a{i}"
                if st == 0 and bt in FLOATS:
                    sig.append(f"uint64_t {a}")
                    ntypes.append("float")
                    call.append(f"FloatArg({a}, \"{owner}::{mname}\")")
                elif st == 0 and bt == "HINSTANCE":
                    sig.append(f"uint32_t {a}")
                    ntypes.append("void*")
                    call.append(f"Instance32({a})")
                elif st == 0 and bt in HANDLES:
                    sig.append(f"uint32_t {a}")
                    ntypes.append("void*")
                    call.append(f"Handle32({a})")
                elif st == 0:
                    sig.append(f"uint32_t {a}")
                    ntypes.append("uint32_t")
                    call.append(a)
                elif st == 1 and bt in known:
                    sig.append(f"uint32_t {a}")
                    ntypes.append("void*")
                    call.append(f"Unwrap({a})")
                elif st == 1 and bt in HANDLES:
                    sig.append(f"uint32_t {a}")
                    ntypes.append("void*")
                    pre.append(f"void* h{i} = {a} ? Handle32(*At<uint32_t>({a})) : nullptr;")
                    call.append(f"{a} ? &h{i} : nullptr")
                    post.append(f"if ({a}) *At<uint32_t>({a}) = Low(h{i});")
                elif st == 2 and bt in known:
                    sig.append(f"uint32_t {a}")
                    ntypes.append("void*")
                    pre.append(f"void* o{i} = nullptr;")
                    call.append(f"{a} ? &o{i} : nullptr")
                    post.append(f"if ({a}) *At<uint32_t>({a}) = Wrap(o{i}, &{bt}_32);")
                elif st == 2 and bt == "void":
                    # (an interface by the IID before it, QueryInterface's; else memory: Lock's)
                    sig.append(f"uint32_t {a}")
                    ntypes.append("void*")
                    pre.append(f"void* o{i} = nullptr;")
                    call.append(f"{a} ? &o{i} : nullptr")
                    riid = next((f"a{j}" for j in range(i - 1, -1, -1) if kinds[j][1] == "IID"), None)
                    if riid:
                        post.append(f"if ({a}) *At<uint32_t>({a}) = Wrap(o{i}, TypeOf({riid}));")
                    else:
                        post.append(f"if ({a}) *At<uint32_t>({a}) = Low(o{i});")
                elif st == 1:
                    sig.append(f"uint32_t {a}")
                    ntypes.append("void*")
                    call.append(f"At<void>({a})")
                    flat_ptrs.add(bt)
                else:
                    sys.exit(f"com32gen: {owner}::{mname}: {t} ({bt}, {st} deep) not handled")
            rtype = "void" if ret == "void" else "float" if ret in FLOATS else "uint32_t"
            fptr = f"{rtype} (STDMETHODCALLTYPE*)({', '.join(ntypes)})"
            lines.append(f"static unsigned int {fn}({', '.join(sig)}) {{")
            # (its calls counted, Com32.h's ComStat: <ENV>_COMSTATS prints them)
            lines.append(f'    static ComStat stat = {{"{owner}::{mname}", 0, 0, nullptr}};')
            lines.append("    ComCount(&stat);")
            lines.append("    void* n = Unwrap(self);")
            lines += ["    " + p for p in pre]
            invoke = f"reinterpret_cast<{fptr}>(Slot(n, {k}))({', '.join(call)})"
            if rtype == "void":
                lines.append(f"    {invoke};")
                lines += ["    " + p for p in post]
                lines.append("    return 0;")
            elif rtype == "float":
                lines.append(f"    float r = {invoke};")
                lines += ["    " + p for p in post]
                lines.append("    uint32_t bits;")
                lines.append("    memcpy(&bits, &r, 4);")
                lines.append("    return bits;")
            else:
                lines.append(f"    uint32_t r = {invoke};")
                lines += ["    " + p for p in post]
                lines.append("    return r;")
            lines.append("}")
            names.append(fn)
        lines.append(f"static void* const {iface}_thunks[] = {{")
        lines += [f"    reinterpret_cast<void*>({n})," for n in names]
        lines.append("};")
        base = ifaces[iface][0]
        base_ref = f"&{base}_32" if base in wanted else "nullptr"
        iid = iids.get(iface)
        lines.append(f"static const GUID {iface}_iid = {guid_init(iid)};" if iid else "")
        lines.append(f"Type32 {iface}_32 = {{\"{iface}\", {('&' + iface + '_iid') if iid else 'nullptr'}, "
                     f"{base_ref}, {iface}_thunks, {len(names)}, 0}};")
        lines.append("")
        # (bases first: a derived type points at its base's Type32)
    # (Com32.cpp's, by their C names: each takes the reference's words as its own parameters)
    head = [f'extern "C" unsigned int {d}(void);' for d in decls]
    head_ext = [f"extern Type32 {n}_32;" for n in wanted]
    table = ["Type32* const kTypes[] = {"] + [f"    &{n}_32," for n in wanted] + ["    nullptr,", "};"]
    lines = lines[:5] + head_ext + [""] + head + [""] + lines[5:] + table + ["", "}  // namespace com32", ""]
    lines.insert(2, "// The pointers to structures passed through as they are, all laid out alike on x86 and x64: "
                 + ", ".join(sorted(flat_ptrs)))
    return "\n".join(lines)


def guid_init(s):
    p = s.split("-")
    b = p[3] + p[4]
    return ("{0x%s, 0x%s, 0x%s, {%s}}" % (p[0], p[1], p[2], ", ".join("0x" + b[i:i + 2] for i in range(0, 16, 2))))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sdk", type=Path, default=SDK)
    a = ap.parse_args()
    ifaces, iids, typedefs, callbacks = parse(a.sdk)
    missing = [n for hs in HEADERS.values() for n in hs if n not in ifaces]
    if missing:
        sys.exit(f"com32gen: not in the headers: {missing}")
    OUT.write_text(generate(ifaces, iids, typedefs, callbacks), newline="\n")
    print(f"com32gen: {OUT}")


if __name__ == "__main__":
    main()

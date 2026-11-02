// The D3D9 shader translator (Shader.h): shader model 1.1-3.0 bytecode to SPIR-V 1.3 for Vulkan.
//
// The shape of a translated shader: every D3D register file is a Private array of vec4 (r, v, t,
// o, oD, oC), a0 an ivec4, aL an int, p0 a bvec4, oPos/oFog/oPts/oDepth vec4s, all zeroed. The
// D3D program is one SPIR-V function (`d3dmain`), each `label` another (D3D subroutines share the
// registers, so they need no parameters), and the entry point copies the stage's inputs into the
// files, calls d3dmain, then does what D3D's fixed stages after the shader did: the half-pixel
// offset and Y flip of the position, the clamp of shader model 1/2 colors, alpha test, and writes
// the outputs. Constants: c[], i[] and b[] read the stage's uniform block unless a def/defi/defb
// gave the register (the def wins, also under relative addressing: a select per def'd register).
//
// D3D9 numerics followed (DXVK's "strict" float emulation and the D3D9 docs where they differ):
//   mul/mad/dp*/m*x*/dst/dp2add: 0 * anything is 0 (inf and NaN included), as D3D9 hardware did
//   rcp(0) = +inf, rsq(0) = +inf (of |x|), log(0) = -inf (of |x|), pow(x, y) = pow(|x|, y) with
//   pow(0, 0) = 1, pow(0, y<0) = +inf; explicit selects so a driver's 1/0 never decides
//   _sat clamps NaN to 0 (NClamp); cmp is src0 >= 0; cnd is src0 > 0.5; texkill: any of xyz < 0
//   (shader model 1) or of the param's write mask (2+, Wine's reading)
//   nrm of a zero vector is 0 (its rsq taken as FLT_MAX); sincos writes cos to .x, sin to .y
//   mova rounds half away from zero, vs_1_1's mov a0 floors; c[a0.x + n] clamps to the file
//   loop/rep counts clamp to 0..255
#include "Shader.h"

#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <limits>
#include <map>

#include "Runtime.h"
#include "SpirvBuilder.h"

namespace rh::d3d9vk {

uint32_t LinkLocation(uint8_t usage, uint8_t index) {
    auto pair = [&](uint32_t base) { return base + (index < 2 ? index : 1); };
    switch (usage) {
    case 5: return index < 16 ? index : 15;    // TEXCOORD
    case 10: return index < 2 ? 16 + index : 31;   // COLOR
    case 11: return 18;                        // FOG
    case 4: return 19;                         // PSIZE
    case 3: return pair(20);                   // NORMAL
    case 6: return pair(22);                   // TANGENT
    case 7: return pair(24);                   // BINORMAL
    case 0: return pair(26);                   // POSITION (as a varying)
    case 1: return 28;                         // BLENDWEIGHT
    case 2: return 29;                         // BLENDINDICES
    case 12: return 30;                        // DEPTH
    default: return 31;                        // TESSFACTOR, POSITIONT, SAMPLE ...
    }
}

namespace {

// ---- the bytecode (d3d9types.h's D3DSIO_*, D3DSPR_*, D3DSPSM_*) -----------------------------------
enum Opcode : uint32_t {
    kNop = 0, kMov, kAdd, kSub, kMad, kMul, kRcp, kRsq, kDp3, kDp4, kMin, kMax, kSlt, kSge, kExp, kLog, kLit,
    kDst, kLrp, kFrc, kM4x4, kM4x3, kM3x4, kM3x3, kM3x2, kCall, kCallnz, kLoop, kRet, kEndloop, kLabel, kDcl,
    kPow, kCrs, kSgn, kAbs, kNrm, kSincos, kRep, kEndrep, kIf, kIfc, kElse, kEndif, kBreak, kBreakc, kMova,
    kDefb, kDefi,
    kTexcoord = 64, kTexkill, kTex, kTexbem, kTexbeml, kTexreg2ar, kTexreg2gb, kTexm3x2pad, kTexm3x2tex,
    kTexm3x3pad, kTexm3x3tex, kReserved0, kTexm3x3spec, kTexm3x3vspec, kExpp, kLogp, kCnd, kDef, kTexreg2rgb,
    kTexdp3tex, kTexm3x2depth, kTexdp3, kTexm3x3, kTexdepth, kCmp, kBem, kDp2add, kDsx, kDsy, kTexldd, kSetp,
    kTexldl, kBreakp,
    kPhase = 0xFFFD, kComment = 0xFFFE, kEnd = 0xFFFF,
};

enum RegType : uint32_t {
    kRegTemp = 0, kRegInput = 1, kRegConst = 2, kRegAddr = 3, kRegTexture = 3, kRegRastOut = 4, kRegAttrOut = 5,
    kRegOutput = 6, kRegConstInt = 7, kRegColorOut = 8, kRegDepthOut = 9, kRegSampler = 10, kRegConst2 = 11,
    kRegConst3 = 12, kRegConst4 = 13, kRegConstBool = 14, kRegLoop = 15, kRegTempFloat16 = 16, kRegMisc = 17,
    kRegLabel = 18, kRegPredicate = 19,
};

enum SrcMod : uint32_t {
    kModNone = 0, kModNeg, kModBias, kModBiasNeg, kModSign, kModSignNeg, kModComp, kModX2, kModX2Neg, kModDz,
    kModDw, kModAbs, kModAbsNeg, kModNot,
};

constexpr uint32_t kSwizzleIdentity = 0xE4;
constexpr bool kLegacyMul = true;   // 0 * x = 0 in the multiplies (see the top)
constexpr float kInf = std::numeric_limits<float>::infinity();
constexpr float kFltMax = std::numeric_limits<float>::max();

uint32_t RegTypeOf(uint32_t tok) { return ((tok >> 28) & 7) | ((tok >> 8) & 0x18); }

struct Param {
    uint32_t tok = 0, type = 0, reg = 0;
    bool rel = false;                       // relative addressing
    uint32_t relType = kRegAddr, relComp = 0;   // by a0.<relComp> or aL
    uint32_t Swizzle() const { return (tok >> 16) & 0xff; }
    uint32_t Swz(uint32_t c) const { return (tok >> (16 + 2 * c)) & 3; }
    uint32_t Mask() const {
        uint32_t m = (tok >> 16) & 0xf;
        return m ? m : 0xf;
    }
    uint32_t Mod() const { return (tok >> 24) & 0xf; }
    bool Saturate() const { return (tok & (1u << 20)) != 0; }
    int Shift() const { return static_cast<int32_t>(tok << 4) >> 28; }   // ps_1_x _x2 .. _d8
};

struct Inst {
    uint32_t op = 0, ctrl = 0;   // ctrl: bits 16-23 (the comparison, texld's project / bias)
    bool predicated = false, coissue = false, hasDst = false;
    Param dst, pred;
    std::vector<Param> src;
};

struct Decl {
    uint32_t usage = 0, index = 0, samplerType = 0;
    Param reg;
};

bool HasDst(uint32_t op) {
    switch (op) {
    case kNop: case kCall: case kCallnz: case kLoop: case kRet: case kEndloop: case kLabel: case kRep:
    case kEndrep: case kIf: case kIfc: case kElse: case kEndif: case kBreak: case kBreakc: case kBreakp:
    case kPhase:
        return false;
    default:
        return true;   // texkill's one param is encoded as a destination
    }
}

class Translator {
public:
    Translator(ShaderInfo* info, std::string* error) : info_(info), error_(error) {}
    std::vector<uint32_t> Run(const uint32_t* tokens, size_t count);

private:
    struct File {
        uint32_t var = 0, size = 0;
    };
    struct Construct {
        bool loop = false, hadElse = false, usesAL = false;
        uint32_t merge = 0, cont = 0, elseLabel = 0, header = 0;
        uint32_t counter = 0, step = 0, savedAL = 0;   // Function-storage ints
    };
    struct IoDecl {
        uint32_t usage, index, reg, mask;
    };
    struct SamplerVar {
        uint32_t type = 0, var = 0, sampledType = 0;
    };

    bool Fail(const char* fmt, ...) __attribute__((format(printf, 2, 3)));
    bool Parse(const uint32_t* t, size_t n);
    void Prescan();
    void Declare();
    void EmitProgram();
    void Prologue();
    void Epilogue();
    void EmitInst(const Inst& in);

    // values
    uint32_t F(float f) { return b_.ConstF(f); }
    uint32_t I(int32_t i) { return b_.ConstI(i); }
    uint32_t U(uint32_t u) { return b_.ConstU(u); }
    uint32_t Vec4(float x, float y, float z, float w) { return b_.ConstComposite(tVec4_, {F(x), F(y), F(z), F(w)}); }
    uint32_t Splat(uint32_t s) { return b_.Emit(spv::OpCompositeConstruct, tVec4_, {s, s, s, s}); }
    uint32_t SplatB(uint32_t s) { return b_.Emit(spv::OpCompositeConstruct, tBVec4_, {s, s, s, s}); }
    uint32_t Comp(uint32_t v, uint32_t c, uint32_t type = 0) {
        return b_.Emit(spv::OpCompositeExtract, type ? type : tFloat_, {v, c});
    }
    uint32_t Vec(uint32_t x, uint32_t y, uint32_t z, uint32_t w) {
        return b_.Emit(spv::OpCompositeConstruct, tVec4_, {x, y, z, w});
    }
    uint32_t Shuffle(uint32_t type, uint32_t a, uint32_t b, std::initializer_list<uint32_t> comps) {
        std::vector<uint32_t> w{a, b};
        w.insert(w.end(), comps.begin(), comps.end());
        return b_.Emit(spv::OpVectorShuffle, type, w);
    }
    uint32_t Merge(uint32_t type, uint32_t old, uint32_t nw, uint32_t mask) {
        return Shuffle(type, old, nw, {mask & 1 ? 4u : 0u, mask & 2 ? 5u : 1u, mask & 4 ? 6u : 2u, mask & 8 ? 7u : 3u});
    }
    uint32_t Bin(uint32_t op, uint32_t type, uint32_t a, uint32_t b) { return b_.Emit(op, type, {a, b}); }
    uint32_t Select(uint32_t type, uint32_t c, uint32_t a, uint32_t b) {
        return b_.Emit(spv::OpSelect, type, {c, a, b});
    }
    uint32_t LMul(uint32_t a, uint32_t b);    // vec4, 0 * x = 0
    uint32_t LMulS(uint32_t a, uint32_t b);   // float
    uint32_t Dot(uint32_t a, uint32_t b, uint32_t n);
    uint32_t Compare(uint32_t ctrl, uint32_t type, uint32_t a, uint32_t b);
    uint32_t Log2D3D(uint32_t s);   // log2(|s|), -inf at 0

    // registers
    const File* FileOf(uint32_t type) const;
    uint32_t RelIndex(const Param& p);
    uint32_t Index(const Param& p, uint32_t offset, uint32_t size);
    uint32_t RegPtr(const Param& p, uint32_t offset);
    uint32_t LoadReg(const Param& p, uint32_t offset);
    uint32_t LoadConst(const Param& p, uint32_t n);
    uint32_t LoadIntReg(uint32_t reg);
    uint32_t LoadBool(uint32_t reg);
    uint32_t ApplySwizzle(uint32_t v, const Param& p, uint32_t type = 0);
    uint32_t Src(const Inst& in, size_t k, uint32_t offset = 0);
    uint32_t BoolSrc(const Param& p);
    uint32_t PredVec(const Param& p);
    void StoreDst(const Inst& in, uint32_t value);
    void StorePred(const Inst& in, uint32_t value);
    void Flush();

    // flow control
    void BeginIf(uint32_t cond);
    void Else();
    void EndIf();
    void BeginLoop(bool withAL, const Param& ireg);
    void EndLoop(bool withAL);
    const Construct* InnermostLoop() const;
    void KillIf(uint32_t cond);

    // textures and interface
    void AddSampler(uint32_t reg, uint32_t type);
    enum SampleKind { kImplicit, kBias, kLod, kGrad };
    uint32_t Sample(uint32_t reg, uint32_t coord, SampleKind kind, uint32_t extra = 0, uint32_t ddy = 0);
    uint32_t InputAt(uint32_t location);
    uint32_t OutputAt(uint32_t location);
    uint32_t BuiltInVar(uint32_t ptrType, uint32_t storage, uint32_t builtin);
    uint32_t FragCoord();
    uint32_t FrontFacing();

    spv::Builder b_;
    ShaderInfo* info_;
    std::string* error_;
    bool failed_ = false;
    bool ps_ = false;
    uint32_t major_ = 0, minor_ = 0;

    std::vector<Inst> insts_;
    std::vector<Decl> decls_;
    std::map<uint32_t, std::array<uint32_t, 4>> defF_, defI_;
    std::map<uint32_t, uint32_t> defB_;

    // what the prescan found
    std::vector<IoDecl> inDecls_, outDecls_;   // ps_3_0 inputs, vs_3_0 outputs
    struct VsIn {
        bool declared = false;
        uint32_t usage = 0, index = 0;
    } vsIn_[16];
    uint32_t vsUsed_ = 0;                  // v registers read (vertex)
    uint32_t psV_ = 0, psT_ = 0;           // v / t registers used (pixel, shader model 1/2)
    uint32_t rastWritten_ = 0, dWritten_ = 0, tWritten_ = 0;   // shader model 1/2 vertex outputs
    std::map<uint32_t, uint32_t> labels_;  // D3D label -> SPIR-V function

    // types
    uint32_t tVoid_ = 0, tBool_ = 0, tInt_ = 0, tUint_ = 0, tFloat_ = 0, tVec2_ = 0, tVec3_ = 0, tVec4_ = 0;
    uint32_t tIVec4_ = 0, tBVec4_ = 0, tFnVoid_ = 0;
    uint32_t pPrivVec4_ = 0, pFnInt_ = 0, pUniVec4_ = 0, pUniIVec4_ = 0, pUniUint_ = 0;
    uint32_t pPushVec4_ = 0, pPushUint_ = 0, pPushFloat_ = 0, pInVec4_ = 0, pOutVec4_ = 0;

    // variables
    File r_, v_, t_, o_, oD_, oC_;
    uint32_t a0_ = 0, aL_ = 0, p0_ = 0, oPos_ = 0, oFog_ = 0, oPts_ = 0, oDepth_ = 0;
    uint32_t consts_ = 0, push_ = 0, constCount_ = 0;
    uint32_t fragCoord_ = 0, frontFacing_ = 0;
    SamplerVar samplers_[16];
    std::map<uint32_t, uint32_t> inVars_, outVars_;
    std::vector<uint32_t> iface_;

    std::vector<Construct> flow_;
    bool defer_ = false;   // ps_1_x coissue: the pair's stores wait until both have read
    std::vector<std::pair<const Inst*, uint32_t>> pending_;
};

bool Translator::Fail(const char* fmt, ...) {
    if (!failed_) {
        char buf[256];
        va_list ap;
        va_start(ap, fmt);
        vsnprintf(buf, sizeof buf, fmt, ap);
        va_end(ap);
        if (error_) *error_ = buf;
    }
    failed_ = true;
    return false;
}

// ---- parsing ---------------------------------------------------------------------------------------
bool Translator::Parse(const uint32_t* t, size_t n) {
    if (!t || n < 2) return Fail("no bytecode");
    uint32_t ver = t[0];
    if ((ver >> 16) == 0xFFFE) ps_ = false;
    else if ((ver >> 16) == 0xFFFF) ps_ = true;
    else return Fail("bad version token %#x", ver);
    major_ = (ver >> 8) & 0xff;
    minor_ = ver & 0xff;
    if (major_ < 1 || major_ > 3) return Fail("%s_%u_%u", ps_ ? "ps" : "vs", major_, minor_);

    for (size_t i = 1; i < n;) {
        uint32_t tok = t[i];
        uint32_t op = tok & 0xffff;
        if (op == kEnd) return true;
        if (op == kComment) {   // CTAB and the like
            i += 1 + ((tok >> 16) & 0x7fff);
            continue;
        }
        // shader model 2+ says its length; 1 doesn't: every parameter token has bit 31 set, the next
        // instruction token not, except def's four literals
        size_t len;
        if (major_ >= 2) len = (tok >> 24) & 0xf;
        else if (op == kDef) len = 5;
        else for (len = 0; i + 1 + len < n && (t[i + 1 + len] & 0x80000000u); ++len) {}
        if (i + 1 + len > n) return Fail("truncated at token %zu", i);
        const uint32_t* p = t + i + 1;
        i += 1 + len;

        size_t k = 0;
        bool ok = true;
        auto param = [&](Param& pr) {
            if (k >= len) {
                ok = false;
                return;
            }
            pr.tok = p[k++];
            pr.type = RegTypeOf(pr.tok);
            pr.reg = pr.tok & 0x7ff;
            pr.rel = (pr.tok & 0x2000) != 0;
            if (pr.rel && major_ >= 2) {   // the address token follows; vs_1_1's is a0.x implied
                if (k >= len) {
                    ok = false;
                    return;
                }
                uint32_t a = p[k++];
                pr.relType = RegTypeOf(a);
                pr.relComp = (a >> 16) & 3;
            }
        };

        if (op == kDcl) {
            if (len < 2) return Fail("short dcl");
            Decl d;
            d.usage = p[0] & 0x1f;
            d.index = (p[0] >> 16) & 0xf;
            d.samplerType = (p[0] >> 27) & 0xf;
            k = 1;
            param(d.reg);
            if (!ok) return Fail("bad dcl");
            decls_.push_back(d);
            continue;
        }
        if (op == kDef || op == kDefi || op == kDefb) {
            Param d;
            param(d);
            size_t lits = op == kDefb ? 1 : 4;
            if (!ok || len < 1 + lits) return Fail("short def");
            if (op == kDefb) defB_[d.reg] = p[1];
            else (op == kDef ? defF_ : defI_)[d.reg] = {p[1], p[2], p[3], p[4]};
            continue;
        }
        if (op == kPhase || op == kNop) continue;

        Inst in;
        in.op = op;
        in.ctrl = (tok >> 16) & 0xff;
        in.predicated = (tok & 0x10000000u) != 0;
        in.coissue = (tok & 0x40000000u) != 0 && ps_ && major_ == 1;
        in.hasDst = HasDst(op);
        if (in.hasDst) param(in.dst);
        if (in.predicated) param(in.pred);
        while (ok && k < len) {
            Param s;
            param(s);
            if (ok) in.src.push_back(s);
        }
        if (!ok) return Fail("bad parameters of opcode %u", op);
        insts_.push_back(std::move(in));
    }
    return true;   // no end token: what came is the shader
}

void Translator::AddSampler(uint32_t reg, uint32_t type) {
    if (reg >= 16) return;
    if (!samplers_[reg].type) samplers_[reg].type = type;
}

void Translator::Prescan() {
    for (const Decl& d : decls_) {
        const Param& r = d.reg;
        if (r.type == kRegSampler) {
            uint32_t type = d.samplerType;
            if (type < 2 || type > 4) {
                LogOnce("d3d9vk.samplertype", "d3d9vk: sampler type %u taken as 2D", type);
                type = 2;
            }
            AddSampler(r.reg, type);
        } else if (!ps_ && r.type == kRegInput && r.reg < 16) {
            vsIn_[r.reg] = {true, d.usage, d.index};
        } else if (!ps_ && r.type == kRegOutput && major_ >= 3) {
            outDecls_.push_back({d.usage, d.index, r.reg, r.Mask()});
        } else if (ps_ && r.type == kRegInput && major_ >= 3) {
            inDecls_.push_back({d.usage, d.index, r.reg, r.Mask()});
        } else if (ps_ && r.type == kRegInput && r.reg < 10) {
            psV_ |= 1u << r.reg;
        } else if (ps_ && r.type == kRegTexture && r.reg < 8) {
            psT_ |= 1u << r.reg;
        }
    }
    uint32_t constCount = ps_ ? 224 : 256;
    for (const Inst& in : insts_) {
        auto ref = [&](const Param& p, bool write) {
            // what the uniform block must hold: c up to the highest read (+3: a m4x4's rows), all of
            // it under relative addressing; i and b when read (loop / rep / if b# read them as sources)
            if (!write) {
                if (p.type == kRegConst)   // (the banks past 2047 read zero, not the block)
                    info_->floatConsts = std::max(info_->floatConsts, p.rel ? constCount : std::min(constCount, p.reg + 4));
                else if (p.type == kRegConstInt) info_->intConsts = true;
                else if (p.type == kRegConstBool) info_->boolConsts = true;
            }
            if (!ps_) {
                if (!write && p.type == kRegInput && p.reg < 16) vsUsed_ |= p.rel ? 0xffffu : 1u << p.reg;
                if (write && p.type == kRegRastOut && p.reg < 3) rastWritten_ |= 1u << p.reg;
                if (write && p.type == kRegAttrOut && p.reg < 2) dWritten_ |= 1u << p.reg;
                if (write && p.type == kRegOutput && major_ < 3 && p.reg < 8) tWritten_ |= 1u << p.reg;
            } else {
                if (major_ < 3 && p.type == kRegInput && p.reg < 10) psV_ |= 1u << p.reg;
                if (major_ < 3 && p.type == kRegTexture && p.reg < 8) psT_ |= 1u << p.reg;
                if (write && p.type == kRegColorOut && p.reg < 4) info_->outputColors |= 1u << p.reg;
                if (write && p.type == kRegDepthOut) info_->writesDepth = true;
            }
        };
        if (in.hasDst) ref(in.dst, in.op != kTexkill);
        for (const Param& s : in.src) ref(s, false);
        if (in.op == kLabel && !in.src.empty()) labels_[in.src[0].reg] = b_.Id();
        if (ps_ && in.op == kTex && major_ == 1) AddSampler(in.dst.reg, 2);   // ps_1_x: no dcl, 2D assumed
        if ((in.op == kTex || in.op == kTexldl || in.op == kTexldd) && major_ >= 2 && in.src.size() > 1)
            AddSampler(in.src[1].reg, 2);   // undeclared: 2D
    }
    if (ps_ && major_ == 1) info_->outputColors = 1;   // r0
}

// ---- the module's declarations -------------------------------------------------------------------
void Translator::Declare() {
    using namespace spv;
    b_.Capability(1);   // Shader
    tVoid_ = b_.TypeVoid();
    tBool_ = b_.TypeBool();
    tInt_ = b_.TypeInt(true);
    tUint_ = b_.TypeInt(false);
    tFloat_ = b_.TypeFloat();
    tVec2_ = b_.TypeVector(tFloat_, 2);
    tVec3_ = b_.TypeVector(tFloat_, 3);
    tVec4_ = b_.TypeVector(tFloat_, 4);
    tIVec4_ = b_.TypeVector(tInt_, 4);
    tBVec4_ = b_.TypeVector(tBool_, 4);
    tFnVoid_ = b_.TypeFunction(tVoid_);
    pPrivVec4_ = b_.TypePointer(Private, tVec4_);
    pFnInt_ = b_.TypePointer(Function, tInt_);
    pUniVec4_ = b_.TypePointer(Uniform, tVec4_);
    pUniIVec4_ = b_.TypePointer(Uniform, tIVec4_);
    pUniUint_ = b_.TypePointer(Uniform, tUint_);
    pPushVec4_ = b_.TypePointer(PushConstant, tVec4_);
    pPushUint_ = b_.TypePointer(PushConstant, tUint_);
    pPushFloat_ = b_.TypePointer(PushConstant, tFloat_);
    pInVec4_ = b_.TypePointer(spv::Input, tVec4_);   // (rh::d3d9vk::Input is Shader.h's struct)
    pOutVec4_ = b_.TypePointer(Output, tVec4_);

    // the constants: { vec4 c[N]; ivec4 i[16]; uint b[16]; } std140 (every array stride 16)
    constCount_ = ps_ ? 224 : 256;
    uint32_t cArr = b_.TypeLayoutArray(tVec4_, constCount_, 16);
    uint32_t iArr = b_.TypeLayoutArray(tIVec4_, 16, 16);
    uint32_t bArr = b_.TypeLayoutArray(tUint_, 16, 16);
    uint32_t block = b_.TypeStruct({cArr, iArr, bArr});
    b_.Decorate(block, Block);
    b_.MemberDecorate(block, 0, Offset, {0});
    b_.MemberDecorate(block, 1, Offset, {constCount_ * 16});
    b_.MemberDecorate(block, 2, Offset, {constCount_ * 16 + 256});
    consts_ = b_.GlobalVariable(b_.TypePointer(Uniform, block), Uniform);
    b_.Decorate(consts_, DescriptorSet, {0});
    b_.Decorate(consts_, Binding, {ps_ ? 1u : 0u});
    b_.Name(consts_, ps_ ? "PsConsts" : "VsConsts");

    // the push constants: { vec4 viewport; uint alphaFunc; float alphaRef; uint flags; uint pad; }
    uint32_t pushBlock = b_.TypeStruct({tVec4_, tUint_, tFloat_, tUint_, tUint_});
    b_.Decorate(pushBlock, Block);
    const uint32_t offsets[5] = {0, 16, 20, 24, 28};
    for (uint32_t m = 0; m < 5; ++m) b_.MemberDecorate(pushBlock, m, Offset, {offsets[m]});
    push_ = b_.GlobalVariable(b_.TypePointer(PushConstant, pushBlock), PushConstant);

    // the register files
    auto file = [&](uint32_t size) {
        uint32_t arr = b_.TypeArray(tVec4_, size);
        return File{b_.GlobalVariable(b_.TypePointer(Private, arr), Private, b_.ConstNull(arr)), size};
    };
    auto priv = [&](uint32_t type) { return b_.GlobalVariable(b_.TypePointer(Private, type), Private, b_.ConstNull(type)); };
    r_ = file(32);
    if (ps_) {
        v_ = file(10);
        t_ = file(8);
        oC_ = file(4);
        oDepth_ = priv(tVec4_);
    } else {
        v_ = file(16);
        o_ = file(12);
        oD_ = file(2);
        oPos_ = priv(tVec4_);
        oFog_ = priv(tVec4_);
        oPts_ = priv(tVec4_);
        a0_ = priv(tIVec4_);
    }
    aL_ = priv(tInt_);
    p0_ = priv(tBVec4_);

    // the samplers
    for (uint32_t s = 0; s < 16; ++s) {
        SamplerVar& sv = samplers_[s];
        if (!sv.type) continue;
        if (!ps_ && s >= 4) {
            Fail("vertex sampler s%u", s);
            continue;
        }
        uint32_t dim = sv.type == 3 ? DimCube : sv.type == 4 ? Dim3D : Dim2D;
        sv.sampledType = b_.TypeSampledImage(b_.TypeImage(tFloat_, dim));
        sv.var = b_.GlobalVariable(b_.TypePointer(UniformConstant, sv.sampledType), UniformConstant);
        b_.Decorate(sv.var, DescriptorSet, {0});
        b_.Decorate(sv.var, Binding, {(ps_ ? 2u : 18u) + s});
        info_->samplers.push_back({static_cast<uint8_t>(s), static_cast<uint8_t>(sv.type)});
    }
}

uint32_t Translator::InputAt(uint32_t location) {
    uint32_t& v = inVars_[location];
    if (!v) {
        v = b_.GlobalVariable(pInVec4_, spv::Input);
        b_.Decorate(v, spv::Location, {location});
        iface_.push_back(v);
    }
    return v;
}

uint32_t Translator::OutputAt(uint32_t location) {
    uint32_t& v = outVars_[location];
    if (!v) {
        v = b_.GlobalVariable(pOutVec4_, spv::Output);
        b_.Decorate(v, spv::Location, {location});
        iface_.push_back(v);
    }
    return v;
}

uint32_t Translator::BuiltInVar(uint32_t ptrType, uint32_t storage, uint32_t builtin) {
    uint32_t v = b_.GlobalVariable(ptrType, storage);
    b_.Decorate(v, spv::BuiltIn, {builtin});
    iface_.push_back(v);
    return v;
}

uint32_t Translator::FragCoord() {
    if (!fragCoord_) fragCoord_ = BuiltInVar(pInVec4_, spv::Input, spv::FragCoord);
    return fragCoord_;
}

uint32_t Translator::FrontFacing() {
    if (!frontFacing_) frontFacing_ = BuiltInVar(b_.TypePointer(spv::Input, tBool_), spv::Input, spv::FrontFacing);
    return frontFacing_;
}

// ---- arithmetic helpers --------------------------------------------------------------------------
uint32_t Translator::LMul(uint32_t a, uint32_t b) {
    uint32_t prod = Bin(spv::OpFMul, tVec4_, a, b);
    if (!kLegacyMul) return prod;
    uint32_t zero = Vec4(0, 0, 0, 0);
    uint32_t either = Bin(spv::OpLogicalOr, tBVec4_, Bin(spv::OpFOrdEqual, tBVec4_, a, zero),
                          Bin(spv::OpFOrdEqual, tBVec4_, b, zero));
    return Select(tVec4_, either, zero, prod);
}

uint32_t Translator::LMulS(uint32_t a, uint32_t b) {
    uint32_t prod = Bin(spv::OpFMul, tFloat_, a, b);
    if (!kLegacyMul) return prod;
    uint32_t either = Bin(spv::OpLogicalOr, tBool_, Bin(spv::OpFOrdEqual, tBool_, a, F(0)),
                          Bin(spv::OpFOrdEqual, tBool_, b, F(0)));
    return Select(tFloat_, either, F(0), prod);
}

uint32_t Translator::Dot(uint32_t a, uint32_t b, uint32_t n) {
    uint32_t p = LMul(a, b);
    uint32_t sum = Comp(p, 0);
    for (uint32_t c = 1; c < n; ++c) sum = Bin(spv::OpFAdd, tFloat_, sum, Comp(p, c));
    return sum;
}

uint32_t Translator::Compare(uint32_t ctrl, uint32_t type, uint32_t a, uint32_t b) {
    uint32_t op;
    switch (ctrl & 7) {
    case 1: op = spv::OpFOrdGreaterThan; break;
    case 2: op = spv::OpFOrdEqual; break;
    case 3: op = spv::OpFOrdGreaterThanEqual; break;
    case 4: op = spv::OpFOrdLessThan; break;
    case 5: op = spv::OpFUnordNotEqual; break;
    case 6: op = spv::OpFOrdLessThanEqual; break;
    default:
        Fail("comparison %u", ctrl & 7);
        op = spv::OpFOrdEqual;
    }
    return Bin(op, type, a, b);
}

uint32_t Translator::Log2D3D(uint32_t s) {
    uint32_t a = b_.Ext(tFloat_, spv::FAbs, {s});
    return Select(tFloat_, Bin(spv::OpFOrdEqual, tBool_, a, F(0)), F(-kInf), b_.Ext(tFloat_, spv::Log2, {a}));
}

// ---- registers -----------------------------------------------------------------------------------
const Translator::File* Translator::FileOf(uint32_t type) const {
    switch (type) {
    case kRegTemp: case kRegTempFloat16: return &r_;
    case kRegInput: return &v_;
    case kRegTexture: return ps_ ? &t_ : nullptr;   // (a0 in a vertex shader)
    case kRegAttrOut: return ps_ ? nullptr : &oD_;
    case kRegOutput: return ps_ ? nullptr : &o_;
    case kRegColorOut: return ps_ ? &oC_ : nullptr;
    default: return nullptr;
    }
}

uint32_t Translator::RelIndex(const Param& p) {
    if (p.relType == kRegLoop) return b_.Load(tInt_, aL_);
    if (!a0_) {
        Fail("relative addressing by a0 in a pixel shader");
        return I(0);
    }
    return Comp(b_.Load(tIVec4_, a0_), p.relComp, tInt_);
}

uint32_t Translator::Index(const Param& p, uint32_t offset, uint32_t size) {
    uint32_t n = p.reg + offset;
    if (!p.rel) return I(static_cast<int32_t>(std::min(n, size - 1)));
    uint32_t idx = Bin(spv::OpIAdd, tInt_, RelIndex(p), I(static_cast<int32_t>(n)));
    return b_.Ext(tInt_, spv::SClamp, {idx, I(0), I(static_cast<int32_t>(size - 1))});
}

uint32_t Translator::RegPtr(const Param& p, uint32_t offset) {
    if (const File* f = FileOf(p.type)) return b_.Emit(spv::OpAccessChain, pPrivVec4_, {f->var, Index(p, offset, f->size)});
    if (!ps_ && p.type == kRegRastOut) return p.reg == 0 ? oPos_ : p.reg == 1 ? oFog_ : oPts_;
    if (ps_ && p.type == kRegDepthOut) return oDepth_;
    return 0;
}

uint32_t Translator::LoadIntReg(uint32_t reg) {
    auto it = defI_.find(reg);
    if (it != defI_.end()) {
        const auto& v = it->second;
        return b_.ConstComposite(tIVec4_, {I(int32_t(v[0])), I(int32_t(v[1])), I(int32_t(v[2])), I(int32_t(v[3]))});
    }
    uint32_t ptr = b_.Emit(spv::OpAccessChain, pUniIVec4_, {consts_, I(1), I(static_cast<int32_t>(reg & 15))});
    return b_.Load(tIVec4_, ptr);
}

uint32_t Translator::LoadBool(uint32_t reg) {
    auto it = defB_.find(reg);
    if (it != defB_.end()) return b_.ConstBool(it->second != 0);
    uint32_t ptr = b_.Emit(spv::OpAccessChain, pUniUint_, {consts_, I(2), I(static_cast<int32_t>(reg & 15))});
    return Bin(spv::OpINotEqual, tBool_, b_.Load(tUint_, ptr), U(0));
}

uint32_t Translator::LoadConst(const Param& p, uint32_t n) {
    auto defConst = [&](const std::array<uint32_t, 4>& v) {
        float f[4];
        memcpy(f, v.data(), 16);
        return Vec4(f[0], f[1], f[2], f[3]);
    };
    if (!p.rel) {
        auto it = defF_.find(n);
        if (it != defF_.end()) return defConst(it->second);
        if (n >= constCount_) return Vec4(0, 0, 0, 0);
        uint32_t ptr = b_.Emit(spv::OpAccessChain, pUniVec4_, {consts_, I(0), I(static_cast<int32_t>(n))});
        return b_.Load(tVec4_, ptr);
    }
    uint32_t idx = Bin(spv::OpIAdd, tInt_, RelIndex(p), I(static_cast<int32_t>(n)));
    idx = b_.Ext(tInt_, spv::SClamp, {idx, I(0), I(static_cast<int32_t>(constCount_ - 1))});
    uint32_t v = b_.Load(tVec4_, b_.Emit(spv::OpAccessChain, pUniVec4_, {consts_, I(0), idx}));
    // the def'd registers are what a relative read of them sees too
    for (const auto& [reg, value] : defF_) {
        if (reg >= constCount_) continue;
        uint32_t hit = Bin(spv::OpIEqual, tBool_, idx, I(static_cast<int32_t>(reg)));
        v = Select(tVec4_, SplatB(hit), defConst(value), v);
    }
    return v;
}

uint32_t Translator::LoadReg(const Param& p, uint32_t offset) {
    switch (p.type) {
    case kRegConst: return LoadConst(p, p.reg + offset);
    case kRegConst2: case kRegConst3: case kRegConst4:
        LogOnce("d3d9vk.const2", "d3d9vk: constant bank %u (registers past 2047) read", p.type);
        return LoadConst(p, p.reg + offset + 2048 * (p.type - kRegConst2 + 1));
    case kRegConstInt: return b_.Emit(spv::OpConvertSToF, tVec4_, {LoadIntReg(p.reg + offset)});
    case kRegConstBool: return Select(tVec4_, SplatB(LoadBool(p.reg + offset)), Vec4(1, 1, 1, 1), Vec4(0, 0, 0, 0));
    case kRegLoop: return Splat(b_.Emit(spv::OpConvertSToF, tFloat_, {b_.Load(tInt_, aL_)}));
    case kRegPredicate: return Select(tVec4_, b_.Load(tBVec4_, p0_), Vec4(1, 1, 1, 1), Vec4(0, 0, 0, 0));
    case kRegMisc:
        if (!ps_) break;
        if (p.reg == 0)   // vPos: D3D9's pixel centers are on the integers, Vulkan's on the halves
            return Bin(spv::OpFSub, tVec4_, b_.Load(tVec4_, FragCoord()), Vec4(0.5f, 0.5f, 0, 0));
        // vFace: +1 front, -1 back
        return Splat(Select(tFloat_, b_.Load(tBool_, FrontFacing()), F(1), F(-1)));
    case kRegAddr:
        if (!ps_) return b_.Emit(spv::OpConvertSToF, tVec4_, {b_.Load(tIVec4_, a0_)});
        break;   // t, a file
    default: break;
    }
    if (uint32_t ptr = RegPtr(p, offset)) return b_.Load(tVec4_, ptr);
    Fail("read of register type %u", p.type);
    return Vec4(0, 0, 0, 0);
}

uint32_t Translator::ApplySwizzle(uint32_t v, const Param& p, uint32_t type) {
    if (p.Swizzle() == kSwizzleIdentity) return v;
    return Shuffle(type ? type : tVec4_, v, v, {p.Swz(0), p.Swz(1), p.Swz(2), p.Swz(3)});
}

uint32_t Translator::Src(const Inst& in, size_t k, uint32_t offset) {
    if (k >= in.src.size()) {
        Fail("opcode %u: source %zu missing", in.op, k);
        return Vec4(0, 0, 0, 0);
    }
    const Param& p = in.src[k];
    uint32_t v = ApplySwizzle(LoadReg(p, offset), p);
    auto neg = [&](uint32_t x) { return b_.Emit(spv::OpFNegate, tVec4_, {x}); };
    switch (p.Mod()) {
    case kModNone: return v;
    case kModNeg: return neg(v);
    case kModBias: return Bin(spv::OpFSub, tVec4_, v, Vec4(0.5f, 0.5f, 0.5f, 0.5f));
    case kModBiasNeg: return neg(Bin(spv::OpFSub, tVec4_, v, Vec4(0.5f, 0.5f, 0.5f, 0.5f)));
    case kModSign:
        return Bin(spv::OpFSub, tVec4_, Bin(spv::OpFMul, tVec4_, v, Vec4(2, 2, 2, 2)), Vec4(1, 1, 1, 1));
    case kModSignNeg:
        return neg(Bin(spv::OpFSub, tVec4_, Bin(spv::OpFMul, tVec4_, v, Vec4(2, 2, 2, 2)), Vec4(1, 1, 1, 1)));
    case kModComp: return Bin(spv::OpFSub, tVec4_, Vec4(1, 1, 1, 1), v);
    case kModX2: return Bin(spv::OpFMul, tVec4_, v, Vec4(2, 2, 2, 2));
    case kModX2Neg: return neg(Bin(spv::OpFMul, tVec4_, v, Vec4(2, 2, 2, 2)));
    case kModDz: return Bin(spv::OpFDiv, tVec4_, v, Splat(Comp(v, 2)));
    case kModDw: return Bin(spv::OpFDiv, tVec4_, v, Splat(Comp(v, 3)));
    case kModAbs: return b_.Ext(tVec4_, spv::FAbs, {v});
    case kModAbsNeg: return neg(b_.Ext(tVec4_, spv::FAbs, {v}));
    case kModNot: return Bin(spv::OpFSub, tVec4_, Vec4(1, 1, 1, 1), v);   // (a bool read as a float)
    default:
        Fail("source modifier %u", p.Mod());
        return v;
    }
}

// a condition: a bool register, a predicate component, or (else) a float's .x != 0
uint32_t Translator::BoolSrc(const Param& p) {
    uint32_t c;
    if (p.type == kRegConstBool) {
        c = LoadBool(p.reg);
    } else if (p.type == kRegPredicate) {
        c = Comp(b_.Load(tBVec4_, p0_), p.Swz(0), tBool_);
    } else {
        uint32_t v = ApplySwizzle(LoadReg(p, 0), p);
        c = Bin(spv::OpFUnordNotEqual, tBool_, Comp(v, 0), F(0));
    }
    if (p.Mod() == kModNot) c = b_.Emit(spv::OpLogicalNot, tBool_, {c});
    return c;
}

uint32_t Translator::PredVec(const Param& p) {
    uint32_t v = ApplySwizzle(b_.Load(tBVec4_, p0_), p, tBVec4_);
    if (p.Mod() == kModNot) v = b_.Emit(spv::OpLogicalNot, tBVec4_, {v});
    return v;
}

void Translator::StoreDst(const Inst& in, uint32_t value) {
    if (defer_) {
        pending_.emplace_back(&in, value);
        return;
    }
    const Param& d = in.dst;
    uint32_t mask = d.Mask();
    uint32_t v = value;
    if (int sh = d.Shift()) {   // ps_1_x: _x2 _x4 _x8 / _d2 _d4 _d8
        float s = sh > 0 ? float(1 << sh) : 1.0f / float(1 << -sh);
        v = Bin(spv::OpFMul, tVec4_, v, Vec4(s, s, s, s));
    }
    if (d.Saturate()) v = b_.Ext(tVec4_, spv::NClamp, {v, Vec4(0, 0, 0, 0), Vec4(1, 1, 1, 1)});

    if (!ps_ && d.type == kRegAddr) {   // a0: mova rounds half away from zero, vs_1_1's mov floors
        uint32_t rounded;
        if (in.op == kMova) {
            uint32_t mag = b_.Ext(tVec4_, spv::Floor,
                                  {Bin(spv::OpFAdd, tVec4_, b_.Ext(tVec4_, spv::FAbs, {v}), Vec4(.5f, .5f, .5f, .5f))});
            rounded = Bin(spv::OpFMul, tVec4_, mag, b_.Ext(tVec4_, spv::FSign, {v}));
        } else {
            rounded = b_.Ext(tVec4_, spv::Floor, {v});
        }
        uint32_t iv = b_.Emit(spv::OpConvertFToS, tIVec4_, {rounded});
        uint32_t old = b_.Load(tIVec4_, a0_);
        uint32_t merged = mask == 0xf ? iv : Merge(tIVec4_, old, iv, mask);
        if (in.predicated) merged = Select(tIVec4_, PredVec(in.pred), merged, old);
        b_.Store(a0_, merged);
        return;
    }
    uint32_t ptr = RegPtr(d, 0);
    if (!ptr) {
        Fail("write of register type %u", d.type);
        return;
    }
    if (mask == 0xf && !in.predicated) {
        b_.Store(ptr, v);
        return;
    }
    uint32_t old = b_.Load(tVec4_, ptr);
    uint32_t merged = mask == 0xf ? v : Merge(tVec4_, old, v, mask);
    if (in.predicated) merged = Select(tVec4_, PredVec(in.pred), merged, old);
    b_.Store(ptr, merged);
}

void Translator::StorePred(const Inst& in, uint32_t value) {
    if (in.dst.type != kRegPredicate) {
        Fail("setp to register type %u", in.dst.type);
        return;
    }
    uint32_t mask = in.dst.Mask();
    uint32_t old = b_.Load(tBVec4_, p0_);
    uint32_t merged = mask == 0xf ? value : Merge(tBVec4_, old, value, mask);
    if (in.predicated) merged = Select(tBVec4_, PredVec(in.pred), merged, old);
    b_.Store(p0_, merged);
}

void Translator::Flush() {
    auto pending = std::move(pending_);
    pending_.clear();
    for (const auto& [in, v] : pending) StoreDst(*in, v);
}

// ---- flow control --------------------------------------------------------------------------------
void Translator::BeginIf(uint32_t cond) {
    Construct c;
    c.merge = b_.Id();
    c.elseLabel = b_.Id();
    uint32_t then = b_.Id();
    b_.SelectionMerge(c.merge);
    b_.BranchCond(cond, then, c.elseLabel);
    b_.Label(then);
    flow_.push_back(c);
}

void Translator::Else() {
    if (flow_.empty() || flow_.back().loop || flow_.back().hadElse) {
        Fail("else without if");
        return;
    }
    Construct& c = flow_.back();
    b_.Branch(c.merge);
    b_.Label(c.elseLabel);
    c.hadElse = true;
}

void Translator::EndIf() {
    if (flow_.empty() || flow_.back().loop) {
        Fail("endif without if");
        return;
    }
    Construct c = flow_.back();
    flow_.pop_back();
    b_.Branch(c.merge);
    if (!c.hadElse) {
        b_.Label(c.elseLabel);
        b_.Branch(c.merge);
    }
    b_.Label(c.merge);
}

// loop aL, i#: i.x iterations (0..255), aL from i.y by i.z; rep i#: i.x iterations. aL is restored
// after the loop (the enclosing loop's again)
void Translator::BeginLoop(bool withAL, const Param& ireg) {
    if (ireg.type != kRegConstInt) Fail("loop count from register type %u", ireg.type);
    uint32_t iv = LoadIntReg(ireg.reg);
    uint32_t count = b_.Ext(tInt_, spv::SClamp, {Comp(iv, 0, tInt_), I(0), I(255)});
    Construct c;
    c.loop = true;
    c.usesAL = withAL;
    c.counter = b_.LocalVariable(pFnInt_);
    b_.Store(c.counter, count);
    if (withAL) {
        c.savedAL = b_.LocalVariable(pFnInt_);
        c.step = b_.LocalVariable(pFnInt_);
        b_.Store(c.savedAL, b_.Load(tInt_, aL_));
        b_.Store(aL_, Comp(iv, 1, tInt_));
        b_.Store(c.step, Comp(iv, 2, tInt_));
    }
    c.header = b_.Id();
    c.cont = b_.Id();
    c.merge = b_.Id();
    uint32_t body = b_.Id();
    b_.Branch(c.header);
    b_.Label(c.header);
    uint32_t go = Bin(spv::OpSGreaterThan, tBool_, b_.Load(tInt_, c.counter), I(0));
    b_.LoopMerge(c.merge, c.cont);
    b_.BranchCond(go, body, c.merge);
    b_.Label(body);
    flow_.push_back(c);
}

void Translator::EndLoop(bool withAL) {
    if (flow_.empty() || !flow_.back().loop || flow_.back().usesAL != withAL) {
        Fail("%s without %s", withAL ? "endloop" : "endrep", withAL ? "loop" : "rep");
        return;
    }
    Construct c = flow_.back();
    flow_.pop_back();
    b_.Branch(c.cont);
    b_.Label(c.cont);
    b_.Store(c.counter, Bin(spv::OpISub, tInt_, b_.Load(tInt_, c.counter), I(1)));
    if (withAL) b_.Store(aL_, Bin(spv::OpIAdd, tInt_, b_.Load(tInt_, aL_), b_.Load(tInt_, c.step)));
    b_.Branch(c.header);
    b_.Label(c.merge);
    if (withAL) b_.Store(aL_, b_.Load(tInt_, c.savedAL));
}

const Translator::Construct* Translator::InnermostLoop() const {
    for (auto it = flow_.rbegin(); it != flow_.rend(); ++it)
        if (it->loop) return &*it;
    return nullptr;
}

void Translator::KillIf(uint32_t cond) {
    uint32_t kill = b_.Id(), after = b_.Id();
    b_.SelectionMerge(after);
    b_.BranchCond(cond, kill, after);
    b_.Label(kill);
    b_.Kill();
    b_.Label(after);
}

// ---- textures ------------------------------------------------------------------------------------
uint32_t Translator::Sample(uint32_t reg, uint32_t coord, SampleKind kind, uint32_t extra, uint32_t ddy) {
    if (reg >= 16 || !samplers_[reg].var) {
        Fail("sample from undeclared s%u", reg);
        return Vec4(0, 0, 0, 0);
    }
    const SamplerVar& s = samplers_[reg];
    uint32_t img = b_.Load(s.sampledType, s.var);
    bool two = s.type == 2;
    uint32_t ct = two ? tVec2_ : tVec3_;
    auto fit = [&](uint32_t v) { return two ? Shuffle(ct, v, v, {0, 1}) : Shuffle(ct, v, v, {0, 1, 2}); };
    uint32_t c = fit(coord);
    if (!ps_ && (kind == kImplicit || kind == kBias)) {   // no implicit lod outside fragment shaders
        kind = kLod;
        extra = F(0);
    }
    switch (kind) {
    case kImplicit: return b_.Emit(spv::OpImageSampleImplicitLod, tVec4_, {img, c});
    case kBias: return b_.Emit(spv::OpImageSampleImplicitLod, tVec4_, {img, c, spv::Bias, extra});
    case kLod: return b_.Emit(spv::OpImageSampleExplicitLod, tVec4_, {img, c, spv::Lod, extra});
    case kGrad: return b_.Emit(spv::OpImageSampleExplicitLod, tVec4_, {img, c, spv::Grad, fit(extra), fit(ddy)});
    }
    return Vec4(0, 0, 0, 0);
}

// ---- instructions --------------------------------------------------------------------------------
void Translator::EmitInst(const Inst& in) {
    using namespace spv;
    auto src = [&](size_t k) { return Src(in, k); };
    auto ext = [&](uint32_t inst, uint32_t v) { return b_.Ext(tVec4_, inst, {v}); };
    auto bin = [&](uint32_t op, uint32_t a, uint32_t b) { return Bin(op, tVec4_, a, b); };
    auto scalar = [&](size_t k) { return Comp(src(k), 3); };   // a replicate swizzle; .w without one
    const uint32_t zero4 = Vec4(0, 0, 0, 0), one4 = Vec4(1, 1, 1, 1);

    switch (in.op) {
    case kMov: case kMova: StoreDst(in, src(0)); return;
    case kAdd: StoreDst(in, bin(OpFAdd, src(0), src(1))); return;
    case kSub: StoreDst(in, bin(OpFSub, src(0), src(1))); return;
    case kMul: StoreDst(in, LMul(src(0), src(1))); return;
    case kMad: {
        uint32_t p = LMul(src(0), src(1));
        StoreDst(in, bin(OpFAdd, p, src(2)));
        return;
    }
    case kRcp: {
        uint32_t s = scalar(0);
        uint32_t r = Select(tFloat_, Bin(OpFOrdEqual, tBool_, s, F(0)), F(kInf), Bin(OpFDiv, tFloat_, F(1), s));
        StoreDst(in, Splat(r));
        return;
    }
    case kRsq: {
        uint32_t s = b_.Ext(tFloat_, FAbs, {scalar(0)});
        uint32_t r = Select(tFloat_, Bin(OpFOrdEqual, tBool_, s, F(0)), F(kInf), b_.Ext(tFloat_, InverseSqrt, {s}));
        StoreDst(in, Splat(r));
        return;
    }
    case kExp: StoreDst(in, Splat(b_.Ext(tFloat_, Exp2, {scalar(0)}))); return;
    case kExpp: {
        uint32_t s = scalar(0);
        if (major_ >= 2) {
            StoreDst(in, Splat(b_.Ext(tFloat_, Exp2, {s})));
            return;
        }
        // vs_1_1: 2^floor(s), fract(s), 2^s, 1
        uint32_t fl = b_.Ext(tFloat_, Floor, {s});
        StoreDst(in, Vec(b_.Ext(tFloat_, Exp2, {fl}), Bin(OpFSub, tFloat_, s, fl), b_.Ext(tFloat_, Exp2, {s}), F(1)));
        return;
    }
    case kLog: StoreDst(in, Splat(Log2D3D(scalar(0)))); return;
    case kLogp: {
        uint32_t s = scalar(0);
        uint32_t l = Log2D3D(s);
        if (major_ >= 2) {
            StoreDst(in, Splat(l));
            return;
        }
        // vs_1_1: exponent, mantissa, log2, 1
        uint32_t ex = b_.Ext(tFloat_, Floor, {l});
        uint32_t mant = Bin(OpFDiv, tFloat_, b_.Ext(tFloat_, FAbs, {s}), b_.Ext(tFloat_, Exp2, {ex}));
        StoreDst(in, Vec(ex, mant, l, F(1)));
        return;
    }
    case kDp3: StoreDst(in, Splat(Dot(src(0), src(1), 3))); return;
    case kDp4: StoreDst(in, Splat(Dot(src(0), src(1), 4))); return;
    case kMin: StoreDst(in, b_.Ext(tVec4_, FMin, {src(0), src(1)})); return;
    case kMax: StoreDst(in, b_.Ext(tVec4_, FMax, {src(0), src(1)})); return;
    case kSlt: StoreDst(in, Select(tVec4_, Bin(OpFOrdLessThan, tBVec4_, src(0), src(1)), one4, zero4)); return;
    case kSge:
        StoreDst(in, Select(tVec4_, Bin(OpFOrdGreaterThanEqual, tBVec4_, src(0), src(1)), one4, zero4));
        return;
    case kLit: {
        // (1, max(x, 0), x > 0 && y > 0 ? y^clamp(w, -128, 128) : 0, 1)
        uint32_t v = src(0);
        uint32_t x = Comp(v, 0), y = Comp(v, 1), w = Comp(v, 3);
        uint32_t pw = b_.Ext(tFloat_, Pow, {y, b_.Ext(tFloat_, FClamp, {w, F(-128), F(128)})});
        uint32_t lit = Bin(OpLogicalAnd, tBool_, Bin(OpFOrdGreaterThan, tBool_, x, F(0)),
                           Bin(OpFOrdGreaterThan, tBool_, y, F(0)));
        StoreDst(in, Vec(F(1), b_.Ext(tFloat_, FMax, {x, F(0)}), Select(tFloat_, lit, pw, F(0)), F(1)));
        return;
    }
    case kDst: {
        uint32_t a = src(0), b = src(1);
        StoreDst(in, Vec(F(1), LMulS(Comp(a, 1), Comp(b, 1)), Comp(a, 2), Comp(b, 3)));
        return;
    }
    case kLrp: {   // src0 * (src1 - src2) + src2
        uint32_t a = src(0), b = src(1), c = src(2);
        StoreDst(in, bin(OpFAdd, bin(OpFMul, a, bin(OpFSub, b, c)), c));
        return;
    }
    case kFrc: StoreDst(in, ext(Fract, src(0))); return;
    case kM4x4: case kM4x3: case kM3x4: case kM3x3: case kM3x2: {
        uint32_t n = in.op <= kM4x3 ? 4 : 3;
        uint32_t rows = in.op == kM4x4 || in.op == kM3x4 ? 4 : in.op == kM3x2 ? 2 : 3;
        uint32_t a = src(0);
        uint32_t c[4] = {F(0), F(0), F(0), F(0)};
        for (uint32_t r = 0; r < rows; ++r) c[r] = Dot(a, Src(in, 1, r), n);
        StoreDst(in, Vec(c[0], c[1], c[2], c[3]));
        return;
    }
    case kPow: {   // |x|^y; 0^0 = 1, 0^-y = inf
        uint32_t a = b_.Ext(tFloat_, FAbs, {scalar(0)}), e = scalar(1);
        uint32_t p = b_.Ext(tFloat_, Pow, {a, e});
        uint32_t atZero = Select(tFloat_, Bin(OpFOrdGreaterThan, tBool_, e, F(0)), F(0), F(kInf));
        atZero = Select(tFloat_, Bin(OpFOrdEqual, tBool_, e, F(0)), F(1), atZero);
        StoreDst(in, Splat(Select(tFloat_, Bin(OpFOrdEqual, tBool_, a, F(0)), atZero, p)));
        return;
    }
    case kCrs: {
        uint32_t a = src(0), b = src(1);
        uint32_t c = b_.Ext(tVec3_, Cross, {Shuffle(tVec3_, a, a, {0, 1, 2}), Shuffle(tVec3_, b, b, {0, 1, 2})});
        StoreDst(in, Shuffle(tVec4_, c, c, {0, 1, 2, 2}));   // (w is never in crs's mask)
        return;
    }
    case kSgn: StoreDst(in, ext(FSign, src(0))); return;
    case kAbs: StoreDst(in, ext(FAbs, src(0))); return;
    case kNrm: {
        uint32_t v = src(0);
        uint32_t xyz = Shuffle(tVec4_, v, zero4, {0, 1, 2, 4});
        uint32_t d = Dot(xyz, xyz, 3);
        uint32_t rs = Select(tFloat_, Bin(OpFOrdEqual, tBool_, d, F(0)), F(kFltMax), b_.Ext(tFloat_, InverseSqrt, {d}));
        StoreDst(in, bin(OpFMul, v, Splat(rs)));
        return;
    }
    case kSincos: {
        uint32_t s = scalar(0);
        StoreDst(in, Vec(b_.Ext(tFloat_, Cos, {s}), b_.Ext(tFloat_, Sin, {s}), F(0), F(0)));
        return;
    }
    case kDp2add: {
        uint32_t p = LMul(src(0), src(1));
        uint32_t s = Bin(OpFAdd, tFloat_, Bin(OpFAdd, tFloat_, Comp(p, 0), Comp(p, 1)), Comp(src(2), 0));
        StoreDst(in, Splat(s));
        return;
    }
    case kCmp: {
        uint32_t c = Bin(OpFOrdGreaterThanEqual, tBVec4_, src(0), zero4);
        uint32_t a = src(1), b = src(2);
        StoreDst(in, Select(tVec4_, c, a, b));
        return;
    }
    case kCnd: {
        uint32_t c = Bin(OpFOrdGreaterThan, tBVec4_, src(0), Vec4(.5f, .5f, .5f, .5f));
        uint32_t a = src(1), b = src(2);
        StoreDst(in, Select(tVec4_, c, a, b));
        return;
    }
    case kDsx: case kDsy:
        if (!ps_) {
            Fail("dsx/dsy in a vertex shader");
            return;
        }
        StoreDst(in, b_.Emit(in.op == kDsx ? OpDPdx : OpDPdy, tVec4_, {src(0)}));
        return;
    case kSetp: StorePred(in, Compare(in.ctrl, tBVec4_, src(0), src(1))); return;

    // ---- textures ----
    case kTex: {
        if (ps_ && major_ == 1 && minor_ < 4) {   // tex tN: sampler N at texture coordinate N
            uint32_t coord = b_.Load(tVec4_, RegPtr(in.dst, 0));
            StoreDst(in, Sample(in.dst.reg, coord, kImplicit));
            return;
        }
        if (ps_ && major_ == 1) {   // ps_1_4 texld rN, tM/rM: sampler N
            StoreDst(in, Sample(in.dst.reg, src(0), kImplicit));
            return;
        }
        // texld / texldp / texldb dst, coord, sN
        uint32_t coord = src(0);
        if (in.src.size() < 2) {
            Fail("texld without a sampler");
            return;
        }
        uint32_t r;
        if (in.ctrl & 2) {
            r = Sample(in.src[1].reg, coord, kBias, Comp(coord, 3));
        } else {
            if (in.ctrl & 1) coord = bin(OpFDiv, coord, Splat(Comp(coord, 3)));
            r = Sample(in.src[1].reg, coord, kImplicit);
        }
        StoreDst(in, ApplySwizzle(r, in.src[1]));
        return;
    }
    case kTexldl: {
        if (in.src.size() < 2) {
            Fail("texldl without a sampler");
            return;
        }
        uint32_t coord = src(0);
        StoreDst(in, ApplySwizzle(Sample(in.src[1].reg, coord, kLod, Comp(coord, 3)), in.src[1]));
        return;
    }
    case kTexldd: {
        if (in.src.size() < 4) {
            Fail("texldd without gradients");
            return;
        }
        uint32_t coord = src(0), dx = src(2), dy = src(3);
        StoreDst(in, ApplySwizzle(Sample(in.src[1].reg, coord, kGrad, dx, dy), in.src[1]));
        return;
    }
    case kTexcoord: {
        if (ps_ && major_ == 1 && minor_ < 4) {   // texcoord tN: the coordinate clamped, w = 1
            uint32_t v = b_.Load(tVec4_, RegPtr(in.dst, 0));
            v = b_.Ext(tVec4_, NClamp, {v, zero4, one4});
            StoreDst(in, Shuffle(tVec4_, v, one4, {0, 1, 2, 7}));
            return;
        }
        StoreDst(in, src(0));   // ps_1_4 texcrd
        return;
    }
    case kTexkill: {
        if (!ps_) {
            Fail("texkill in a vertex shader");
            return;
        }
        uint32_t ptr = RegPtr(in.dst, 0);
        if (!ptr) {
            Fail("texkill of register type %u", in.dst.type);
            return;
        }
        uint32_t lt = Bin(OpFOrdLessThan, tBVec4_, b_.Load(tVec4_, ptr), zero4);
        uint32_t mask = major_ == 1 ? 7 : in.dst.Mask();
        uint32_t any = 0;
        for (uint32_t c = 0; c < 4; ++c) {
            if (!(mask & (1u << c))) continue;
            uint32_t b = Comp(lt, c, tBool_);
            any = any ? Bin(OpLogicalOr, tBool_, any, b) : b;
        }
        if (any) KillIf(any);
        return;
    }

    // ---- flow control ----
    case kIf:
        if (in.src.empty()) {
            Fail("if without a condition");
            return;
        }
        BeginIf(BoolSrc(in.src[0]));
        return;
    case kIfc: BeginIf(Compare(in.ctrl, tBool_, Comp(src(0), 0), Comp(src(1), 0))); return;
    case kElse: Else(); return;
    case kEndif: EndIf(); return;
    case kLoop:
        if (in.src.size() < 2) {
            Fail("loop without its i register");
            return;
        }
        BeginLoop(true, in.src[1]);
        return;
    case kRep:
        if (in.src.empty()) {
            Fail("rep without its i register");
            return;
        }
        BeginLoop(false, in.src[0]);
        return;
    case kEndloop: EndLoop(true); return;
    case kEndrep: EndLoop(false); return;
    case kBreak: case kBreakc: case kBreakp: {
        const Construct* loop = InnermostLoop();
        if (!loop) {
            Fail("break outside a loop");
            return;
        }
        uint32_t merge = loop->merge;
        if (in.op == kBreak) {
            b_.Branch(merge);
            return;
        }
        if (in.src.empty()) {
            Fail("conditional break without a condition");
            return;
        }
        uint32_t cond = in.op == kBreakc ? Compare(in.ctrl, tBool_, Comp(src(0), 0), Comp(src(1), 0))
                                         : BoolSrc(in.src[0]);
        uint32_t brk = b_.Id(), after = b_.Id();
        b_.SelectionMerge(after);
        b_.BranchCond(cond, brk, after);
        b_.Label(brk);
        b_.Branch(merge);
        b_.Label(after);
        return;
    }
    case kCall: case kCallnz: {
        auto it = in.src.empty() ? labels_.end() : labels_.find(in.src[0].reg);
        if (it == labels_.end()) {
            Fail("call of an undefined label");
            return;
        }
        if (in.op == kCallnz) {
            if (in.src.size() < 2) {
                Fail("callnz without a condition");
                return;
            }
            BeginIf(BoolSrc(in.src[1]));
            b_.Emit(OpFunctionCall, tVoid_, {it->second});
            EndIf();
            return;
        }
        b_.Emit(OpFunctionCall, tVoid_, {it->second});
        return;
    }

    case kTexbem: case kTexbeml: case kTexreg2ar: case kTexreg2gb: case kTexm3x2pad: case kTexm3x2tex:
    case kTexm3x3pad: case kTexm3x3tex: case kTexm3x3spec: case kTexm3x3vspec: case kTexreg2rgb: case kTexdp3tex:
    case kTexm3x2depth: case kTexdp3: case kTexm3x3: case kTexdepth: case kBem:
        Fail("ps_1_x texture instruction %u not supported", in.op);
        return;
    default:
        Fail("opcode %u not supported", in.op);
        return;
    }
}

// ---- the program -----------------------------------------------------------------------------------
void Translator::EmitProgram() {
    uint32_t d3dMain = b_.Id();
    b_.Name(d3dMain, "d3dmain");
    b_.BeginFunction(d3dMain, tVoid_, tFnVoid_);
    for (size_t i = 0; i < insts_.size() && !failed_; ++i) {
        const Inst& in = insts_[i];
        if (in.op == kLabel) {   // the previous function ends, the label's begins
            if (!flow_.empty() || in.src.empty()) {
                Fail("label inside flow control");
                break;
            }
            b_.EndFunction();
            b_.BeginFunction(labels_[in.src[0].reg], tVoid_, tFnVoid_);
            continue;
        }
        if (in.op == kRet) {
            b_.Return();
            continue;
        }
        bool pairs = i + 1 < insts_.size() && insts_[i + 1].coissue;
        if (pairs) defer_ = true;
        EmitInst(in);
        if (in.coissue) {
            defer_ = false;
            Flush();
        }
    }
    if (!failed_ && !flow_.empty()) Fail("unclosed if/loop/rep");
    defer_ = false;
    Flush();
    b_.EndFunction();
    if (failed_) return;

    uint32_t entry = b_.Id();
    b_.Name(entry, "main");
    b_.BeginFunction(entry, tVoid_, tFnVoid_);
    Prologue();
    b_.Emit(spv::OpFunctionCall, tVoid_, {d3dMain});
    Epilogue();
    b_.Return();
    b_.EndFunction();

    b_.EntryPoint(ps_ ? spv::Fragment : spv::Vertex, entry, "main", iface_);
    if (ps_) {
        b_.ExecutionMode(entry, spv::OriginUpperLeft);
        if (info_->writesDepth) b_.ExecutionMode(entry, spv::DepthReplacing);
    }
}

// the stage's inputs into the register files
void Translator::Prologue() {
    auto store = [&](const File& f, uint32_t reg, uint32_t value) {
        b_.Store(b_.Emit(spv::OpAccessChain, pPrivVec4_, {f.var, I(static_cast<int32_t>(reg))}), value);
    };
    if (!ps_) {
        // a location per v register (its number); the device binds the element of its usage there
        for (uint32_t reg = 0; reg < 16; ++reg) {
            const VsIn& d = vsIn_[reg];
            if (!d.declared && !(vsUsed_ & (1u << reg))) continue;
            uint32_t var = b_.GlobalVariable(pInVec4_, spv::Input);
            b_.Decorate(var, spv::Location, {reg});
            iface_.push_back(var);
            store(v_, reg, b_.Load(tVec4_, var));
            info_->inputs.push_back({static_cast<uint8_t>(d.declared ? d.usage : 0xff),
                                     static_cast<uint8_t>(d.declared ? d.index : 0), static_cast<uint8_t>(reg),
                                     static_cast<uint8_t>(reg)});
        }
        return;
    }
    // point sprites (the push constants' flags bit 1): every texture coordinate is (PointCoord, 0, 1)
    uint32_t sprite = 0, spriteCoord = 0;
    auto texcoord = [&](uint32_t value) {
        if (!sprite) {
            uint32_t flags = b_.Load(tUint_, b_.Emit(spv::OpAccessChain, pPushUint_, {push_, I(3)}));
            sprite = SplatB(Bin(spv::OpINotEqual, tBool_, Bin(spv::OpBitwiseAnd, tUint_, flags, U(2)), U(0)));
            uint32_t pc = b_.Load(tVec2_, BuiltInVar(b_.TypePointer(spv::Input, tVec2_), spv::Input, spv::PointCoord));
            spriteCoord = Vec(Comp(pc, 0), Comp(pc, 1), F(0), F(1));
        }
        return Select(tVec4_, sprite, spriteCoord, value);
    };
    if (major_ >= 3) {
        // by (usage, index); a register carrying two semantics (dcl_texcoord0 v1.xy, dcl_texcoord1
        // v1.zw) takes each one's components from its location
        std::map<uint32_t, std::vector<const IoDecl*>> byReg;
        for (const IoDecl& d : inDecls_) byReg[d.reg].push_back(&d);
        for (const auto& [reg, ds] : byReg) {
            if (reg >= v_.size) continue;
            uint32_t value = 0;
            for (const IoDecl* d : ds) {
                uint32_t x = b_.Load(tVec4_, InputAt(LinkLocation(uint8_t(d->usage), uint8_t(d->index))));
                if (d->usage == 5) x = texcoord(x);
                if (ds.size() == 1) value = x;
                else value = Merge(tVec4_, value ? value : Vec4(0, 0, 0, 0), x, d->mask);
            }
            store(v_, reg, value);
        }
        return;
    }
    // shader model 1/2: tN is TEXCOORDn, vN COLORn
    for (uint32_t reg = 0; reg < 8; ++reg)
        if (psT_ & (1u << reg)) store(t_, reg, texcoord(b_.Load(tVec4_, InputAt(LinkLocation(5, uint8_t(reg))))));
    for (uint32_t reg = 0; reg < 2; ++reg)
        if (psV_ & (1u << reg)) store(v_, reg, b_.Load(tVec4_, InputAt(LinkLocation(10, uint8_t(reg)))));
}

// what D3D's stages after the shader did, and the outputs
void Translator::Epilogue() {
    using namespace spv;
    auto load = [&](const File& f, uint32_t reg) {
        return b_.Load(tVec4_, b_.Emit(OpAccessChain, pPrivVec4_, {f.var, I(static_cast<int32_t>(reg))}));
    };
    auto push = [&](uint32_t ptrType, uint32_t type, int32_t member) {
        return b_.Load(type, b_.Emit(OpAccessChain, ptrType, {push_, I(member)}));
    };
    const uint32_t zero4 = Vec4(0, 0, 0, 0), one4 = Vec4(1, 1, 1, 1);

    if (!ps_) {
        uint32_t pos = 0, psize = 0;
        if (major_ >= 3) {
            for (const IoDecl& d : outDecls_) {
                if (d.reg >= o_.size) continue;
                if (d.usage == 0 && d.index == 0) {
                    if (!pos) pos = load(o_, d.reg);
                } else if (d.usage == 4) {
                    if (!psize) psize = Comp(load(o_, d.reg), 0);
                } else {
                    uint32_t loc = LinkLocation(uint8_t(d.usage), uint8_t(d.index));
                    if (!outVars_.count(loc)) b_.Store(OutputAt(loc), load(o_, d.reg));
                }
            }
            if (!pos) {
                LogOnce("d3d9vk.nopos", "d3d9vk: a vs_3_0 without a position output");
                pos = Vec4(0, 0, 0, 1);
            }
        } else {
            pos = b_.Load(tVec4_, oPos_);
            if (rastWritten_ & 4) psize = Comp(b_.Load(tVec4_, oPts_), 0);
            if (rastWritten_ & 2) b_.Store(OutputAt(LinkLocation(11, 0)), b_.Load(tVec4_, oFog_));
            for (uint32_t k = 0; k < 2; ++k)   // shader model 1/2 colors are clamped
                if (dWritten_ & (1u << k))
                    b_.Store(OutputAt(LinkLocation(10, uint8_t(k))), b_.Ext(tVec4_, NClamp, {load(oD_, k), zero4, one4}));
            for (uint32_t k = 0; k < 8; ++k)
                if (tWritten_ & (1u << k)) b_.Store(OutputAt(LinkLocation(5, uint8_t(k))), load(o_, k));
        }
        // the half-pixel offset, (-viewport.x, +viewport.y) * w / 2, then the Y flip
        uint32_t vp = push(pPushVec4_, tVec4_, 0);
        uint32_t w = Comp(pos, 3);
        uint32_t x = Bin(OpFSub, tFloat_, Comp(pos, 0),
                         Bin(OpFMul, tFloat_, Bin(OpFMul, tFloat_, Comp(vp, 0), F(0.5f)), w));
        uint32_t y = Bin(OpFAdd, tFloat_, Comp(pos, 1),
                         Bin(OpFMul, tFloat_, Bin(OpFMul, tFloat_, Comp(vp, 1), F(0.5f)), w));
        uint32_t flags = push(pPushUint_, tUint_, 3);
        uint32_t flip = Bin(OpINotEqual, tBool_, Bin(OpBitwiseAnd, tUint_, flags, U(1)), U(0));
        y = Select(tFloat_, flip, b_.Emit(OpFNegate, tFloat_, {y}), y);
        b_.Store(BuiltInVar(pOutVec4_, Output, Position), Vec(x, y, Comp(pos, 2), w));
        // the point size: the shader's (clamped to POINTSIZE_MAX), else D3DRS_POINTSIZE (viewport.z);
        // always written, so a point list draws at the size D3D9 does whatever the shader
        uint32_t size = psize ? b_.Ext(tFloat_, FMin, {psize, Comp(vp, 3)}) : Comp(vp, 2);
        b_.Store(BuiltInVar(b_.TypePointer(Output, tFloat_), Output, PointSize), size);
        return;
    }

    auto color = [&](uint32_t k) { return major_ == 1 ? load(r_, 0) : load(oC_, k); };
    if (info_->outputColors & 1) {
        // alpha test on oC0.a: D3DCMPFUNC - 1 is a mask of less (1), equal (2), greater (4)
        uint32_t a = Comp(color(0), 3);
        uint32_t func = push(pPushUint_, tUint_, 1);
        uint32_t ref = push(pPushFloat_, tFloat_, 2);
        uint32_t bits = Bin(OpISub, tUint_, func, U(1));
        auto when = [&](uint32_t cmp, uint32_t bit) {
            uint32_t on = Bin(OpINotEqual, tBool_, Bin(OpBitwiseAnd, tUint_, bits, U(bit)), U(0));
            return Bin(OpLogicalAnd, tBool_, Bin(cmp, tBool_, a, ref), on);
        };
        uint32_t pass = Bin(OpLogicalOr, tBool_, when(OpFOrdLessThan, 1), when(OpFOrdEqual, 2));
        pass = Bin(OpLogicalOr, tBool_, pass, when(OpFOrdGreaterThan, 4));
        pass = Bin(OpLogicalOr, tBool_, pass, Bin(OpIEqual, tBool_, func, U(8)));
        KillIf(b_.Emit(OpLogicalNot, tBool_, {pass}));
    }
    for (uint32_t k = 0; k < 4; ++k)
        if (info_->outputColors & (1u << k)) b_.Store(OutputAt(k), color(k));
    if (info_->writesDepth)   // (clamped to [0, 1] as D3D9 does: Vulkan's is undefined outside it)
        b_.Store(BuiltInVar(b_.TypePointer(Output, tFloat_), Output, FragDepth),
                 b_.Ext(tFloat_, NClamp, {Comp(b_.Load(tVec4_, oDepth_), 0), F(0), F(1)}));
}

std::vector<uint32_t> Translator::Run(const uint32_t* tokens, size_t count) {
    if (!Parse(tokens, count)) return {};
    info_->stage = ps_ ? Stage::Pixel : Stage::Vertex;
    info_->major = static_cast<uint8_t>(major_);
    info_->minor = static_cast<uint8_t>(minor_);
    Prescan();
    Declare();
    if (failed_) return {};
    EmitProgram();
    if (failed_) return {};
    return b_.Finish();
}

}  // namespace

std::vector<uint32_t> TranslateShader(const uint32_t* tokens, size_t count, ShaderInfo* info, std::string* error) {
    ShaderInfo local;
    ShaderInfo* out = info ? info : &local;
    *out = ShaderInfo{};
    Translator t(out, error);
    std::vector<uint32_t> spirv = t.Run(tokens, count);
    if (spirv.empty() && error && error->empty()) *error = "translation failed";
    return spirv;
}

}  // namespace rh::d3d9vk

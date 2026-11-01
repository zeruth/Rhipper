// d3d9vk's fixed function: what a draw with no vertex or no pixel shader runs. Two shaders, made
// here as SPIR-V words, whose behaviour comes from a uniform block the device fills from its state,
// so one pipeline serves every FVF draw of the same layout:
//
//   vertex: a pre-transformed position (XYZRHW, screen pixels: a UI quad) to clip space through the
//           viewport, or an untransformed one (XYZ) through world * view * projection; diffuse,
//           specular and two texture coordinate sets passed on at the locations a translated pixel
//           shader reads them (LinkLocation), so either half may be the reference's own
//   pixel:  texture stage 0 as out = clamp(scale * (m*a1*a2 + s1*a1 + s2*a2 + bias)), color and alpha
//           apart, each argument a mix of texture, diffuse, texture factor and specular (one of them
//           selected, or its complement): DISABLE, SELECTARG1/2, MODULATE(2X/4X), ADD(SIGNED(2X)),
//           SUBTRACT, ADDSMOOTH. Then the alpha test from the push constants, as Shader.h's shaders do.
//
// Not covered (logged once each): lighting, fog, texture transforms, TEXCOORDINDEX, stages past 0,
// the blend ops (BLENDDIFFUSEALPHA ...), ALPHAREPLICATE, vertex blending, point sprites.
#include <initializer_list>

#include "Vk.h"

namespace rh::d3d9vk {

namespace {

// ---- a minimal SPIR-V 1.0 builder ------------------------------------------------------------------------
enum : uint32_t {
    OpExtInstImport = 11, OpExtInst = 12, OpMemoryModel = 14, OpEntryPoint = 15, OpExecutionMode = 16,
    OpCapability = 17, OpTypeVoid = 19, OpTypeBool = 20, OpTypeInt = 21, OpTypeFloat = 22, OpTypeVector = 23,
    OpTypeImage = 25, OpTypeSampledImage = 27, OpTypeArray = 28, OpTypeStruct = 30, OpTypePointer = 32,
    OpTypeFunction = 33, OpConstant = 43, OpConstantComposite = 44, OpFunction = 54, OpFunctionEnd = 56,
    OpVariable = 59, OpLoad = 61, OpStore = 62, OpAccessChain = 65, OpDecorate = 71, OpMemberDecorate = 72,
    OpVectorShuffle = 79, OpCompositeConstruct = 80, OpCompositeExtract = 81, OpImageSampleImplicitLod = 87,
    OpFNegate = 127, OpISub = 130, OpFAdd = 129, OpFSub = 131, OpFMul = 133, OpFDiv = 136,
    OpVectorTimesScalar = 142, OpDot = 148, OpSelect = 169, OpINotEqual = 171, OpFOrdEqual = 180,
    OpFOrdLessThan = 184, OpFOrdGreaterThan = 186, OpBitwiseOr = 197, OpBitwiseAnd = 199,
    OpSelectionMerge = 247, OpLabel = 248, OpBranchConditional = 250, OpKill = 252, OpReturn = 253,
};
enum : uint32_t {
    DecBlock = 2, DecArrayStride = 6, DecBuiltIn = 11, DecLocation = 30, DecBinding = 33, DecDescriptorSet = 34,
    DecOffset = 35,
};
enum : uint32_t { SCUniformConstant = 0, SCInput = 1, SCUniform = 2, SCOutput = 3, SCPushConstant = 9, SCFunction = 7 };
enum : uint32_t { GlslFloor = 8, GlslFClamp = 43 };

class Spv {
public:
    uint32_t Id() { return next_++; }

    static void Emit(std::vector<uint32_t>& s, uint32_t op, std::initializer_list<uint32_t> w) {
        s.push_back(static_cast<uint32_t>((w.size() + 1) << 16) | op);
        s.insert(s.end(), w.begin(), w.end());
    }
    static void Emit(std::vector<uint32_t>& s, uint32_t op, const std::vector<uint32_t>& w) {
        s.push_back(static_cast<uint32_t>((w.size() + 1) << 16) | op);
        s.insert(s.end(), w.begin(), w.end());
    }
    static std::vector<uint32_t> Str(const char* str) {
        std::vector<uint32_t> w((strlen(str) + 4) / 4, 0);
        memcpy(w.data(), str, strlen(str));
        return w;
    }

    // a type or constant, made once per opcode and operands
    uint32_t Type(uint32_t op, std::vector<uint32_t> operands) {
        std::vector<uint32_t> key = operands;
        key.insert(key.begin(), op);
        auto it = types_.find(key);
        if (it != types_.end()) return it->second;
        uint32_t id = Id();
        std::vector<uint32_t> w = {id};
        w.insert(w.end(), operands.begin(), operands.end());
        Emit(globals, op, w);
        types_[key] = id;
        return id;
    }
    uint32_t Constant(uint32_t type, std::vector<uint32_t> operands, uint32_t op = OpConstant) {
        std::vector<uint32_t> key = operands;
        key.insert(key.begin(), {op, type});
        auto it = types_.find(key);
        if (it != types_.end()) return it->second;
        uint32_t id = Id();
        std::vector<uint32_t> w = {type, id};
        w.insert(w.end(), operands.begin(), operands.end());
        Emit(globals, op, w);
        types_[key] = id;
        return id;
    }
    uint32_t Void() { return Type(OpTypeVoid, {}); }
    uint32_t Bool() { return Type(OpTypeBool, {}); }
    uint32_t F32() { return Type(OpTypeFloat, {32}); }
    uint32_t U32() { return Type(OpTypeInt, {32, 0}); }
    uint32_t I32() { return Type(OpTypeInt, {32, 1}); }
    uint32_t Vec(uint32_t comp, uint32_t n) { return Type(OpTypeVector, {comp, n}); }
    uint32_t V4() { return Vec(F32(), 4); }
    uint32_t Ptr(uint32_t sc, uint32_t type) { return Type(OpTypePointer, {sc, type}); }
    uint32_t F(float v) {
        uint32_t bits;
        memcpy(&bits, &v, 4);
        return Constant(F32(), {bits});
    }
    uint32_t U(uint32_t v) { return Constant(U32(), {v}); }
    uint32_t I(int32_t v) { return Constant(I32(), {static_cast<uint32_t>(v)}); }
    uint32_t Splat(float v) { return Constant(V4(), {F(v), F(v), F(v), F(v)}, OpConstantComposite); }

    // a global variable (its decorations by the caller)
    uint32_t Var(uint32_t sc, uint32_t type) {
        uint32_t id = Id();
        Emit(globals, OpVariable, {Ptr(sc, type), id, sc});
        if (sc == SCInput || sc == SCOutput) interface.push_back(id);
        return id;
    }
    void Decorate(uint32_t id, uint32_t dec, std::initializer_list<uint32_t> args = {}) {
        std::vector<uint32_t> w = {id, dec};
        w.insert(w.end(), args.begin(), args.end());
        Emit(decorations, OpDecorate, w);
    }
    void MemberDecorate(uint32_t id, uint32_t member, uint32_t dec, uint32_t arg) {
        Emit(decorations, OpMemberDecorate, {id, member, dec, arg});
    }

    // an instruction in the function, its result id returned
    uint32_t Op(uint32_t op, uint32_t type, std::vector<uint32_t> operands) {
        uint32_t id = Id();
        std::vector<uint32_t> w = {type, id};
        w.insert(w.end(), operands.begin(), operands.end());
        Emit(code, op, w);
        return id;
    }
    void Raw(uint32_t op, std::vector<uint32_t> operands) { Emit(code, op, operands); }
    uint32_t Load(uint32_t type, uint32_t ptr) { return Op(OpLoad, type, {ptr}); }
    void Store(uint32_t ptr, uint32_t v) { Raw(OpStore, {ptr, v}); }
    uint32_t X(uint32_t v, uint32_t k) { return Op(OpCompositeExtract, F32(), {v, k}); }
    uint32_t Ext(uint32_t type, uint32_t inst, std::vector<uint32_t> args) {
        std::vector<uint32_t> w = {glsl_, inst};
        w.insert(w.end(), args.begin(), args.end());
        return Op(OpExtInst, type, w);
    }
    uint32_t Add(uint32_t t, uint32_t a, uint32_t b) { return Op(OpFAdd, t, {a, b}); }
    uint32_t Sub(uint32_t t, uint32_t a, uint32_t b) { return Op(OpFSub, t, {a, b}); }
    uint32_t Mul(uint32_t t, uint32_t a, uint32_t b) { return Op(OpFMul, t, {a, b}); }
    uint32_t Scale(uint32_t v, uint32_t s) { return Op(OpVectorTimesScalar, V4(), {v, s}); }

    // a vec4 of a uniform block's array `c` (member 0), element k
    uint32_t UniformVec(uint32_t block, uint32_t k) {
        uint32_t p = Op(OpAccessChain, Ptr(SCUniform, V4()), {block, I(0), I(static_cast<int32_t>(k))});
        return Load(V4(), p);
    }
    // a uniform block { vec4 c[16]; } at a binding of set 0
    uint32_t UniformBlock(uint32_t binding) {
        uint32_t arr = Id();
        Emit(globals, OpTypeArray, {arr, V4(), U(16)});
        Decorate(arr, DecArrayStride, {16});
        uint32_t st = Id();
        Emit(globals, OpTypeStruct, {st, arr});
        Decorate(st, DecBlock);
        MemberDecorate(st, 0, DecOffset, 0);
        uint32_t v = Var(SCUniform, st);
        Decorate(v, DecDescriptorSet, {0});
        Decorate(v, DecBinding, {binding});
        return v;
    }

    void Begin(uint32_t model) {
        model_ = model;
        glsl_ = Id();
        main_ = Id();
        uint32_t fnType = Type(OpTypeFunction, {Void()});
        Emit(code, OpFunction, {Void(), main_, 0, fnType});
        Emit(code, OpLabel, {Id()});
    }
    std::vector<uint32_t> End() {
        Raw(OpReturn, {});
        Raw(OpFunctionEnd, {});
        std::vector<uint32_t> out = {0x07230203u, 0x00010000u, 0, next_, 0};
        Emit(out, OpCapability, {1 /* Shader */});
        std::vector<uint32_t> name = Str("GLSL.std.450");
        name.insert(name.begin(), glsl_);
        Emit(out, OpExtInstImport, name);
        Emit(out, OpMemoryModel, {0 /* Logical */, 1 /* GLSL450 */});
        std::vector<uint32_t> ep = {model_, main_};
        std::vector<uint32_t> mainName = Str("main");
        ep.insert(ep.end(), mainName.begin(), mainName.end());
        ep.insert(ep.end(), interface.begin(), interface.end());
        Emit(out, OpEntryPoint, ep);
        if (model_ == 4) Emit(out, OpExecutionMode, {main_, 7 /* OriginUpperLeft */});
        out.insert(out.end(), decorations.begin(), decorations.end());
        out.insert(out.end(), globals.begin(), globals.end());
        out.insert(out.end(), code.begin(), code.end());
        out[3] = next_;
        return out;
    }

    std::vector<uint32_t> decorations, globals, code, interface;

private:
    uint32_t next_ = 1, glsl_ = 0, main_ = 0, model_ = 0;
    std::map<std::vector<uint32_t>, uint32_t> types_;
};

uint32_t InputVar(Spv& s, uint32_t location) {
    uint32_t v = s.Var(SCInput, s.V4());
    s.Decorate(v, DecLocation, {location});
    return v;
}
uint32_t OutputVar(Spv& s, uint32_t location) {
    uint32_t v = s.Var(SCOutput, s.V4());
    s.Decorate(v, DecLocation, {location});
    return v;
}

}  // namespace

// c[0..3]: the columns of world * view * projection (row vectors, D3D's), c[4].x: 1 for a
// pre-transformed position, c[5]: 2/width, 2/height, the viewport's x, y
std::vector<uint32_t> FixedVertexSpirv() {
    Spv s;
    s.Begin(0 /* Vertex */);
    uint32_t v4 = s.V4(), f32 = s.F32(), b = s.Bool();
    uint32_t inPos = InputVar(s, 0), inCol0 = InputVar(s, 1), inCol1 = InputVar(s, 2), inTex0 = InputVar(s, 3),
             inTex1 = InputVar(s, 4);
    uint32_t outPos = s.Var(SCOutput, v4);
    s.Decorate(outPos, DecBuiltIn, {0 /* Position */});
    uint32_t outCol0 = OutputVar(s, LinkLocation(DU_COLOR, 0)), outCol1 = OutputVar(s, LinkLocation(DU_COLOR, 1));
    uint32_t outTex[8];
    for (uint32_t k = 0; k < 8; k++) outTex[k] = OutputVar(s, LinkLocation(DU_TEXCOORD, static_cast<uint8_t>(k)));
    uint32_t ub = s.UniformBlock(0);

    uint32_t p = s.Load(v4, inPos);
    uint32_t c[6];
    for (uint32_t k = 0; k < 6; k++) c[k] = s.UniformVec(ub, k);
    uint32_t px = s.X(p, 0), py = s.X(p, 1), pz = s.X(p, 2), pw = s.X(p, 3);
    // transformed: clip = p.xyz1 * M, Y flipped into Vulkan's
    uint32_t p1 = s.Op(OpCompositeConstruct, v4, {px, py, pz, s.F(1.0f)});
    uint32_t tx = s.Op(OpDot, f32, {c[0], p1}), ty = s.Op(OpDot, f32, {c[1], p1}), tz = s.Op(OpDot, f32, {c[2], p1}),
             tw = s.Op(OpDot, f32, {c[3], p1});
    uint32_t posT = s.Op(OpCompositeConstruct, v4, {tx, s.Op(OpFNegate, f32, {ty}), tz, tw});
    // pre-transformed: screen pixels through the viewport, w = 1 / rhw
    uint32_t wZero = s.Op(OpFOrdEqual, b, {pw, s.F(0.0f)});
    uint32_t w = s.Op(OpSelect, f32, {wZero, s.F(1.0f), s.Op(OpFDiv, f32, {s.F(1.0f), pw})});
    uint32_t sx = s.X(c[5], 0), sy = s.X(c[5], 1), ox = s.X(c[5], 2), oy = s.X(c[5], 3);
    uint32_t nx = s.Sub(f32, s.Mul(f32, s.Sub(f32, px, ox), sx), s.F(1.0f));
    uint32_t ny = s.Sub(f32, s.Mul(f32, s.Sub(f32, py, oy), sy), s.F(1.0f));
    uint32_t posR = s.Op(OpCompositeConstruct, v4, {s.Mul(f32, nx, w), s.Mul(f32, ny, w), s.Mul(f32, pz, w), w});
    uint32_t rhw = s.Op(OpFOrdGreaterThan, b, {s.X(c[4], 0), s.F(0.5f)});
    uint32_t rhw4 = s.Op(OpCompositeConstruct, s.Vec(b, 4), {rhw, rhw, rhw, rhw});
    s.Store(outPos, s.Op(OpSelect, v4, {rhw4, posR, posT}));
    s.Store(outCol0, s.Load(v4, inCol0));
    s.Store(outCol1, s.Load(v4, inCol1));
    s.Store(outTex[0], s.Load(v4, inTex0));
    s.Store(outTex[1], s.Load(v4, inTex1));
    for (uint32_t k = 2; k < 8; k++) s.Store(outTex[k], s.Splat(0.0f));
    return s.End();
}

// c[0], c[1]: color arguments 1 and 2 as weights of (texture, diffuse, factor, specular); c[2]: m, s1,
// s2, scale; c[3]: bias, complement 1, complement 2. c[4..7] the same for alpha. c[8]: the factor.
std::vector<uint32_t> FixedPixelSpirv() {
    Spv s;
    s.Begin(4 /* Fragment */);
    uint32_t v4 = s.V4(), f32 = s.F32(), u32 = s.U32(), b = s.Bool();
    uint32_t inCol0 = InputVar(s, LinkLocation(DU_COLOR, 0)), inCol1 = InputVar(s, LinkLocation(DU_COLOR, 1)),
             inTex0 = InputVar(s, LinkLocation(DU_TEXCOORD, 0));
    uint32_t out = OutputVar(s, 0);
    uint32_t ub = s.UniformBlock(1);
    uint32_t image = s.Type(OpTypeImage, {f32, 1 /* 2D */, 0, 0, 0, 1, 0 /* Unknown */});
    uint32_t sampled = s.Type(OpTypeSampledImage, {image});
    uint32_t sampler = s.Var(SCUniformConstant, sampled);
    s.Decorate(sampler, DecDescriptorSet, {0});
    s.Decorate(sampler, DecBinding, {2});
    // the push constants (Shader.h): vec4 viewport; uint alphaFunc; float alphaRef; uint flags, pad
    uint32_t pcType = s.Id();
    Spv::Emit(s.globals, OpTypeStruct, {pcType, v4, u32, f32, u32, u32});
    s.Decorate(pcType, DecBlock);
    s.MemberDecorate(pcType, 0, DecOffset, 0);
    s.MemberDecorate(pcType, 1, DecOffset, 16);
    s.MemberDecorate(pcType, 2, DecOffset, 20);
    s.MemberDecorate(pcType, 3, DecOffset, 24);
    s.MemberDecorate(pcType, 4, DecOffset, 28);
    uint32_t pc = s.Var(SCPushConstant, pcType);

    uint32_t col0 = s.Load(v4, inCol0), col1 = s.Load(v4, inCol1), tc = s.Load(v4, inTex0);
    uint32_t uv = s.Op(OpVectorShuffle, s.Vec(f32, 2), {tc, tc, 0, 1});
    uint32_t tex = s.Op(OpImageSampleImplicitLod, v4, {s.Load(sampled, sampler), uv});
    uint32_t c[9];
    for (uint32_t k = 0; k < 9; k++) c[k] = s.UniformVec(ub, k);
    auto arg = [&](uint32_t weights, uint32_t complement) {
        uint32_t a = s.Scale(tex, s.X(weights, 0));
        a = s.Add(v4, a, s.Scale(col0, s.X(weights, 1)));
        a = s.Add(v4, a, s.Scale(c[8], s.X(weights, 2)));
        a = s.Add(v4, a, s.Scale(col1, s.X(weights, 3)));
        // x * (1 - 2k) + k: x, or 1 - x
        uint32_t k = complement;
        uint32_t f = s.Sub(f32, s.F(1.0f), s.Mul(f32, s.F(2.0f), k));
        uint32_t k4 = s.Op(OpCompositeConstruct, v4, {k, k, k, k});
        return s.Add(v4, s.Scale(a, f), k4);
    };
    auto stage = [&](unsigned base) {
        uint32_t ops = c[base + 2], extra = c[base + 3];
        uint32_t a1 = arg(c[base], s.X(extra, 1)), a2 = arg(c[base + 1], s.X(extra, 2));
        uint32_t r = s.Scale(s.Mul(v4, a1, a2), s.X(ops, 0));
        r = s.Add(v4, r, s.Scale(a1, s.X(ops, 1)));
        r = s.Add(v4, r, s.Scale(a2, s.X(ops, 2)));
        uint32_t bias = s.X(extra, 0);
        r = s.Add(v4, r, s.Op(OpCompositeConstruct, v4, {bias, bias, bias, bias}));
        r = s.Scale(r, s.X(ops, 3));
        return s.Ext(v4, GlslFClamp, {r, s.Splat(0.0f), s.Splat(1.0f)});
    };
    uint32_t color = stage(0), alpha = stage(4);
    uint32_t a = s.X(alpha, 3);
    uint32_t result = s.Op(OpCompositeConstruct, v4, {s.X(color, 0), s.X(color, 1), s.X(color, 2), a});

    // the alpha test at 8 bits, as D3D9 compares: pass when (func - 1) has the bit of <, = or >
    uint32_t pfunc = s.Op(OpAccessChain, s.Ptr(SCPushConstant, u32), {pc, s.I(1)});
    uint32_t pref = s.Op(OpAccessChain, s.Ptr(SCPushConstant, f32), {pc, s.I(2)});
    uint32_t func = s.Load(u32, pfunc), ref = s.Load(f32, pref);
    uint32_t a8 = s.Ext(f32, GlslFloor, {s.Add(f32, s.Mul(f32, s.Ext(f32, GlslFClamp, {a, s.F(0.0f), s.F(1.0f)}), s.F(255.0f)), s.F(0.5f))});
    uint32_t r8 = s.Ext(f32, GlslFloor, {s.Add(f32, s.Mul(f32, ref, s.F(255.0f)), s.F(0.5f))});
    uint32_t lt = s.Op(OpSelect, u32, {s.Op(OpFOrdLessThan, b, {a8, r8}), s.U(1), s.U(0)});
    uint32_t eq = s.Op(OpSelect, u32, {s.Op(OpFOrdEqual, b, {a8, r8}), s.U(2), s.U(0)});
    uint32_t gt = s.Op(OpSelect, u32, {s.Op(OpFOrdGreaterThan, b, {a8, r8}), s.U(4), s.U(0)});
    uint32_t bits = s.Op(OpBitwiseOr, u32, {s.Op(OpBitwiseOr, u32, {lt, eq}), gt});
    uint32_t mask = s.Op(OpISub, u32, {func, s.U(1)});
    uint32_t pass = s.Op(OpINotEqual, b, {s.Op(OpBitwiseAnd, u32, {mask, bits}), s.U(0)});
    uint32_t merge = s.Id(), kill = s.Id();
    s.Raw(OpSelectionMerge, {merge, 0});
    s.Raw(OpBranchConditional, {pass, merge, kill});
    s.Raw(OpLabel, {kill});
    s.Raw(OpKill, {});
    s.Raw(OpLabel, {merge});
    s.Store(out, result);
    return s.End();
}

void FixedVertexInfo(ShaderInfo* info) {
    info->stage = Stage::Vertex;
    info->major = 3, info->minor = 0;
    info->inputs = {{DU_POSITION, 0, 0, 0}, {DU_COLOR, 0, 1, 1}, {DU_COLOR, 1, 2, 2}, {DU_TEXCOORD, 0, 3, 3},
                    {DU_TEXCOORD, 1, 4, 4}};
    info->samplers.clear();
}
void FixedPixelInfo(ShaderInfo* info) {
    info->stage = Stage::Pixel;
    info->major = 3, info->minor = 0;
    info->inputs.clear();
    info->samplers = {{0, 2}};
    info->outputColors = 1;
}

namespace {
void Mul4(const float* a, const float* b, float* out) {
    float t[16];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++) {
            float v = 0;
            for (int k = 0; k < 4; k++) v += a[r * 4 + k] * b[k * 4 + c];
            t[r * 4 + c] = v;
        }
    memcpy(out, t, sizeof t);
}
void ColorOf(uint32_t c, float out[4]) {
    out[0] = ((c >> 16) & 255) / 255.0f;
    out[1] = ((c >> 8) & 255) / 255.0f;
    out[2] = (c & 255) / 255.0f;
    out[3] = (c >> 24) / 255.0f;
}
}  // namespace

void FixedVertexConstants(const State& s, uint32_t fvf, float out[16][4]) {
    memset(out, 0, 16 * 16);
    float m[16];
    Mul4(s.transforms[0], s.transforms[1], m);
    Mul4(m, s.transforms[2], m);
    for (int j = 0; j < 4; j++)
        for (int i = 0; i < 4; i++) out[j][i] = m[i * 4 + j];
    out[4][0] = (fvf & FVF_POSITION_MASK) == FVF_XYZRHW ? 1.0f : 0.0f;
    out[5][0] = 2.0f / static_cast<float>(std::max(1u, s.vp.w));
    out[5][1] = 2.0f / static_cast<float>(std::max(1u, s.vp.h));
    out[5][2] = static_cast<float>(s.vp.x);
    out[5][3] = static_cast<float>(s.vp.y);
    if ((fvf & FVF_POSITION_MASK) != FVF_XYZRHW && s.rs[RS_LIGHTING] && (fvf & FVF_NORMAL))
        LogOnce("vk-ff-lighting", "d3d9vk: fixed-function lighting is not done (FVF %#x): vertices unlit", fvf);
    if (s.rs[RS_FOGENABLE]) LogOnce("vk-ff-fog", "d3d9vk: fixed-function fog is not done");
}

void FixedPixelConstants(const State& s, bool textured, float out[16][4]) {
    (void)textured;
    memset(out, 0, 16 * 16);
    auto weights = [&](uint32_t a, float* w, float* complement) {
        switch (a & 0xF) {
            case 0: case 1: w[1] = 1; break;   // DIFFUSE, CURRENT (stage 0's current is diffuse)
            case 2: w[0] = 1; break;           // TEXTURE
            case 3: w[2] = 1; break;           // TFACTOR
            case 4: w[3] = 1; break;           // SPECULAR
            default:
                LogOnce(("vk-ff-arg-" + std::to_string(a & 0xF)).c_str(), "d3d9vk: fixed-function argument %u read as diffuse", a & 0xF);
                w[1] = 1;
                break;
        }
        if (a & 0x10) *complement = 1;
        if (a & 0x20) LogOnce("vk-ff-replicate", "d3d9vk: fixed-function ALPHAREPLICATE is not done");
    };
    auto op = [&](uint32_t o, uint32_t a1, uint32_t a2, float (*c)[4]) {
        float* w1 = c[0];
        float* w2 = c[1];
        float* ops = c[2];   // m, s1, s2, scale
        float* extra = c[3]; // bias, complement 1, complement 2
        ops[3] = 1;
        if (o == 1 /* DISABLE: the current color, diffuse at stage 0 */) {
            w1[1] = 1, ops[1] = 1;
            return;
        }
        weights(a1, w1, &extra[1]);
        weights(a2, w2, &extra[2]);
        switch (o) {
            case 2: ops[1] = 1; break;                                     // SELECTARG1
            case 3: ops[2] = 1; break;                                     // SELECTARG2
            case 4: ops[0] = 1; break;                                     // MODULATE
            case 5: ops[0] = 1, ops[3] = 2; break;                         // MODULATE2X
            case 6: ops[0] = 1, ops[3] = 4; break;                         // MODULATE4X
            case 7: ops[1] = ops[2] = 1; break;                            // ADD
            case 8: ops[1] = ops[2] = 1, extra[0] = -0.5f; break;          // ADDSIGNED
            case 9: ops[1] = ops[2] = 1, extra[0] = -0.5f, ops[3] = 2; break;   // ADDSIGNED2X
            case 10: ops[1] = 1, ops[2] = -1; break;                       // SUBTRACT
            case 11: ops[0] = -1, ops[1] = ops[2] = 1; break;              // ADDSMOOTH
            default:
                LogOnce(("vk-ff-op-" + std::to_string(o)).c_str(), "d3d9vk: fixed-function op %u done as MODULATE", o);
                ops[0] = 1;
                break;
        }
    };
    uint32_t colorOp = s.tss[0][TSS_COLOROP], alphaOp = s.tss[0][TSS_ALPHAOP];
    if (colorOp == 1) alphaOp = 1;   // (a disabled color stage disables its alpha)
    op(colorOp, s.tss[0][TSS_COLORARG1], s.tss[0][TSS_COLORARG2], &out[0]);
    op(alphaOp, s.tss[0][TSS_ALPHAARG1], s.tss[0][TSS_ALPHAARG2], &out[4]);
    ColorOf(s.rs[RS_TEXTUREFACTOR], out[8]);
    if (colorOp != 1 && s.tss[1][TSS_COLOROP] != 1)
        LogOnce("vk-ff-stage1", "d3d9vk: fixed-function texture stage 1 (op %u) is not done: stage 0 only",
                s.tss[1][TSS_COLOROP]);
}

}  // namespace rh::d3d9vk

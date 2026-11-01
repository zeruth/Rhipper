// A small SPIR-V module builder for the D3D9 shader translator (Shader.cpp): ids, the module's
// sections in the order the spec wants them, types and constants deduplicated, decorations,
// functions with their Function-storage variables hoisted to the first block, and blocks.
//
// Blocks: the builder knows whether a block is open. An instruction emitted with none open opens
// an unreachable one first (what follows a D3D `break` or `ret` lands there), a terminator with
// none open is dropped (a `break` already left), and a Label with one still open branches to it
// first (falling through). So the translator's structured constructs stay valid whatever D3D code
// sits between them.
#pragma once

#include <cstdint>
#include <initializer_list>
#include <map>
#include <vector>

namespace rh::d3d9vk::spv {

// ---- the enumerants used (the unified SPIR-V spec's and GLSL.std.450's numbers) -----------------
enum Op : uint32_t {
    OpName = 5, OpExtInstImport = 11, OpExtInst = 12, OpMemoryModel = 14, OpEntryPoint = 15,
    OpExecutionMode = 16, OpCapability = 17, OpTypeVoid = 19, OpTypeBool = 20, OpTypeInt = 21,
    OpTypeFloat = 22, OpTypeVector = 23, OpTypeImage = 25, OpTypeSampledImage = 27, OpTypeArray = 28,
    OpTypeStruct = 30, OpTypePointer = 32, OpTypeFunction = 33, OpConstantTrue = 41, OpConstantFalse = 42,
    OpConstant = 43, OpConstantComposite = 44, OpConstantNull = 46, OpFunction = 54, OpFunctionEnd = 56,
    OpFunctionCall = 57, OpVariable = 59, OpLoad = 61, OpStore = 62, OpAccessChain = 65, OpDecorate = 71,
    OpMemberDecorate = 72, OpVectorShuffle = 79, OpCompositeConstruct = 80, OpCompositeExtract = 81,
    OpImageSampleImplicitLod = 87, OpImageSampleExplicitLod = 88, OpConvertFToS = 110, OpConvertSToF = 111,
    OpConvertUToF = 112, OpBitcast = 124, OpSNegate = 126, OpFNegate = 127, OpIAdd = 128, OpFAdd = 129,
    OpISub = 130, OpFSub = 131, OpIMul = 132, OpFMul = 133, OpFDiv = 136, OpAny = 154, OpAll = 155,
    OpLogicalOr = 166, OpLogicalAnd = 167, OpLogicalNot = 168, OpSelect = 169, OpIEqual = 170,
    OpINotEqual = 171, OpSGreaterThan = 173, OpSGreaterThanEqual = 175, OpSLessThan = 177,
    OpFOrdEqual = 180, OpFUnordNotEqual = 183, OpFOrdLessThan = 184, OpFOrdGreaterThan = 186,
    OpFOrdLessThanEqual = 188, OpFOrdGreaterThanEqual = 190, OpBitwiseAnd = 199, OpDPdx = 207, OpDPdy = 208,
    OpLoopMerge = 246, OpSelectionMerge = 247, OpLabel = 248, OpBranch = 249, OpBranchConditional = 250,
    OpKill = 252, OpReturn = 253,
};

enum Storage : uint32_t {
    UniformConstant = 0, Input = 1, Uniform = 2, Output = 3, Private = 6, Function = 7, PushConstant = 9,
};

enum Decoration : uint32_t {
    Block = 2, ArrayStride = 6, BuiltIn = 11, Flat = 14, Centroid = 16, NonWritable = 24, Location = 30,
    Binding = 33, DescriptorSet = 34, Offset = 35,
};

enum BuiltInKind : uint32_t { Position = 0, PointSize = 1, FragCoord = 15, FrontFacing = 17, FragDepth = 22 };

enum Model : uint32_t { Vertex = 0, Fragment = 4 };
enum Mode : uint32_t { OriginUpperLeft = 7, DepthReplacing = 12 };
enum Dim : uint32_t { Dim2D = 1, Dim3D = 2, DimCube = 3 };
enum ImageOperand : uint32_t { Bias = 1, Lod = 2, Grad = 4 };

// GLSL.std.450
enum GlslOp : uint32_t {
    Round = 1, Trunc = 3, FAbs = 4, FSign = 6, Floor = 8, Fract = 10, Sin = 13, Cos = 14, Pow = 26,
    Exp2 = 29, Log2 = 30, Sqrt = 31, InverseSqrt = 32, FMin = 37, FMax = 40, SMin = 39, SMax = 42,
    FClamp = 43, SClamp = 45, Cross = 68, NMin = 79, NMax = 80, NClamp = 81,
};

class Builder {
public:
    Builder();

    uint32_t Id() { return bound_++; }

    // ---- module level ----------------------------------------------------------------------------
    void Capability(uint32_t cap);
    uint32_t Glsl();   // the GLSL.std.450 import, made once
    void EntryPoint(uint32_t model, uint32_t fn, const char* name, const std::vector<uint32_t>& iface);
    void ExecutionMode(uint32_t fn, uint32_t mode);
    void Name(uint32_t id, const char* name);
    void Decorate(uint32_t id, uint32_t dec, std::initializer_list<uint32_t> args = {});
    void MemberDecorate(uint32_t st, uint32_t member, uint32_t dec, std::initializer_list<uint32_t> args = {});

    // ---- types (deduplicated, except the ones that carry a layout or are aggregates of a block) ----
    uint32_t TypeVoid();
    uint32_t TypeBool();
    uint32_t TypeInt(bool sign);
    uint32_t TypeFloat();
    uint32_t TypeVector(uint32_t comp, uint32_t n);
    uint32_t TypeArray(uint32_t elem, uint32_t len);                          // no layout (Private ...)
    uint32_t TypeLayoutArray(uint32_t elem, uint32_t len, uint32_t stride);   // a new one, ArrayStride
    uint32_t TypeStruct(const std::vector<uint32_t>& members);                // a new one every call
    uint32_t TypePointer(uint32_t storage, uint32_t type);
    uint32_t TypeFunction(uint32_t ret, const std::vector<uint32_t>& params = {});
    uint32_t TypeImage(uint32_t sampled, uint32_t dim);   // sampled, not depth, not arrayed, format unknown
    uint32_t TypeSampledImage(uint32_t image);

    // ---- constants (deduplicated) -----------------------------------------------------------------
    uint32_t ConstU(uint32_t v);
    uint32_t ConstI(int32_t v);
    uint32_t ConstF(float v);
    uint32_t ConstBool(bool v);
    uint32_t ConstComposite(uint32_t type, const std::vector<uint32_t>& parts);
    uint32_t ConstNull(uint32_t type);

    // a module-scope variable (`init`: a constant, or 0)
    uint32_t GlobalVariable(uint32_t ptrType, uint32_t storage, uint32_t init = 0);

    // ---- functions --------------------------------------------------------------------------------
    // opens the function `id` (made by Id(), so calls can refer to it before) and its first block
    void BeginFunction(uint32_t id, uint32_t ret, uint32_t fnType);
    // closes it; an open block returns (void functions only reach here so)
    void EndFunction();
    // a Function-storage variable, declared in the current function's first block
    uint32_t LocalVariable(uint32_t ptrType);

    // ---- instructions -----------------------------------------------------------------------------
    uint32_t Emit(uint32_t op, uint32_t type, std::initializer_list<uint32_t> operands);
    uint32_t Emit(uint32_t op, uint32_t type, const std::vector<uint32_t>& operands);
    void EmitVoid(uint32_t op, std::initializer_list<uint32_t> operands);
    void EmitVoid(uint32_t op, const std::vector<uint32_t>& operands);
    uint32_t Ext(uint32_t type, uint32_t inst, std::initializer_list<uint32_t> args);

    uint32_t Load(uint32_t type, uint32_t ptr) { return Emit(OpLoad, type, {ptr}); }
    void Store(uint32_t ptr, uint32_t value) { EmitVoid(OpStore, {ptr, value}); }

    void Label(uint32_t id);
    void Branch(uint32_t target);
    void BranchCond(uint32_t cond, uint32_t t, uint32_t f);
    void SelectionMerge(uint32_t merge);
    void LoopMerge(uint32_t merge, uint32_t cont);
    void Return();
    void Kill();
    bool InBlock() const { return inBlock_; }

    // the module's words (the header's bound filled in)
    std::vector<uint32_t> Finish();

private:
    static void Put(std::vector<uint32_t>& to, uint32_t op, const uint32_t* words, size_t n);
    static void Put(std::vector<uint32_t>& to, uint32_t op, std::initializer_list<uint32_t> words) {
        Put(to, op, words.begin(), words.size());
    }
    static void PutString(std::vector<uint32_t>& to, const char* s);
    // a deduplicated type or constant: `typed` ones (constants) have their type before the result id
    uint32_t Unique(uint32_t op, const std::vector<uint32_t>& operands, bool typed);
    void Open();   // an unreachable block when none is open

    uint32_t bound_ = 1;
    uint32_t glsl_ = 0;
    std::vector<uint32_t> caps_, imports_, entries_, modes_, debug_, annotations_, globals_, code_;
    std::map<std::vector<uint32_t>, uint32_t> unique_;

    // the function being built
    std::vector<uint32_t> fnHead_, fnVars_, fnBody_;
    bool inFunction_ = false, inBlock_ = false;
};

}  // namespace rh::d3d9vk::spv

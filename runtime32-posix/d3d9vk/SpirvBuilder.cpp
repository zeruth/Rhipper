// The SPIR-V builder (SpirvBuilder.h): the module's sections kept apart while the translator fills
// them in whatever order it finds things, joined in the spec's order by Finish().
#include "SpirvBuilder.h"

#include <cstring>

namespace rh::d3d9vk::spv {

namespace {
constexpr uint32_t kMagic = 0x07230203, kVersion13 = 0x00010300;
constexpr uint32_t kAddressingLogical = 0, kMemoryGlsl450 = 1;
}  // namespace

Builder::Builder() {
    // OpMemoryModel goes between the imports and the entry points: Finish() writes it
}

void Builder::Put(std::vector<uint32_t>& to, uint32_t op, const uint32_t* words, size_t n) {
    to.push_back(static_cast<uint32_t>((n + 1) << 16) | op);
    to.insert(to.end(), words, words + n);
}

// a literal string: UTF-8, nul-terminated, padded with nuls to a word
void Builder::PutString(std::vector<uint32_t>& to, const char* s) {
    size_t len = strlen(s) + 1, words = (len + 3) / 4;
    size_t at = to.size();
    to.resize(at + words, 0);
    memcpy(&to[at], s, len);
}

uint32_t Builder::Unique(uint32_t op, const std::vector<uint32_t>& operands, bool typed) {
    std::vector<uint32_t> key;
    key.reserve(operands.size() + 1);
    key.push_back(op);
    key.insert(key.end(), operands.begin(), operands.end());
    auto it = unique_.find(key);
    if (it != unique_.end()) return it->second;
    uint32_t id = Id();
    std::vector<uint32_t> words;
    if (typed) {
        words.push_back(operands[0]);
        words.push_back(id);
        words.insert(words.end(), operands.begin() + 1, operands.end());
    } else {
        words.push_back(id);
        words.insert(words.end(), operands.begin(), operands.end());
    }
    Put(globals_, op, words.data(), words.size());
    unique_.emplace(std::move(key), id);
    return id;
}

// ---- module level --------------------------------------------------------------------------------
void Builder::Capability(uint32_t cap) { Put(caps_, OpCapability, {cap}); }

uint32_t Builder::Glsl() {
    if (glsl_) return glsl_;
    glsl_ = Id();
    std::vector<uint32_t> w{glsl_};
    PutString(w, "GLSL.std.450");
    Put(imports_, OpExtInstImport, w.data(), w.size());
    return glsl_;
}

void Builder::EntryPoint(uint32_t model, uint32_t fn, const char* name, const std::vector<uint32_t>& iface) {
    std::vector<uint32_t> w{model, fn};
    PutString(w, name);
    w.insert(w.end(), iface.begin(), iface.end());
    Put(entries_, OpEntryPoint, w.data(), w.size());
}

void Builder::ExecutionMode(uint32_t fn, uint32_t mode) { Put(modes_, OpExecutionMode, {fn, mode}); }

void Builder::Name(uint32_t id, const char* name) {
    std::vector<uint32_t> w{id};
    PutString(w, name);
    Put(debug_, OpName, w.data(), w.size());
}

void Builder::Decorate(uint32_t id, uint32_t dec, std::initializer_list<uint32_t> args) {
    std::vector<uint32_t> w{id, dec};
    w.insert(w.end(), args.begin(), args.end());
    Put(annotations_, OpDecorate, w.data(), w.size());
}

void Builder::MemberDecorate(uint32_t st, uint32_t member, uint32_t dec, std::initializer_list<uint32_t> args) {
    std::vector<uint32_t> w{st, member, dec};
    w.insert(w.end(), args.begin(), args.end());
    Put(annotations_, OpMemberDecorate, w.data(), w.size());
}

// ---- types ---------------------------------------------------------------------------------------
uint32_t Builder::TypeVoid() { return Unique(OpTypeVoid, {}, false); }
uint32_t Builder::TypeBool() { return Unique(OpTypeBool, {}, false); }
uint32_t Builder::TypeInt(bool sign) { return Unique(OpTypeInt, {32, sign ? 1u : 0u}, false); }
uint32_t Builder::TypeFloat() { return Unique(OpTypeFloat, {32}, false); }
uint32_t Builder::TypeVector(uint32_t comp, uint32_t n) { return Unique(OpTypeVector, {comp, n}, false); }

uint32_t Builder::TypeArray(uint32_t elem, uint32_t len) {
    return Unique(OpTypeArray, {elem, ConstU(len)}, false);
}

uint32_t Builder::TypeLayoutArray(uint32_t elem, uint32_t len, uint32_t stride) {
    // not deduplicated: the same element and length without the stride may be a Private array, and
    // explicit layout must stay off the types of those
    uint32_t lenId = ConstU(len);
    uint32_t id = Id();
    Put(globals_, OpTypeArray, {id, elem, lenId});
    Decorate(id, ArrayStride, {stride});
    return id;
}

uint32_t Builder::TypeStruct(const std::vector<uint32_t>& members) {
    uint32_t id = Id();
    std::vector<uint32_t> w{id};
    w.insert(w.end(), members.begin(), members.end());
    Put(globals_, OpTypeStruct, w.data(), w.size());
    return id;
}

uint32_t Builder::TypePointer(uint32_t storage, uint32_t type) {
    return Unique(OpTypePointer, {storage, type}, false);
}

uint32_t Builder::TypeFunction(uint32_t ret, const std::vector<uint32_t>& params) {
    std::vector<uint32_t> w{ret};
    w.insert(w.end(), params.begin(), params.end());
    return Unique(OpTypeFunction, w, false);
}

uint32_t Builder::TypeImage(uint32_t sampled, uint32_t dim) {
    // sampled type, dim, depth 0, arrayed 0, multisampled 0, sampled 1 (with a sampler), Unknown format
    return Unique(OpTypeImage, {sampled, dim, 0, 0, 0, 1, 0}, false);
}

uint32_t Builder::TypeSampledImage(uint32_t image) { return Unique(OpTypeSampledImage, {image}, false); }

// ---- constants -----------------------------------------------------------------------------------
uint32_t Builder::ConstU(uint32_t v) { return Unique(OpConstant, {TypeInt(false), v}, true); }
uint32_t Builder::ConstI(int32_t v) { return Unique(OpConstant, {TypeInt(true), static_cast<uint32_t>(v)}, true); }

uint32_t Builder::ConstF(float v) {
    uint32_t bits;
    memcpy(&bits, &v, 4);
    return Unique(OpConstant, {TypeFloat(), bits}, true);
}

uint32_t Builder::ConstBool(bool v) { return Unique(v ? OpConstantTrue : OpConstantFalse, {TypeBool()}, true); }

uint32_t Builder::ConstComposite(uint32_t type, const std::vector<uint32_t>& parts) {
    std::vector<uint32_t> w{type};
    w.insert(w.end(), parts.begin(), parts.end());
    return Unique(OpConstantComposite, w, true);
}

uint32_t Builder::ConstNull(uint32_t type) { return Unique(OpConstantNull, {type}, true); }

uint32_t Builder::GlobalVariable(uint32_t ptrType, uint32_t storage, uint32_t init) {
    uint32_t id = Id();
    if (init) Put(globals_, OpVariable, {ptrType, id, storage, init});
    else Put(globals_, OpVariable, {ptrType, id, storage});
    return id;
}

// ---- functions -----------------------------------------------------------------------------------
void Builder::BeginFunction(uint32_t id, uint32_t ret, uint32_t fnType) {
    fnHead_.clear();
    fnVars_.clear();
    fnBody_.clear();
    Put(fnHead_, OpFunction, {ret, id, 0, fnType});
    Put(fnHead_, OpLabel, {Id()});
    inFunction_ = true;
    inBlock_ = true;
}

void Builder::EndFunction() {
    if (inBlock_) Return();
    code_.insert(code_.end(), fnHead_.begin(), fnHead_.end());
    code_.insert(code_.end(), fnVars_.begin(), fnVars_.end());
    code_.insert(code_.end(), fnBody_.begin(), fnBody_.end());
    Put(code_, OpFunctionEnd, {});
    inFunction_ = false;
}

uint32_t Builder::LocalVariable(uint32_t ptrType) {
    uint32_t id = Id();
    Put(fnVars_, OpVariable, {ptrType, id, Function});
    return id;
}

// ---- instructions --------------------------------------------------------------------------------
void Builder::Open() {
    if (!inBlock_) Label(Id());
}

uint32_t Builder::Emit(uint32_t op, uint32_t type, std::initializer_list<uint32_t> operands) {
    Open();
    uint32_t id = Id();
    std::vector<uint32_t> w{type, id};
    w.insert(w.end(), operands.begin(), operands.end());
    Put(fnBody_, op, w.data(), w.size());
    return id;
}

uint32_t Builder::Emit(uint32_t op, uint32_t type, const std::vector<uint32_t>& operands) {
    Open();
    uint32_t id = Id();
    std::vector<uint32_t> w{type, id};
    w.insert(w.end(), operands.begin(), operands.end());
    Put(fnBody_, op, w.data(), w.size());
    return id;
}

void Builder::EmitVoid(uint32_t op, std::initializer_list<uint32_t> operands) {
    Open();
    Put(fnBody_, op, operands.begin(), operands.size());
}

void Builder::EmitVoid(uint32_t op, const std::vector<uint32_t>& operands) {
    Open();
    Put(fnBody_, op, operands.data(), operands.size());
}

uint32_t Builder::Ext(uint32_t type, uint32_t inst, std::initializer_list<uint32_t> args) {
    std::vector<uint32_t> w{Glsl(), inst};
    w.insert(w.end(), args.begin(), args.end());
    return Emit(OpExtInst, type, w);
}

void Builder::Label(uint32_t id) {
    if (inBlock_) Put(fnBody_, OpBranch, {id});   // fall through into it
    Put(fnBody_, OpLabel, {id});
    inBlock_ = true;
}

void Builder::Branch(uint32_t target) {
    if (!inBlock_) return;
    Put(fnBody_, OpBranch, {target});
    inBlock_ = false;
}

void Builder::BranchCond(uint32_t cond, uint32_t t, uint32_t f) {
    if (!inBlock_) return;
    Put(fnBody_, OpBranchConditional, {cond, t, f});
    inBlock_ = false;
}

void Builder::SelectionMerge(uint32_t merge) {
    Open();
    Put(fnBody_, OpSelectionMerge, {merge, 0});
}

void Builder::LoopMerge(uint32_t merge, uint32_t cont) {
    Open();
    Put(fnBody_, OpLoopMerge, {merge, cont, 0});
}

void Builder::Return() {
    if (!inBlock_) return;
    Put(fnBody_, OpReturn, {});
    inBlock_ = false;
}

void Builder::Kill() {
    if (!inBlock_) return;
    Put(fnBody_, OpKill, {});
    inBlock_ = false;
}

std::vector<uint32_t> Builder::Finish() {
    std::vector<uint32_t> out{kMagic, kVersion13, 0, bound_, 0};
    out.insert(out.end(), caps_.begin(), caps_.end());
    out.insert(out.end(), imports_.begin(), imports_.end());
    Put(out, OpMemoryModel, {kAddressingLogical, kMemoryGlsl450});
    out.insert(out.end(), entries_.begin(), entries_.end());
    out.insert(out.end(), modes_.begin(), modes_.end());
    out.insert(out.end(), debug_.begin(), debug_.end());
    out.insert(out.end(), annotations_.begin(), annotations_.end());
    out.insert(out.end(), globals_.begin(), globals_.end());
    out.insert(out.end(), code_.begin(), code_.end());
    return out;
}

}  // namespace rh::d3d9vk::spv

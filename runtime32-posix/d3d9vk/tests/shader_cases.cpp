// d3d9vk's shader translator on hand-assembled D3D9 bytecode: each case is translated and written
// as <out dir>/<name>.spv for spirv-val. A host build, apart from the runtime (Log/LogOnce are
// stubbed here):
//
//   clang++ -std=c++17 -I runtime32-posix runtime32-posix/d3d9vk/tests/shader_cases.cpp \
//       runtime32-posix/d3d9vk/Shader.cpp runtime32-posix/d3d9vk/SpirvBuilder.cpp -o shader_cases
//   ./shader_cases out && for f in out/*.spv; do spirv-val --target-env vulkan1.1 $f; done
//
// The token helpers below follow d3d9types.h: an instruction token (opcode, controls, length in
// shader model 2+), parameter tokens with bit 31 set (register type split over bits 28-30 and
// 11-12, swizzle or write mask at 16, modifiers at 20 / 24, relative addressing bit 13).
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "d3d9vk/Shader.h"

namespace rh {
void Log(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
void LogOnce(const char*, const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}
}  // namespace rh

namespace {

enum : uint32_t {
    TEMP = 0, INPUT = 1, CONST = 2, ADDR = 3, TEXTURE = 3, RASTOUT = 4, ATTROUT = 5, OUTPUT = 6, CONSTINT = 7,
    COLOROUT = 8, DEPTHOUT = 9, SAMPLER = 10, CONSTBOOL = 14, LOOPREG = 15, LABELREG = 18, PREDICATE = 19,
};
enum : uint32_t {
    MOV = 1, ADD = 2, MUL = 5, RCP = 6, DP4 = 9, M4X4 = 20, CALL = 25, LOOP = 27, RET = 28, ENDLOOP = 29,
    LABEL = 30, DCL = 31, IF = 40, ELSE = 42, ENDIF = 43, BREAKC = 45, MOVA = 46, DEFI = 48, TEXKILL = 65,
    TEX = 66, DEF = 81, SETP = 94, END = 0xFFFF,
};
constexpr uint32_t X = 0x00, Y = 0x55, Z = 0xAA, W = 0xFF, XYZW = 0xE4;   // swizzles

uint32_t Type(uint32_t t) { return ((t & 7) << 28) | ((t & 0x18) << 8); }
uint32_t Ins(uint32_t op, uint32_t len, uint32_t ctrl = 0) { return op | (ctrl << 16) | (len << 24); }
uint32_t Dst(uint32_t type, uint32_t reg, uint32_t mask = 0xf, uint32_t mod = 0) {
    return 0x80000000u | Type(type) | (mask << 16) | (mod << 20) | reg;
}
uint32_t Src(uint32_t type, uint32_t reg, uint32_t swz = XYZW, uint32_t mod = 0, bool rel = false) {
    return 0x80000000u | Type(type) | (swz << 16) | (mod << 24) | (rel ? 0x2000u : 0u) | reg;
}
uint32_t Usage(uint32_t usage, uint32_t index) { return 0x80000000u | usage | (index << 16); }
uint32_t SamplerDcl(uint32_t type) { return 0x80000000u | (type << 27); }
uint32_t Fl(float f) {
    uint32_t u;
    memcpy(&u, &f, 4);
    return u;
}

struct Case {
    const char* name;
    std::vector<uint32_t> tokens;
};

std::vector<Case> Cases() {
    std::vector<Case> cs;

    // vs_3_0: position by a matrix, a texture coordinate through
    cs.push_back({"vs30_passthrough", {
        0xFFFE0300,
        Ins(DCL, 2), Usage(0, 0), Dst(INPUT, 0),
        Ins(DCL, 2), Usage(5, 0), Dst(INPUT, 1),
        Ins(DCL, 2), Usage(0, 0), Dst(OUTPUT, 0),
        Ins(DCL, 2), Usage(5, 0), Dst(OUTPUT, 1),
        Ins(M4X4, 3), Dst(OUTPUT, 0), Src(INPUT, 0), Src(CONST, 0),
        Ins(MOV, 2), Dst(OUTPUT, 1), Src(INPUT, 1),
        END}});

    // ps_2_0: texld t0 from a 2D sampler, times a def'd constant
    cs.push_back({"ps20_texture", {
        0xFFFF0200,
        Ins(DEF, 5), Dst(CONST, 1), Fl(0.5f), Fl(0.5f), Fl(0.5f), Fl(1.0f),
        Ins(DCL, 2), 0x80000000u, Dst(TEXTURE, 0, 0x3),
        Ins(DCL, 2), SamplerDcl(2), Dst(SAMPLER, 0),
        Ins(TEX, 3), Dst(TEMP, 0), Src(TEXTURE, 0), Src(SAMPLER, 0),
        Ins(MUL, 3), Dst(TEMP, 0), Src(TEMP, 0), Src(CONST, 1),
        Ins(MOV, 2), Dst(COLOROUT, 0), Src(TEMP, 0),
        END}});

    // ps_3_0: a loop with a breakc, if/else on a bool constant, setp and a predicated mov, texkill
    cs.push_back({"ps30_flow", {
        0xFFFF0300,
        Ins(DEFI, 5), Dst(CONSTINT, 0), 4, 0, 1, 0,
        Ins(DEF, 5), Dst(CONST, 0), Fl(0.0f), Fl(0.25f), Fl(1.0f), Fl(0.0f),
        Ins(DCL, 2), Usage(5, 0), Dst(INPUT, 0),
        Ins(MOV, 2), Dst(TEMP, 0), Src(CONST, 0, X),
        Ins(LOOP, 2), Src(LOOPREG, 0), Src(CONSTINT, 0),
        Ins(ADD, 3), Dst(TEMP, 0), Src(TEMP, 0), Src(CONST, 0, Y),
        Ins(BREAKC, 2, 1), Src(TEMP, 0, X), Src(CONST, 0, Z),   // breakc_gt
        Ins(ENDLOOP, 0),
        Ins(IF, 1), Src(CONSTBOOL, 0),
        Ins(MOV, 2), Dst(TEMP, 0, 0x2), Src(INPUT, 0, X),
        Ins(ELSE, 0),
        Ins(SETP, 3, 4), Dst(PREDICATE, 0), Src(INPUT, 0), Src(CONST, 0, X),   // setp_lt
        Ins(MOV, 3) | 0x10000000u, Dst(TEMP, 0, 0x4), Src(PREDICATE, 0, X), Src(CONST, 0, Z),   // (p0.x) mov
        Ins(ENDIF, 0),
        Ins(TEXKILL, 1), Dst(TEMP, 0),
        Ins(MOV, 2), Dst(COLOROUT, 0), Src(TEMP, 0),
        END}});

    // vs_2_0: c[a0.x + n] skinning-style rows, a subroutine writing oD0 and oT0
    cs.push_back({"vs20_relative_call", {
        0xFFFE0200,
        Ins(DCL, 2), Usage(0, 0), Dst(INPUT, 0),
        Ins(DCL, 2), Usage(2, 0), Dst(INPUT, 1),
        Ins(MOVA, 2), Dst(ADDR, 0, 0x1), Src(INPUT, 1, X),
        Ins(DP4, 4), Dst(RASTOUT, 0, 0x1), Src(INPUT, 0), Src(CONST, 10, XYZW, 0, true), Src(ADDR, 0, X),
        Ins(DP4, 4), Dst(RASTOUT, 0, 0x2), Src(INPUT, 0), Src(CONST, 11, XYZW, 0, true), Src(ADDR, 0, X),
        Ins(DP4, 4), Dst(RASTOUT, 0, 0x4), Src(INPUT, 0), Src(CONST, 12, XYZW, 0, true), Src(ADDR, 0, X),
        Ins(DP4, 4), Dst(RASTOUT, 0, 0x8), Src(INPUT, 0), Src(CONST, 13, XYZW, 0, true), Src(ADDR, 0, X),
        Ins(CALL, 1), Src(LABELREG, 0),
        Ins(RET, 0),
        Ins(LABEL, 1), Src(LABELREG, 0),
        Ins(MOV, 2), Dst(ATTROUT, 0), Src(CONST, 0),
        Ins(RCP, 2), Dst(TEMP, 0, 0x1), Src(INPUT, 0, W),
        Ins(MUL, 3), Dst(OUTPUT, 0), Src(INPUT, 0), Src(TEMP, 0, X),
        Ins(RET, 0),
        END}});

    // ps_1_1: tex t0, then a coissued pair (shader model 1: no length field)
    cs.push_back({"ps11_coissue", {
        0xFFFF0101,
        Ins(TEX, 0), Dst(TEXTURE, 0),
        Ins(MUL, 0), Dst(TEMP, 0, 0x7), Src(TEXTURE, 0), Src(INPUT, 0),
        Ins(MOV, 0) | 0x40000000u, Dst(TEMP, 0, 0x8), Src(INPUT, 0, W),
        END}});

    // vs_3_0: a point size output (clamped to POINTSIZE_MAX); c read up to c7 (floatConsts 11)
    cs.push_back({"vs30_psize", {
        0xFFFE0300,
        Ins(DCL, 2), Usage(0, 0), Dst(INPUT, 0),
        Ins(DCL, 2), Usage(0, 0), Dst(OUTPUT, 0),
        Ins(DCL, 2), Usage(4, 0), Dst(OUTPUT, 1, 0x1),
        Ins(MOV, 2), Dst(OUTPUT, 0), Src(INPUT, 0),
        Ins(MOV, 2), Dst(OUTPUT, 1, 0x1), Src(CONST, 7, X),
        END}});

    // ps_3_0: a texture coordinate (a point sprite's when the push flag says), oDepth (clamped)
    cs.push_back({"ps30_sprite_depth", {
        0xFFFF0300,
        Ins(DCL, 2), Usage(5, 0), Dst(INPUT, 0),
        Ins(DCL, 2), SamplerDcl(2), Dst(SAMPLER, 0),
        Ins(TEX, 3), Dst(TEMP, 0), Src(INPUT, 0), Src(SAMPLER, 0),
        Ins(MOV, 2), Dst(COLOROUT, 0), Src(TEMP, 0),
        Ins(MOV, 2), Dst(DEPTHOUT, 0, 0x1), Src(INPUT, 0, Z),
        END}});

    return cs;
}

}  // namespace

int main(int argc, char** argv) {
    std::string dir = argc > 1 ? argv[1] : ".";
    int failures = 0;
    for (const Case& c : Cases()) {
        rh::d3d9vk::ShaderInfo info;
        std::string error;
        std::vector<uint32_t> spirv = rh::d3d9vk::TranslateShader(c.tokens.data(), c.tokens.size(), &info, &error);
        if (spirv.empty()) {
            printf("%-22s FAILED: %s\n", c.name, error.c_str());
            ++failures;
            continue;
        }
        std::string path = dir + "/" + c.name + ".spv";
        FILE* f = fopen(path.c_str(), "wb");
        if (!f) {
            printf("%-22s cannot write %s\n", c.name, path.c_str());
            ++failures;
            continue;
        }
        fwrite(spirv.data(), 4, spirv.size(), f);
        fclose(f);
        printf("%-22s %s_%u_%u  %zu words  inputs %zu  samplers %zu  colors %#x%s  c %u%s%s\n", c.name,
               info.stage == rh::d3d9vk::Stage::Pixel ? "ps" : "vs", info.major, info.minor, spirv.size(),
               info.inputs.size(), info.samplers.size(), info.outputColors, info.writesDepth ? "  depth" : "",
               info.floatConsts, info.intConsts ? " i" : "", info.boolConsts ? " b" : "");
    }
    return failures ? 1 : 0;
}

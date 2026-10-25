# Ghidra's decompiler built from the sources its release ships, with Rhipper's fixes on top.
#
#   decompile.exe   the Ghidra-mode decompiler: install.sh puts it in place of the release's
#   decomp_dbg.exe  the console, which replays a function from a decompiler debug XML
#                   (ghidra/DebugDecompile.java) without a Ghidra session
#
# A file in patch/ replaces the release's file of the same name; nothing else is changed.
#
#   cmake -S ghidra/decompiler -B build/decompiler -DGHIDRA=<install> && cmake --build build/decompiler --config Release
cmake_minimum_required(VERSION 3.20)
project(rhipper_decompiler CXX C)

if(NOT GHIDRA)
    file(GLOB GHIDRA_GUESS "C:/Users/tyler/tools/ghidra_*")
    list(GET GHIDRA_GUESS 0 GHIDRA)
endif()
set(SRC "${GHIDRA}/Ghidra/Features/Decompiler/src/decompile/cpp")
set(ZLIB "${GHIDRA}/Ghidra/Features/Decompiler/src/decompile/zlib")
set(PATCH "${CMAKE_CURRENT_SOURCE_DIR}/patch")

# the Makefile's sets
set(CORE xml marshal space float address pcoderaw translate opcodes globalcontext)
set(DECCORE capability architecture options graph cover block cast typeop database cpool comment
    stringmanage modelrules fspec action loadimage grammar varnode op type variable varmap jumptable
    emulate emulateutil flow userop expression multiprecision funcdata funcdata_block funcdata_op
    funcdata_varnode unionresolve pcodeinject heritage prefersplit rangeutil ruleaction subflow
    blockaction merge double transform constseq bitfield coreaction condexe override dynamic crc32
    prettyprint printlanguage printc printjava memstate opbehavior paramid signature)
set(SLEIGH sleigh pcodeparse pcodecompile sleighbase slghsymbol slghpatexpress slghpattern semantics
    context slaformat compression filemanage)
set(GHIDRA_SET ghidra_arch inject_ghidra ghidra_translate loadimage_ghidra typegrp_ghidra
    database_ghidra ghidra_context cpool_ghidra ghidra_process comment_ghidra string_ghidra
    signature_ghidra)
# the console's extras (EXTRA in the Makefile), without what needs GNU BFD (the loaders and
# codedata's and analyzesigs' optional commands)
set(CONSOLE_EXTRA callgraph ifacedecomp ifaceterm inject_sleigh interface
    libdecomp loadimage_xml raw_arch rulecompile sleigh_arch testfunction unify xml_arch consolemain)

function(sources_of out)
    set(files)
    foreach(n ${ARGN})
        if(EXISTS "${PATCH}/${n}.cc")
            list(APPEND files "${PATCH}/${n}.cc")
        else()
            list(APPEND files "${SRC}/${n}.cc")
        endif()
    endforeach()
    set(${out} ${files} PARENT_SCOPE)
endfunction()

file(GLOB ZLIB_C "${ZLIB}/*.c")
add_library(rh_zlib STATIC ${ZLIB_C})
target_compile_definitions(rh_zlib PRIVATE NO_GZIP _CRT_SECURE_NO_DEPRECATE _CRT_NONSTDC_NO_DEPRECATE)

set(DEFS WINDOWS _WINDOWS WIN32 _WIN32 WIN64 _WIN64 _SECURE_SCL=0 _HAS_ITERATOR_DEBUGGING=0 LOCAL_ZLIB
    _CRT_SECURE_NO_WARNINGS)
# (/MP4: a few compilers, not every core, beside whatever else is building)
set(OPTS /EHsc /W1 /O2 /Zi /bigobj /MP4)

sources_of(GHIDRA_SRCS ${CORE} ${DECCORE} ${GHIDRA_SET})
add_executable(decompile ${GHIDRA_SRCS})
target_include_directories(decompile PRIVATE "${PATCH}" "${SRC}" "${ZLIB}")
target_compile_definitions(decompile PRIVATE ${DEFS})
target_compile_options(decompile PRIVATE ${OPTS})
target_link_options(decompile PRIVATE /DEBUG)

sources_of(CONSOLE_SRCS ${CORE} ${DECCORE} ${SLEIGH} ${CONSOLE_EXTRA})
add_executable(decomp_dbg ${CONSOLE_SRCS})
target_include_directories(decomp_dbg PRIVATE "${PATCH}" "${SRC}" "${ZLIB}")
# (CPUI_DEBUG brings the action tracing too: `trace address <addr>` before `decompile` shows each
# rule that changes the ops at an address)
target_compile_definitions(decomp_dbg PRIVATE ${DEFS} CPUI_DEBUG)
target_compile_options(decomp_dbg PRIVATE ${OPTS})
target_link_options(decomp_dbg PRIVATE /DEBUG)
target_link_libraries(decomp_dbg PRIVATE rh_zlib)

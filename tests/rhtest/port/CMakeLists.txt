cmake_minimum_required(VERSION 3.24)
project(rhtest_port C CXX)

# The port of one rhtest project (-DRHTEST_VARIANT=<work/name-variant>): its translation (gen/,
# written by translate32.py) and Rhipper's 32-bit runtime, as a real project builds its own.
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "the port builds as x64 (-A x64)")
endif()
if(NOT RHTEST_VARIANT)
  message(FATAL_ERROR "-DRHTEST_VARIANT=<project dir> (tests/rhtest/work/core-O2, ...)")
endif()
get_filename_component(RHIPPER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../.. ABSOLUTE)
set(RUNTIME32 ${RHIPPER_DIR}/runtime32)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 17)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

file(GLOB GEN_SOURCES CONFIGURE_DEPENDS ${RHTEST_VARIANT}/gen/*.c)
add_library(gen OBJECT ${GEN_SOURCES})
target_include_directories(gen PRIVATE ${RHTEST_VARIANT}/gen)
# (the memory model's conversions, as in a real project's CMakeLists.txt; an undeclared call is an
# error. -DRHTEST_MEASURE=ON: the translation built as written as can be, /O1 /Ob0, for fidelity32.py: /O2
# unrolls and inlines what the translation says, /Od spells each index out in instructions (no
# `[reg+4]` for `p[1]`), and fidelity measures the translation)
if(RHTEST_MEASURE)
  set(GEN_OPT /O1 /Ob0)
else()
  set(GEN_OPT /O2)
endif()
target_compile_options(gen PRIVATE /W1 /bigobj ${GEN_OPT} /GS- /TC /Zi
  /we4013 /wd4022 /wd4024 /wd4028 /wd4047 /wd4090 /wd4133 /wd4146 /wd4244 /wd4305 /wd4311 /wd4312
  /wd4554 /wd4700 /wd4715 /wd4716)

add_executable(rhtest-port
  ${RUNTIME32}/Main.cpp
  ${RUNTIME32}/RefImage.cpp
  ${RUNTIME32}/Adapters.cpp
  ${RUNTIME32}/Trace.cpp
  ${RUNTIME32}/Com32.cpp
  ${RUNTIME32}/Com32Gen.cpp
  ${RUNTIME32}/DxDiagBridge.cpp
  $<TARGET_OBJECTS:gen>)
target_compile_options(rhtest-port PRIVATE /W3 /Zi)
target_link_libraries(rhtest-port PRIVATE dbghelp)
# (no identical-code folding: two adapters of one body folded were one PDB name for both)
target_link_options(rhtest-port PRIVATE /DEBUG:FULL /OPT:REF /OPT:NOICF)
target_compile_definitions(rhtest-port PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
  RHIPPER_NAME="rhtest" RHIPPER_ENV="RHTEST" RHIPPER_REF=L"rhtest.exe")
# everything below 2 GB, the port at a fixed base above the reference's image (runtime32/Main.cpp)
target_link_options(rhtest-port PRIVATE /LARGEADDRESSAWARE:NO /DYNAMICBASE:NO /FIXED /BASE:0x60000000
  /SUBSYSTEM:CONSOLE)

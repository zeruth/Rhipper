# Rhipper's 32-bit runtime for an x64 port, from a project's CMakeLists.txt:
#
#   set(RUNTIME32 <rhipper>/runtime32)
#   include(${RUNTIME32}/Runtime32.cmake)
#   add_executable(<target> $<TARGET_OBJECTS:gen>)
#   rhipper_runtime32(<target> NAME <log prefix> ENV <environment prefix> REF <reference file name>)
#
# The runtime's sources, its names for the project (RHIPPER_NAME, RHIPPER_ENV: <ENV>_TRACE,
# <ENV>_REF, ...; RHIPPER_REF), the memory model's link options, and the x86 helpers it starts,
# built next to the executable. A project keeps its own debug and folding options (/OPT:ICF).

set(RUNTIME32_SOURCES
  ${RUNTIME32}/Main.cpp
  ${RUNTIME32}/RefImage.cpp
  ${RUNTIME32}/Adapters.cpp
  ${RUNTIME32}/Trace.cpp
  ${RUNTIME32}/Com32.cpp
  ${RUNTIME32}/Com32Gen.cpp
  ${RUNTIME32}/DxDiagBridge.cpp)

# The checked build's (a project's GEN_CHECKED, its translation built by clang-cl; Checked.cpp):
# for the gen library, clang's AddressSanitizer instrumentation with Checked.cpp for its runtime
# (the shadow's address read per function, no globals' redzones, no use-after-return or -scope,
# reports that return), and the translation's clang dialect as Runtime32Posix.cmake's: wrapping
# arithmetic, no fused multiply-adds, no loop vectorizer over __ptr32 stores, and only the
# functions marked inline inlined, so a report's function is the translated one, F_<address>.
# (clang-cl's driver ignores the GCC-style -f options it does not know: those through /clang:)
set(RUNTIME32_CHECKED_GEN_FLAGS
  -w -fwrapv -fno-delete-null-pointer-checks /clang:-ffp-contract=off /clang:-fno-vectorize
  /clang:-finline-hint-functions
  -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-incompatible-function-pointer-types
  -Wno-return-mismatch -Wno-return-type -Werror=implicit-function-declaration
  -fsanitize=address -fsanitize-recover=address -fno-sanitize-address-use-after-scope
  -fsanitize-address-use-after-return=never
  "SHELL:-mllvm -asan-globals=0" "SHELL:-mllvm -asan-force-dynamic-shadow=1")

function(rhipper_runtime32 target)
  cmake_parse_arguments(R "" "NAME;ENV;REF" "" ${ARGN})
  if(NOT R_NAME OR NOT R_ENV OR NOT R_REF)
    message(FATAL_ERROR "rhipper_runtime32(${target} NAME <name> ENV <ENV> REF <file.exe>)")
  endif()
  target_sources(${target} PRIVATE ${RUNTIME32_SOURCES})
  target_compile_options(${target} PRIVATE /W3 /Zi)
  target_link_libraries(${target} PRIVATE dbghelp)
  target_compile_definitions(${target} PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE
    RHIPPER_NAME="${R_NAME}" RHIPPER_ENV="${R_ENV}" RHIPPER_REF=L"${R_REF}")
  # Everything of the process below 2 GB, the port at a fixed base above the reference's image, so
  # the reference's 4-byte slots hold any address it is given and a jmp rel32 reaches the port from
  # the reference's code (Main.cpp). Subsystem version 5.02, the lowest x64 takes, as a 32-bit
  # reference's 5.x: below 6.0 Windows gives a window the legacy frame and AdjustWindowRect's
  # sizes with it; at 6.0 a port's window took a WM_SIZE its reference's never did
  target_link_options(${target} PRIVATE /LARGEADDRESSAWARE:NO /DYNAMICBASE:NO /FIXED /BASE:0x60000000
    /SUBSYSTEM:CONSOLE,5.02)
  # (the checked build: its runtime, Checked.cpp, the runtime's hooks for it, and its own name,
  # <target>_checked.exe, beside the normal one's)
  if(GEN_CHECKED)
    target_sources(${target} PRIVATE ${RUNTIME32}/Checked.cpp)
    target_compile_definitions(${target} PRIVATE GEN_CHECKED)
    set_target_properties(${target} PROPERTIES OUTPUT_NAME ${target}_checked)
  endif()

  # the x86 helpers, next to the executable: DxDiag32.exe answers DxDiag as a 32-bit reference's
  # provider does (DxDiagBridge.cpp); built with Visual Studio's x86 compiler (helpers32/build32.bat)
  if(CMAKE_RUNTIME_OUTPUT_DIRECTORY)
    set(dir ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
  else()
    set(dir ${CMAKE_CURRENT_BINARY_DIR})
  endif()
  get_property(multi GLOBAL PROPERTY GENERATOR_IS_MULTI_CONFIG)
  if(multi)
    set(dir ${dir}/$<CONFIG>)
  endif()
  set(dxdiag32 ${dir}/DxDiag32.exe)
  add_custom_command(OUTPUT ${dxdiag32}
    COMMAND cmd /c ${RUNTIME32}/helpers32/build32.bat ${RUNTIME32}/helpers32/DxDiag32.cpp ${dxdiag32}
    DEPENDS ${RUNTIME32}/helpers32/DxDiag32.cpp ${RUNTIME32}/helpers32/DxDiagWire.h
    COMMENT "DxDiag32.exe (x86)" VERBATIM)
  add_custom_target(${target}_helpers32 ALL DEPENDS ${dxdiag32})
  add_dependencies(${target} ${target}_helpers32)
endfunction()

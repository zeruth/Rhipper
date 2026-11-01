# Rhipper's POSIX/Android runtime for an x64-of-x86 port, the counterpart of runtime32/Runtime32.cmake.
# From a project's CMakeLists.txt, built with the Android toolchain (toolchains/android-arm64-llvm.cmake):
#
#   set(RUNTIME32_POSIX <rhipper>/runtime32-posix)
#   include(${RUNTIME32_POSIX}/Runtime32Posix.cmake)
#   add_library(crystalcore SHARED $<TARGET_OBJECTS:gen>)
#   rhipper_runtime32_posix(crystalcore NAME CrystalCore ENV CRYSTALCORE REF ffxiv.exe)
#
# It makes two libraries (see android_jni.c and the README for why):
#   lib<name>.so        the translation (the gen object library) and this runtime, loaded by the boot
#                       library into a reservation below 2 GB. Exports rhipper_host_*.
#   lib<name>_boot.so   the JNI glue (android_jni.c); what the app's System.loadLibrary loads. It
#                       reserves the low range and loads lib<name>.so into it, then forwards.
#
# The `target` the project passes becomes lib<name>.so; the boot library is added as <target>_boot.

set(RUNTIME32_POSIX_SOURCES
  ${RUNTIME32_POSIX}/Log.cpp
  ${RUNTIME32_POSIX}/LowMem.cpp
  ${RUNTIME32_POSIX}/Islands.cpp
  ${RUNTIME32_POSIX}/RefImage.cpp
  ${RUNTIME32_POSIX}/Hooks.cpp
  ${RUNTIME32_POSIX}/Eh.cpp
  ${RUNTIME32_POSIX}/Trace.cpp
  ${RUNTIME32_POSIX}/Host.cpp
  ${RUNTIME32_POSIX}/Strings.cpp
  ${RUNTIME32_POSIX}/Paths.cpp
  ${RUNTIME32_POSIX}/Resources.cpp
  ${RUNTIME32_POSIX}/kernel32_sync.cpp
  ${RUNTIME32_POSIX}/kernel32_thread.cpp
  ${RUNTIME32_POSIX}/kernel32_file.cpp
  ${RUNTIME32_POSIX}/kernel32_misc.cpp
  ${RUNTIME32_POSIX}/user32.cpp
  ${RUNTIME32_POSIX}/gdi32_imm32.cpp
  ${RUNTIME32_POSIX}/advapi32.cpp
  ${RUNTIME32_POSIX}/ws2_32.cpp
  ${RUNTIME32_POSIX}/winmm.cpp
  ${RUNTIME32_POSIX}/winhttp.cpp
  ${RUNTIME32_POSIX}/xinput.cpp
  ${RUNTIME32_POSIX}/Com32Posix.cpp
  ${RUNTIME32_POSIX}/d3d9_null.cpp
  ${RUNTIME32_POSIX}/dinput8.cpp
  ${RUNTIME32_POSIX}/input.cpp
  ${RUNTIME32_POSIX}/xaudio2.cpp
  ${RUNTIME32_POSIX}/d3d9vk/Shader.cpp
  ${RUNTIME32_POSIX}/d3d9vk/SpirvBuilder.cpp
  ${RUNTIME32_POSIX}/d3d9vk/Device.cpp
  ${RUNTIME32_POSIX}/d3d9vk/Draw.cpp
  ${RUNTIME32_POSIX}/d3d9vk/Pipeline.cpp
  ${RUNTIME32_POSIX}/d3d9vk/Image.cpp
  ${RUNTIME32_POSIX}/d3d9vk/VkResources.cpp
  ${RUNTIME32_POSIX}/d3d9vk/Formats.cpp
  ${RUNTIME32_POSIX}/d3d9vk/FixedFunction.cpp)

# The flags the translation (a project's gen object library) builds with. Ghidra32.h's aarch64 branch
# says why each: C17 for the unprototyped `code()`, x86's signed char, no fused multiply-add, MSVC's
# aliasing and wrapping overflow, no fortified memcpy over the frame buffers. The -Wno-* are what
# runtime32's MSVC build disables as /wd for the same reasons (the memory model's int/pointer
# conversions C4047/C4133/C4022/C4024, the decompiler's missing returns C4715/C4716): clang >= 16
# makes them errors by default. A call without a declaration stays an error (C4013 /we on Windows).
# No loop vectorizer: it makes vector addrspacecasts to __ptr32 that AArch64's backend can't legalize
# (tests/ptr32_vector.c, checked below so a toolchain that still crashes fails here, not mid-gen).
# No wcslen builtin: with -fshort-wchar the loop idiom pass turns a UTF-16 length loop into a call to
# bionic's wcslen, which counts 4-byte units, and every such length came out half
# (tests/wcslen_idiom.c, linked below with no libc so a wcslen the compiler adds fails it).
set(RUNTIME32_POSIX_GEN_FLAGS
  -std=gnu17 -fms-extensions -fshort-wchar -fsigned-char -fno-strict-aliasing -fwrapv -ffp-contract=off
  -fno-delete-null-pointer-checks -U_FORTIFY_SOURCE -fPIC -fno-omit-frame-pointer -fno-vectorize
  -fno-builtin-wcslen
  -Wno-int-conversion -Wno-incompatible-pointer-types -Wno-incompatible-function-pointer-types
  -Wno-return-mismatch -Wno-return-type -Werror=implicit-function-declaration)
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
try_compile(_rhipper_ptr32_vector ${CMAKE_BINARY_DIR}/rhipper_ptr32_vector
  SOURCES ${RUNTIME32_POSIX}/tests/ptr32_vector.c
  COMPILE_DEFINITIONS ${RUNTIME32_POSIX_GEN_FLAGS} -O2
  OUTPUT_VARIABLE _rhipper_ptr32_vector_out)
unset(CMAKE_TRY_COMPILE_TARGET_TYPE)
if(NOT _rhipper_ptr32_vector)
  message(FATAL_ERROR "runtime32-posix: tests/ptr32_vector.c does not build with the gen flags:\n${_rhipper_ptr32_vector_out}")
endif()
try_compile(_rhipper_wcslen_idiom ${CMAKE_BINARY_DIR}/rhipper_wcslen_idiom
  SOURCES ${RUNTIME32_POSIX}/tests/wcslen_idiom.c
  COMPILE_DEFINITIONS ${RUNTIME32_POSIX_GEN_FLAGS} -O2
  LINK_OPTIONS -nostdlib -Wl,-e,start
  OUTPUT_VARIABLE _rhipper_wcslen_idiom_out)
if(NOT _rhipper_wcslen_idiom)
  message(FATAL_ERROR "runtime32-posix: tests/wcslen_idiom.c calls a library wcslen with the gen flags:\n${_rhipper_wcslen_idiom_out}")
endif()
# A narrowed store through a __ptr32 pointer comes out 8 bytes wide from AArch64's backend; Ghidra32.h's
# GEN_NE routes every such store through a host pointer instead (tests/ptr32_truncstore.c). Compiled
# to assembly with the gen flags and runtime32's Ghidra32.h: no 64-bit store may be left in it.
get_filename_component(_rhipper_runtime32 ${RUNTIME32_POSIX}/../runtime32 ABSOLUTE)
execute_process(
  COMMAND ${CMAKE_C_COMPILER} --target=${CMAKE_C_COMPILER_TARGET} --sysroot=${CMAKE_SYSROOT}
          -I${_rhipper_runtime32} ${RUNTIME32_POSIX_GEN_FLAGS} -O2 -fomit-frame-pointer -S -o -
          ${RUNTIME32_POSIX}/tests/ptr32_truncstore.c
  OUTPUT_VARIABLE _rhipper_truncstore_asm ERROR_VARIABLE _rhipper_truncstore_err
  RESULT_VARIABLE _rhipper_truncstore_rc)
if(NOT _rhipper_truncstore_rc EQUAL 0)
  message(FATAL_ERROR "runtime32-posix: tests/ptr32_truncstore.c does not compile with the gen flags:\n${_rhipper_truncstore_err}")
endif()
string(REGEX MATCH "(str|stur)[ \t]+x[0-9]+, \\[x[0-9]+" _rhipper_truncstore_wide "${_rhipper_truncstore_asm}")
if(_rhipper_truncstore_wide)
  message(FATAL_ERROR "runtime32-posix: a narrowed store through a __ptr32 pointer is 8 bytes wide (`${_rhipper_truncstore_wide}`): "
                      "Ghidra32.h's GEN_NE must take the host-pointer form on this host (tests/ptr32_truncstore.c)\n${_rhipper_truncstore_asm}")
endif()
function(rhipper_gen_posix gen)
  target_compile_options(${gen} PRIVATE ${RUNTIME32_POSIX_GEN_FLAGS})
endfunction()

function(rhipper_runtime32_posix target)
  cmake_parse_arguments(R "" "NAME;ENV;REF" "" ${ARGN})
  if(NOT R_NAME OR NOT R_ENV)
    message(FATAL_ERROR "rhipper_runtime32_posix(${target} NAME <name> ENV <ENV> [REF <file.exe>])")
  endif()
  if(NOT ANDROID)
    message(FATAL_ERROR "runtime32-posix is for Android (use toolchains/android-arm64-llvm.cmake)")
  endif()
  if(NOT CMAKE_ANDROID_ARCH_ABI STREQUAL "arm64-v8a" AND NOT CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64")
    message(FATAL_ERROR "runtime32-posix targets arm64-v8a only")
  endif()

  # ---- the real library: the translation and this runtime ----------------------------------------
  # Its soname is lib<name>.so; the boot library loads it by that name from the APK's lib directory.
  set_target_properties(${target} PROPERTIES OUTPUT_NAME ${R_NAME})
  target_sources(${target} PRIVATE ${RUNTIME32_POSIX_SOURCES})
  target_include_directories(${target} PRIVATE ${RUNTIME32_POSIX})
  target_compile_features(${target} PRIVATE cxx_std_17)
  target_compile_definitions(${target} PRIVATE
    RHIPPER_NAME="${R_NAME}" RHIPPER_ENV="${R_ENV}")
  if(R_REF)
    target_compile_definitions(${target} PRIVATE RHIPPER_REF="${R_REF}")
  endif()
  # The runtime's own C++, with the platform's 4-byte wchar_t: its UTF-16 is char16_t, and under
  # -fshort-wchar clang made Len16's loop a call to bionic's 4-byte wcslen (and libc++'s inline
  # wide-string code would disagree with the libc++ it links). The gen flags stay on the gen library.
  target_compile_options(${target} PRIVATE -fms-extensions -Wall -g
    -fno-omit-frame-pointer -funwind-tables)
  # The runtime's registry of Win32 functions is built from static constructors (RH_REG): keep them
  # even though nothing references them from the object files.
  target_link_options(${target} PRIVATE
    -Wl,--no-undefined
    -Wl,-z,max-page-size=16384   # correct on 16 KB-page devices
    -Wl,--build-id=sha1)
  target_link_libraries(${target} PRIVATE log android dl aaudio vulkan)
  # (frame pointers kept across the whole library so the crash handler's backtrace can walk it)

  # ---- the boot / JNI library --------------------------------------------------------------------
  add_library(${target}_boot SHARED ${RUNTIME32_POSIX}/android_jni.c)
  set_target_properties(${target}_boot PROPERTIES OUTPUT_NAME ${R_NAME}_boot)
  target_include_directories(${target}_boot PRIVATE ${RUNTIME32_POSIX})
  target_compile_definitions(${target}_boot PRIVATE RHIPPER_REAL_LIB="${R_NAME}")
  target_compile_options(${target}_boot PRIVATE -Wall -g)
  target_link_libraries(${target}_boot PRIVATE log android dl)
  # Both end up in the APK's lib/arm64-v8a; the boot library finds lib<name>.so beside itself.
  add_dependencies(${target}_boot ${target})
endfunction()

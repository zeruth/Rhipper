# A CMake toolchain for building a Rhipper POSIX port for Android arm64, with stock LLVM clang (>= 22)
# and the NDK's sysroot, rather than the NDK's own clang. The runtime needs __ptr32 on aarch64
# (Ghidra32.h), which stock clang 22 has and the NDK's older clang does not.
#
#   cmake -B build-android \
#     -DCMAKE_TOOLCHAIN_FILE=<rhipper>/toolchains/android-arm64-llvm.cmake \
#     -DANDROID_NDK=/path/to/android-ndk-r27 \
#     [-DLLVM_DIR=C:/Program Files/LLVM] [-DANDROID_API=29]
#
# LLVM_DIR / env LLVM_DIR: the stock LLVM (default C:/Program Files/LLVM). ANDROID_NDK / env
# ANDROID_NDK: the NDK, for its sysroot (bionic, libc++, the Android system stubs) and compiler-rt.

# (Linux, not Android: CMake's Android platform module picks the NDK's own clang whatever
# CMAKE_C_COMPILER says. The triple and the sysroot make it Android; ANDROID is set below.)
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)
# (try_compile's projects re-read this file without the cache: hand them these)
list(APPEND CMAKE_TRY_COMPILE_PLATFORM_VARIABLES ANDROID_NDK LLVM_DIR ANDROID_API)

# API level 29 (Android 10): the lowest that has android_dlopen_ext with ANDROID_DLEXT_RESERVED_ADDRESS
# (API 21+ actually), 64-bit-only app support, and a bionic new enough that MAP_FIXED_NOREPLACE
# (kernel 4.17, required for the low reservation to be safe) is present on the devices that run it.
# The target device is Android 17, far above this, so 29 is a conservative floor that still covers the
# whole fleet a port might be sideloaded onto.
if(NOT DEFINED ANDROID_API)
  if(DEFINED ENV{ANDROID_API})
    set(ANDROID_API $ENV{ANDROID_API})
  else()
    set(ANDROID_API 29)
  endif()
endif()
set(CMAKE_ANDROID_ARCH_ABI arm64-v8a)

# ---- the NDK (its sysroot and compiler-rt) ---------------------------------------------------------
if(NOT DEFINED ANDROID_NDK)
  if(DEFINED ENV{ANDROID_NDK})
    set(ANDROID_NDK $ENV{ANDROID_NDK})
  elseif(DEFINED ENV{ANDROID_NDK_HOME})
    set(ANDROID_NDK $ENV{ANDROID_NDK_HOME})
  else()
    message(FATAL_ERROR "set ANDROID_NDK (the Android NDK path) for the sysroot")
  endif()
endif()
file(TO_CMAKE_PATH "${ANDROID_NDK}" ANDROID_NDK)

# the prebuilt toolchain directory inside the NDK, whatever the host (its sysroot and lib are here)
if(CMAKE_HOST_WIN32)
  set(_ndk_host windows-x86_64)
elseif(CMAKE_HOST_APPLE)
  set(_ndk_host darwin-x86_64)
else()
  set(_ndk_host linux-x86_64)
endif()
set(_ndk_tc "${ANDROID_NDK}/toolchains/llvm/prebuilt/${_ndk_host}")
set(CMAKE_SYSROOT "${_ndk_tc}/sysroot")
if(NOT EXISTS "${CMAKE_SYSROOT}/usr/include/android/api-level.h")
  message(FATAL_ERROR "no NDK sysroot at ${CMAKE_SYSROOT} (ANDROID_NDK wrong, or an unexpected layout)")
endif()

# ---- stock LLVM -----------------------------------------------------------------------------------
if(NOT DEFINED LLVM_DIR)
  if(DEFINED ENV{LLVM_DIR})
    set(LLVM_DIR $ENV{LLVM_DIR})
  elseif(CMAKE_HOST_WIN32)
    set(LLVM_DIR "C:/Program Files/LLVM")
  else()
    set(LLVM_DIR "/usr/local")
  endif()
endif()
file(TO_CMAKE_PATH "${LLVM_DIR}" LLVM_DIR)
if(CMAKE_HOST_WIN32)
  set(_exe ".exe")
else()
  set(_exe "")
endif()
set(CMAKE_C_COMPILER   "${LLVM_DIR}/bin/clang${_exe}")
set(CMAKE_CXX_COMPILER "${LLVM_DIR}/bin/clang++${_exe}")
set(CMAKE_AR           "${LLVM_DIR}/bin/llvm-ar${_exe}")
set(CMAKE_RANLIB       "${LLVM_DIR}/bin/llvm-ranlib${_exe}")
set(CMAKE_STRIP        "${LLVM_DIR}/bin/llvm-strip${_exe}")
foreach(_c "${CMAKE_C_COMPILER}" "${CMAKE_CXX_COMPILER}")
  if(NOT EXISTS "${_c}")
    message(FATAL_ERROR "no clang at ${_c} (set LLVM_DIR to a stock LLVM >= 22)")
  endif()
endforeach()

# the Android target triple; the API level rides in it so clang picks the right crt objects
set(_triple "aarch64-linux-android${ANDROID_API}")
set(CMAKE_C_COMPILER_TARGET ${_triple})
set(CMAKE_CXX_COMPILER_TARGET ${_triple})

# lld (stock LLVM's), and libc++ and the runtime from the NDK, not stock LLVM's (its must match
# bionic). compiler-rt's builtins come from the NDK's clang resource directory, found by its version.
file(GLOB _rt_dirs "${_ndk_tc}/lib/clang/*")
if(NOT _rt_dirs)
  message(FATAL_ERROR "no clang resource directory in ${_ndk_tc}/lib/clang (the NDK's compiler-rt)")
endif()
list(GET _rt_dirs 0 _ndk_resource)

set(_common "-fuse-ld=lld -stdlib=libc++")
# the NDK's per-API link directory (the Android system stub libraries: log, android, dl, ...) and
# its compiler-rt builtins
set(_libdir "${_ndk_tc}/sysroot/usr/lib/aarch64-linux-android")
set(_linkdirs "-L${_libdir}/${ANDROID_API} -L${_libdir}")
# (at the link only: stock clang looks for compiler-rt and libunwind in its own resource directory,
# which has none for Android; the NDK's has both. Compiles keep stock clang's own headers.)
set(_linkdirs "${_linkdirs} -resource-dir=${_ndk_resource} -L${_ndk_resource}/lib/linux/aarch64 --rtlib=compiler-rt")

set(CMAKE_C_FLAGS_INIT "${_common}")
set(CMAKE_CXX_FLAGS_INIT "${_common}")
# static libc++ (an app ships no libc++_shared unless it bundles one), the unwinder and compiler-rt
set(_link "${_common} -static-libstdc++ ${_linkdirs} -Wl,-z,max-page-size=16384 -Wl,--build-id=sha1")
set(CMAKE_SHARED_LINKER_FLAGS_INIT "${_link}")
set(CMAKE_EXE_LINKER_FLAGS_INIT "${_link}")

set(ANDROID 1)
set(CMAKE_ANDROID_NDK "${ANDROID_NDK}")

# look for headers and libraries in the sysroot, programs on the host
set(CMAKE_FIND_ROOT_PATH "${CMAKE_SYSROOT}")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

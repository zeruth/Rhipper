#pragma once

#include <cstdint>

// The project's names, as its build defines them: the log lines' prefix, and its environment
// variables' (<ENV>_REF, the reference's path; <ENV>_HANGDUMP, seconds before a stack dump)
#ifndef RHIPPER_NAME
#define RHIPPER_NAME "port"
#endif
#ifndef RHIPPER_ENV
#define RHIPPER_ENV "PORT"
#endif
// the reference's file name, looked for in the working directory unless <ENV>_REF names another
#ifndef RHIPPER_REF
#define RHIPPER_REF L"reference.exe"
#endif

// an environment variable of the project's, RHIPPER_ENV "_" suffix, into buf: its length, 0 unset
unsigned RefEnv(const char* suffix, wchar_t* buf, unsigned size);
// sets (or with nullptr clears) one
void RefSetEnv(const char* suffix, const wchar_t* value);

// The reference's image in the port's process: its sections at their own addresses, a jump at
// each function's entry to its translation, its import slots holding the port's adapters.
struct RefLayout {
    uint32_t base;
    uint32_t size;
};

const wchar_t* RefImagePath();
bool RefReadLayout(const wchar_t* path, RefLayout* out);
// maps the image into the range the launcher reserved, writes the jumps, fills the imports
bool RefMapImage(const wchar_t* path);
// runs the reference's entry point (its CRT startup, then WinMain); the process's exit code
int RefRun();
// the shadow trace (Trace.cpp): started from <ENV>_TRACE, flushed at exit and on a crash
void RefTraceStart();
void RefTraceFlush();

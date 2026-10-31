/* The bootstrap/JNI library (lib<port>_boot.so), what System.loadLibrary loads. It exists only to
   put the real library below 2 GB: the generated code truncates host addresses to 32 bits (a string
   literal passed to an `unsigned int`, an adapter's address returned as a uint32), so the port's own
   code, rodata, data and bss must all sit under 2 GB, not only the reference's heap. The Android
   linker loads a .so high, so this small library — which holds no such truncated address — is loaded
   normally, reserves a low range, and loads the real lib<port>.so into it with android_dlopen_ext
   and ANDROID_DLEXT_RESERVED_ADDRESS. The reference's image goes below it (its own base, 0x400000),
   its islands right after it so the 4-byte `B` at each function entry reaches them within ±128 MB.

   The host loads this library (its name is <port> + "_boot"); its RhipperNative methods forward to
   rhipper_host.h in the real library, resolved by dlsym. JNI method names and signatures are
   RhipperNative.kt's, unchanged.

   Link with: -landroid -llog -ldl. */
#ifdef __ANDROID__

#include <android/dlext.h>
#include <android/log.h>
#include <android/native_window.h>
#include <android/native_window_jni.h>
#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <jni.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "rhipper_host.h"

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

#define TAG "rhipper"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)

/* the real library's exports (rhipper_host.h), resolved by dlsym after it is loaded low */
static int (*p_run)(const char *, const char *, int, const char *const *);
static void (*p_set_log_dir)(const char *);
static void (*p_set_window)(void *, int, int);
static void (*p_set_pad)(int, const RhipperPad *);
static void (*p_set_rumble)(RhipperRumbleFn);
static void (*p_lifecycle)(int);

static JavaVM *g_vm;
static jclass g_native_class;
static jmethodID g_on_rumble;
static void *g_real;   /* the real library, kept loaded for the life of the process */

/* ---- place the real library below 2 GB ---------------------------------------------------------- */

/* the real library's mapped size, from its ELF program headers (the max p_vaddr + p_memsz) */
static size_t mapped_size(const char *path) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    Elf64_Ehdr eh;
    if (read(fd, &eh, sizeof eh) != (ssize_t)sizeof eh || memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        close(fd);
        return 0;
    }
    size_t hi = 0;
    for (int k = 0; k < eh.e_phnum; k++) {
        Elf64_Phdr ph;
        if (pread(fd, &ph, sizeof ph, eh.e_phoff + (off_t)k * eh.e_phentsize) != (ssize_t)sizeof ph) break;
        if (ph.p_type == PT_LOAD && ph.p_vaddr + ph.p_memsz > hi) hi = ph.p_vaddr + ph.p_memsz;
    }
    close(fd);
    return hi;
}

/* a region below 2 GB, above the reference's image and its islands, large enough for the library and
   16 KB-aligned (ANDROID_DLEXT_RESERVED_ADDRESS wants a page-aligned region) */
static int reserve_low(size_t size, void **addr_out, size_t *size_out) {
    size_t page = (size_t)sysconf(_SC_PAGESIZE);
    size = (size + page - 1) & ~(page - 1);
    /* Leave the low 256 MB to the reference (image at 0x400000, its heaps, stacks) and start the
       search above it; the island table sits between the image and here, within a branch's 128 MB of
       the image. Walk down from just under 2 GB so the big library does not fragment the low heap. */
    for (uintptr_t at = 0x70000000; at >= 0x10000000; at -= 0x1000000) {
        void *want = (void *)at;
        void *got = mmap(want, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED_NOREPLACE, -1, 0);
        if (got == want) {
            *addr_out = got;
            *size_out = size;
            return 1;
        }
        if (got != MAP_FAILED) munmap(got, size);
    }
    return 0;
}

/* load lib<port>.so into a low reservation; its path is beside this library in the APK's lib dir */
static void *load_real_low(const char *real_name) {
    Dl_info self;
    if (!dladdr((void *)&load_real_low, &self) || !self.dli_fname) {
        LOGE("boot: cannot find my own path");
        return NULL;
    }
    char path[1024];
    const char *slash = strrchr(self.dli_fname, '/');
    int dirlen = slash ? (int)(slash - self.dli_fname) : 0;
    snprintf(path, sizeof path, "%.*s/lib%s.so", dirlen, self.dli_fname, real_name);

    size_t need = mapped_size(path);
    if (!need) {
        LOGE("boot: cannot read %s", path);
        return NULL;
    }
    void *addr = NULL;
    size_t size = 0;
    void *lib = NULL;
    if (reserve_low(need, &addr, &size)) {
        android_dlextinfo info;
        memset(&info, 0, sizeof info);
        info.flags = ANDROID_DLEXT_RESERVED_ADDRESS;
        info.reserved_addr = addr;
        info.reserved_size = size;
        lib = android_dlopen_ext(path, RTLD_NOW | RTLD_GLOBAL, &info);
        if (!lib) {
            LOGE("boot: android_dlopen_ext at %p failed: %s", addr, dlerror());
            munmap(addr, size);
        } else {
            LOGI("boot: %s loaded at %p (%zu bytes), below 2 GB", path, addr, size);
        }
    }
    if (!lib) {
        /* a hint, as a fallback: the linker places it near the address, maybe not exactly */
        if (reserve_low(need, &addr, &size)) {
            android_dlextinfo info;
            memset(&info, 0, sizeof info);
            info.flags = ANDROID_DLEXT_RESERVED_ADDRESS_HINT;
            info.reserved_addr = addr;
            info.reserved_size = size;
            lib = android_dlopen_ext(path, RTLD_NOW | RTLD_GLOBAL, &info);
            if (lib) {
                Dl_info where;
                if (dladdr(dlsym(lib, "rhipper_host_run"), &where))
                    LOGI("boot: %s loaded near %p (hint)", path, where.dli_fbase);
            }
        }
    }
    if (!lib) {
        LOGE("boot: could not load %s below 2 GB; the translation's 4-byte slots will not hold its "
             "addresses", path);
        lib = dlopen(path, RTLD_NOW | RTLD_GLOBAL);   /* (loaded high: a diagnostic, it will fault) */
    }
    return lib;
}

static int resolve(void) {
    if (!g_real) return 0;
#define SYM(var, name)                                     \
    *(void **)(&var) = dlsym(g_real, name);                \
    if (!var) {                                            \
        LOGE("boot: %s not found in the real library", name); \
        return 0;                                          \
    }
    SYM(p_run, "rhipper_host_run");
    SYM(p_set_log_dir, "rhipper_host_set_log_dir");
    SYM(p_set_window, "rhipper_host_set_window");
    SYM(p_set_pad, "rhipper_host_set_pad");
    SYM(p_set_rumble, "rhipper_host_set_rumble");
    SYM(p_lifecycle, "rhipper_host_lifecycle");
#undef SYM
    return 1;
}

/* ---- native threads calling into Java (the rumble callback) ------------------------------------- */
static pthread_key_t g_detach_key;
static pthread_once_t g_detach_once = PTHREAD_ONCE_INIT;
static void detach_on_exit(void *unused) {
    (void)unused;
    if (g_vm) (*g_vm)->DetachCurrentThread(g_vm);
}
static void make_detach_key(void) { pthread_key_create(&g_detach_key, detach_on_exit); }

static JNIEnv *thread_env(void) {
    JNIEnv *env = NULL;
    if (!g_vm) return NULL;
    jint r = (*g_vm)->GetEnv(g_vm, (void **)&env, JNI_VERSION_1_6);
    if (r == JNI_OK) return env;
    if (r != JNI_EDETACHED) return NULL;
    JavaVMAttachArgs args = {JNI_VERSION_1_6, "rhipper-native", NULL};
    if ((*g_vm)->AttachCurrentThreadAsDaemon(g_vm, &env, &args) != JNI_OK) return NULL;
    pthread_once(&g_detach_once, make_detach_key);
    pthread_setspecific(g_detach_key, env);
    return env;
}

static void jni_rumble(int index, uint16_t low_motor, uint16_t high_motor) {
    JNIEnv *env = thread_env();
    if (!env || !g_on_rumble) return;
    (*env)->CallStaticVoidMethod(env, g_native_class, g_on_rumble, (jint)index, (jint)low_motor, (jint)high_motor);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }
}

/* ---- RhipperNative, forwarding to the real library ----------------------------------------------- */

/* the real library's name, lib<this one minus "_boot">.so: a build define, or guessed. The host's
   own library name is <port>_boot; the real one is <port>. */
#ifndef RHIPPER_REAL_LIB
#define RHIPPER_REAL_LIB "rhipper"
#endif

JNIEXPORT jint JNICALL
Java_dev_rhipper_host_RhipperNative_nativeInit(JNIEnv *env, jclass cls) {
    if (!g_vm) (*env)->GetJavaVM(env, &g_vm);
    if (!g_native_class) {
        g_native_class = (jclass)(*env)->NewGlobalRef(env, cls);
        g_on_rumble = (*env)->GetStaticMethodID(env, cls, "onRumble", "(III)V");
        if (!g_on_rumble) {
            (*env)->ExceptionClear(env);
            LOGE("RhipperNative.onRumble(int, int, int) not found: no rumble");
        }
    }
    if (!g_real) {
        g_real = load_real_low(RHIPPER_REAL_LIB);
        if (!g_real || !resolve()) return -1;
    }
    p_set_rumble(g_on_rumble ? jni_rumble : NULL);
    return RHIPPER_HOST_VERSION;
}

JNIEXPORT void JNICALL
Java_dev_rhipper_host_RhipperNative_nativeSetLogDir(JNIEnv *env, jclass cls, jstring dir) {
    (void)cls;
    if (!p_set_log_dir) return;
    const char *s = (*env)->GetStringUTFChars(env, dir, NULL);
    if (!s) return;
    p_set_log_dir(s);
    (*env)->ReleaseStringUTFChars(env, dir, s);
}

static ANativeWindow *g_window;
static pthread_mutex_t g_window_lock = PTHREAD_MUTEX_INITIALIZER;

JNIEXPORT void JNICALL
Java_dev_rhipper_host_RhipperNative_nativeSetSurface(JNIEnv *env, jclass cls, jobject surface, jint width, jint height) {
    (void)cls;
    if (!p_set_window) return;
    ANativeWindow *window = surface ? ANativeWindow_fromSurface(env, surface) : NULL;
    pthread_mutex_lock(&g_window_lock);
    ANativeWindow *old = g_window;
    g_window = window;
    p_set_window(window, window ? width : 0, window ? height : 0);
    pthread_mutex_unlock(&g_window_lock);
    if (old) ANativeWindow_release(old);
}

JNIEXPORT void JNICALL
Java_dev_rhipper_host_RhipperNative_nativeSetPad(JNIEnv *env, jclass cls, jint index, jboolean connected, jint buttons,
                                                 jint left_trigger, jint right_trigger,
                                                 jint thumb_lx, jint thumb_ly, jint thumb_rx, jint thumb_ry) {
    (void)env; (void)cls;
    if (!p_set_pad) return;
    RhipperPad pad;
    memset(&pad, 0, sizeof pad);
    pad.connected = connected ? 1 : 0;
    pad.buttons = (uint16_t)buttons;
    pad.left_trigger = (uint8_t)left_trigger;
    pad.right_trigger = (uint8_t)right_trigger;
    pad.thumb_lx = (int16_t)thumb_lx;
    pad.thumb_ly = (int16_t)thumb_ly;
    pad.thumb_rx = (int16_t)thumb_rx;
    pad.thumb_ry = (int16_t)thumb_ry;
    p_set_pad(index, &pad);
}

JNIEXPORT void JNICALL
Java_dev_rhipper_host_RhipperNative_nativeLifecycle(JNIEnv *env, jclass cls, jint event) {
    (void)env; (void)cls;
    if (p_lifecycle) p_lifecycle(event);
}

static char *copy_string(JNIEnv *env, jstring s) {
    if (!s) return NULL;
    const char *chars = (*env)->GetStringUTFChars(env, s, NULL);
    if (!chars) return NULL;
    char *copy = strdup(chars);
    (*env)->ReleaseStringUTFChars(env, s, chars);
    return copy;
}

JNIEXPORT jint JNICALL
Java_dev_rhipper_host_RhipperNative_nativeRun(JNIEnv *env, jclass cls, jstring ref_exe, jstring cwd, jobjectArray argv) {
    (void)cls;
    if (!p_run) return -1;
    char *exe = copy_string(env, ref_exe);
    char *dir = copy_string(env, cwd);
    int argc = argv ? (*env)->GetArrayLength(env, argv) : 0;
    char **args = calloc((size_t)argc + 1, sizeof *args);
    for (int i = 0; i < argc; i++) {
        jstring a = (jstring)(*env)->GetObjectArrayElement(env, argv, i);
        args[i] = copy_string(env, a);
        if (!args[i]) args[i] = strdup("");
        (*env)->DeleteLocalRef(env, a);
    }
    int code = p_run(exe, dir, argc, (const char *const *)args);
    for (int i = 0; i < argc; i++) free(args[i]);
    free(args);
    free(dir);
    free(exe);
    return code;
}

#endif /* __ANDROID__ */

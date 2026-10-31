# The JNI glue (runtime32-posix/android_jni.c) binds these by name: the native methods, and
# onRumble, which native code calls back.
-keep class dev.rhipper.host.RhipperNative {
    native <methods>;
    public static void onRumble(int, int, int);
}

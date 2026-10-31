package dev.rhipper.host

import android.content.Intent

/**
 * What a port's game activity runs: the native library holding the translation and the runtime
 * (its name as System.loadLibrary takes it: "crystalcore" for libcrystalcore.so), the reference
 * executable, its working directory, its arguments (without argv[0]) and where the runtime logs.
 * Passed to [RhipperActivity] as Intent extras, or built by a subclass overriding
 * [RhipperActivity.createConfig].
 */
data class RhipperConfig(
    val library: String,
    val referenceExe: String,
    val workingDir: String,
    val args: List<String>,
    val logDir: String,
) {
    /** The command line as the reference sees it: argv[0] is the program itself. */
    val argv: Array<String> get() = (listOf(referenceExe) + args).toTypedArray()

    fun putInto(intent: Intent): Intent = intent
        .putExtra(EXTRA_LIBRARY, library)
        .putExtra(EXTRA_REFERENCE_EXE, referenceExe)
        .putExtra(EXTRA_WORKING_DIR, workingDir)
        .putExtra(EXTRA_ARGS, args.toTypedArray())
        .putExtra(EXTRA_LOG_DIR, logDir)

    companion object {
        const val EXTRA_LIBRARY = "dev.rhipper.host.LIBRARY"
        const val EXTRA_REFERENCE_EXE = "dev.rhipper.host.REFERENCE_EXE"
        const val EXTRA_WORKING_DIR = "dev.rhipper.host.WORKING_DIR"
        const val EXTRA_ARGS = "dev.rhipper.host.ARGS"
        const val EXTRA_LOG_DIR = "dev.rhipper.host.LOG_DIR"

        /** The config in [intent]'s extras, or null when it has none. */
        fun fromIntent(intent: Intent): RhipperConfig? {
            val library = intent.getStringExtra(EXTRA_LIBRARY) ?: return null
            val exe = intent.getStringExtra(EXTRA_REFERENCE_EXE) ?: return null
            return RhipperConfig(
                library = library,
                referenceExe = exe,
                workingDir = intent.getStringExtra(EXTRA_WORKING_DIR) ?: exe.substringBeforeLast('/'),
                args = intent.getStringArrayExtra(EXTRA_ARGS)?.toList().orEmpty(),
                logDir = intent.getStringExtra(EXTRA_LOG_DIR) ?: exe.substringBeforeLast('/'),
            )
        }
    }
}

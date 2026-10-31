package dev.rhipper.host

import android.app.ActivityManager
import android.app.ApplicationExitInfo
import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * How the game process ended when it did not end through [RhipperActivity] (which shows its own
 * dialog): a native crash in the translation or the runtime, an ANR, the system killing it for
 * memory. Android keeps these per process (ApplicationExitInfo); a native crash comes with its
 * tombstone, saved to the log dir so it can be shared and symbolized.
 */
object RhipperExitReports {
    data class Report(val time: Long, val reason: String, val description: String?, val trace: File?)

    private const val PREFS = "rhipper_exit_reports"
    private const val KEY_LAST_SEEN = "last_seen"

    private val reported = setOf(
        ApplicationExitInfo.REASON_CRASH,
        ApplicationExitInfo.REASON_CRASH_NATIVE,
        ApplicationExitInfo.REASON_ANR,
        ApplicationExitInfo.REASON_LOW_MEMORY,
        ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE,
        ApplicationExitInfo.REASON_INITIALIZATION_FAILURE,
        ApplicationExitInfo.REASON_DEPENDENCY_DIED,
    )

    /**
     * The game process's abnormal exits since the last call ([processSuffix]: its
     * android:process, e.g. ":game"), newest first. Call it from the app's main process, e.g. when
     * the launcher resumes. Blocking file I/O: small, but off the main thread is better.
     */
    fun collect(context: Context, processSuffix: String, logDir: File): List<Report> {
        val am = context.getSystemService(ActivityManager::class.java)
        val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val lastSeen = prefs.getLong(KEY_LAST_SEEN, 0L)
        val process = context.packageName + processSuffix
        val exits = am.getHistoricalProcessExitReasons(context.packageName, 0, 16)
            .filter { it.processName == process && it.timestamp > lastSeen }
        if (exits.isEmpty()) return emptyList()
        prefs.edit().putLong(KEY_LAST_SEEN, exits.maxOf { it.timestamp }).apply()
        return exits.filter { it.reason in reported }.map { info ->
            Report(info.timestamp, reasonName(info.reason), info.description, saveTrace(info, logDir))
        }
    }

    private fun saveTrace(info: ApplicationExitInfo, logDir: File): File? = runCatching {
        val stream = info.traceInputStream ?: return null
        logDir.mkdirs()
        val stamp = SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).format(Date(info.timestamp))
        // a native crash's trace is the tombstone in protobuf form (read it with pbtombstone);
        // an ANR's is text
        val ext = if (info.reason == ApplicationExitInfo.REASON_CRASH_NATIVE) "tombstone.pb" else "txt"
        val file = File(logDir, "exit-$stamp-${reasonName(info.reason)}.$ext")
        stream.use { input -> file.outputStream().use { input.copyTo(it) } }
        file
    }.getOrNull()

    private fun reasonName(reason: Int) = when (reason) {
        ApplicationExitInfo.REASON_CRASH -> "crash"
        ApplicationExitInfo.REASON_CRASH_NATIVE -> "native-crash"
        ApplicationExitInfo.REASON_ANR -> "anr"
        ApplicationExitInfo.REASON_LOW_MEMORY -> "low-memory"
        ApplicationExitInfo.REASON_EXCESSIVE_RESOURCE_USAGE -> "excessive-resource-use"
        ApplicationExitInfo.REASON_INITIALIZATION_FAILURE -> "initialization-failure"
        ApplicationExitInfo.REASON_DEPENDENCY_DIED -> "dependency-died"
        else -> "reason-$reason"
    }
}

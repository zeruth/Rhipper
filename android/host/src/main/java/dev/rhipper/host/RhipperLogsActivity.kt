package dev.rhipper.host

import android.app.Activity
import android.app.AlertDialog
import android.content.Context
import android.content.Intent
import android.graphics.Typeface
import android.os.Bundle
import android.text.format.DateUtils
import android.text.format.Formatter
import android.view.Gravity
import android.widget.ArrayAdapter
import android.widget.FrameLayout
import android.widget.ListView
import android.widget.ScrollView
import android.widget.TextView
import androidx.core.content.FileProvider
import java.io.File
import java.io.RandomAccessFile
import kotlin.concurrent.thread

/** The runtime's log dir: its files newest first; tap one to read its end or share it. */
class RhipperLogsActivity : Activity() {
    private lateinit var dir: File
    private lateinit var list: ListView
    private var files: List<File> = emptyList()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        dir = File(intent.getStringExtra(EXTRA_DIR) ?: filesDir.path)
        val pad = (16 * resources.displayMetrics.density).toInt()
        val empty = TextView(this).apply {
            text = getString(R.string.rhipper_logs_empty, dir.path)
            gravity = Gravity.CENTER
            setPadding(pad, pad, pad, pad)
        }
        list = ListView(this).apply {
            clipToPadding = false
            emptyView = empty
            setOnItemClickListener { _, _, position, _ -> open(files[position]) }
        }
        val root = FrameLayout(this).apply {
            addView(list)
            addView(empty)
        }
        setContentView(root)
        root.padForSystemBars()
    }

    override fun onResume() {
        super.onResume()
        files = dir.listFiles()?.filter { it.isFile }?.sortedByDescending { it.lastModified() }.orEmpty()
        list.adapter = ArrayAdapter(
            this, android.R.layout.simple_list_item_1,
            files.map { f ->
                "${f.name}\n${Formatter.formatFileSize(this, f.length())} · " +
                    DateUtils.getRelativeTimeSpanString(f.lastModified())
            },
        )
    }

    private fun open(file: File) {
        thread(name = "rhipper-log-read") {
            val text = readTail(file)
            runOnUiThread { if (!isFinishing) show(file, text) }
        }
    }

    private fun show(file: File, text: String) {
        val pad = (12 * resources.displayMetrics.density).toInt()
        val body = TextView(this).apply {
            this.text = text
            typeface = Typeface.MONOSPACE
            textSize = 11f
            setTextIsSelectable(true)
            setPadding(pad, pad, pad, pad)
        }
        val scroll = ScrollView(this).apply { addView(body) }
        AlertDialog.Builder(this)
            .setTitle(file.name)
            .setView(scroll)
            .setPositiveButton(R.string.rhipper_share) { _, _ -> share(file) }
            .setNegativeButton(R.string.rhipper_close, null)
            .show()
        // the end of a log is what matters
        scroll.post { scroll.fullScroll(ScrollView.FOCUS_DOWN) }
    }

    /** The last [TAIL_BYTES] of a text file; binary files (tombstones, traces) only by name. */
    private fun readTail(file: File): String = runCatching {
        RandomAccessFile(file, "r").use { f ->
            val start = maxOf(0L, f.length() - TAIL_BYTES)
            val bytes = ByteArray((f.length() - start).toInt())
            f.seek(start)
            f.readFully(bytes)
            if (bytes.take(4096).any { it == 0.toByte() }) {
                getString(R.string.rhipper_logs_binary, file.name, Formatter.formatFileSize(this, file.length()))
            } else {
                (if (start > 0) "…\n" else "") + String(bytes, Charsets.UTF_8)
            }
        }
    }.getOrElse { it.toString() }

    private fun share(file: File) {
        val uri = FileProvider.getUriForFile(this, "$packageName.rhipper.files", file)
        val send = Intent(Intent.ACTION_SEND)
            .setType(if (file.extension in setOf("txt", "log", "json", "csv")) "text/plain" else "application/octet-stream")
            .putExtra(Intent.EXTRA_STREAM, uri)
            .putExtra(Intent.EXTRA_SUBJECT, file.name)
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        startActivity(Intent.createChooser(send, file.name))
    }

    companion object {
        const val EXTRA_DIR = "dev.rhipper.host.LOG_DIR"
        private const val TAIL_BYTES = 128L * 1024

        fun intent(context: Context, dir: File): Intent =
            Intent(context, RhipperLogsActivity::class.java).putExtra(EXTRA_DIR, dir.path)
    }
}

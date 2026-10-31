package dev.rhipper.host

import android.view.View
import android.view.WindowInsets

/**
 * Pads this view by the system bars, the display cutout and the keyboard, on top of its own
 * padding: apps targeting SDK 35+ are drawn edge to edge whether they like it or not.
 */
fun View.padForSystemBars() {
    val left = paddingLeft
    val top = paddingTop
    val right = paddingRight
    val bottom = paddingBottom
    setOnApplyWindowInsetsListener { view, insets ->
        val bars = insets.getInsets(
            WindowInsets.Type.systemBars() or WindowInsets.Type.displayCutout() or WindowInsets.Type.ime(),
        )
        view.setPadding(left + bars.left, top + bars.top, right + bars.right, bottom + bars.bottom)
        insets
    }
    requestApplyInsets()
}

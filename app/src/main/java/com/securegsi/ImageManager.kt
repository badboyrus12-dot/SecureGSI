package com.securegsi

import android.content.Context
import android.net.Uri

data class ImageInfo(
    val name: String,
    val size: Long,
    val uri: Uri,
    val sha256: String
)

object ImageManager {

    private fun debugPrintStackTrace(error: Throwable) {
        if (android.os.Debug.isDebuggerConnected()) {
            error.printStackTrace()
        }
    }

    fun getImageInfo(
        context: Context,
        uri: Uri
    ): ImageInfo? {

        return try {
            val resolver = context.contentResolver

            val name = uri.lastPathSegment ?: "Unknown image"

            val size = resolver
                .openFileDescriptor(uri, "r")
                ?.use { it.statSize }
                ?: -1L

            val sha256 = resolver
                .openFileDescriptor(uri, "r")
                ?.use { RustBridge.sha256(it) }
                ?: return null

            ImageInfo(
                name = name,
                size = size,
                uri = uri,
                sha256 = sha256
            )

        } catch (e: Exception) {
            debugPrintStackTrace(e)
            null
        }
    }
}
package com.securegsi

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile

data class ImageInfo(
    val name: String,
    val size: Long,
    val uri: Uri
)

object ImageManager {

    fun getImageInfo(
        context: Context,
        uri: Uri
    ): ImageInfo? {

        val document = DocumentFile.fromSingleUri(
            context,
            uri
        ) ?: return null

        return ImageInfo(
            name = document.name ?: "Unknown image",
            size = document.length(),
            uri = uri
        )
    }
}
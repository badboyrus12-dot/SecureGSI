package com.securegsi

import android.content.Context
import android.net.Uri
import androidx.documentfile.provider.DocumentFile
import java.security.MessageDigest

data class ImageInfo(
    val name: String,
    val size: Long,
    val uri: Uri,
    val sha256: String
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

        val sha256 = calculateSha256(
            context,
            uri
        ) ?: return null

        return ImageInfo(
            name = document.name ?: "Unknown image",
            size = document.length(),
            uri = uri,
            sha256 = sha256
        )
    }

    private fun calculateSha256(
        context: Context,
        uri: Uri
    ): String? {

        return try {

            val digest = MessageDigest.getInstance("SHA-256")

            context.contentResolver.openInputStream(uri)?.use { input ->

                val buffer = ByteArray(1024 * 1024)

                while (true) {

                    val bytesRead = input.read(buffer)

                    if (bytesRead == -1) {
                        break
                    }

                    digest.update(
                        buffer,
                        0,
                        bytesRead
                    )
                }
            } ?: return null

            digest.digest()
                .joinToString("") { byte ->
                    "%02x".format(byte)
                }

        } catch (e: Exception) {

            e.printStackTrace()
            null
        }
    }
}
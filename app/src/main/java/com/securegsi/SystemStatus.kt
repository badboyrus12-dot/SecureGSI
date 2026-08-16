package com.securegsi

import android.content.Context
import android.os.Build

data class SystemStatus(
    val architecture: String,
    val androidVersion: String,
    val sdkVersion: Int,
    val device: String,
    val manufacturer: String,
    val avfAvailable: Boolean,
    val protectedKvmAvailable: Boolean
)

object SystemStatusReader {

    fun read(context: Context): SystemStatus {
        return SystemStatus(
            architecture = getArchitecture(),
            androidVersion = Build.VERSION.RELEASE,
            sdkVersion = Build.VERSION.SDK_INT,
            device = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            avfAvailable = isAvfAvailable(context),
            protectedKvmAvailable = isProtectedKvmAvailable()
        )
    }

    private fun getArchitecture(): String {
        return Build.SUPPORTED_ABIS.firstOrNull() ?: "Unknown"
    }

    private fun isAvfAvailable(context: Context): Boolean {
        return try {
            context.packageManager.hasSystemFeature(
                "android.software.virtualization_framework"
            )
        } catch (_: Exception) {
            false
        }
    }

    private fun isProtectedKvmAvailable(): Boolean {
        return try {
            Build.SUPPORTED_ABIS.any {
                it == "arm64-v8a"
            }
        } catch (_: Exception) {
            false
        }
    }
}


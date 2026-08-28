package com.securegsi

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

@RunWith(AndroidJUnit4::class)
class PersistentExecutorInstrumentedTest {

    companion object {
        private const val TAG = "SecureGSI-PersistentTest"
        private const val TIMEOUT_SECONDS = 15L
    }

    @Test
    fun startPingStatusShutdown() {
        val context =
            InstrumentationRegistry
                .getInstrumentation()
                .targetContext

        var started = false

        try {
            val startResult =
                awaitResult("START") { callback ->
                    AegisIsolatedClient.startPersistentExecutor(
                        context = context,
                        onResult = callback
                    )
                }

            assertHealthy(
                operation = "START",
                result = startResult
            )

            started = true

            val pingResult =
                awaitResult("PING") { callback ->
                    AegisIsolatedClient.pingPersistentExecutor(
                        onResult = callback
                    )
                }

            assertHealthy(
                operation = "PING",
                result = pingResult
            )

            val statusResult =
                awaitResult("STATUS") { callback ->
                    AegisIsolatedClient.persistentExecutorStatus(
                        onResult = callback
                    )
                }

            assertHealthy(
                operation = "STATUS",
                result = statusResult
            )

        } finally {
            if (started) {
                val shutdownResult =
                    awaitResult("SHUTDOWN") { callback ->
                        AegisIsolatedClient.shutdownPersistentExecutor(
                            onResult = callback
                        )
                    }

                assertHealthy(
                    operation = "SHUTDOWN",
                    result = shutdownResult
                )
            }
        }
    }

    private fun awaitResult(
        operation: String,
        invoke: ((String) -> Unit) -> Unit
    ): String {
        val latch = CountDownLatch(1)
        val resultRef = AtomicReference<String?>()

        invoke { result ->
            resultRef.set(result)

            Log.i(
                TAG,
                "$operation=${result.replace("\n", " | ")}"
            )

            latch.countDown()
        }

        val completed =
            latch.await(
                TIMEOUT_SECONDS,
                TimeUnit.SECONDS
            )

        assertTrue(
            "$operation timed out after $TIMEOUT_SECONDS seconds",
            completed
        )

        val result = resultRef.get()

        assertNotNull(
            "$operation returned null",
            result
        )

        return result!!
    }

    private fun assertHealthy(
        operation: String,
        result: String
    ) {
        assertTrue(
            "$operation returned an empty result",
            result.isNotBlank()
        )

        val lower =
            result.lowercase()

        assertFalse(
            "$operation failed: $result",
            lower.contains("jni_failed")
        )

        assertFalse(
            "$operation failed: $result",
            lower.contains("not connected")
        )

        assertFalse(
            "$operation failed: $result",
            lower.contains("binder transaction failed")
        )

        assertFalse(
            "$operation failed: $result",
            lower.contains("returned no result")
        )
    }
}
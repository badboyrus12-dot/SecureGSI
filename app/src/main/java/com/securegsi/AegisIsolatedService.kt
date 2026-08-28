package com.securegsi

import android.app.Service
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process
import android.system.Os
import android.util.Log
import java.io.File

class AegisIsolatedService : Service() {

    companion object {
        const val DESCRIPTOR =
            "com.securegsi.AegisIsolatedService"

        /*
         * Kept under the existing name so MainActivity/client compatibility
         * is not disturbed. The transaction now returns:
         *
         *   PID
         *   UID
         *   isolated Guest Executor proof result
         */
        const val TRANSACTION_GET_IDENTITY =
            IBinder.FIRST_CALL_TRANSACTION

        const val TRANSACTION_START_EXECUTOR =
            IBinder.FIRST_CALL_TRANSACTION + 1

        const val TRANSACTION_PING_EXECUTOR =
            IBinder.FIRST_CALL_TRANSACTION + 2

        const val TRANSACTION_EXECUTOR_STATUS =
            IBinder.FIRST_CALL_TRANSACTION + 3

        const val TRANSACTION_SHUTDOWN_EXECUTOR =
            IBinder.FIRST_CALL_TRANSACTION + 4

        private const val TAG =
            "Aegis-Isolated"
    }

    private val binder = object : Binder() {

        override fun onTransact(
            code: Int,
            data: Parcel,
            reply: Parcel?,
            flags: Int
        ): Boolean {

            if (code == TRANSACTION_START_EXECUTOR) {
                data.enforceInterface(DESCRIPTOR)

                val result =
                    try {
                        RustBridge.startPersistentExecutor()
                    } catch (e: Throwable) {
                        "PERSISTENT_EXECUTOR_START: JNI_FAILED\n" +
                                (e.message ?: e.javaClass.simpleName)
                    }

                Log.i(
                    TAG,
                    "PERSISTENT_EXECUTOR_START_RESULT=$result"
                )

                logPersistentExecutorFdsForDebug(result)

                reply?.writeNoException()
                reply?.writeString(result)

                return true
            }

            if (code == TRANSACTION_PING_EXECUTOR) {
                data.enforceInterface(DESCRIPTOR)

                val result =
                    try {
                        RustBridge.pingPersistentExecutor()
                    } catch (e: Throwable) {
                        "PERSISTENT_EXECUTOR_PING: JNI_FAILED\n" +
                                (e.message ?: e.javaClass.simpleName)
                    }

                Log.i(
                    TAG,
                    "PERSISTENT_EXECUTOR_PING_RESULT=$result"
                )

                reply?.writeNoException()
                reply?.writeString(result)

                return true
            }

            if (code == TRANSACTION_EXECUTOR_STATUS) {
                data.enforceInterface(DESCRIPTOR)

                val result =
                    try {
                        RustBridge.persistentExecutorStatus()
                    } catch (e: Throwable) {
                        "PERSISTENT_EXECUTOR_STATUS: JNI_FAILED\n" +
                                (e.message ?: e.javaClass.simpleName)
                    }

                Log.i(
                    TAG,
                    "PERSISTENT_EXECUTOR_STATUS_RESULT=$result"
                )

                reply?.writeNoException()
                reply?.writeString(result)

                return true
            }

            if (code == TRANSACTION_SHUTDOWN_EXECUTOR) {
                data.enforceInterface(DESCRIPTOR)

                val result =
                    try {
                        RustBridge.shutdownPersistentExecutor()
                    } catch (e: Throwable) {
                        "PERSISTENT_EXECUTOR_SHUTDOWN: JNI_FAILED\n" +
                                (e.message ?: e.javaClass.simpleName)
                    }

                Log.i(
                    TAG,
                    "PERSISTENT_EXECUTOR_SHUTDOWN_RESULT=$result"
                )

                reply?.writeNoException()
                reply?.writeString(result)

                return true
            }

            if (code != TRANSACTION_GET_IDENTITY) {
                return super.onTransact(
                    code,
                    data,
                    reply,
                    flags
                )
            }

            data.enforceInterface(DESCRIPTOR)

            /*
             * IMPORTANT:
             *
             * This method is executing inside Android isolatedProcess.
             *
             * Rust forks a tiny proof child. After fork the child performs
             * only the minimal native sequence:
             *
             *   PR_SET_NO_NEW_PRIVS
             *        ->
             *   seccomp
             *        ->
             *   direct ARM64 svc #0
             *        ->
             *   _exit()
             *
             * No guest filesystem or bootstrap is involved in this proof.
             */
            val executorProof =
                try {
                    RustBridge.runIsolatedExecutorProof()
                } catch (e: Throwable) {
                    "ISOLATED_EXECUTOR_PROOF: JNI_FAILED\n" +
                            (e.message ?: e.javaClass.simpleName)
                }

            Log.i(
                TAG,
                "EXECUTOR_PROOF_RESULT=$executorProof"
            )

            reply?.writeNoException()
            reply?.writeInt(Process.myPid())
            reply?.writeInt(Process.myUid())
            reply?.writeString(executorProof)

            return true
        }
    }

    override fun onCreate() {
        super.onCreate()

        Log.i(
            TAG,
            "started pid=${Process.myPid()} uid=${Process.myUid()}"
        )

        try {
            val selinuxContext =
                File("/proc/self/attr/current")
                    .readText()
                    .trim()

            Log.i(
                TAG,
                "SELinux=$selinuxContext"
            )

            val statusBefore =
                readSecurityStatus()

            Log.i(
                TAG,
                "STATUS_BEFORE=$statusBefore"
            )

            /*
             * Service-thread control proof.
             *
             * This is deliberately kept separate from the forked
             * Guest Executor proof above.
             */
            val noNewPrivsResult =
                RustBridge.enableNoNewPrivs()

            Log.i(
                TAG,
                "NNP_RESULT=$noNewPrivsResult"
            )

            val statusAfterNnp =
                readSecurityStatus()

            Log.i(
                TAG,
                "STATUS_AFTER_NNP=$statusAfterNnp"
            )

            /*
             * Minimal PoC policy:
             *
             *   getppid() -> EPERM
             *   everything else -> ALLOW
             *
             * This is NOT the final Guest Executor allowlist.
             */
            val seccompResult =
                RustBridge.installMinimalSeccomp()

            Log.i(
                TAG,
                "SECCOMP_RESULT=$seccompResult"
            )

            val seccompTestResult =
                RustBridge.testMinimalSeccomp()

            Log.i(
                TAG,
                "SECCOMP_TEST_RESULT=$seccompTestResult"
            )

            val directSvcTestResult =
                RustBridge.testDirectSvcSeccomp()

            Log.i(
                TAG,
                "DIRECT_SVC_TEST_RESULT=$directSvcTestResult"
            )

            val statusAfterSeccomp =
                readSecurityStatus()

            Log.i(
                TAG,
                "STATUS_AFTER_SECCOMP=$statusAfterSeccomp"
            )
        } catch (e: Throwable) {
            Log.e(
                TAG,
                "security probe failed",
                e
            )
        }
    }

    private fun logPersistentExecutorFdsForDebug(
        startResult: String
    ) {
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE == 0) {
            return
        }

        val pid =
            Regex("""(?m)^PID:\s*(\d+)\s*$""")
                .find(startResult)
                ?.groupValues
                ?.getOrNull(1)
                ?.toIntOrNull()

        if (pid == null) {
            Log.w(
                TAG,
                "PERSISTENT_EXECUTOR_FD_AUDIT: PID_NOT_FOUND"
            )
            return
        }

        val fdDirectory =
            File("/proc/$pid/fd")

        val entries =
            try {
                fdDirectory
                    .listFiles()
                    ?.sortedBy {
                        it.name.toIntOrNull()
                            ?: Int.MAX_VALUE
                    }
            } catch (e: Throwable) {
                Log.w(
                    TAG,
                    "PERSISTENT_EXECUTOR_FD_AUDIT: FAILED pid=$pid",
                    e
                )
                null
            }

        if (entries == null) {
            Log.w(
                TAG,
                "PERSISTENT_EXECUTOR_FD_AUDIT: UNAVAILABLE pid=$pid"
            )
            return
        }

        val details =
            entries.joinToString(" | ") { entry ->
                val target =
                    try {
                        Os.readlink(entry.absolutePath)
                    } catch (e: Throwable) {
                        "<unreadable:${e.javaClass.simpleName}>"
                    }

                "${entry.name} -> $target"
            }

        Log.i(
            TAG,
            "PERSISTENT_EXECUTOR_FD_AUDIT " +
                    "pid=$pid count=${entries.size} fds=[$details]"
        )
    }

    private fun readSecurityStatus(): String {
        return File("/proc/self/status")
            .readLines()
            .filter { line ->
                line.startsWith("Uid:") ||
                        line.startsWith("Gid:") ||
                        line.startsWith("Groups:") ||
                        line.startsWith("CapInh:") ||
                        line.startsWith("CapPrm:") ||
                        line.startsWith("CapEff:") ||
                        line.startsWith("CapBnd:") ||
                        line.startsWith("NoNewPrivs:") ||
                        line.startsWith("Seccomp:")
            }
            .joinToString(" | ")
    }

    override fun onBind(intent: Intent?): IBinder {
        return binder
    }
}
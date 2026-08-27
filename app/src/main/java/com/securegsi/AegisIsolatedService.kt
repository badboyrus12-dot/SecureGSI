package com.securegsi

import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import android.os.Parcel
import android.os.Process
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
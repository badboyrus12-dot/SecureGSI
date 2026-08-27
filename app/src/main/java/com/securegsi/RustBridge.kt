package com.securegsi

import android.content.Context
import android.os.ParcelFileDescriptor
import android.system.Os
import java.io.File
import java.io.FileOutputStream

object RustBridge {

    private const val BOOTSTRAP_ASSET =
        "bootstrap/securegsi-bootstrap"

    private const val BOOTSTRAP_DIR =
        "bootstrap"

    private const val BOOTSTRAP_FILE =
        "securegsi-bootstrap"

    init {
        System.loadLibrary("rust")
    }

    private external fun sha256Fd(
        fd: Int
    ): String?

    private external fun readHeader(
        fd: Int
    ): String?

    private external fun testContainerRuntimeNative(): String?

    private external fun startGuestProbeNative(): String?

    private external fun stopGuestNative(): String?

    private external fun guestStatusNative(): String?

    private external fun enableNoNewPrivsNative(): String?

    private external fun installMinimalSeccompNative(): String?

    private external fun testMinimalSeccompNative(): String?

    private external fun testDirectSvcSeccompNative(): String?

    private external fun runIsolatedExecutorProofNative(): String?

    private external fun configureDuressNative(
        filesDir: String,
        pin: String
    ): String?

    private external fun duressStatusNative(
        filesDir: String
    ): String?

    private external fun checkDuressAndWipeNative(
        filesDir: String,
        pin: String
    ): String?

    fun sha256(
        fileDescriptor: ParcelFileDescriptor
    ): String {
        return sha256Fd(fileDescriptor.fd)
            ?: throw IllegalStateException(
                "Rust SHA-256 failed"
            )
    }

    fun readHeader(
        fileDescriptor: ParcelFileDescriptor
    ): String {
        return readHeader(fileDescriptor.fd)
            ?: throw IllegalStateException(
                "Rust header read failed"
            )
    }

    fun testContainerRuntime(): String {
        return testContainerRuntimeNative()
            ?: "Rust runtime test failed"
    }

    /**
     * Enables Linux PR_SET_NO_NEW_PRIVS on the calling native task
     * and verifies it with PR_GET_NO_NEW_PRIVS.
     */
    fun enableNoNewPrivs(): String {
        return enableNoNewPrivsNative()
            ?: "PR_SET_NO_NEW_PRIVS JNI call failed"
    }

    /**
     * Installs the current minimal stacked-seccomp PoC.
     *
     * Current test policy:
     *
     *   getppid() -> EPERM
     *   everything else -> ALLOW
     *
     * This is not the final Guest Executor allowlist.
     */
    fun installMinimalSeccomp(): String {
        return installMinimalSeccompNative()
            ?: "Stacked seccomp JNI call failed"
    }

    /**
     * Exercises the current seccomp filter through libc::syscall().
     */
    fun testMinimalSeccomp(): String {
        return testMinimalSeccompNative()
            ?: "Stacked seccomp test JNI call failed"
    }

    /**
     * Bypasses libc and exercises the current seccomp filter
     * with a direct ARM64 `svc #0`.
     */
    fun testDirectSvcSeccomp(): String {
        return testDirectSvcSeccompNative()
            ?: "Direct ARM64 svc #0 seccomp test JNI call failed"
    }

    /**
     * Runs the forked Guest Executor security proof from whichever
     * Android process invokes this JNI method.
     *
     * For the current milestone it must be invoked by
     * AegisIsolatedService, so the proof child originates inside
     * Android isolatedProcess.
     */
    fun runIsolatedExecutorProof(): String {
        return runIsolatedExecutorProofNative()
            ?: "Isolated Guest Executor proof JNI call failed"
    }

    /**
     * Copies the ARM64 SecureGSI bootstrap from APK assets into
     * the normal app-private files directory.
     *
     * This existing path belongs to the normal application process.
     * It is intentionally NOT used by runIsolatedExecutorProof().
     */
    fun prepareBootstrap(
        context: Context
    ): File {
        val appContext =
            context.applicationContext

        val bootstrapDir =
            File(
                appContext.filesDir,
                BOOTSTRAP_DIR
            )

        if (!bootstrapDir.exists()) {
            check(
                bootstrapDir.mkdirs()
            ) {
                "Failed to create bootstrap directory: " +
                        bootstrapDir.absolutePath
            }
        }

        val bootstrapFile =
            File(
                bootstrapDir,
                BOOTSTRAP_FILE
            )

        /*
         * Always replace the extracted binary so a newly installed
         * APK cannot accidentally execute an older bootstrap.
         */
        appContext.assets
            .open(BOOTSTRAP_ASSET)
            .use { input ->

                FileOutputStream(
                    bootstrapFile,
                    false
                ).use { output ->

                    input.copyTo(output)

                    output.flush()

                    output.fd.sync()
                }
            }

        /*
         * 0700 decimal = 448.
         */
        Os.chmod(
            bootstrapFile.absolutePath,
            448
        )

        check(
            bootstrapFile.exists()
        ) {
            "Bootstrap extraction failed"
        }

        check(
            bootstrapFile.length() > 0L
        ) {
            "Bootstrap is empty"
        }

        return bootstrapFile
    }

    /**
     * Existing normal-process guest runtime path.
     *
     * Do not treat this method as the final isolated Guest Executor
     * architecture. The current isolated proof uses the dedicated
     * runIsolatedExecutorProof() path above.
     */
    fun startGuestProbe(
        context: Context
    ): String {
        val bootstrap =
            prepareBootstrap(context)

        check(
            bootstrap.canExecute()
        ) {
            "Bootstrap is not executable: " +
                    bootstrap.absolutePath
        }

        return startGuestProbeNative()
            ?: "Guest runtime failed"
    }

    /**
     * Temporarily kept for compatibility with existing callers.
     */
    fun startGuestProbe(): String {
        return startGuestProbeNative()
            ?: "Guest runtime failed"
    }

    fun stopGuest(): String {
        return stopGuestNative()
            ?: "Failed to stop guest"
    }

    fun guestStatus(): String {
        return guestStatusNative()
            ?: "SecureGSI Guest Runtime\nStatus: UNKNOWN"
    }

    fun configureDuress(
        context: Context,
        pin: String
    ): String {
        require(pin.length in 4..64) {
            "Duress PIN must contain 4..64 characters"
        }

        val filesDir =
            context.applicationContext.filesDir.absolutePath

        return configureDuressNative(
            filesDir,
            pin
        ) ?: "DURESS_CONFIG_FAILED"
    }

    fun duressStatus(
        context: Context
    ): String {
        val filesDir =
            context.applicationContext.filesDir.absolutePath

        return duressStatusNative(
            filesDir
        ) ?: "DURESS_STATUS_FAILED"
    }

    fun checkDuressAndWipe(
        context: Context,
        pin: String
    ): String {
        val filesDir =
            context.applicationContext.filesDir.absolutePath

        return checkDuressAndWipeNative(
            filesDir,
            pin
        ) ?: "DURESS_CHECK_FAILED"
    }

}
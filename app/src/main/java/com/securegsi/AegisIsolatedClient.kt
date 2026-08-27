package com.securegsi

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.IBinder
import android.os.Parcel

object AegisIsolatedClient {

    fun probe(
        context: Context,
        onResult: (String) -> Unit
    ) {
        val appContext =
            context.applicationContext

        val connection =
            object : ServiceConnection {

                override fun onServiceConnected(
                    name: ComponentName?,
                    service: IBinder?
                ) {
                    if (service == null) {
                        onResult(
                            "Isolated service returned null Binder"
                        )

                        try {
                            appContext.unbindService(this)
                        } catch (_: Throwable) {
                        }

                        return
                    }

                    val data =
                        Parcel.obtain()

                    val reply =
                        Parcel.obtain()

                    try {
                        data.writeInterfaceToken(
                            AegisIsolatedService.DESCRIPTOR
                        )

                        /*
                         * One synchronous probe transaction returns:
                         *
                         *   1. isolated process PID
                         *   2. isolated process UID
                         *   3. forked Guest Executor proof report
                         */
                        val ok =
                            service.transact(
                                AegisIsolatedService.TRANSACTION_GET_IDENTITY,
                                data,
                                reply,
                                0
                            )

                        if (!ok) {
                            onResult(
                                "Binder transaction failed"
                            )

                            return
                        }

                        reply.readException()

                        val pid =
                            reply.readInt()

                        val uid =
                            reply.readInt()

                        val executorProof =
                            reply.readString()
                                ?: "ISOLATED_EXECUTOR_PROOF: NO_RESULT"

                        onResult(
                            "Aegis isolated process\n" +
                                    "PID: $pid\n" +
                                    "UID: $uid\n\n" +
                                    executorProof
                        )
                    } catch (e: Throwable) {
                        onResult(
                            "Isolated probe failed: " +
                                    (e.message
                                        ?: e.javaClass.simpleName)
                        )
                    } finally {
                        reply.recycle()
                        data.recycle()

                        try {
                            appContext.unbindService(this)
                        } catch (_: Throwable) {
                        }
                    }
                }

                override fun onServiceDisconnected(
                    name: ComponentName?
                ) = Unit
            }

        val intent =
            Intent(
                appContext,
                AegisIsolatedService::class.java
            )

        val bound =
            appContext.bindService(
                intent,
                connection,
                Context.BIND_AUTO_CREATE
            )

        if (!bound) {
            onResult(
                "Failed to bind isolated service"
            )
        }
    }
}
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
    /*
     * Persistent binding is intentionally separate from probe().
     * probe() remains a one-shot bind/transact/unbind path.
     */
    private val persistentLock = Any()

    private var persistentAppContext: Context? = null
    private var persistentConnection: ServiceConnection? = null
    private var persistentBinder: IBinder? = null

    fun startPersistentExecutor(
        context: Context,
        onResult: (String) -> Unit
    ) {
        val appContext =
            context.applicationContext

        val currentBinder =
            synchronized(persistentLock) {
                persistentBinder
            }

        if (currentBinder != null) {
            onResult(
                transactPersistent(
                    currentBinder,
                    AegisIsolatedService.TRANSACTION_START_EXECUTOR
                )
            )
            return
        }

        val connection =
            object : ServiceConnection {

                override fun onServiceConnected(
                    name: ComponentName?,
                    service: IBinder?
                ) {
                    if (service == null) {
                        releasePersistentBinding()
                        onResult(
                            "Persistent isolated service returned null Binder"
                        )
                        return
                    }

                    synchronized(persistentLock) {
                        persistentBinder = service
                    }

                    onResult(
                        transactPersistent(
                            service,
                            AegisIsolatedService.TRANSACTION_START_EXECUTOR
                        )
                    )
                }

                override fun onServiceDisconnected(
                    name: ComponentName?
                ) {
                    clearPersistentStateWithoutUnbind()
                }

                override fun onBindingDied(
                    name: ComponentName?
                ) {
                    releasePersistentBinding()
                }

                override fun onNullBinding(
                    name: ComponentName?
                ) {
                    releasePersistentBinding()
                    onResult(
                        "Persistent isolated service returned null binding"
                    )
                }
            }

        val accepted =
            synchronized(persistentLock) {
                if (
                    persistentBinder != null ||
                    persistentConnection != null
                ) {
                    false
                } else {
                    persistentAppContext = appContext
                    persistentConnection = connection
                    true
                }
            }

        if (!accepted) {
            val binder =
                synchronized(persistentLock) {
                    persistentBinder
                }

            if (binder != null) {
                onResult(
                    transactPersistent(
                        binder,
                        AegisIsolatedService.TRANSACTION_START_EXECUTOR
                    )
                )
            } else {
                onResult(
                    "Persistent isolated service binding already in progress"
                )
            }

            return
        }

        val intent =
            Intent(
                appContext,
                AegisIsolatedService::class.java
            )

        val bound =
            try {
                appContext.bindService(
                    intent,
                    connection,
                    Context.BIND_AUTO_CREATE
                )
            } catch (e: Throwable) {
                releasePersistentBinding()
                onResult(
                    "Failed to bind persistent isolated service: " +
                            (e.message ?: e.javaClass.simpleName)
                )
                return
            }

        if (!bound) {
            releasePersistentBinding()
            onResult(
                "Failed to bind persistent isolated service"
            )
        }
    }

    fun pingPersistentExecutor(
        onResult: (String) -> Unit
    ) {
        onResult(
            transactCurrentPersistent(
                AegisIsolatedService.TRANSACTION_PING_EXECUTOR
            )
        )
    }

    fun persistentExecutorStatus(
        onResult: (String) -> Unit
    ) {
        onResult(
            transactCurrentPersistent(
                AegisIsolatedService.TRANSACTION_EXECUTOR_STATUS
            )
        )
    }

    fun shutdownPersistentExecutor(
        onResult: (String) -> Unit
    ) {
        val result =
            transactCurrentPersistent(
                AegisIsolatedService.TRANSACTION_SHUTDOWN_EXECUTOR
            )

        releasePersistentBinding()
        onResult(result)
    }

    private fun transactCurrentPersistent(
        transactionCode: Int
    ): String {
        val service =
            synchronized(persistentLock) {
                persistentBinder
            }
            ?: return "Persistent isolated service is not connected"

        return transactPersistent(
            service,
            transactionCode
        )
    }

    private fun transactPersistent(
        service: IBinder,
        transactionCode: Int
    ): String {
        val data = Parcel.obtain()
        val reply = Parcel.obtain()

        return try {
            data.writeInterfaceToken(
                AegisIsolatedService.DESCRIPTOR
            )

            val ok =
                service.transact(
                    transactionCode,
                    data,
                    reply,
                    0
                )

            if (!ok) {
                "Persistent Binder transaction failed"
            } else {
                reply.readException()
                reply.readString()
                    ?: "Persistent Binder returned no result"
            }
        } catch (e: Throwable) {
            "Persistent Binder transaction failed: " +
                    (e.message ?: e.javaClass.simpleName)
        } finally {
            reply.recycle()
            data.recycle()
        }
    }

    private fun releasePersistentBinding() {
        val state =
            synchronized(persistentLock) {
                val context = persistentAppContext
                val connection = persistentConnection

                persistentAppContext = null
                persistentConnection = null
                persistentBinder = null

                Pair(context, connection)
            }

        val context = state.first
        val connection = state.second

        if (context != null && connection != null) {
            try {
                context.unbindService(connection)
            } catch (_: Throwable) {
            }
        }
    }

    private fun clearPersistentStateWithoutUnbind() {
        synchronized(persistentLock) {
            persistentAppContext = null
            persistentConnection = null
            persistentBinder = null
        }
    }

}
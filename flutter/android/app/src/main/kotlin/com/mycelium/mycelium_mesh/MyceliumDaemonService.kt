package com.mycelium.mycelium_mesh

import android.app.*
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat

/**
 * Foreground service that keeps the Mycelium process alive even when the
 * Flutter UI is backgrounded or swiped away.
 *
 * The Rust node, Tokio runtime, BLE service, and API server all live in
 * this same process. The foreground service prevents Android from killing it.
 *
 * When the Flutter Activity is destroyed and later recreated, Dart reconnects
 * to the still-running Rust API server via REST/WebSocket.
 */
class MyceliumDaemonService : Service() {
    companion object {
        private const val TAG = "MyceliumDaemon"
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "mycelium_daemon"

        @Volatile
        var isRunning = false
            private set
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "Daemon service created")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (isRunning) {
            Log.d(TAG, "Already running, ignoring start")
            return START_STICKY
        }

        // Promote to foreground immediately (Android requires this within 5s)
        startForeground(NOTIFICATION_ID, buildNotification("Mycelium mesh active"))
        isRunning = true
        Log.i(TAG, "Daemon service started as foreground")

        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "Daemon service destroyed")
        isRunning = false
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // --- Notifications ---

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Mycelium Mesh",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Keeps the mesh network running in the background"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Mycelium")
            .setContentText(text)
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
            .setOngoing(true)
            .setContentIntent(pendingIntent)
            .build()
    }
}

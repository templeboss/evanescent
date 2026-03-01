package net.evanescent.provider

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.*
import net.evanescent.App
import net.evanescent.R

private const val TAG = "Evanescent"
private const val NOTIFICATION_ID = 1
private const val CHANNEL_ID = "evanescent_connection"

/**
 * Foreground service maintaining the persistent WebSocket connection to the provider.
 * Runs continuously even when the app is backgrounded.
 */
class ProviderService : Service() {

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(NOTIFICATION_ID, buildNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val onionAddress = intent?.getStringExtra(EXTRA_ONION_ADDRESS) ?: return START_NOT_STICKY

        if (!OrbotHelper.isOrbotInstalled(this)) {
            Log.e(TAG, "Orbot not installed — cannot start provider connection")
            stopSelf()
            return START_NOT_STICKY
        }

        OrbotHelper.requestOrbotStart(this)

        scope.launch {
            delay(3_000) // Give Orbot time to start.
            val app = applicationContext as App
            app.providerClient.connect(onionAddress)
        }

        return START_STICKY
    }

    override fun onDestroy() {
        scope.cancel()
        val app = applicationContext as App
        app.providerClient.disconnect()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun buildNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            packageManager.getLaunchIntentForPackage(packageName),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.notification_title))
            .setContentText(getString(R.string.notification_text))
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                getString(R.string.notification_channel_name),
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    companion object {
        const val EXTRA_ONION_ADDRESS = "onion_address"

        fun start(context: Context, onionAddress: String) {
            val intent = Intent(context, ProviderService::class.java)
                .putExtra(EXTRA_ONION_ADDRESS, onionAddress)
            context.startForegroundService(intent)
        }
    }
}

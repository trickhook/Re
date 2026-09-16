package com.trickhook.mcp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import androidx.core.content.ContextCompat
import com.trickhook.MainActivity
import com.trickhook.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.net.BindException

/**
 * The listener's lifetime, and the notification that makes it impossible to
 * forget about.
 *
 * A foreground service for two reasons. The practical one: Android freezes and
 * then kills background processes, and a socket in one stops answering without
 * saying so. The real one: this app is listening on a network port, and the
 * person carrying the phone has to be able to see that at a glance, from the
 * status bar, without opening anything. The notification names the interface
 * and the address it is bound to, says whether writes are allowed, and carries
 * a Stop button.
 *
 * Nothing starts this but a tap. There is no BOOT_COMPLETED receiver, nothing
 * on app launch, and [onStartCommand] returns START_NOT_STICKY so the system
 * will not bring it back after a kill. `android:stopWithTask="true"` in the
 * manifest takes it down when the app is swiped away, and [McpRuntime.detach]
 * takes it down when the analysis screen is finished.
 */
class McpService : Service() {

    companion object {
        private const val ACTION_START = "com.trickhook.mcp.START"
        private const val ACTION_STOP = "com.trickhook.mcp.STOP"
        private const val EXTRA_REASON = "com.trickhook.mcp.REASON"
        private const val CHANNEL_ID = "mcp-server"
        private const val NOTIFICATION_ID = 0x4D4350

        @Volatile
        private var instance: McpService? = null

        @Volatile
        private var held: Context? = null

        /**
         * An application context, live only while the service is. The write
         * tools use it to reach the project database, so a write is impossible
         * unless a listener is actually running.
         */
        fun appContextOrNull(): Context? = held

        fun start(context: Context) {
            val intent = Intent(context, McpService::class.java).setAction(ACTION_START)
            ContextCompat.startForegroundService(context.applicationContext, intent)
        }

        /**
         * Stop, with a sentence saying why for the sheet. Called straight on
         * the live instance rather than through an Intent: the self-stop paths
         * (idle timeout, a run of bad tokens) fire from a socket thread while
         * the app may be in the background, where starting a service is
         * refused.
         */
        fun stop(context: Context, reason: String) {
            val live = instance
            if (live != null) {
                live.shutdown(reason)
                return
            }
            McpRuntime.markStopped(reason)
        }
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile
    private var server: McpServer? = null

    /**
     * Set the moment a start is accepted and cleared when it resolves, so two
     * quick taps cannot put two listeners on one port. `server` alone is not
     * enough: it stays null for as long as the bind is in flight.
     */
    @Volatile
    private var launching = false

    override fun onCreate() {
        super.onCreate()
        instance = this
        held = applicationContext
        createChannel()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                shutdown(intent.getStringExtra(EXTRA_REASON) ?: "stopped from the notification")
                return START_NOT_STICKY
            }

            ACTION_START -> {
                if (server == null && !launching) launchServer()
            }

            else -> {
                // A start with no action of ours — a system restart, or an
                // Intent from nowhere. There is nothing to run and a foreground
                // service that never shows a notification is killed for it, so
                // go away quietly.
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun launchServer() {
        // startForeground first and within a few seconds of the start request,
        // which is what Android requires; the bind below is fast but is still
        // I/O and belongs off the main thread.
        launching = true
        goForeground(notification("Starting…", "Choosing an address"))
        val token = McpRuntime.markStarting(this)
        val wantsLoopback = McpRuntime.bindMode == McpRuntime.MODE_LOOPBACK
        val allowWrites = !McpRuntime.readOnly
        scope.launch {
            val endpoint = if (wantsLoopback) {
                McpNetwork.loopbackEndpoint()
            } else {
                McpNetwork.preferred()
            }
            if (endpoint == null) {
                launching = false
                fail(
                    "This device is not on a network right now, so there is no address to " +
                        "bind. Join a Wi-Fi network, or switch to loopback and use adb forward."
                )
                return@launch
            }
            val fresh = McpServer(endpoint, token, allowWrites) { reason -> shutdown(reason) }
            try {
                fresh.start()
            } catch (e: BindException) {
                launching = false
                fail("Port ${McpRuntime.PORT} is already in use on this device.")
                return@launch
            } catch (e: Exception) {
                launching = false
                fail(
                    "Could not listen on ${endpoint.host}: " +
                        (e.message ?: e.javaClass.simpleName)
                )
                return@launch
            }
            server = fresh
            launching = false
            McpRuntime.markRunning(endpoint)
            goForeground(
                notification(
                    "Listening on ${endpoint.host}:${McpRuntime.PORT}",
                    endpoint.kind + " · " + endpoint.iface + " · " +
                        (if (allowWrites) "writes allowed" else "read-only")
                )
            )
        }
    }

    private fun fail(why: String) {
        McpRuntime.markFailed(why)
        stopEverything()
    }

    /** Public stop path: tear the listener down and say why. */
    fun shutdown(reason: String) {
        launching = false
        server?.stop()
        server = null
        McpRuntime.markStopped(reason)
        stopEverything()
    }

    private fun stopEverything() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    override fun onDestroy() {
        server?.stop()
        server = null
        // Only when nothing has already explained itself: shutdown() and fail()
        // both set the state before they stop the service, and overwriting
        // their reason here would throw away the only thing the sheet can show.
        val standing = McpRuntime.status
        if (standing == McpRuntime.Status.RUNNING || standing == McpRuntime.Status.STARTING) {
            McpRuntime.markStopped("the service was shut down")
        }
        scope.cancel()
        if (instance === this) instance = null
        held = null
        super.onDestroy()
    }

    // ------------------------------------------------------ notification --

    private fun createChannel() {
        val channel = NotificationChannel(
            CHANNEL_ID,
            "MCP server",
            NotificationManager.IMPORTANCE_LOW
        )
        channel.description = "Shown whenever Nocturne is listening for an MCP client."
        channel.setShowBadge(false)
        val manager = getSystemService(NotificationManager::class.java)
        manager?.createNotificationChannel(channel)
    }

    private fun notification(title: String, text: String): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java)
                .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, McpService::class.java)
                .setAction(ACTION_STOP)
                .putExtra(EXTRA_REASON, "stopped from the notification"),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_mcp_notification)
            .setContentTitle("Nocturne MCP server")
            .setContentText(title)
            .setStyle(NotificationCompat.BigTextStyle().bigText(title + "\n" + text))
            .setSubText(text)
            .setOngoing(true)
            .setSilent(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            // Deliberately NOT VISIBILITY_SECRET. The whole point of this
            // notification is that a person can see their phone is listening,
            // and a secret notification is invisible on the lock screen — which
            // is exactly where they would want to notice it.
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .build()
    }

    private fun goForeground(n: Notification) {
        // The specialUse foreground-service type only exists from API 34, and
        // the typed call validates the type against the manifest. Below 34 the
        // untyped call is both correct and the one that cannot throw.
        //
        // Wrapped because the second call — the one that rewrites the text once
        // an address is bound — runs on an IO thread and can land while the
        // service is already going away. A failed notification update must not
        // take a working listener down with it.
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                ServiceCompat.startForeground(
                    this, NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, n)
            }
        } catch (e: Exception) {
            // Nothing to recover: either the notification is up or it is not,
            // and the socket does not depend on it.
        }
    }
}

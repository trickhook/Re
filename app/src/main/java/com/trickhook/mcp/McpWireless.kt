package com.trickhook.mcp

import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.nsd.NsdManager
import android.net.nsd.NsdServiceInfo
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.provider.Settings
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.net.NetworkInterface
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit

/**
 * Android 11's Wireless debugging, which is what makes [McpRuntime.MODE_LOOPBACK]
 * usable without a cable — and therefore what lets loopback be the default.
 *
 * ---------------------------------------------------------------------------
 *
 * WHY THIS EXISTS.
 *
 * The listener has two honest positions and they used to trade off badly. Bind
 * the Wi-Fi address and a laptop reaches it with no setup — but the port is on
 * the network, the 256-bit token is the entire boundary, and the traffic is
 * plain HTTP that anyone on the network can read. Bind 127.0.0.1 and none of
 * that is true — but `adb forward` was the only way in, and that meant a USB
 * cable and platform-tools.
 *
 * Android 11 removed the cable from that sentence. `adb forward` is a host-side
 * command: the adb server on the computer opens a local listening socket and
 * proxies each accepted connection over whichever transport that device is
 * attached on, and adbd opens the matching connection on the device. Nothing in
 * it is USB-specific. Once a device is attached over Wi-Fi it forwards exactly
 * as it does on a cable, so the whole of the loopback mode's cost was the
 * cable, and Wireless debugging pays it off.
 *
 * What crosses the Wi-Fi then is adb's own TLS connection — see below — rather
 * than this server's plaintext HTTP, and the MCP port itself is never bound to
 * a network address at all. That is strictly better than the LAN mode on every
 * axis except one: the user needs platform-tools on their computer.
 *
 * ---------------------------------------------------------------------------
 *
 * THE MECHANISM, and its port semantics, because they are easy to get wrong.
 *
 * AOSP's adb documentation (packages/modules/adb, docs/dev/adb_wifi.md) names
 * three mDNS service types:
 *
 *   `_adb._tcp`              the legacy service from `adb tcpip <PORT>`
 *   `_adb-tls-pairing._tcp`  advertised while the device PAIRING SERVER is up
 *   `_adb-tls-connect._tcp`  advertised while the device TLS SERVER is up
 *
 * and its own worked example is exactly the shape of the flow this file drives:
 *
 *     $ adb pair 192.168.86.38:43811
 *     Enter pairing code: 515109
 *     $ adb connect 192.168.86.34:44643
 *
 * TWO DIFFERENT PORTS. 43811 is the pairing port; 44643 is the connect port.
 * They are not the same number and neither is fixed.
 *
 * The PAIRING port is the ephemeral one, and it is worse than ephemeral: the
 * same document notes that `_adb-tls-pairing._tcp` is published through
 * NsdServiceInfo rather than by adbd, because the pairing server belongs to the
 * Settings app's *Pair device with pairing code* dialog. It exists only while
 * that dialog is on screen and goes away when the dialog does — along with the
 * six-digit code, which is generated there and is not exposed by any API. So
 * this app deliberately does NOT try to show the pairing port: by the time
 * Nocturne is back on screen, the number it could have captured is dead. The
 * dialog shows the port and the code together; the user reads both from there,
 * with the dialog still open, which is the only moment either one is valid.
 *
 * The CONNECT port is the one worth finding. adbd publishes it directly and
 * keeps it up for as long as Wireless debugging is on, so it survives the user
 * walking back into this app — and it is the annoying one, because it is
 * random, it is on a different screen from the pairing code, and it changes
 * every time Wireless debugging is toggled or the device reboots. [connectPort]
 * discovers it with [NsdManager], which needs no privilege of any kind: the
 * service adbd registers is visible to an ordinary app on the same device. This
 * is the same mechanism Shizuku uses to start itself over wireless adb.
 *
 * SHIZUKU BUYS NOTHING HERE. It hands an app a binder running as the shell UID.
 * That is not a tunnel, and there is no device-side `adb forward` for it to
 * call — the forward lives in the adb server on the computer. It could flip
 * `adb_wifi_enabled`, which saves one tap on a screen the user has to open
 * anyway to read the pairing code, and it cannot reach the code or the pairing
 * port at all. Reading the connect port, the one thing that genuinely helps,
 * needs no privilege. And Shizuku's own setup on an unrooted phone is this
 * pairing dance, so depending on it to explain the pairing dance is circular.
 *
 * ---------------------------------------------------------------------------
 *
 * WHAT THIS DOES NOT FIX. AP client isolation. A router that blocks traffic
 * between its clients blocks the computer from reaching adbd's TLS port exactly
 * as it blocks it from reaching this server's port — it is client-to-client
 * either way. The answers there are a USB cable, or the phone's own hotspot
 * (traffic to the access point is not traffic between its clients). docs/MCP.md
 * says so rather than pointing at this page as a cure.
 */
object McpWireless {

    /** Android 11. Below it there is no Wireless debugging to pair with. */
    private const val MIN_SDK = Build.VERSION_CODES.R

    /**
     * Published by adbd for as long as Wireless debugging is on, carrying the
     * port `adb connect` wants. The pairing service is deliberately not watched
     * for — see the note above on why its port cannot be shown usefully.
     */
    private const val SERVICE_CONNECT = "_adb-tls-connect._tcp"

    /**
     * Not in the public SDK, on purpose or otherwise, and missing on some
     * builds — so it is an attempt, not an assumption, and
     * [Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS] catches the fall.
     */
    private const val ACTION_WIRELESS_DEBUGGING = "android.settings.WIRELESS_DEBUGGING_SETTINGS"

    /**
     * The Settings app's own "scroll to and highlight this preference" extras.
     * Undocumented, ignored where unrecognised, and worth it: without them the
     * fallback drops the user at the top of a long Developer options list.
     */
    private const val EXTRA_FRAGMENT_ARGS = ":settings:show_fragment_args"
    private const val EXTRA_FRAGMENT_KEY = ":settings:fragment_args_key"
    private const val PREF_ADB_WIRELESS = "toggle_adb_wireless"

    /** Global setting adbd's Wi-Fi listener follows. Readable; writing needs a permission. */
    private const val SETTING_ADB_WIFI = "adb_wifi_enabled"

    /** [connectPort]: this Android is too old for Wireless debugging. */
    const val PORT_UNSUPPORTED = -1

    /** [connectPort]: nothing on this device answered for the service. */
    const val PORT_NONE = 0

    /**
     * How long a scan listens before giving up.
     *
     * Six seconds. mDNS answers in well under one when the service is there, so
     * this is the budget for the case where it is NOT there — a user who has
     * not turned Wireless debugging on yet — and the point is to reach "read it
     * off the settings screen instead" quickly rather than to keep hoping.
     */
    private const val DISCOVER_MS = 6_000L

    /** Per-service resolve budget, inside the scan budget above. */
    private const val RESOLVE_MS = 2_500L

    /** Marker for a resolve that failed, so the queue below can carry both outcomes. */
    private val RESOLVE_FAILED = Any()

    /** Wireless debugging exists from Android 11. */
    val supported: Boolean get() = Build.VERSION.SDK_INT >= MIN_SDK

    /**
     * True when Wireless debugging is on, false when it is off, and null when
     * this device will not say.
     *
     * The key is not part of the public SDK, so a device that does not carry it
     * — or has renamed it — answers null rather than a confident "off". A wrong
     * "Wireless debugging is off" next to a screen that says it is on would
     * teach people to stop reading this sheet.
     */
    fun wirelessDebuggingOn(context: Context): Boolean? {
        if (!supported) return null
        return try {
            when (Settings.Global.getInt(context.contentResolver, SETTING_ADB_WIFI, -1)) {
                1 -> true
                0 -> false
                else -> null
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * The port `adb connect` wants, discovered over mDNS, or [PORT_NONE] /
     * [PORT_UNSUPPORTED].
     *
     * Blocking, and deliberately so: [NsdManager] is a callback API with a
     * long-standing reputation for reporting a service found, lost and found
     * again, and a bounded loop on an IO thread is far easier to reason about
     * than a state machine spread over six callbacks. Everything is inside one
     * deadline and the listener is always unregistered.
     *
     * Discovery sees every adb-capable device on the network, not just this
     * one, so each service is resolved and its address checked against this
     * device's own — a laptop's port would be a confidently wrong answer.
     * Resolves happen one at a time because NsdManager refuses a second resolve
     * while one is in flight.
     */
    @Suppress("DEPRECATION")
    suspend fun connectPort(context: Context): Int = withContext(Dispatchers.IO) {
        if (!supported) return@withContext PORT_UNSUPPORTED
        val nsd = try {
            context.applicationContext.getSystemService(NsdManager::class.java)
        } catch (e: Exception) {
            null
        } ?: return@withContext PORT_NONE

        val mine = ownAddresses()
        if (mine.isEmpty()) return@withContext PORT_NONE

        val seen = LinkedBlockingQueue<NsdServiceInfo>()
        val listener = object : NsdManager.DiscoveryListener {
            override fun onStartDiscoveryFailed(serviceType: String?, errorCode: Int) = Unit
            override fun onStopDiscoveryFailed(serviceType: String?, errorCode: Int) = Unit
            override fun onDiscoveryStarted(serviceType: String?) = Unit
            override fun onDiscoveryStopped(serviceType: String?) = Unit
            override fun onServiceLost(serviceInfo: NsdServiceInfo?) = Unit
            override fun onServiceFound(serviceInfo: NsdServiceInfo?) {
                if (serviceInfo != null) seen.offer(serviceInfo)
            }
        }

        try {
            nsd.discoverServices(SERVICE_CONNECT, NsdManager.PROTOCOL_DNS_SD, listener)
        } catch (e: Exception) {
            // Wi-Fi off, the service unavailable, or a listener the framework
            // thinks is already registered. Nothing to discover either way.
            return@withContext PORT_NONE
        }

        try {
            val deadline = SystemClock.elapsedRealtime() + DISCOVER_MS
            val tried = HashSet<String>()
            while (true) {
                val left = deadline - SystemClock.elapsedRealtime()
                if (left <= 0L) break
                val found = seen.poll(left, TimeUnit.MILLISECONDS) ?: break
                // The same service is reported more than once on some builds,
                // and a resolve costs most of the budget.
                if (!tried.add(found.serviceName ?: "")) continue
                val resolved = resolve(nsd, found) ?: continue
                val port = resolved.port
                if (port <= 0) continue
                val address = resolved.host ?: continue
                if (!isOwnAddress(address, mine)) continue
                return@withContext port
            }
            PORT_NONE
        } finally {
            try {
                nsd.stopServiceDiscovery(listener)
            } catch (e: Exception) {
                // Already stopped, or never started. Either way there is
                // nothing left to unregister.
            }
        }
    }

    /**
     * Resolve one advertised service to an address and a port, or null.
     *
     * Synchronous by the same argument as [connectPort], and one at a time: a
     * second [NsdManager.resolveService] while one is outstanding is refused,
     * and on older releases it throws rather than calling back.
     */
    @Suppress("DEPRECATION")
    private fun resolve(nsd: NsdManager, service: NsdServiceInfo): NsdServiceInfo? {
        val answer = ArrayBlockingQueue<Any>(1)
        val listener = object : NsdManager.ResolveListener {
            override fun onResolveFailed(serviceInfo: NsdServiceInfo?, errorCode: Int) {
                answer.offer(RESOLVE_FAILED)
            }

            override fun onServiceResolved(serviceInfo: NsdServiceInfo?) {
                answer.offer(serviceInfo ?: RESOLVE_FAILED)
            }
        }
        try {
            nsd.resolveService(service, listener)
        } catch (e: Exception) {
            return null
        }
        return answer.poll(RESOLVE_MS, TimeUnit.MILLISECONDS) as? NsdServiceInfo
    }

    /**
     * Every address this device holds, IPv4 and IPv6, for deciding whether a
     * discovered service is ours. Broader than [McpNetwork.candidates], which
     * answers a different question — what can be bound — and so throws away
     * link-local and IPv6 addresses that an mDNS record may perfectly well name.
     */
    private fun ownAddresses(): Set<String> {
        val out = HashSet<String>()
        val interfaces = try {
            NetworkInterface.getNetworkInterfaces()
        } catch (e: Exception) {
            null
        } ?: return out
        for (ni in interfaces) {
            for (address in ni.inetAddresses) {
                val text = address.hostAddress ?: continue
                out.add(withoutScope(text))
            }
        }
        return out
    }

    private fun isOwnAddress(address: InetAddress, mine: Set<String>): Boolean {
        val text = address.hostAddress ?: return false
        return withoutScope(text) in mine
    }

    /**
     * `fe80::1%wlan0` and `fe80::1` are the same address wearing different
     * clothes; the interface suffix is a local annotation, and comparing the
     * two strings without stripping it is how an own-address check silently
     * never matches on IPv6.
     */
    private fun withoutScope(host: String): String {
        val cut = host.indexOf('%')
        return if (cut < 0) host else host.substring(0, cut)
    }

    /**
     * Open the Wireless debugging screen, or the nearest thing this device has.
     *
     * Two attempts, narrowing, the same shape as the updater's
     * `openUnknownSourcesSettings`: the specific screen, then Developer options
     * with the Wireless debugging row asked for by name. False means nothing on
     * this device answered at all, and the sheet then says where to go by hand
     * rather than leaving a dead row.
     */
    fun openWirelessDebugging(context: Context): Boolean {
        if (supported && start(context, Intent(ACTION_WIRELESS_DEBUGGING))) return true
        val developer = Intent(Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS)
        if (supported) {
            val args = Bundle()
            args.putString(EXTRA_FRAGMENT_KEY, PREF_ADB_WIRELESS)
            developer.putExtra(EXTRA_FRAGMENT_KEY, PREF_ADB_WIRELESS)
            developer.putExtra(EXTRA_FRAGMENT_ARGS, args)
        }
        return start(context, developer)
    }

    private fun start(context: Context, intent: Intent): Boolean = try {
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
        true
    } catch (e: ActivityNotFoundException) {
        false
    } catch (e: SecurityException) {
        false
    }
}

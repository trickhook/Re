package com.trickhook.mcp

import java.net.Inet4Address
import java.net.InetAddress
import java.net.NetworkInterface

/**
 * Which address the listener binds, and what we can honestly say about it.
 *
 * The server never binds 0.0.0.0. It binds ONE address: either loopback, or one
 * interface that the user can see named in the sheet. The difference matters —
 * "listening on wlan0, 192.168.1.42" is something a person can reason about;
 * "listening on every interface this phone has" is not, and on a phone that is
 * a longer list than anyone expects (Wi-Fi, mobile data, a tether, a VPN, a
 * Wi-Fi Direct link).
 *
 * Nocturne deliberately does NOT ask for the location permission, which is what
 * Android requires before it will tell an app the Wi-Fi SSID. So the sheet
 * names the interface and the address and says plainly that it cannot name the
 * network — a warning that is true beats a green dot that is a guess.
 */
object McpNetwork {

    /** One bindable address, with everything the UI needs to describe it. */
    class Endpoint(
        val address: InetAddress,
        val host: String,
        val iface: String,
        /** "Wi-Fi", "Mobile data", "USB or Ethernet", "VPN", "Loopback", "Network". */
        val kind: String,
        /** True for RFC1918 / CGNAT space. False means this is routable from the internet. */
        val privateAddress: Boolean
    )

    /**
     * 127.0.0.1, spelled out rather than resolved.
     *
     * [InetAddress.getLoopbackAddress] can hand back ::1 on a device whose
     * stack prefers IPv6, and `adb forward` speaks to 127.0.0.1. Building the
     * address from its four bytes involves no resolver and cannot surprise
     * anyone.
     */
    fun loopback(): InetAddress = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))

    fun loopbackEndpoint(): Endpoint =
        Endpoint(loopback(), "127.0.0.1", "lo", "Loopback", true)

    /**
     * Every IPv4 address on an interface that is up and is not loopback, best
     * candidate first: Wi-Fi, then wired or tethered, then anything else, with
     * mobile data and VPN tunnels last.
     */
    fun candidates(): List<Endpoint> {
        val out = ArrayList<Endpoint>()
        val interfaces = try {
            NetworkInterface.getNetworkInterfaces()
        } catch (e: Exception) {
            null
        } ?: return out
        for (ni in interfaces) {
            val up = try {
                ni.isUp && !ni.isLoopback
            } catch (e: Exception) {
                false
            }
            if (!up) continue
            val name = ni.name ?: continue
            for (addr in ni.inetAddresses) {
                if (addr !is Inet4Address) continue
                if (addr.isLoopbackAddress || addr.isLinkLocalAddress || addr.isAnyLocalAddress) continue
                val host = addr.hostAddress ?: continue
                out.add(Endpoint(addr, host, name, kindOf(name), isPrivate(addr)))
            }
        }
        out.sortBy { rank(it.iface) }
        return out
    }

    fun preferred(): Endpoint? = candidates().firstOrNull()

    private fun rank(iface: String): Int = when {
        iface.startsWith("wlan") || iface.startsWith("wifi") -> 0
        iface.startsWith("eth") || iface.startsWith("usb") || iface.startsWith("rndis") -> 1
        iface.startsWith("ap") || iface.startsWith("swlan") -> 2
        iface.startsWith("tun") || iface.startsWith("ppp") || iface.startsWith("ipsec") -> 4
        iface.startsWith("rmnet") || iface.startsWith("ccmni") || iface.startsWith("pdp") -> 5
        else -> 3
    }

    private fun kindOf(iface: String): String = when {
        iface.startsWith("wlan") || iface.startsWith("wifi") -> "Wi-Fi"
        iface.startsWith("ap") || iface.startsWith("swlan") -> "Hotspot"
        iface.startsWith("eth") || iface.startsWith("usb") || iface.startsWith("rndis") ->
            "USB or Ethernet"
        iface.startsWith("tun") || iface.startsWith("ppp") || iface.startsWith("ipsec") -> "VPN"
        iface.startsWith("rmnet") || iface.startsWith("ccmni") || iface.startsWith("pdp") ->
            "Mobile data"
        else -> "Network"
    }

    /**
     * RFC1918, plus the carrier-grade NAT block. Anything else on a phone is a
     * public address, and a public address means the port is not behind a
     * router at all — worth saying out loud.
     */
    private fun isPrivate(addr: Inet4Address): Boolean {
        val b = addr.address
        val a0 = b[0].toInt() and 0xFF
        val a1 = b[1].toInt() and 0xFF
        return when {
            a0 == 10 -> true
            a0 == 192 && a1 == 168 -> true
            a0 == 172 && a1 in 16..31 -> true
            a0 == 100 && a1 in 64..127 -> true
            else -> false
        }
    }
}

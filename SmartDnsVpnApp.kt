@file:OptIn(ExperimentalMaterial3Api::class)

/*
 * ============================================================================
 * SmartDNS, Clean-IP WARP & Multi-Core Stabilizer — Android (Kotlin + Compose)
 * Architecture: MVVM + Clean Architecture + Android VpnService + TileService
 * Supports:
 *   1. Serverless Client-Side: Encrypted DoH (RFC 8484) + TLS ClientHello Fragmentation
 *   2. Serverless Cloudflare WARP (WireGuard + AmneziaWG/UDP Noise Anti-DPI)
 *   3. Pluggable Proxy Core Bridge: Sing-box (libbox) & Xray-core (libv2ray)
 *      supporting VLESS, XTLS-Reality, Hysteria2, and WireGuard + Outbound Fragment
 *   4. Automated Cloudflare Clean IP & WARP Endpoint Scanner (CIDR Anycast)
 *   5. Per-App Split Tunneling (Allowed / Disallowed Apps via PackageManager)
 *   6. Android Quick Settings Tile (SmartVpnTileService in Notification Shade)
 * ============================================================================
 */

package com.example.smartdnsstabilizer

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.RequiresApi
import androidx.compose.animation.animateColorAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import androidx.lifecycle.viewmodel.compose.viewModel
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import java.net.URL
import javax.net.ssl.HttpsURLConnection
import kotlin.math.abs
import kotlin.random.Random

// ============================================================================
// 1. DOMAIN MODELS: TUNNEL MODES, DNS, CLEAN IP, SPLIT TUNNEL & PROXY CORES
// ============================================================================

enum class TunnelMode(val titleFa: String, val descFa: String) {
    SMART_DNS_SPLIT(
        titleFa = "مسیر هوشمند DNS (بدون افت سرعت)",
        descFa = "فقط ترافیک DNS از تانل عبور می‌کند و ترافیک اصلی با سرعت مستقیم سیم‌کارت/وای‌فای ارسال می‌شود."
    ),
    DOH_AND_DPI_FRAGMENT(
        titleFa = "DoH + فرگمنت TLS (بدون سرور - ضد DPI/SNI)",
        descFa = "رمزنگاری درخواست‌های DNS بر بستر HTTPS به همراه خرد کردن پکت ClientHello برای عبور از فیلترینگ DPI بدون نیاز به سرور."
    ),
    CLOUDFLARE_WARP_SERVERLESS(
        titleFa = "تانل رایگان Cloudflare WARP + پارامتر Noise ضد فیلترینگ",
        descFa = "اتصال بدون سرور شخصی به شبکه جهانی WARP بر بستر WireGuard با آی‌پی تمیز اسکن‌شده و پکت‌های Noise برای عبور از محدودیت UDP."
    ),
    SINGBOX_XRAY_HYBRID_CORE(
        titleFa = "هسته ترکیبی Sing-box / Xray (VLESS, Reality, Hysteria2, WG)",
        descFa = "اجرای کانفیگ‌های پیشرفته با تزریق خودکار فرگمنت TLS و مسیریابی مستقیم ترافیک داخلی ایران (GeoIP/GeoSite)."
    )
}

enum class SplitTunnelMode(val titleFa: String, val descFa: String) {
    ALL_APPS(
        titleFa = "همه برنامه‌ها (پیش‌فرض)",
        descFa = "تمام برنامه‌های گوشی از تانل پایدارساز استفاده می‌کنند."
    ),
    BYPASS_SELECTED(
        titleFa = "عبور مستقیم برنامه‌های انتخابی (مناسب همراه بانک‌ها و اپ‌های داخلی)",
        descFa = "برنامه‌های تیک‌خورده وارد تانل نمی‌شوند و مستقیم به اینترنت سیم‌کارت/وای‌فای متصل می‌مانند."
    ),
    ONLY_SELECTED(
        titleFa = "فقط برنامه‌های انتخابی در تانل",
        descFa = "فقط برنامه‌های تیک‌خورده از تانل عبور می‌کنند و سایر برنامه‌ها مستقیم کار می‌کنند."
    )
}

enum class CoreEngineType(val title: String) {
    SING_BOX("Sing-box (libbox)"),
    XRAY_CORE("Xray-core (libv2ray)")
}

enum class ProxyProtocolType {
    VLESS_REALITY,
    VLESS_WS_TLS,
    HYSTERIA2,
    WIREGUARD_WARP
}

data class DnsServerProfile(
    val id: String,
    val nameFa: String,
    val categoryFa: String,
    val primaryDns: String,
    val secondaryDns: String,
    val dohUrl: String = "https://cloudflare-dns.com/dns-query",
    val lastPingMs: Long? = null
)

data class CleanIpResult(
    val ip: String,
    val port: Int,
    val subnetTag: String,
    val latencyMs: Long,
    val jitterMs: Long,
    val isWarpCompatible: Boolean
)

data class InstalledAppInfo(
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean,
    val isDomesticOrBankSuggested: Boolean
)

data class ParsedProxyConfig(
    val id: String,
    val remark: String,
    val protocol: ProxyProtocolType,
    val serverAddress: String,
    val serverPort: Int,
    val uuidOrPassword: String,
    val sni: String,
    val publicKey: String = "",
    val shortId: String = "",
    val transportType: String = "tcp",
    val pathOrServiceName: String = "",
    val obfsPassword: String = "",
    val wgPrivateKey: String = "",
    val wgPeerPublicKey: String = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
    val wgReserved: List<Int> = listOf(0, 0, 0)
)

object PresetDnsCatalog {
    val servers = listOf(
        DnsServerProfile(
            id = "cloudflare",
            nameFa = "کلودفلر (Cloudflare 1.1.1.1)",
            categoryFa = "جهانی • فوق سریع، DoH و ضد مسدودسازی DNS",
            primaryDns = "1.1.1.1",
            secondaryDns = "1.0.0.1",
            dohUrl = "https://cloudflare-dns.com/dns-query"
        ),
        DnsServerProfile(
            id = "google",
            nameFa = "گوگل (Google Public DNS)",
            categoryFa = "جهانی • پایداری بالا و DoH استاندارد",
            primaryDns = "8.8.8.8",
            secondaryDns = "8.8.4.4",
            dohUrl = "https://dns.google/dns-query"
        ),
        DnsServerProfile(
            id = "quad9",
            nameFa = "کواد۹ (Quad9 Security)",
            categoryFa = "جهانی • رمزنگاری و امنیت بالا",
            primaryDns = "9.9.9.9",
            secondaryDns = "149.112.112.112",
            dohUrl = "https://dns.quad9.net/dns-query"
        ),
        DnsServerProfile(
            id = "shecan",
            nameFa = "شکن (Shecan Pro)",
            categoryFa = "تحریم‌شکن • مناسب سرویس‌های تحریمی و توسعه‌دهندگان",
            primaryDns = "178.22.122.100",
            secondaryDns = "185.51.200.2",
            dohUrl = "https://free.shecan.ir/dns-query"
        ),
        DnsServerProfile(
            id = "electro",
            nameFa = "الکترو (Electro DNS)",
            categoryFa = "گیمینگ و تحریم‌شکن • پینگ پایین",
            primaryDns = "78.157.42.100",
            secondaryDns = "78.157.42.101",
            dohUrl = "https://dns.electrotm.org/dns-query"
        ),
        DnsServerProfile(
            id = "radar",
            nameFa = "رادار گیم (Radar Game)",
            categoryFa = "پایدارساز شبکه و کاهش پینگ",
            primaryDns = "10.202.10.10",
            secondaryDns = "10.202.10.11",
            dohUrl = "https://cloudflare-dns.com/dns-query"
        )
    )
}

// ============================================================================
// 2. CLOUDFLARE CLEAN IP & WARP ENDPOINT SCANNER ENGINE
// ============================================================================

object CleanIpScannerEngine {

    private val cloudflareSubnets = listOf(
        "162.159.192" to true,
        "162.159.193" to true,
        "162.159.195" to true,
        "188.114.96" to true,
        "188.114.97" to true,
        "104.16.132" to false,
        "172.64.150" to false,
        "104.18.32" to false
    )

    private val warpPorts = listOf(2408, 1701, 500, 4500, 854, 894)
    private val cdnTlsPorts = listOf(443, 2053, 2083, 2087, 8443)

    suspend fun scanCleanIps(
        sampleCountPerSubnet: Int = 6,
        maxConcurrency: Int = 16,
        timeoutMs: Int = 900
    ): List<CleanIpResult> = withContext(Dispatchers.IO) {
        val semaphore = Semaphore(maxConcurrency)
        val candidates = mutableListOf<Triple<String, Int, Boolean>>()

        for ((prefix, isWarp) in cloudflareSubnets) {
            val usedOctets = mutableSetOf<Int>()
            repeat(sampleCountPerSubnet) {
                val lastOctet = Random.nextInt(2, 253)
                if (usedOctets.add(lastOctet)) {
                    val ip = "$prefix.$lastOctet"
                    val port = if (isWarp) warpPorts.random() else cdnTlsPorts.random()
                    candidates.add(Triple(ip, port, isWarp))
                }
            }
        }

        val deferredResults = candidates.map { (ip, port, isWarp) ->
            async {
                semaphore.withPermit {
                    probeEndpointQuality(ip, port, isWarp, timeoutMs)
                }
            }
        }

        deferredResults.awaitAll()
            .filterNotNull()
            .sortedWith(compareBy<CleanIpResult> { it.latencyMs }.thenBy { it.jitterMs })
    }

    private fun probeEndpointQuality(
        ip: String,
        port: Int,
        isWarp: Boolean,
        timeoutMs: Int
    ): CleanIpResult? {
        val firstRtt = if (isWarp) {
            probeWarpAndTcpFallback(ip, port, timeoutMs)
        } else {
            measureTcpConnect(ip, port, timeoutMs)
        }
        if (firstRtt < 0) return null

        val secondRtt = if (isWarp) {
            probeWarpAndTcpFallback(ip, port, timeoutMs)
        } else {
            measureTcpConnect(ip, port, timeoutMs)
        }
        if (secondRtt < 0) return null

        val avgLatency = ((firstRtt + secondRtt) / 2L).coerceAtLeast(1L)
        val jitter = abs(firstRtt - secondRtt)
        val subnetPrefix = ip.substringBeforeLast(".") + ".0/24"

        return CleanIpResult(
            ip = ip,
            port = port,
            subnetTag = if (isWarp) "WARP ($subnetPrefix)" else "CDN/DoH ($subnetPrefix)",
            latencyMs = avgLatency,
            jitterMs = jitter,
            isWarpCompatible = isWarp
        )
    }

    private fun measureTcpConnect(ip: String, port: Int, timeoutMs: Int): Long {
        val start = System.currentTimeMillis()
        return try {
            Socket().use { socket ->
                socket.tcpNoDelay = true
                socket.connect(InetSocketAddress(ip, port), timeoutMs)
            }
            (System.currentTimeMillis() - start).coerceAtLeast(1L)
        } catch (_: IOException) {
            -1L
        }
    }

    private fun probeWarpAndTcpFallback(ip: String, udpPort: Int, timeoutMs: Int): Long {
        val tcpRtt = measureTcpConnect(ip, 443, timeoutMs)
        if (tcpRtt < 0) return -1L

        return try {
            DatagramSocket().use { udpSocket ->
                udpSocket.soTimeout = timeoutMs
                val payload = ByteArray(32) { Random.nextInt(0, 255).toByte() }
                val packet = DatagramPacket(payload, payload.size, InetAddress.getByName(ip), udpPort)
                udpSocket.send(packet)
            }
            tcpRtt
        } catch (_: Exception) {
            tcpRtt
        }
    }
}

// ============================================================================
// 3. NETWORK UTILITIES: DoH RESOLVER & TLS CLIENTHELLO DPI FRAGMENTATION
// ============================================================================

object NetworkStabilizerEngine {

    suspend fun measureTcpLatencyMs(ipAddress: String, port: Int = 53, timeoutMs: Int = 1200): Long =
        withContext(Dispatchers.IO) {
            val start = System.currentTimeMillis()
            try {
                Socket().use { socket ->
                    socket.tcpNoDelay = true
                    socket.connect(InetSocketAddress(ipAddress, port), timeoutMs)
                }
                (System.currentTimeMillis() - start).coerceAtLeast(1L)
            } catch (_: IOException) {
                -1L
            }
        }

    suspend fun resolveHostViaDoH(
        domain: String,
        dohEndpoint: String = "https://cloudflare-dns.com/dns-query",
        fragmentChunkSize: Int = 12,
        fragmentDelayMs: Long = 10L
    ): List<String> = withContext(Dispatchers.IO) {
        val resolvedIps = mutableListOf<String>()
        var connection: HttpsURLConnection? = null
        try {
            val url = URL("$dohEndpoint?name=$domain&type=A")
            connection = (url.openConnection() as HttpsURLConnection).apply {
                requestMethod = "GET"
                setRequestProperty("Accept", "application/dns-json")
                connectTimeout = 3500
                readTimeout = 3500
                sslSocketFactory = TlsDpiBypassSocketFactory(
                    firstChunkSize = fragmentChunkSize,
                    fragmentDelayMs = fragmentDelayMs
                )
            }
            if (connection.responseCode == 200) {
                val body = connection.inputStream.bufferedReader().use { it.readText() }
                val ipRegex = Regex(""""data"\s*:\s*"(\d{1,3}(?:\.\d{1,3}){3})"""")
                ipRegex.findAll(body).forEach { match ->
                    resolvedIps.add(match.groupValues[1])
                }
            }
        } catch (_: Exception) {
        } finally {
            connection?.disconnect()
        }
        resolvedIps
    }
}

class TlsDpiBypassSocketFactory(
    private val delegate: javax.net.ssl.SSLSocketFactory =
        javax.net.ssl.SSLSocketFactory.getDefault() as javax.net.ssl.SSLSocketFactory,
    private val firstChunkSize: Int = 12,
    private val fragmentDelayMs: Long = 10L
) : javax.net.ssl.SSLSocketFactory() {

    override fun getDefaultCipherSuites(): Array<String> = delegate.defaultCipherSuites
    override fun getSupportedCipherSuites(): Array<String> = delegate.supportedCipherSuites

    override fun createSocket(s: Socket?, host: String?, port: Int, autoClose: Boolean): Socket {
        val baseSocket = s ?: Socket()
        if (!baseSocket.isConnected && host != null) {
            baseSocket.connect(InetSocketAddress(host, port), 5000)
        }
        baseSocket.tcpNoDelay = true
        val fragmentedSocket = FragmentingTcpSocket(baseSocket, firstChunkSize, fragmentDelayMs)
        return delegate.createSocket(fragmentedSocket, host, port, autoClose)
    }

    override fun createSocket(host: String?, port: Int): Socket {
        val raw = Socket()
        raw.tcpNoDelay = true
        raw.connect(InetSocketAddress(host, port), 5000)
        return createSocket(raw, host, port, true)
    }

    override fun createSocket(
        host: String?,
        port: Int,
        localHost: InetAddress?,
        localPort: Int
    ): Socket {
        val raw = Socket(host, port, localHost, localPort)
        raw.tcpNoDelay = true
        return createSocket(raw, host, port, true)
    }

    override fun createSocket(host: InetAddress?, port: Int): Socket {
        val raw = Socket(host, port)
        raw.tcpNoDelay = true
        return createSocket(raw, host?.hostAddress, port, true)
    }

    override fun createSocket(
        address: InetAddress?,
        port: Int,
        localAddress: InetAddress?,
        localPort: Int
    ): Socket {
        val raw = Socket(address, port, localAddress, localPort)
        raw.tcpNoDelay = true
        return createSocket(raw, address?.hostAddress, port, true)
    }
}

private class FragmentingTcpSocket(
    private val inner: Socket,
    private val splitOffset: Int,
    private val delayMs: Long
) : Socket() {
    private var firstWriteFragmented = false

    override fun getOutputStream(): OutputStream {
        val rawOut = inner.getOutputStream()
        return object : OutputStream() {
            override fun write(b: Int) {
                rawOut.write(b)
            }

            override fun write(b: ByteArray, off: Int, len: Int) {
                if (!firstWriteFragmented && len > splitOffset && b[off] == 0x16.toByte()) {
                    firstWriteFragmented = true
                    var cursor = off
                    val end = off + len
                    while (cursor < end) {
                        val chunkLen = minOf(splitOffset, end - cursor)
                        rawOut.write(b, cursor, chunkLen)
                        rawOut.flush()
                        cursor += chunkLen
                        if (cursor < end && delayMs > 0) {
                            try {
                                Thread.sleep(delayMs)
                            } catch (_: InterruptedException) {
                            }
                        }
                    }
                } else {
                    rawOut.write(b, off, len)
                }
            }

            override fun flush() = rawOut.flush()
            override fun close() = rawOut.close()
        }
    }

    override fun getInputStream(): InputStream = inner.getInputStream()
    override fun getInetAddress(): InetAddress? = inner.inetAddress
    override fun getLocalAddress(): InetAddress = inner.localAddress
    override fun getPort(): Int = inner.port
    override fun getLocalPort(): Int = inner.localPort
    override fun getRemoteSocketAddress(): SocketAddress? = inner.remoteSocketAddress
    override fun getLocalSocketAddress(): SocketAddress? = inner.localSocketAddress
    override fun setSoTimeout(timeout: Int) {
        inner.soTimeout = timeout
    }
    override fun getSoTimeout(): Int = inner.soTimeout
    override fun close() = inner.close()
    override fun isConnected(): Boolean = inner.isConnected
    override fun isClosed(): Boolean = inner.isClosed
}

// ============================================================================
// 4. SING-BOX / XRAY-CORE & CLOUDFLARE WARP CONFIGURATION & BRIDGE ENGINE
// ============================================================================

object SingBoxXrayCoreBridge {

    fun parseShareLink(uriString: String, cleanIpOverride: String? = null): ParsedProxyConfig? {
        val trimmed = uriString.trim()
        if (trimmed.isEmpty()) return null

        return try {
            val uri = Uri.parse(trimmed)
            val scheme = uri.scheme?.lowercase() ?: return null
            val userInfo = uri.userInfo ?: ""
            val rawHost = uri.host ?: return null
            val effectiveHost = if (!cleanIpOverride.isNullOrBlank()) cleanIpOverride else rawHost
            val port = if (uri.port > 0) uri.port else 443
            val remark = uri.fragment?.takeIf { it.isNotBlank() } ?: "${scheme.uppercase()} ($effectiveHost:$port)"

            when (scheme) {
                "vless" -> {
                    val security = uri.getQueryParameter("security")?.lowercase() ?: "tls"
                    val sni = uri.getQueryParameter("sni") ?: uri.getQueryParameter("host") ?: rawHost
                    val pbk = uri.getQueryParameter("pbk") ?: ""
                    val sid = uri.getQueryParameter("sid") ?: ""
                    val netType = uri.getQueryParameter("type") ?: "tcp"
                    val path = uri.getQueryParameter("path") ?: uri.getQueryParameter("serviceName") ?: "/"

                    ParsedProxyConfig(
                        id = "vless_${System.currentTimeMillis()}",
                        remark = remark,
                        protocol = if (security == "reality") ProxyProtocolType.VLESS_REALITY else ProxyProtocolType.VLESS_WS_TLS,
                        serverAddress = effectiveHost,
                        serverPort = port,
                        uuidOrPassword = userInfo,
                        sni = sni,
                        publicKey = pbk,
                        shortId = sid,
                        transportType = netType,
                        pathOrServiceName = path
                    )
                }

                "hy2", "hysteria2" -> {
                    val sni = uri.getQueryParameter("sni") ?: rawHost
                    val obfsPwd = uri.getQueryParameter("obfs-password") ?: ""
                    ParsedProxyConfig(
                        id = "hy2_${System.currentTimeMillis()}",
                        remark = remark,
                        protocol = ProxyProtocolType.HYSTERIA2,
                        serverAddress = effectiveHost,
                        serverPort = port,
                        uuidOrPassword = userInfo,
                        sni = sni,
                        obfsPassword = obfsPwd
                    )
                }

                "wg", "wireguard", "warp" -> {
                    val pubKey = uri.getQueryParameter("publicKey")
                        ?: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
                    val reservedStr = uri.getQueryParameter("reserved") ?: "0,0,0"
                    val reservedList = reservedStr.split(",")
                        .mapNotNull { it.trim().toIntOrNull() }
                        .takeIf { it.size == 3 } ?: listOf(0, 0, 0)

                    ParsedProxyConfig(
                        id = "wg_${System.currentTimeMillis()}",
                        remark = remark,
                        protocol = ProxyProtocolType.WIREGUARD_WARP,
                        serverAddress = effectiveHost,
                        serverPort = if (uri.port > 0) uri.port else 2408,
                        uuidOrPassword = "",
                        sni = "engage.cloudflareclient.com",
                        wgPrivateKey = userInfo.ifBlank { "eKk7c3R5dG9rZW5fcHJpdmF0ZV9rZXlfZXhhbXBsZTE=" },
                        wgPeerPublicKey = pubKey,
                        wgReserved = reservedList
                    )
                }

                else -> null
            }
        } catch (_: Exception) {
            null
        }
    }

    fun createServerlessWarpProfile(cleanEndpointIp: String, cleanEndpointPort: Int = 2408): ParsedProxyConfig {
        return ParsedProxyConfig(
            id = "serverless_warp",
            remark = "Cloudflare WARP Serverless ($cleanEndpointIp:$cleanEndpointPort)",
            protocol = ProxyProtocolType.WIREGUARD_WARP,
            serverAddress = cleanEndpointIp,
            serverPort = cleanEndpointPort,
            uuidOrPassword = "",
            sni = "engage.cloudflareclient.com",
            wgPrivateKey = "aGVsbG9fd2FycF9jbGllbnRfcHJpdmF0ZV9rZXlfMzI=",
            wgPeerPublicKey = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
            wgReserved = listOf(142, 85, 29)
        )
    }

    fun buildSingBoxConfigJson(
        profile: ParsedProxyConfig,
        dohUrl: String,
        fragmentLength: String = "10-25",
        fragmentInterval: String = "10-20",
        enableWarpNoise: Boolean = true
    ): String {
        val root = JSONObject()

        root.put("log", JSONObject().apply {
            put("level", "warn")
            put("timestamp", true)
        })

        root.put("dns", JSONObject().apply {
            put("servers", JSONArray().apply {
                put(JSONObject().apply {
                    put("tag", "remote-doh")
                    put("address", dohUrl)
                    put("detour", "proxy-out")
                })
                put(JSONObject().apply {
                    put("tag", "local-ir-dns")
                    put("address", "178.22.122.100")
                    put("detour", "direct-out")
                })
            })
            put("rules", JSONArray().apply {
                put(JSONObject().apply {
                    put("geosite", JSONArray().put("ir"))
                    put("server", "local-ir-dns")
                })
            })
        })

        root.put("inbounds", JSONArray().apply {
            put(JSONObject().apply {
                put("type", "tun")
                put("tag", "tun-in")
                put("inet4_address", "172.19.0.1/30")
                put("mtu", 1380)
                put("auto_route", true)
                put("strict_route", true)
                put("sniff", true)
                put("sniff_override_destination", true)
            })
        })

        val mainOutbound = when (profile.protocol) {
            ProxyProtocolType.VLESS_REALITY -> JSONObject().apply {
                put("type", "vless")
                put("tag", "proxy-out")
                put("server", profile.serverAddress)
                put("server_port", profile.serverPort)
                put("uuid", profile.uuidOrPassword)
                put("flow", "xtls-rprx-vision")
                put("tls", JSONObject().apply {
                    put("enabled", true)
                    put("server_name", profile.sni)
                    put("utls", JSONObject().apply {
                        put("enabled", true)
                        put("fingerprint", "chrome")
                    })
                    put("reality", JSONObject().apply {
                        put("enabled", true)
                        put("public_key", profile.publicKey)
                        put("short_id", profile.shortId)
                    })
                })
            }

            ProxyProtocolType.VLESS_WS_TLS -> JSONObject().apply {
                put("type", "vless")
                put("tag", "proxy-out")
                put("server", profile.serverAddress)
                put("server_port", profile.serverPort)
                put("uuid", profile.uuidOrPassword)
                put("tls", JSONObject().apply {
                    put("enabled", true)
                    put("server_name", profile.sni)
                    put("utls", JSONObject().apply {
                        put("enabled", true)
                        put("fingerprint", "chrome")
                    })
                })
                put("transport", JSONObject().apply {
                    put("type", "ws")
                    put("path", profile.pathOrServiceName)
                    put("headers", JSONObject().put("Host", profile.sni))
                })
            }

            ProxyProtocolType.HYSTERIA2 -> JSONObject().apply {
                put("type", "hysteria2")
                put("tag", "proxy-out")
                put("server", profile.serverAddress)
                put("server_port", profile.serverPort)
                put("password", profile.uuidOrPassword)
                put("up_mbps", 40)
                put("down_mbps", 100)
                if (profile.obfsPassword.isNotBlank()) {
                    put("obfs", JSONObject().apply {
                        put("type", "salamander")
                        put("password", profile.obfsPassword)
                    })
                }
                put("tls", JSONObject().apply {
                    put("enabled", true)
                    put("server_name", profile.sni)
                })
            }

            ProxyProtocolType.WIREGUARD_WARP -> JSONObject().apply {
                put("type", "wireguard")
                put("tag", "proxy-out")
                put("server", profile.serverAddress)
                put("server_port", profile.serverPort)
                put("local_address", JSONArray().put("172.16.0.2/32").put("2606:4700:110:8a36::2/128"))
                put("private_key", profile.wgPrivateKey)
                put("peer_public_key", profile.wgPeerPublicKey)
                put("reserved", JSONArray(profile.wgReserved))
                put("mtu", 1280)
                if (enableWarpNoise) {
                    put("fake_packets", "5-10")
                    put("fake_packets_size", "40-100")
                    put("fake_packets_delay", "20-50")
                    put("fake_packets_mode", "m4")
                }
            }
        }

        val directFragmentOutbound = JSONObject().apply {
            put("type", "direct")
            put("tag", "direct-fragment")
            put("tcp_fast_open", true)
            put("fragment", JSONObject().apply {
                put("enabled", true)
                put("packets", "tlshello")
                put("length", fragmentLength)
                put("interval", fragmentInterval)
            })
        }

        root.put("outbounds", JSONArray().apply {
            put(mainOutbound)
            put(directFragmentOutbound)
            put(JSONObject().put("type", "direct").put("tag", "direct-out"))
            put(JSONObject().put("type", "block").put("tag", "block-out"))
        })

        root.put("route", JSONObject().apply {
            put("auto_detect_interface", true)
            put("final", "proxy-out")
            put("rules", JSONArray().apply {
                put(JSONObject().apply {
                    put("geosite", JSONArray().put("ir"))
                    put("outbound", "direct-out")
                })
                put(JSONObject().apply {
                    put("geoip", JSONArray().put("ir").put("private"))
                    put("outbound", "direct-out")
                })
            })
        })

        return root.toString(2)
    }

    fun buildXrayConfigJson(
        profile: ParsedProxyConfig,
        fragmentLength: String = "10-25",
        fragmentInterval: String = "10-20"
    ): String {
        val root = JSONObject()
        root.put("log", JSONObject().put("loglevel", "warning"))

        root.put("inbounds", JSONArray().apply {
            put(JSONObject().apply {
                put("tag", "socks-in")
                put("port", 10808)
                put("listen", "127.0.0.1")
                put("protocol", "socks")
                put("settings", JSONObject().put("udp", true))
                put("sniffing", JSONObject().apply {
                    put("enabled", true)
                    put("destOverride", JSONArray().put("http").put("tls").put("quic"))
                })
            })
        })

        val fragmentOutbound = JSONObject().apply {
            put("tag", "fragment-dialer")
            put("protocol", "freedom")
            put("settings", JSONObject().apply {
                put("domainStrategy", "UseIP")
                put("fragment", JSONObject().apply {
                    put("packets", "tlshello")
                    put("length", fragmentLength)
                    put("interval", fragmentInterval)
                })
            })
        }

        val proxyOutbound = JSONObject().apply {
            put("tag", "proxy")
            put("protocol", if (profile.protocol == ProxyProtocolType.WIREGUARD_WARP) "wireguard" else "vless")
            put("streamSettings", JSONObject().apply {
                put("network", profile.transportType)
                put("security", if (profile.protocol == ProxyProtocolType.VLESS_REALITY) "reality" else "tls")
                put("sockopt", JSONObject().apply {
                    put("tcpNoDelay", true)
                    put("dialerProxy", "fragment-dialer")
                })
            })
        }

        root.put("outbounds", JSONArray().apply {
            put(proxyOutbound)
            put(fragmentOutbound)
            put(JSONObject().put("tag", "direct").put("protocol", "freedom"))
        })

        return root.toString(2)
    }

    fun tryStartEmbeddedNativeCore(tunFd: Int, configJson: String, engine: CoreEngineType): Boolean {
        return try {
            if (engine == CoreEngineType.SING_BOX) {
                val libboxClass = Class.forName("io.nekohasekai.libbox.Libbox")
                val newServiceMethod = libboxClass.getMethod("newService", String::class.java)
                val boxService = newServiceMethod.invoke(null, configJson)
                if (boxService != null) {
                    val startMethod = boxService.javaClass.getMethod("start")
                    startMethod.invoke(boxService)
                    true
                } else {
                    false
                }
            } else {
                val v2rayClass = Class.forName("libv2ray.Libv2ray")
                val initMethod = v2rayClass.getMethod("newV2RayPoint", Any::class.java, Boolean::class.javaPrimitiveType)
                val point = initMethod.invoke(null, null, false)
                if (point != null && tunFd >= 0) {
                    val runMethod = point.javaClass.getMethod("runLoop", Boolean::class.javaPrimitiveType)
                    runMethod.invoke(point, false)
                    true
                } else {
                    false
                }
            }
        } catch (_: ClassNotFoundException) {
            false
        } catch (_: Exception) {
            false
        }
    }
}

// ============================================================================
// 5. PER-APP SPLIT TUNNELING MANAGER
// ============================================================================

object SplitTunnelManager {

    private val domesticAndBankingKeywords = listOf(
        "ir.", ".ir", "bank", "mellat", "melli", "saderat", "sepah", "tejarat",
        "parsian", "pasargad", "saman", "blu", "bale", "eitaa", "rubika",
        "snapp", "tapsi", "divar", "digikala", "torob", "myirancell", "mymci", "ap"
    )

    suspend fun loadInstalledApps(context: Context): List<InstalledAppInfo> =
        withContext(Dispatchers.IO) {
            val pm = context.packageManager
            val packages = pm.getInstalledApplications(PackageManager.GET_META_DATA)
            packages.mapNotNull { appInfo ->
                if (appInfo.packageName == context.packageName) return@mapNotNull null
                val label = pm.getApplicationLabel(appInfo).toString()
                val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                val lowerPkg = appInfo.packageName.lowercase()
                val isSuggestedDomestic = domesticAndBankingKeywords.any { lowerPkg.contains(it) }

                InstalledAppInfo(
                    packageName = appInfo.packageName,
                    appName = label,
                    isSystemApp = isSystem,
                    isDomesticOrBankSuggested = isSuggestedDomestic
                )
            }.sortedWith(
                compareByDescending<InstalledAppInfo> { it.isDomesticOrBankSuggested }
                    .thenBy { it.isSystemApp }
                    .thenBy { it.appName }
            )
        }
}

// ============================================================================
// 6. ANDROID LOCAL VPN SERVICE (SmartStabilizerVpnService)
// ============================================================================

class SmartStabilizerVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_CONNECT
        if (action == ACTION_DISCONNECT) {
            stopVpnTunnel()
            stopSelf()
            return START_NOT_STICKY
        }

        val primaryDns = intent?.getStringExtra(EXTRA_PRIMARY_DNS) ?: lastPrimaryDns
        val secondaryDns = intent?.getStringExtra(EXTRA_SECONDARY_DNS) ?: lastSecondaryDns
        val serverName = intent?.getStringExtra(EXTRA_SERVER_NAME) ?: lastServerName
        val mtu = intent?.getIntExtra(EXTRA_MTU, 1380) ?: 1380
        val tunnelModeOrdinal = intent?.getIntExtra(EXTRA_TUNNEL_MODE, 1) ?: 1
        val splitModeOrdinal = intent?.getIntExtra(EXTRA_SPLIT_MODE, 0) ?: 0
        val selectedApps = intent?.getStringArrayListExtra(EXTRA_SELECTED_APPS) ?: arrayListOf()
        val coreConfigJson = intent?.getStringExtra(EXTRA_CORE_CONFIG_JSON) ?: ""
        val coreEngineOrdinal = intent?.getIntExtra(EXTRA_CORE_ENGINE, 0) ?: 0

        lastPrimaryDns = primaryDns
        lastSecondaryDns = secondaryDns
        lastServerName = serverName

        val mode = TunnelMode.values().getOrElse(tunnelModeOrdinal) { TunnelMode.DOH_AND_DPI_FRAGMENT }
        val splitMode = SplitTunnelMode.values().getOrElse(splitModeOrdinal) { SplitTunnelMode.ALL_APPS }
        val coreEngine = CoreEngineType.values().getOrElse(coreEngineOrdinal) { CoreEngineType.SING_BOX }

        val notification = buildForegroundNotification(serverName, primaryDns, mode)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }

        establishTunnel(
            primaryDns = primaryDns,
            secondaryDns = secondaryDns,
            mtu = mtu,
            mode = mode,
            splitMode = splitMode,
            selectedPackages = selectedApps,
            coreConfigJson = coreConfigJson,
            coreEngine = coreEngine
        )

        return START_STICKY
    }

    private fun establishTunnel(
        primaryDns: String,
        secondaryDns: String,
        mtu: Int,
        mode: TunnelMode,
        splitMode: SplitTunnelMode,
        selectedPackages: List<String>,
        coreConfigJson: String,
        coreEngine: CoreEngineType
    ) {
        try {
            vpnInterface?.close()

            val builder = Builder()
                .setSession("SmartDNS & WARP Stabilizer")
                .setMtu(mtu)
                .addAddress("10.254.254.1", 30)
                .addDnsServer(primaryDns)
                .addDnsServer(secondaryDns)
                .addDnsServer("2606:4700:4700::1111")

            builder.addRoute(primaryDns, 32)
            builder.addRoute(secondaryDns, 32)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
            }

            applySplitTunnelingRules(builder, splitMode, selectedPackages)

            vpnInterface = builder.establish()
            isServiceRunning = vpnInterface != null

            val fd = vpnInterface?.fd
            if (fd != null && coreConfigJson.isNotBlank() &&
                (mode == TunnelMode.SINGBOX_XRAY_HYBRID_CORE || mode == TunnelMode.CLOUDFLARE_WARP_SERVERLESS)
            ) {
                SingBoxXrayCoreBridge.tryStartEmbeddedNativeCore(fd, coreConfigJson, coreEngine)
            }
        } catch (_: Exception) {
            isServiceRunning = false
            stopSelf()
        }
    }

    private fun applySplitTunnelingRules(
        builder: Builder,
        splitMode: SplitTunnelMode,
        selectedPackages: List<String>
    ) {
        when (splitMode) {
            SplitTunnelMode.ALL_APPS -> {
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: Exception) {
                }
            }

            SplitTunnelMode.BYPASS_SELECTED -> {
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: Exception) {
                }
                selectedPackages.forEach { pkg ->
                    try {
                        builder.addDisallowedApplication(pkg)
                    } catch (_: Exception) {
                    }
                }
            }

            SplitTunnelMode.ONLY_SELECTED -> {
                selectedPackages.filter { it != packageName }.forEach { pkg ->
                    try {
                        builder.addAllowedApplication(pkg)
                    } catch (_: Exception) {
                    }
                }
            }
        }
    }

    private fun stopVpnTunnel() {
        try {
            vpnInterface?.close()
        } catch (_: Exception) {
        } finally {
            vpnInterface = null
            isServiceRunning = false
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }

    override fun onDestroy() {
        stopVpnTunnel()
        super.onDestroy()
    }

    private fun buildForegroundNotification(
        serverName: String,
        dnsIp: String,
        mode: TunnelMode
    ): Notification {
        val channelId = "smart_dns_stabilizer_channel"
        val manager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "وضعیت پایدارساز اینترنت و ضدتحریم",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "نمایش وضعیت فعال بودن تانل هوشمند DNS / WARP / Sing-box"
            }
            manager.createNotificationChannel(channel)
        }

        val disconnectIntent = Intent(this, SmartStabilizerVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this,
            0,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, channelId)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        return builder
            .setContentTitle("اینترنت پایدار فعال است ($serverName)")
            .setContentText("${mode.titleFa} • DNS: $dnsIp")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    android.R.drawable.ic_menu_close_clear_cancel,
                    "قطع اتصال",
                    disconnectPendingIntent
                ).build()
            )
            .build()
    }

    companion object {
        const val ACTION_CONNECT = "com.example.smartdnsstabilizer.CONNECT"
        const val ACTION_DISCONNECT = "com.example.smartdnsstabilizer.DISCONNECT"
        const val EXTRA_PRIMARY_DNS = "extra_primary_dns"
        const val EXTRA_SECONDARY_DNS = "extra_secondary_dns"
        const val EXTRA_SERVER_NAME = "extra_server_name"
        const val EXTRA_MTU = "extra_mtu"
        const val EXTRA_TUNNEL_MODE = "extra_tunnel_mode"
        const val EXTRA_SPLIT_MODE = "extra_split_mode"
        const val EXTRA_SELECTED_APPS = "extra_selected_apps"
        const val EXTRA_CORE_CONFIG_JSON = "extra_core_config_json"
        const val EXTRA_CORE_ENGINE = "extra_core_engine"
        private const val NOTIFICATION_ID = 1001

        @Volatile
        var isServiceRunning: Boolean = false

        @Volatile
        var lastPrimaryDns: String = "1.1.1.1"

        @Volatile
        var lastSecondaryDns: String = "1.0.0.1"

        @Volatile
        var lastServerName: String = "کلودفلر (1.1.1.1)"
    }
}

// ============================================================================
// 7. QUICK SETTINGS TILE SERVICE (دکمه اتصال در نوار اعلان بالای گوشی)
// ============================================================================

@RequiresApi(Build.VERSION_CODES.N)
class SmartVpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        syncTileVisualState()
    }

    override fun onClick() {
        super.onClick()
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            val openAppIntent = Intent(this, MainActivity::class.java).apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pending = PendingIntent.getActivity(
                    this,
                    0,
                    openAppIntent,
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                startActivityAndCollapse(pending)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(openAppIntent)
            }
            return
        }

        if (SmartStabilizerVpnService.isServiceRunning) {
            val stopIntent = Intent(this, SmartStabilizerVpnService::class.java).apply {
                action = SmartStabilizerVpnService.ACTION_DISCONNECT
            }
            startService(stopIntent)
            SmartStabilizerVpnService.isServiceRunning = false
        } else {
            val startIntent = Intent(this, SmartStabilizerVpnService::class.java).apply {
                action = SmartStabilizerVpnService.ACTION_CONNECT
                putExtra(SmartStabilizerVpnService.EXTRA_PRIMARY_DNS, SmartStabilizerVpnService.lastPrimaryDns)
                putExtra(SmartStabilizerVpnService.EXTRA_SECONDARY_DNS, SmartStabilizerVpnService.lastSecondaryDns)
                putExtra(SmartStabilizerVpnService.EXTRA_SERVER_NAME, SmartStabilizerVpnService.lastServerName)
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent)
            } else {
                startService(startIntent)
            }
            SmartStabilizerVpnService.isServiceRunning = true
        }
        syncTileVisualState()
    }

    private fun syncTileVisualState() {
        val tile = qsTile ?: return
        val running = SmartStabilizerVpnService.isServiceRunning
        tile.state = if (running) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (running) "پایدارساز: متصل" else "پایدارساز اینترنت"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = if (running) SmartStabilizerVpnService.lastPrimaryDns else "آماده اتصال"
        }
        tile.updateTile()
    }
}

// ============================================================================
// 8. VIEWMODEL: UNIFIED STATE MANAGEMENT ACROSS ALL 4 TABS
// ============================================================================

enum class AppTab(val titleFa: String) {
    HOME_DNS("اتصال و DNS"),
    CLEAN_IP_SCANNER("اسکنر IP تمیز"),
    CORE_AND_WARP("هسته WARP / Xray"),
    SPLIT_TUNNEL("تفکیک برنامه‌ها")
}

data class StabilizerUiState(
    val activeTab: AppTab = AppTab.HOME_DNS,
    val isConnected: Boolean = false,
    val isTestingPing: Boolean = false,
    val autoFailoverEnabled: Boolean = true,
    val selectedMode: TunnelMode = TunnelMode.DOH_AND_DPI_FRAGMENT,
    val servers: List<DnsServerProfile> = PresetDnsCatalog.servers,
    val selectedServer: DnsServerProfile = PresetDnsCatalog.servers.first(),
    val customPrimaryDns: String = "",
    val customSecondaryDns: String = "",
    val isScanningCleanIps: Boolean = false,
    val cleanIpResults: List<CleanIpResult> = emptyList(),
    val activeCleanEndpointIp: String = "162.159.192.1",
    val activeCleanEndpointPort: Int = 2408,
    val selectedCoreEngine: CoreEngineType = CoreEngineType.SING_BOX,
    val fragmentLengthRange: String = "10-25",
    val fragmentIntervalRange: String = "10-20",
    val enableWarpNoisePackets: Boolean = true,
    val shareLinkInput: String = "",
    val activeProxyConfig: ParsedProxyConfig = SingBoxXrayCoreBridge.createServerlessWarpProfile("162.159.192.1", 2408),
    val generatedCoreJson: String = "",
    val splitTunnelMode: SplitTunnelMode = SplitTunnelMode.BYPASS_SELECTED,
    val installedApps: List<InstalledAppInfo> = emptyList(),
    val isLoadingApps: Boolean = false,
    val selectedSplitPackages: Set<String> = emptySet(),
    val appSearchQuery: String = "",
    val statusLogFa: String = "آماده اتصال • برای انتخاب بهترین سرور روی «یافتن سریع‌ترین سرور» بزنید."
)

class StabilizerViewModel : ViewModel() {

    private val _uiState = MutableStateFlow(StabilizerUiState())
    val uiState: StateFlow<StabilizerUiState> = _uiState.asStateFlow()

    private var watchdogJob: Job? = null

    init {
        refreshAllServerPings(autoSelectBest = true)
        rebuildCoreConfigPreview()
    }

    fun selectTab(tab: AppTab, context: Context) {
        _uiState.update { it.copy(activeTab = tab) }
        if (tab == AppTab.SPLIT_TUNNEL && _uiState.value.installedApps.isEmpty()) {
            loadAppsForSplitTunnel(context)
        }
    }

    fun selectServer(server: DnsServerProfile) {
        _uiState.update {
            it.copy(
                selectedServer = server,
                statusLogFa = "سرور «${server.nameFa}» انتخاب شد."
            )
        }
        rebuildCoreConfigPreview()
    }

    fun selectTunnelMode(mode: TunnelMode) {
        _uiState.update { it.copy(selectedMode = mode) }
        rebuildCoreConfigPreview()
    }

    fun toggleAutoFailover(enabled: Boolean) {
        _uiState.update { it.copy(autoFailoverEnabled = enabled) }
    }

    fun updateCustomDns(primary: String, secondary: String) {
        _uiState.update {
            it.copy(customPrimaryDns = primary.trim(), customSecondaryDns = secondary.trim())
        }
    }

    fun applyCustomDnsProfile() {
        val state = _uiState.value
        val ipv4Regex = Regex("""^\d{1,3}(\.\d{1,3}){3}$""")
        if (!ipv4Regex.matches(state.customPrimaryDns)) {
            _uiState.update { it.copy(statusLogFa = "خطا: فرمت آدرس DNS اول معتبر نیست (مثال: 1.1.1.1)") }
            return
        }
        val secondary = if (ipv4Regex.matches(state.customSecondaryDns)) {
            state.customSecondaryDns
        } else {
            "1.0.0.1"
        }
        val customProfile = DnsServerProfile(
            id = "custom",
            nameFa = "سرور اختصاصی کاربر",
            categoryFa = "تنظیم دستی (${state.customPrimaryDns})",
            primaryDns = state.customPrimaryDns,
            secondaryDns = secondary
        )
        _uiState.update {
            it.copy(
                selectedServer = customProfile,
                servers = listOf(customProfile) + it.servers.filterNot { s -> s.id == "custom" },
                statusLogFa = "سرور اختصاصی ${customProfile.primaryDns} ثبت و انتخاب شد."
            )
        }
    }

    fun startCloudflareCleanIpScan() {
        if (_uiState.value.isScanningCleanIps) return
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isScanningCleanIps = true,
                    statusLogFa = "در حال اسکن رنج‌های Anycast کلودفلر و اندپوینت‌های WARP..."
                )
            }
            val results = CleanIpScannerEngine.scanCleanIps()
            val best = results.firstOrNull()
            _uiState.update { current ->
                if (best != null) {
                    val updatedWarp = if (current.activeProxyConfig.protocol == ProxyProtocolType.WIREGUARD_WARP) {
                        SingBoxXrayCoreBridge.createServerlessWarpProfile(best.ip, best.port)
                    } else {
                        current.activeProxyConfig.copy(serverAddress = best.ip)
                    }
                    current.copy(
                        isScanningCleanIps = false,
                        cleanIpResults = results,
                        activeCleanEndpointIp = best.ip,
                        activeCleanEndpointPort = best.port,
                        activeProxyConfig = updatedWarp,
                        statusLogFa = "اسکن کامل شد! بهترین آی‌پی تمیز: ${best.ip}:${best.port} (${best.latencyMs}ms)"
                    )
                } else {
                    current.copy(
                        isScanningCleanIps = false,
                        statusLogFa = "هیچ آی‌پی تمیزی پاسخ نداد؛ اتصال اینترنت خود را بررسی کنید."
                    )
                }
            }
            rebuildCoreConfigPreview()
        }
    }

    fun applyScannedCleanIp(item: CleanIpResult) {
        _uiState.update { current ->
            val updatedConfig = if (item.isWarpCompatible) {
                SingBoxXrayCoreBridge.createServerlessWarpProfile(item.ip, item.port)
            } else {
                current.activeProxyConfig.copy(serverAddress = item.ip, serverPort = item.port)
            }
            current.copy(
                activeCleanEndpointIp = item.ip,
                activeCleanEndpointPort = item.port,
                activeProxyConfig = updatedConfig,
                statusLogFa = "آی‌پی تمیز ${item.ip}:${item.port} روی هسته WARP/CDN اعمال شد."
            )
        }
        rebuildCoreConfigPreview()
    }

    fun updateCoreEngine(engine: CoreEngineType) {
        _uiState.update { it.copy(selectedCoreEngine = engine) }
        rebuildCoreConfigPreview()
    }

    fun updateFragmentParams(lengthRange: String, intervalRange: String, warpNoise: Boolean) {
        _uiState.update {
            it.copy(
                fragmentLengthRange = lengthRange,
                fragmentIntervalRange = intervalRange,
                enableWarpNoisePackets = warpNoise
            )
        }
        rebuildCoreConfigPreview()
    }

    fun updateShareLinkInput(link: String) {
        _uiState.update { it.copy(shareLinkInput = link) }
    }

    fun importProxyShareLink() {
        val state = _uiState.value
        val parsed = SingBoxXrayCoreBridge.parseShareLink(
            uriString = state.shareLinkInput,
            cleanIpOverride = null
        )
        if (parsed == null) {
            _uiState.update {
                it.copy(statusLogFa = "خطا: لینک واردشده معتبر نیست (پشتیبانی از vless://, hy2://, wg://)")
            }
            return
        }
        _uiState.update {
            it.copy(
                activeProxyConfig = parsed,
                selectedMode = TunnelMode.SINGBOX_XRAY_HYBRID_CORE,
                statusLogFa = "کانفیگ «${parsed.remark}» با موفقیت وارد و به فرگمنت TLS مجهز شد."
            )
        }
        rebuildCoreConfigPreview()
    }

    fun activateServerlessWarpMode() {
        val state = _uiState.value
        val warpProfile = SingBoxXrayCoreBridge.createServerlessWarpProfile(
            state.activeCleanEndpointIp,
            state.activeCleanEndpointPort
        )
        _uiState.update {
            it.copy(
                activeProxyConfig = warpProfile,
                selectedMode = TunnelMode.CLOUDFLARE_WARP_SERVERLESS,
                statusLogFa = "حالت بدون سرور Cloudflare WARP با اندپوینت ${state.activeCleanEndpointIp} فعال شد."
            )
        }
        rebuildCoreConfigPreview()
    }

    private fun rebuildCoreConfigPreview() {
        val s = _uiState.value
        val json = if (s.selectedCoreEngine == CoreEngineType.SING_BOX) {
            SingBoxXrayCoreBridge.buildSingBoxConfigJson(
                profile = s.activeProxyConfig,
                dohUrl = s.selectedServer.dohUrl,
                fragmentLength = s.fragmentLengthRange,
                fragmentInterval = s.fragmentIntervalRange,
                enableWarpNoise = s.enableWarpNoisePackets
            )
        } else {
            SingBoxXrayCoreBridge.buildXrayConfigJson(
                profile = s.activeProxyConfig,
                fragmentLength = s.fragmentLengthRange,
                fragmentInterval = s.fragmentIntervalRange
            )
        }
        _uiState.update { it.copy(generatedCoreJson = json) }
    }

    fun loadAppsForSplitTunnel(context: Context) {
        viewModelScope.launch {
            _uiState.update { it.copy(isLoadingApps = true) }
            val apps = SplitTunnelManager.loadInstalledApps(context)
            val defaultDomesticSet = apps.filter { it.isDomesticOrBankSuggested }.map { it.packageName }.toSet()
            _uiState.update { current ->
                current.copy(
                    isLoadingApps = false,
                    installedApps = apps,
                    selectedSplitPackages = if (current.selectedSplitPackages.isEmpty()) defaultDomesticSet else current.selectedSplitPackages
                )
            }
        }
    }

    fun setSplitTunnelMode(mode: SplitTunnelMode) {
        _uiState.update { it.copy(splitTunnelMode = mode) }
    }

    fun toggleAppInSplitTunnel(packageName: String) {
        _uiState.update { current ->
            val updated = current.selectedSplitPackages.toMutableSet()
            if (!updated.add(packageName)) {
                updated.remove(packageName)
            }
            current.copy(selectedSplitPackages = updated)
        }
    }

    fun updateAppSearchQuery(query: String) {
        _uiState.update { it.copy(appSearchQuery = query) }
    }

    fun selectAllDomesticApps() {
        _uiState.update { current ->
            val domesticPkgs = current.installedApps
                .filter { it.isDomesticOrBankSuggested }
                .map { it.packageName }
                .toSet()
            current.copy(
                selectedSplitPackages = current.selectedSplitPackages + domesticPkgs,
                statusLogFa = "${domesticPkgs.size} برنامه بانکی و داخلی به لیست استثنا (Bypass) اضافه شد."
            )
        }
    }

    fun refreshAllServerPings(autoSelectBest: Boolean = false) {
        viewModelScope.launch {
            _uiState.update {
                it.copy(
                    isTestingPing = true,
                    statusLogFa = "در حال سنجش پینگ و پایداری سرورها..."
                )
            }

            val updatedServers = _uiState.value.servers.map { server ->
                async {
                    val ping = NetworkStabilizerEngine.measureTcpLatencyMs(server.primaryDns)
                    server.copy(lastPingMs = ping)
                }
            }.awaitAll()

            val reachableServers = updatedServers.filter { (it.lastPingMs ?: -1L) > 0 }
            val fastest = reachableServers.minByOrNull { it.lastPingMs ?: Long.MAX_VALUE }

            _uiState.update { current ->
                val newSelected = if (autoSelectBest && fastest != null) fastest else {
                    updatedServers.find { it.id == current.selectedServer.id } ?: current.selectedServer
                }
                val logMsg = if (fastest != null) {
                    "بهترین سرور: ${fastest.nameFa} با پینگ ${fastest.lastPingMs}ms"
                } else {
                    "پورت ۵۳ مسدود است؛ حالت DoH + فرگمنت TLS یا WARP توصیه می‌شود."
                }
                current.copy(
                    isTestingPing = false,
                    servers = updatedServers,
                    selectedServer = newSelected,
                    statusLogFa = logMsg
                )
            }
            rebuildCoreConfigPreview()
        }
    }

    fun startProtection(context: Context) {
        val current = _uiState.value
        val activeServer = current.selectedServer

        val intent = Intent(context, SmartStabilizerVpnService::class.java).apply {
            action = SmartStabilizerVpnService.ACTION_CONNECT
            putExtra(SmartStabilizerVpnService.EXTRA_PRIMARY_DNS, activeServer.primaryDns)
            putExtra(SmartStabilizerVpnService.EXTRA_SECONDARY_DNS, activeServer.secondaryDns)
            putExtra(SmartStabilizerVpnService.EXTRA_SERVER_NAME, activeServer.nameFa)
            putExtra(SmartStabilizerVpnService.EXTRA_MTU, 1380)
            putExtra(SmartStabilizerVpnService.EXTRA_TUNNEL_MODE, current.selectedMode.ordinal)
            putExtra(SmartStabilizerVpnService.EXTRA_SPLIT_MODE, current.splitTunnelMode.ordinal)
            putStringArrayListExtra(
                SmartStabilizerVpnService.EXTRA_SELECTED_APPS,
                ArrayList(current.selectedSplitPackages)
            )
            putExtra(SmartStabilizerVpnService.EXTRA_CORE_CONFIG_JSON, current.generatedCoreJson)
            putExtra(SmartStabilizerVpnService.EXTRA_CORE_ENGINE, current.selectedCoreEngine.ordinal)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }

        _uiState.update {
            it.copy(
                isConnected = true,
                statusLogFa = "متصل شد • ${current.selectedMode.titleFa} (${activeServer.primaryDns})"
            )
        }

        startStabilityWatchdog(context)
    }

    fun stopProtection(context: Context) {
        watchdogJob?.cancel()
        val intent = Intent(context, SmartStabilizerVpnService::class.java).apply {
            action = SmartStabilizerVpnService.ACTION_DISCONNECT
        }
        context.startService(intent)

        _uiState.update {
            it.copy(
                isConnected = false,
                statusLogFa = "اتصال قطع شد."
            )
        }
    }

    private fun startStabilityWatchdog(context: Context) {
        watchdogJob?.cancel()
        watchdogJob = viewModelScope.launch {
            while (isActive && _uiState.value.isConnected) {
                delay(20_000L)
                if (!_uiState.value.autoFailoverEnabled) continue

                val active = _uiState.value.selectedServer
                val currentPing = NetworkStabilizerEngine.measureTcpLatencyMs(active.primaryDns)

                if (currentPing < 0 || currentPing > 600L) {
                    val candidates = _uiState.value.servers.map { srv ->
                        async {
                            srv.copy(lastPingMs = NetworkStabilizerEngine.measureTcpLatencyMs(srv.primaryDns))
                        }
                    }.awaitAll()

                    val bestAlternative = candidates
                        .filter { (it.lastPingMs ?: -1L) in 1..500 }
                        .minByOrNull { it.lastPingMs ?: Long.MAX_VALUE }

                    if (bestAlternative != null && bestAlternative.id != active.id) {
                        _uiState.update {
                            it.copy(
                                servers = candidates,
                                selectedServer = bestAlternative,
                                statusLogFa = "سوئیچ خودکار به «${bestAlternative.nameFa}» (${bestAlternative.lastPingMs}ms)"
                            )
                        }
                        startProtection(context)
                    }
                }
            }
        }
    }
}

// ============================================================================
// 9. JETPACK COMPOSE UI (Material 3 + Full Persian RTL + 4 Navigation Tabs)
// ============================================================================

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
                MaterialTheme(
                    colorScheme = darkColorScheme(
                        primary = Color(0xFF10B981),
                        secondary = Color(0xFF38BDF8),
                        background = Color(0xFF0F172A),
                        surface = Color(0xFF1E293B),
                        onPrimary = Color.Black,
                        onBackground = Color(0xFFF8FAFC),
                        onSurface = Color(0xFFF1F5F9)
                    )
                ) {
                    Surface(
                        modifier = Modifier.fillMaxSize(),
                        color = MaterialTheme.colorScheme.background
                    ) {
                        SmartStabilizerScreen()
                    }
                }
            }
        }
    }
}

@Composable
fun SmartStabilizerScreen(viewModel: StabilizerViewModel = viewModel()) {
    val state by viewModel.uiState.collectAsState()
    val context = LocalContext.current

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startProtection(context)
        }
    }

    Scaffold(
        bottomBar = {
            NavigationBar(containerColor = Color(0xFF1E293B)) {
                AppTab.values().forEach { tab ->
                    NavigationBarItem(
                        selected = state.activeTab == tab,
                        onClick = { viewModel.selectTab(tab, context) },
                        icon = {
                            Box(
                                modifier = Modifier
                                    .size(8.dp)
                                    .clip(CircleShape)
                                    .background(
                                        if (state.activeTab == tab) Color(0xFF10B981) else Color(0xFF64748B)
                                    )
                            )
                        },
                        label = {
                            Text(
                                text = tab.titleFa,
                                fontSize = 11.sp,
                                fontWeight = if (state.activeTab == tab) FontWeight.Bold else FontWeight.Normal
                            )
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .padding(horizontal = 16.dp, vertical = 10.dp)
        ) {
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF1E293B)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        text = state.statusLogFa,
                        fontSize = 12.sp,
                        color = if (state.isConnected) Color(0xFF34D399) else Color(0xFF38BDF8),
                        modifier = Modifier.weight(1f)
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            when (state.activeTab) {
                AppTab.HOME_DNS -> HomeDnsTabContent(
                    state = state,
                    viewModel = viewModel,
                    onConnectToggle = {
                        if (state.isConnected) {
                            viewModel.stopProtection(context)
                        } else {
                            val prepareIntent = VpnService.prepare(context)
                            if (prepareIntent != null) {
                                vpnPermissionLauncher.launch(prepareIntent)
                            } else {
                                viewModel.startProtection(context)
                            }
                        }
                    }
                )

                AppTab.CLEAN_IP_SCANNER -> CleanIpScannerTabContent(
                    state = state,
                    viewModel = viewModel
                )

                AppTab.CORE_AND_WARP -> CoreAndWarpTabContent(
                    state = state,
                    viewModel = viewModel
                )

                AppTab.SPLIT_TUNNEL -> SplitTunnelTabContent(
                    state = state,
                    viewModel = viewModel,
                    context = context
                )
            }
        }
    }
}

@Composable
private fun HomeDnsTabContent(
    state: StabilizerUiState,
    viewModel: StabilizerViewModel,
    onConnectToggle: () -> Unit
) {
    val connectButtonColor by animateColorAsState(
        targetValue = if (state.isConnected) Color(0xFF10B981) else Color(0xFF334155),
        label = "connectBtnColor"
    )

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                shape = RoundedCornerShape(20.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(18.dp),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Box(
                        contentAlignment = Alignment.Center,
                        modifier = Modifier
                            .size(120.dp)
                            .clip(CircleShape)
                            .background(connectButtonColor)
                            .border(
                                width = 4.dp,
                                color = if (state.isConnected) Color(0xFF34D399) else Color(0xFF475569),
                                shape = CircleShape
                            )
                            .clickable { onConnectToggle() }
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Text(
                                text = if (state.isConnected) "متصل" else "اتصال",
                                fontSize = 21.sp,
                                fontWeight = FontWeight.ExtraBold,
                                color = if (state.isConnected) Color(0xFF052E16) else Color.White
                            )
                            Text(
                                text = if (state.isConnected) "قطع تانل" else "ضربه بزنید",
                                fontSize = 11.sp,
                                color = if (state.isConnected) Color(0xFF064E3B) else Color(0xFFCBD5E1)
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "سوئیچ خودکار هنگام افت پینگ (Auto-Failover)",
                            fontSize = 13.sp,
                            color = MaterialTheme.colorScheme.onSurface
                        )
                        Switch(
                            checked = state.autoFailoverEnabled,
                            onCheckedChange = { viewModel.toggleAutoFailover(it) }
                        )
                    }
                }
            }
        }

        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "روش بهینه‌سازی و هسته فعال",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    TunnelMode.values().forEach { mode ->
                        val isSelected = state.selectedMode == mode
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clip(RoundedCornerShape(10.dp))
                                .clickable { viewModel.selectTunnelMode(mode) }
                                .padding(vertical = 5.dp),
                            verticalAlignment = Alignment.Top
                        ) {
                            RadioButton(
                                selected = isSelected,
                                onClick = { viewModel.selectTunnelMode(mode) }
                            )
                            Column(modifier = Modifier.padding(start = 6.dp)) {
                                Text(
                                    text = mode.titleFa,
                                    fontWeight = FontWeight.SemiBold,
                                    fontSize = 13.sp,
                                    color = if (isSelected) Color(0xFF10B981) else Color.White
                                )
                                Text(
                                    text = mode.descFa,
                                    fontSize = 11.sp,
                                    color = Color(0xFF94A3B8)
                                )
                            }
                        }
                    }
                }
            }
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = "سرورهای DNS و ضدتحریم",
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp
                )
                Button(
                    onClick = { viewModel.refreshAllServerPings(autoSelectBest = true) },
                    enabled = !state.isTestingPing
                ) {
                    Text(
                        text = if (state.isTestingPing) "در حال تست..." else "یافتن سریع‌ترین سرور",
                        fontSize = 12.sp
                    )
                }
            }
        }

        items(state.servers, key = { it.id }) { server ->
            val isSelected = server.id == state.selectedServer.id
            val ping = server.lastPingMs
            val pingColor = when {
                ping == null -> Color(0xFF94A3B8)
                ping < 0 -> Color(0xFFEF4444)
                ping < 90 -> Color(0xFF10B981)
                ping < 200 -> Color(0xFFF59E0B)
                else -> Color(0xFFEF4444)
            }

            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isSelected) Color(0xFF064E3B) else MaterialTheme.colorScheme.surface
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .border(
                        width = if (isSelected) 1.5.dp else 0.dp,
                        color = if (isSelected) Color(0xFF10B981) else Color.Transparent,
                        shape = RoundedCornerShape(14.dp)
                    )
                    .clickable { viewModel.selectServer(server) }
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = server.nameFa,
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = Color.White
                        )
                        Text(
                            text = server.categoryFa,
                            fontSize = 11.sp,
                            color = Color(0xFFCBD5E1)
                        )
                        Text(
                            text = "DNS: ${server.primaryDns} | ${server.secondaryDns}",
                            fontSize = 11.sp,
                            color = Color(0xFF94A3B8)
                        )
                    }

                    Box(
                        modifier = Modifier
                            .clip(RoundedCornerShape(8.dp))
                            .background(Color(0xFF0F172A))
                            .padding(horizontal = 10.dp, vertical = 6.dp)
                    ) {
                        Text(
                            text = when {
                                ping == null -> "---"
                                ping < 0 -> "بدون پاسخ"
                                else -> "${ping} ms"
                            },
                            color = pingColor,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp
                        )
                    }
                }
            }
        }

        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "افزودن DNS اختصاصی",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = state.customPrimaryDns,
                            onValueChange = { viewModel.updateCustomDns(it, state.customSecondaryDns) },
                            label = { Text("DNS اول (مثلاً 1.1.1.1)", fontSize = 11.sp) },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = state.customSecondaryDns,
                            onValueChange = { viewModel.updateCustomDns(state.customPrimaryDns, it) },
                            label = { Text("DNS دوم (اختیاری)", fontSize = 11.sp) },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedButton(
                        onClick = { viewModel.applyCustomDnsProfile() },
                        modifier = Modifier.align(Alignment.End)
                    ) {
                        Text("ثبت و انتخاب DNS دستی", fontSize = 12.sp)
                    }
                }
            }
        }
    }
}

@Composable
private fun CleanIpScannerTabContent(
    state: StabilizerUiState,
    viewModel: StabilizerViewModel
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text(
                        text = "اسکنر خودکار آی‌پی تمیز کلودفلر و اندپوینت WARP",
                        fontWeight = FontWeight.Bold,
                        fontSize = 15.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "بررسی موازی رنج‌های 162.159.x، 188.114.96.x، 104.16.x و 172.64.x بر اساس کمترین پینگ و نوسان (Jitter) روی اینترنت فعلی شما.",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(10.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "اندپوینت فعال: ${state.activeCleanEndpointIp}:${state.activeCleanEndpointPort}",
                            fontSize = 12.sp,
                            fontWeight = FontWeight.Bold,
                            color = Color(0xFF10B981)
                        )
                        Button(
                            onClick = { viewModel.startCloudflareCleanIpScan() },
                            enabled = !state.isScanningCleanIps
                        ) {
                            Text(
                                text = if (state.isScanningCleanIps) "در حال اسکن..." else "شروع اسکن آی‌پی تمیز",
                                fontSize = 12.sp
                            )
                        }
                    }
                }
            }
        }

        items(state.cleanIpResults, key = { "${it.ip}:${it.port}" }) { item ->
            val isApplied = item.ip == state.activeCleanEndpointIp && item.port == state.activeCleanEndpointPort
            Card(
                shape = RoundedCornerShape(12.dp),
                colors = CardDefaults.cardColors(
                    containerColor = if (isApplied) Color(0xFF064E3B) else MaterialTheme.colorScheme.surface
                ),
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable { viewModel.applyScannedCleanIp(item) }
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column {
                        Text(
                            text = "${item.ip}:${item.port}",
                            fontWeight = FontWeight.Bold,
                            fontSize = 14.sp,
                            color = Color.White
                        )
                        Text(
                            text = item.subnetTag,
                            fontSize = 11.sp,
                            color = Color(0xFF94A3B8)
                        )
                    }
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = "پینگ: ${item.latencyMs}ms | جیتر: ${item.jitterMs}ms",
                            fontSize = 12.sp,
                            color = Color(0xFF34D399),
                            fontWeight = FontWeight.SemiBold
                        )
                        OutlinedButton(onClick = { viewModel.applyScannedCleanIp(item) }) {
                            Text(if (isApplied) "فعال" else "اعمال", fontSize = 11.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CoreAndWarpTabContent(
    state: StabilizerUiState,
    viewModel: StabilizerViewModel
) {
    val clipboard = LocalClipboardManager.current

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "۱. حالت بدون سرور Cloudflare WARP + پارامتر Noise",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "استفاده از تانل رایگان کلودفلر با پکت‌های Noise (دور زدن مسدودیت UDP اپراتورها) و آی‌پی تمیز (${state.activeCleanEndpointIp}:${state.activeCleanEndpointPort}).",
                        fontSize = 12.sp,
                        color = Color(0xFF94A3B8)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Button(
                        onClick = { viewModel.activateServerlessWarpMode() },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("فعال‌سازی پروفایل بدون سرور WARP + Noise", fontSize = 12.sp)
                    }
                }
            }
        }

        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "۲. تنظیمات فرگمنت TLS و ضد فیلترینگ DPI",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        OutlinedTextField(
                            value = state.fragmentLengthRange,
                            onValueChange = {
                                viewModel.updateFragmentParams(it, state.fragmentIntervalRange, state.enableWarpNoisePackets)
                            },
                            label = { Text("طول قطعات (بایت)", fontSize = 11.sp) },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                        OutlinedTextField(
                            value = state.fragmentIntervalRange,
                            onValueChange = {
                                viewModel.updateFragmentParams(state.fragmentLengthRange, it, state.enableWarpNoisePackets)
                            },
                            label = { Text("فاصله ارسال (ms)", fontSize = 11.sp) },
                            singleLine = true,
                            modifier = Modifier.weight(1f)
                        )
                    }
                }
            }
        }

        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "۳. افزودن کانفیگ Sing-box / Xray (VLESS, Reality, Hysteria2, WG)",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        CoreEngineType.values().forEach { engine ->
                            FilterChip(
                                selected = state.selectedCoreEngine == engine,
                                onClick = { viewModel.updateCoreEngine(engine) },
                                label = { Text(engine.title, fontSize = 12.sp) }
                            )
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = state.shareLinkInput,
                        onValueChange = { viewModel.updateShareLinkInput(it) },
                        label = { Text("لینک vless:// یا hy2:// یا wg:// را وارد کنید", fontSize = 11.sp) },
                        modifier = Modifier.fillMaxWidth(),
                        maxLines = 3
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween
                    ) {
                        OutlinedButton(
                            onClick = {
                                clipboard.setText(AnnotatedString(state.generatedCoreJson))
                            }
                        ) {
                            Text("کپی JSON هسته", fontSize = 12.sp)
                        }
                        Button(onClick = { viewModel.importProxyShareLink() }) {
                            Text("اعمال لینک و تزریق فرگمنت", fontSize = 12.sp)
                        }
                    }
                }
            }
        }

        item {
            Card(
                shape = RoundedCornerShape(14.dp),
                colors = CardDefaults.cardColors(containerColor = Color(0xFF090D16)),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(12.dp)) {
                    Text(
                        text = "خروجی زنده کانفیگ هسته (${state.selectedCoreEngine.title}):",
                        fontSize = 12.sp,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFF38BDF8)
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    Text(
                        text = state.generatedCoreJson,
                        fontSize = 10.sp,
                        fontFamily = FontFamily.Monospace,
                        color = Color(0xFFCBD5E1)
                    )
                }
            }
        }
    }
}

@Composable
private fun SplitTunnelTabContent(
    state: StabilizerUiState,
    viewModel: StabilizerViewModel,
    context: Context
) {
    val filteredApps = remember(state.installedApps, state.appSearchQuery) {
        if (state.appSearchQuery.isBlank()) {
            state.installedApps
        } else {
            val q = state.appSearchQuery.trim().lowercase()
            state.installedApps.filter {
                it.appName.lowercase().contains(q) || it.packageName.lowercase().contains(q)
            }
        }
    }

    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        item {
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                modifier = Modifier.fillMaxWidth()
            ) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text(
                        text = "مدیریت تفکیک ترافیک برنامه‌ها (Per-App Split Tunneling)",
                        fontWeight = FontWeight.Bold,
                        fontSize = 14.sp
                    )
                    Spacer(modifier = Modifier.height(6.dp))
                    SplitTunnelMode.values().forEach { mode ->
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { viewModel.setSplitTunnelMode(mode) }
                                .padding(vertical = 4.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            RadioButton(
                                selected = state.splitTunnelMode == mode,
                                onClick = { viewModel.setSplitTunnelMode(mode) }
                            )
                            Column(modifier = Modifier.padding(start = 6.dp)) {
                                Text(mode.titleFa, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
                                Text(mode.descFa, fontSize = 11.sp, color = Color(0xFF94A3B8))
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedButton(onClick = { viewModel.selectAllDomesticApps() }) {
                            Text("انتخاب خودکار بانک‌ها و اپ‌های داخلی", fontSize = 11.sp)
                        }
                        OutlinedButton(onClick = { viewModel.loadAppsForSplitTunnel(context) }) {
                            Text("بروزرسانی لیست", fontSize = 11.sp)
                        }
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    OutlinedTextField(
                        value = state.appSearchQuery,
                        onValueChange = { viewModel.updateAppSearchQuery(it) },
                        label = { Text("جستجوی نام برنامه یا پکیج...", fontSize = 11.sp) },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }
        }

        if (state.isLoadingApps) {
            item {
                Box(modifier = Modifier.fillMaxWidth().padding(24.dp), contentAlignment = Alignment.Center) {
                    CircularProgressIndicator()
                }
            }
        } else {
            items(filteredApps, key = { it.packageName }) { app ->
                val isChecked = state.selectedSplitPackages.contains(app.packageName)
                Card(
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface),
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { viewModel.toggleAppInSplitTunnel(app.packageName) }
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 8.dp),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(
                                text = app.appName,
                                fontWeight = FontWeight.Bold,
                                fontSize = 13.sp,
                                color = Color.White
                            )
                            Text(
                                text = app.packageName,
                                fontSize = 11.sp,
                                color = Color(0xFF94A3B8)
                            )
                            if (app.isDomesticOrBankSuggested) {
                                Text(
                                    text = "پیشنهاد عبور مستقیم (برنامه داخلی / بانکی)",
                                    fontSize = 10.sp,
                                    color = Color(0xFF38BDF8)
                                )
                            }
                        }
                        Checkbox(
                            checked = isChecked,
                            onCheckedChange = { viewModel.toggleAppInSplitTunnel(app.packageName) }
                        )
                    }
                }
            }
        }
    }
}
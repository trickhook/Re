package com.trickhook.update

import android.os.Build
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.SocketTimeoutException
import java.net.URL
import java.net.UnknownHostException
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLException

/**
 * The only code in Nocturne that opens a socket.
 *
 * Two requests, both HTTPS, both to GitHub, both only when the user asked:
 * the latest-release document from the REST API, and the release's own
 * metadata asset. A third — the APK itself — happens in [downloadApk] after
 * the user has seen what they are about to fetch.
 *
 * Verification check 1 of 3 lives here: **HTTPS, on every hop.** Automatic
 * redirect following is turned off and each Location is resolved and re-checked
 * by hand, because `HttpURLConnection` follows redirects inside the stack where
 * nothing in this file can see where it ended up. Certificate validation is
 * left exactly as the platform configures it — there is no TrustManager, no
 * HostnameVerifier and no SSLSocketFactory anywhere in this project, and
 * `res/xml/network_security_config.xml` pins the app to the system trust store
 * with cleartext refused outright.
 */

private const val CONNECT_TIMEOUT_MS = 15_000
private const val READ_TIMEOUT_MS = 30_000

/** GitHub redirects an asset download once, to its object store. Five is slack. */
private const val MAX_REDIRECTS = 5

/** The release document and the metadata asset are both a few KB. */
private const val MAX_TEXT_BYTES = 512L * 1024L

private const val DOWNLOAD_BUFFER = 64 * 1024

private const val ACCEPT_GITHUB_API = "application/vnd.github+json"
private const val ACCEPT_TEXT = "application/json, text/plain, */*"
private const val ACCEPT_BINARY = "application/octet-stream, */*"

private val HEX64 = Regex("[0-9a-f]{64}")

/** The identity Nocturne presents. GitHub answers 403 to a request with no User-Agent. */
fun updateUserAgent(versionName: String): String =
    "Nocturne/$versionName (Android ${Build.VERSION.RELEASE}; +https://github.com/trickhook/Re)"

fun latestReleaseUrl(repo: String): String = "https://api.github.com/repos/$repo/releases/latest"

// ------------------------------------------------------------------ check --

/**
 * Ask GitHub for the newest published release of [repo] and read the metadata
 * asset called [manifestAsset] out of it.
 *
 * `/releases/latest` excludes drafts and pre-releases, so a release candidate
 * is never offered to someone who did not go looking for it.
 */
suspend fun fetchLatestRelease(
    repo: String,
    manifestAsset: String,
    userAgent: String
): UpdateRelease = withContext(Dispatchers.IO) {
    val releaseDoc = readText(latestReleaseUrl(repo), ACCEPT_GITHUB_API, userAgent, repo, true)
    val root = try {
        JSONObject(releaseDoc)
    } catch (e: Exception) {
        throw UpdateException(failManifest("GitHub's answer was not valid JSON"))
    }
    val tag = root.optString("tag_name").ifEmpty { "(untagged)" }
    val assets = root.optJSONArray("assets") ?: JSONArray()
    val metaAsset = assetNamed(assets, manifestAsset)
        ?: throw UpdateException(failNoManifest(manifestAsset, tag))
    val metaUrl = metaAsset.optString("browser_download_url")
    if (metaUrl.isBlank()) throw UpdateException(failNoManifest(manifestAsset, tag))
    val metaText = readText(metaUrl, ACCEPT_TEXT, userAgent, repo, false)
    parseUpdateManifest(metaText, assets, tag)
}

/**
 * Turn the metadata asset into an [UpdateRelease], refusing anything it cannot
 * fully account for. Every `throw` here is a release the updater declines to
 * touch; none of them has downloaded a byte of APK yet.
 */
internal fun parseUpdateManifest(text: String, assets: JSONArray, tag: String): UpdateRelease {
    val o = try {
        JSONObject(text)
    } catch (e: Exception) {
        throw UpdateException(failManifest("it is not valid JSON"))
    }

    val schema = o.optInt("schema", 0)
    if (schema != UPDATE_SCHEMA) throw UpdateException(failSchema(schema))

    val versionCode = o.optLong("versionCode", -1L)
    if (versionCode <= 0L) throw UpdateException(failManifestField("versionCode"))
    val versionName = o.optString("versionName").trim()
    if (versionName.isEmpty()) throw UpdateException(failManifestField("versionName"))

    val minSdk = o.optInt("minSdk", 0)
    if (minSdk > Build.VERSION.SDK_INT) {
        throw UpdateException(failMinSdk(minSdk, Build.VERSION.SDK_INT))
    }

    // An APK with no slice for this device installs and then dies on the first
    // JNI call, which is a worse outcome than declining the update.
    val abiArray = o.optJSONArray("abis")
    if (abiArray != null && abiArray.length() > 0) {
        val offered = ArrayList<String>()
        for (i in 0 until abiArray.length()) {
            val abi = abiArray.optString(i)
            if (abi.isNotEmpty()) offered.add(abi)
        }
        val supported = Build.SUPPORTED_ABIS?.toList() ?: emptyList()
        if (offered.isNotEmpty() && supported.isNotEmpty() && offered.none { supported.contains(it) }) {
            throw UpdateException(
                failAbi(offered.joinToString(", "), supported.joinToString(", "))
            )
        }
    }

    val apk = o.optJSONObject("apk") ?: throw UpdateException(failManifestField("apk"))
    val apkName = apk.optString("name").trim()
    if (apkName.isEmpty()) throw UpdateException(failManifestField("apk.name"))
    val apkSize = apk.optLong("size", -1L)
    if (apkSize <= 0L) throw UpdateException(failManifestField("apk.size"))

    val rawSha = apk.optString("sha256")
    if (rawSha.isBlank()) throw UpdateException(failManifestField("apk.sha256"))
    val sha = normalizeHex(rawSha)
    if (!HEX64.matches(sha)) throw UpdateException(failManifestSha(rawSha))

    // Optional: a release that omits it is still verifiable against the
    // installed app's own certificate, which is the check that actually
    // protects the device. When it is present it is one more way for a
    // substituted APK to fail before it reaches the installer.
    val signer = normalizeHex(apk.optString("signerSha256"))

    // The address comes from GitHub's own description of the asset, never from
    // the metadata body — so the contents of a manifest cannot send the
    // downloader anywhere the release does not live.
    val asset = assetNamed(assets, apkName)
        ?: throw UpdateException(failMissingApkAsset(apkName, tag))
    val assetSize = asset.optLong("size", -1L)
    if (assetSize > 0L && assetSize != apkSize) {
        throw UpdateException(failSizeDisagrees(apkSize, assetSize))
    }
    val url = asset.optString("browser_download_url")
    if (url.isBlank()) throw UpdateException(failMissingApkAsset(apkName, tag))

    return UpdateRelease(
        versionCode = versionCode,
        versionName = versionName,
        apkName = apkName,
        apkSize = apkSize,
        sha256 = sha,
        signerSha256 = signer,
        notes = o.optString("notes").trim(),
        apkUrl = url,
        tag = o.optString("tag").ifEmpty { tag },
        prerelease = o.optBoolean("prerelease", false)
    )
}

// --------------------------------------------------------------- download --

/**
 * Stream the release APK into [dest], which must be app-private storage.
 *
 * Nothing here trusts the file afterwards: the caller hashes it and checks its
 * signing certificate before it is shown to anyone. The byte count is compared
 * against the size the release published, so a connection that dies at 90 %
 * fails here rather than as a confusing digest mismatch one step later.
 *
 * [onProgress] is suspending so the caller can throttle it and hop to the main
 * thread; it is called once with (0, total) before the first byte, so a sheet
 * that is already on screen shows a full-width empty bar rather than nothing.
 */
suspend fun downloadApk(
    rel: UpdateRelease,
    dest: File,
    userAgent: String,
    onProgress: suspend (Long, Long) -> Unit
): Unit = withContext(Dispatchers.IO) {
    val host = hostOf(rel.apkUrl)
    val c = try {
        connectFollowing(rel.apkUrl, ACCEPT_BINARY, userAgent)
    } catch (e: UpdateException) {
        throw e
    } catch (e: UnknownHostException) {
        throw UpdateException(failOffline(host))
    } catch (e: SocketTimeoutException) {
        throw UpdateException(failTimeout(host))
    } catch (e: SSLException) {
        throw UpdateException(failNetwork("The secure connection to $host could not be established."))
    } catch (e: IOException) {
        throw UpdateException(failNetwork("The connection to $host failed."))
    }
    var got = 0L
    try {
        demandOk(c, "", false)
        val declared = c.contentLengthLong
        val total = if (declared > 0L) declared else rel.apkSize
        onProgress(0L, total)
        c.inputStream.use { input ->
            FileOutputStream(dest).use { output ->
                val buf = ByteArray(DOWNLOAD_BUFFER)
                while (true) {
                    ensureActive()
                    val n = try {
                        input.read(buf)
                    } catch (e: IOException) {
                        throw UpdateException(failNetwork("The transfer from $host was interrupted."))
                    }
                    if (n < 0) break
                    try {
                        output.write(buf, 0, n)
                    } catch (e: IOException) {
                        throw UpdateException(
                            failWrite("Nocturne's private storage would not take the file")
                        )
                    }
                    got += n
                    onProgress(got, total)
                }
                output.flush()
            }
        }
    } catch (e: UpdateException) {
        throw e
    } catch (e: SocketTimeoutException) {
        throw UpdateException(failTimeout(host))
    } catch (e: IOException) {
        // Cancellation arrives as a CancellationException, which is not an
        // IOException, so it passes straight through this and is not dressed up
        // as a network failure.
        throw UpdateException(failNetwork("The transfer from $host failed."))
    } finally {
        c.disconnect()
    }
    if (got != rel.apkSize) throw UpdateException(failTruncated(got, rel.apkSize))
}

// ------------------------------------------------------------------ plumb --

private fun assetNamed(assets: JSONArray, name: String): JSONObject? {
    for (i in 0 until assets.length()) {
        val a = assets.optJSONObject(i) ?: continue
        if (a.optString("name") == name) return a
    }
    return null
}

private fun hostOf(spec: String): String = try {
    URL(spec).host ?: "github.com"
} catch (e: Exception) {
    "github.com"
}

private fun readText(
    url: String,
    accept: String,
    userAgent: String,
    repo: String,
    releaseLookup: Boolean
): String {
    val host = hostOf(url)
    val c = try {
        connectFollowing(url, accept, userAgent)
    } catch (e: UpdateException) {
        throw e
    } catch (e: UnknownHostException) {
        throw UpdateException(failOffline(host))
    } catch (e: SocketTimeoutException) {
        throw UpdateException(failTimeout(host))
    } catch (e: SSLException) {
        throw UpdateException(failNetwork("The secure connection to $host could not be established."))
    } catch (e: IOException) {
        throw UpdateException(failNetwork("The connection to $host failed."))
    }
    try {
        demandOk(c, repo, releaseLookup)
        val out = ByteArrayOutputStream()
        c.inputStream.use { input ->
            val buf = ByteArray(16 * 1024)
            var total = 0L
            while (true) {
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > MAX_TEXT_BYTES) {
                    throw UpdateException(
                        failManifest("it is larger than ${MAX_TEXT_BYTES / 1024} KB, which no release metadata is")
                    )
                }
                out.write(buf, 0, n)
            }
        }
        return String(out.toByteArray(), Charsets.UTF_8)
    } catch (e: UpdateException) {
        throw e
    } catch (e: SocketTimeoutException) {
        throw UpdateException(failTimeout(host))
    } catch (e: IOException) {
        throw UpdateException(failNetwork("The connection to $host failed."))
    } finally {
        c.disconnect()
    }
}

/**
 * Open [spec], following redirects by hand so that every hop can be checked.
 *
 * `instanceFollowRedirects` is off deliberately. Left on, the platform resolves
 * the chain internally and hands back a connection to wherever it landed, which
 * this code would then have no way to inspect. The loop below refuses anything
 * that is not HTTPS at every single hop, including the first.
 */
private fun connectFollowing(spec: String, accept: String, userAgent: String): HttpsURLConnection {
    var url = URL(spec)
    var hops = 0
    while (true) {
        if (!url.protocol.equals("https", ignoreCase = true)) {
            throw UpdateException(failNotHttps(url.toString()))
        }
        val c = url.openConnection() as? HttpsURLConnection
            ?: throw UpdateException(failNotHttps(url.toString()))
        c.instanceFollowRedirects = false
        c.connectTimeout = CONNECT_TIMEOUT_MS
        c.readTimeout = READ_TIMEOUT_MS
        c.requestMethod = "GET"
        c.setRequestProperty("Accept", accept)
        c.setRequestProperty("User-Agent", userAgent)
        c.setRequestProperty("X-GitHub-Api-Version", "2022-11-28")
        val code = c.responseCode
        if (code == HttpURLConnection.HTTP_MOVED_PERM ||
            code == HttpURLConnection.HTTP_MOVED_TEMP ||
            code == HttpURLConnection.HTTP_SEE_OTHER ||
            code == 307 || code == 308
        ) {
            val location = c.getHeaderField("Location")
            c.disconnect()
            if (location.isNullOrBlank()) {
                throw UpdateException(failGithub(code, "a redirect with nowhere to go"))
            }
            hops++
            if (hops > MAX_REDIRECTS) {
                throw UpdateException(failGithub(code, "the redirects never stopped"))
            }
            url = URL(url, location)
            continue
        }
        return c
    }
}

private fun demandOk(c: HttpsURLConnection, repo: String, releaseLookup: Boolean) {
    val code = c.responseCode
    if (code == HttpURLConnection.HTTP_OK) return
    when (code) {
        HttpURLConnection.HTTP_NOT_FOUND ->
            if (releaseLookup) throw UpdateException(failNoRelease(repo))
            else throw UpdateException(failGithub(code, "the release asset is no longer there"))

        HttpURLConnection.HTTP_FORBIDDEN, 429 -> {
            // 60 requests an hour, unauthenticated, per address. GitHub says so
            // in the headers; repeat it in the device's own clock.
            val remaining = c.getHeaderField("x-ratelimit-remaining")
            val reset = c.getHeaderField("x-ratelimit-reset")?.toLongOrNull()
            if (code == 429 || remaining == "0") throw UpdateException(failRateLimited(reset))
            throw UpdateException(failGithub(code, "access was refused"))
        }

        else -> throw UpdateException(failGithub(code, c.responseMessage.orEmpty()))
    }
}

// -------------------------------------------------------------- hub reuse --

/**
 * A plain HTTPS GET for the Plugin Hub, built on this file's own redirect-checked,
 * HTTPS-only [connectFollowing] so the hub opens no second network stack and
 * inherits the same guarantees: HTTPS on every hop, redirects resolved and
 * re-checked by hand, the platform trust store, the shared User-Agent.
 *
 * Returns the raw response bytes, or null when the server answers 404 — which
 * the registry reads as "not seeded yet" and shows as a calm empty state rather
 * than a failure. Any other non-OK status, or a transport failure, throws
 * [UpdateException] carrying a message already written for a human. Nothing here
 * trusts the bytes: the caller hashes them and verifies the signature.
 */
suspend fun httpGetBytes(
    url: String,
    accept: String,
    userAgent: String,
    maxBytes: Long
): ByteArray? = withContext(Dispatchers.IO) {
    val host = hostOf(url)
    val c = try {
        connectFollowing(url, accept, userAgent)
    } catch (e: UpdateException) {
        throw e
    } catch (e: UnknownHostException) {
        throw UpdateException(failOffline(host))
    } catch (e: SocketTimeoutException) {
        throw UpdateException(failTimeout(host))
    } catch (e: SSLException) {
        throw UpdateException(failNetwork("The secure connection to $host could not be established."))
    } catch (e: IOException) {
        throw UpdateException(failNetwork("The connection to $host failed."))
    }
    try {
        val code = c.responseCode
        if (code == HttpURLConnection.HTTP_NOT_FOUND) return@withContext null
        if (code != HttpURLConnection.HTTP_OK) {
            throw UpdateException(failGithub(code, c.responseMessage.orEmpty()))
        }
        val out = ByteArrayOutputStream()
        c.inputStream.use { input ->
            val buf = ByteArray(16 * 1024)
            var total = 0L
            while (true) {
                ensureActive()
                val n = input.read(buf)
                if (n < 0) break
                total += n
                if (total > maxBytes) {
                    throw UpdateException(
                        failNetwork("The file from $host is larger than the hub allows.")
                    )
                }
                out.write(buf, 0, n)
            }
        }
        out.toByteArray()
    } catch (e: UpdateException) {
        throw e
    } catch (e: SocketTimeoutException) {
        throw UpdateException(failTimeout(host))
    } catch (e: IOException) {
        throw UpdateException(failNetwork("The transfer from $host failed."))
    } finally {
        c.disconnect()
    }
}

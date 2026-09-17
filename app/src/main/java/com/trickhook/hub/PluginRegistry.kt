package com.trickhook.hub

import android.content.Context
import android.util.Base64
import com.trickhook.BuildConfig
import com.trickhook.model.PluginDef
import com.trickhook.update.UpdateException
import com.trickhook.update.httpGetBytes
import com.trickhook.update.updateUserAgent
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URLEncoder

/** One row of the registry index, as published in plugins/index.json. */
data class RegistryEntry(
    val id: String,
    val name: String,
    val version: String,
    val author: String,
    val authorKey: String,
    val authorFingerprint: String,
    val description: String,
    val path: String,
    val sha256: String,
    val signature: String,
    val submittedAt: String
)

/** The outcome of reading the registry index. Empty and Unreachable both read calmly. */
sealed interface IndexResult {
    data class Loaded(val updated: String, val entries: List<RegistryEntry>) : IndexResult

    /** 404 (not seeded yet), or a valid index with no plugins. A normal empty state. */
    object Empty : IndexResult

    /** The registry could not be reached or read. [message] is human-readable. */
    data class Unreachable(val message: String) : IndexResult
}

/** The outcome of an install attempt. A Failure carries a specific, honest reason. */
sealed interface InstallResult {
    data class Success(val id: String, val name: String) : InstallResult
    data class Failure(val message: String) : InstallResult
}

/**
 * The Plugin Hub's registry client and publish builder. It reuses the updater's
 * HTTPS client ([httpGetBytes]) and adds no network or crypto dependency.
 *
 * There is no server. The browser reads a static index.json and the plugin files
 * beside it from the repository's raw host; publishing opens a prefilled GitHub
 * issue that an Action validates and merges. The device signature proves
 * authorship and integrity; the GitHub account authorizes the write.
 */
object PluginHub {
    // The live registry is read from the repository's default branch. The browser
    // is only populated once plugins/index.json exists on that branch; until then
    // fetchIndex returns Empty and the UI shows a calm empty state. To point the
    // app at another branch, change this one line.
    const val REGISTRY_BRANCH = "main"

    const val ISSUE_LABEL = "plugin-submission"

    private const val INDEX_PATH = "plugins/index.json"
    private const val MAX_INDEX_BYTES = 2L * 1024 * 1024
    private const val MAX_FILE_BYTES = 256L * 1024
    private const val ACCEPT = "application/json, text/plain, */*"

    // GitHub truncates an over-long new-issue URL, so above this the publish flow
    // prefills a short instructional body and relies on the clipboard copy.
    private const val MAX_ISSUE_URL = 7000

    private fun rawBase(): String =
        "https://raw.githubusercontent.com/${BuildConfig.UPDATE_REPO}/$REGISTRY_BRANCH/"

    fun indexUrl(): String = rawBase() + INDEX_PATH

    fun fileUrl(path: String): String = rawBase() + path.trimStart('/')

    private fun userAgent(): String = updateUserAgent(BuildConfig.VERSION_NAME)

    // -------------------------------------------------------------- browse --

    suspend fun fetchIndex(): IndexResult {
        val bytes: ByteArray? = try {
            httpGetBytes(indexUrl(), ACCEPT, userAgent(), MAX_INDEX_BYTES)
        } catch (e: UpdateException) {
            return IndexResult.Unreachable(e.failure.title)
        } catch (e: Exception) {
            return IndexResult.Unreachable("The plugin registry could not be reached.")
        }
        if (bytes == null) return IndexResult.Empty
        val parsed = try {
            parseIndex(String(bytes, Charsets.UTF_8))
        } catch (e: Exception) {
            return IndexResult.Unreachable("The registry index could not be read.")
        }
        return if (parsed.second.isEmpty()) IndexResult.Empty
        else IndexResult.Loaded(parsed.first, parsed.second)
    }

    /** Parse index.json into (updated, entries). Rows without an id are skipped. */
    private fun parseIndex(text: String): Pair<String, List<RegistryEntry>> {
        val o = JSONObject(text)
        val arr = o.optJSONArray("plugins") ?: JSONArray()
        val list = ArrayList<RegistryEntry>(arr.length())
        for (i in 0 until arr.length()) {
            val e = arr.optJSONObject(i) ?: continue
            val id = e.optString("id")
            if (id.isEmpty()) continue
            list.add(
                RegistryEntry(
                    id = id,
                    name = e.optString("name", id),
                    version = e.optString("version", ""),
                    author = e.optString("author", "unknown"),
                    authorKey = e.optString("authorKey", ""),
                    authorFingerprint = e.optString("authorFingerprint", ""),
                    description = e.optString("description", ""),
                    path = e.optString("path", ""),
                    sha256 = e.optString("sha256", ""),
                    signature = e.optString("signature", ""),
                    submittedAt = e.optString("submittedAt", "")
                )
            )
        }
        return o.optString("updated", "") to list
    }

    // ------------------------------------------------------------- install --

    /**
     * Download the plugin file named by [entry], verify it, and — only if every
     * check passes — write the exact verified bytes to
     * filesDir/plugins/&lt;id&gt;.nocturneplugin. The caller then calls the
     * existing loadPlugins to pick it up. Nothing is written on any failure.
     *
     * Checks, in order, each a hard stop with its own message:
     *  1. SHA-256 of the downloaded bytes equals the registry's sha256;
     *  2. the ECDSA-SHA256 signature verifies against authorKey over those bytes;
     *  3. authorKey hashes to the fingerprint the registry displays;
     *  4. the file is valid JSON whose id matches the entry and the id grammar.
     */
    suspend fun install(context: Context, entry: RegistryEntry): InstallResult {
        if (entry.path.isBlank()) return InstallResult.Failure("The registry entry has no file path.")
        if (entry.sha256.isBlank() || entry.authorKey.isBlank() || entry.signature.isBlank()) {
            return InstallResult.Failure("The registry entry is missing its checksum, author key or signature.")
        }

        val bytes: ByteArray? = try {
            httpGetBytes(fileUrl(entry.path), ACCEPT, userAgent(), MAX_FILE_BYTES)
        } catch (e: UpdateException) {
            return InstallResult.Failure(e.failure.title)
        } catch (e: Exception) {
            return InstallResult.Failure("The plugin file could not be downloaded.")
        }
        if (bytes == null) {
            return InstallResult.Failure("The plugin file listed in the registry is missing (404). Not installed.")
        }

        val actualSha = PluginCanonical.sha256Hex(bytes)
        if (!actualSha.equals(entry.sha256, ignoreCase = true)) {
            return InstallResult.Failure(
                "Checksum mismatch: the registry lists ${shortHex(entry.sha256)} " +
                    "but the download hashes to ${shortHex(actualSha)}. Not installed."
            )
        }

        val sig = try {
            Base64.decode(entry.signature, Base64.DEFAULT)
        } catch (e: Exception) {
            return InstallResult.Failure("The signature in the registry is not valid base64. Not installed.")
        }
        if (!DeviceKey.verify(bytes, entry.authorKey, sig)) {
            return InstallResult.Failure(
                "The signature does not verify against the author key — the file may be altered. Not installed."
            )
        }

        val fp = DeviceKey.fingerprintOfSpki(entry.authorKey)
        if (fp == null) {
            return InstallResult.Failure("The author key in the registry could not be read. Not installed.")
        }
        if (entry.authorFingerprint.isNotBlank() && !fp.equals(entry.authorFingerprint, ignoreCase = true)) {
            return InstallResult.Failure(
                "The author fingerprint in the registry does not match the author key. Not installed."
            )
        }

        val parsedId = try {
            JSONObject(String(bytes, Charsets.UTF_8)).optString("id")
        } catch (e: Exception) {
            return InstallResult.Failure("The downloaded file is not valid JSON. Not installed.")
        }
        if (parsedId != entry.id) {
            return InstallResult.Failure(
                "The downloaded file's id (\"$parsedId\") does not match the registry entry (\"${entry.id}\"). Not installed."
            )
        }
        if (!PluginCanonical.ID_REGEX.matches(entry.id)) {
            return InstallResult.Failure("The plugin id \"${entry.id}\" is not a valid id. Not installed.")
        }

        return try {
            val dir = File(context.filesDir, "plugins").apply { mkdirs() }
            val dest = File(dir, entry.id + ".nocturneplugin")
            val part = File(dir, entry.id + ".nocturneplugin.part")
            part.writeBytes(bytes)
            if (!part.renameTo(dest)) {
                dest.writeBytes(bytes)
                part.delete()
            }
            InstallResult.Success(entry.id, entry.name)
        } catch (e: Exception) {
            InstallResult.Failure("The verified plugin could not be written to storage.")
        }
    }

    private fun shortHex(hex: String): String = if (hex.length <= 12) hex else hex.substring(0, 12) + "…"

    // ------------------------------------------------------------- publish --

    /**
     * The submission object: the plugin written in its canonical form (so the
     * issue shows the exact signed bytes) beside the author key and signature.
     * The Action re-serializes the parsed plugin canonically before it verifies,
     * so the indentation here is only for a human reading the issue.
     */
    fun submissionJson(plugin: PluginDef, authorKey: String, signatureB64: String): String {
        val canon = PluginCanonical.canonicalString(plugin).trimEnd('\n').replace("\n", "\n  ")
        val sb = StringBuilder()
        sb.append("{\n")
        sb.append("  \"plugin\": ").append(canon).append(",\n")
        sb.append("  \"authorKey\": ").append(PluginCanonical.jsonString(authorKey)).append(",\n")
        sb.append("  \"signature\": ").append(PluginCanonical.jsonString(signatureB64)).append("\n")
        sb.append("}\n")
        return sb.toString()
    }

    fun issueTitle(plugin: PluginDef): String = "Plugin: ${plugin.id} ${plugin.version}"

    /** The full issue body: one fenced json block holding the submission. */
    fun fencedBody(submissionJson: String): String =
        "Automated plugin submission from Nocturne. The block below is validated " +
            "and merged by an automated check.\n\n" +
            "```json\n" + submissionJson.trimEnd('\n') + "\n```\n"

    /** The fallback body when the full one would overflow the issue URL. */
    fun shortBody(): String =
        "Automated plugin submission from Nocturne.\n\n" +
            "The submission JSON was copied to your clipboard because it is too large to " +
            "prefill here. Paste it below inside a single fenced json block, between the " +
            "```json and ``` lines, then submit.\n\n" +
            "```json\n\n```\n"

    fun issueUrl(title: String, body: String): String {
        val base = "https://github.com/${BuildConfig.UPDATE_REPO}/issues/new"
        return base + "?labels=" + enc(ISSUE_LABEL) + "&title=" + enc(title) + "&body=" + enc(body)
    }

    /**
     * The URL to open for [submissionJson], and whether it carries the full block.
     * When false, the caller must have put [submissionJson] on the clipboard for
     * the user to paste — the URL then holds only the short instructional body.
     */
    fun issueUrlFor(plugin: PluginDef, submissionJson: String): Pair<String, Boolean> {
        val title = issueTitle(plugin)
        val full = issueUrl(title, fencedBody(submissionJson))
        return if (full.length <= MAX_ISSUE_URL) full to true
        else issueUrl(title, shortBody()) to false
    }

    private fun enc(s: String): String = URLEncoder.encode(s, "UTF-8").replace("+", "%20")
}

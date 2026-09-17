package com.trickhook.hub

import com.trickhook.model.PluginDef
import java.security.MessageDigest

/**
 * The one canonical byte form of a .nocturneplugin file, shared by both sides of
 * the hub. It MUST be byte-identical to what the registry's CI serializes, or no
 * signature ever verifies — the whole scheme hinges on both sides producing the
 * same bytes.
 *
 * The form, fixed:
 *  - a JSON object with the six fields in this exact order:
 *    id, name, version, author, description, script;
 *  - two-space indentation, one level deep (each field on its own line);
 *  - a single space after each key's colon;
 *  - UTF-8; newlines are the single byte 0x0A; one trailing 0x0A at end of file;
 *  - strings escaped exactly as Android org.json JSONStringer does it: a double
 *    quote, a backslash AND a forward slash are escaped (org.json writes `\/`,
 *    which plain JSON.stringify does not — this is the one byte the two rules
 *    disagree on); backspace, tab, newline, form-feed and carriage return take
 *    their short escapes; any other control character below U+0020 becomes a
 *    lower-case \\u00xx. Everything else, including all non-ASCII, is emitted as
 *    raw UTF-8.
 *
 * That is exactly Android org.json's JSONObject.toString(2) followed by one
 * newline — NOT JavaScript's JSON.stringify, which differs precisely on the
 * forward slash. The registry's CI serializer (.github/scripts/canonical.mjs)
 * reproduces the same org.json rule, so the two sides agree byte for byte; the
 * escaped `/` is what made a plugin whose script contains a slash — nearly all
 * of them — verify. This matters only for PUBLISH, where the registry
 * re-serializes the parsed plugin and must produce the identical bytes or the
 * signature will not verify; INSTALL hashes the exact downloaded bytes and never
 * re-serializes, so it is unaffected either way.
 */
object PluginCanonical {
    const val MAX_SCRIPT_BYTES = 64 * 1024
    const val MAX_FILE_BYTES = 128 * 1024

    /** Lower-case, digits, hyphens; 3 to 40 chars; no leading or trailing hyphen. */
    val ID_REGEX = Regex("^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$")

    /** MAJOR.MINOR or MAJOR.MINOR.PATCH, digits and dots only. */
    val VERSION_REGEX = Regex("^[0-9]+\\.[0-9]+(?:\\.[0-9]+)?$")

    private val ORDER = listOf("id", "name", "version", "author", "description", "script")

    fun canonicalString(p: PluginDef): String {
        val values = mapOf(
            "id" to p.id,
            "name" to p.name,
            "version" to p.version,
            "author" to p.author,
            "description" to p.description,
            "script" to p.script
        )
        val sb = StringBuilder()
        sb.append("{\n")
        for ((i, k) in ORDER.withIndex()) {
            sb.append("  ")
            appendJsonString(sb, k)
            sb.append(": ")
            appendJsonString(sb, values.getValue(k))
            if (i != ORDER.lastIndex) sb.append(",")
            sb.append("\n")
        }
        sb.append("}\n")
        return sb.toString()
    }

    fun canonicalBytes(p: PluginDef): ByteArray = canonicalString(p).toByteArray(Charsets.UTF_8)

    /** SHA-256 over [bytes] as a lower-case hex string. */
    fun sha256Hex(bytes: ByteArray): String {
        val h = MessageDigest.getInstance("SHA-256").digest(bytes)
        val sb = StringBuilder(h.size * 2)
        for (b in h) sb.append("%02x".format(b.toInt() and 0xFF))
        return sb.toString()
    }

    /** One JSON string literal, quoted and escaped per the rules above. */
    fun jsonString(s: String): String {
        val sb = StringBuilder(s.length + 2)
        appendJsonString(sb, s)
        return sb.toString()
    }

    /**
     * A candidate id derived from a display name, shaped toward the id grammar:
     * lower-cased, runs of non-alphanumerics collapsed to single hyphens, no
     * leading or trailing hyphen, clamped to 40 chars. It may still be too short
     * or otherwise invalid — [ID_REGEX] is the authority and the editor checks it.
     */
    fun slugify(name: String): String {
        val s = StringBuilder()
        var pendingHyphen = false
        for (c in name.lowercase()) {
            if (c in 'a'..'z' || c in '0'..'9') {
                if (pendingHyphen && s.isNotEmpty()) s.append('-')
                pendingHyphen = false
                s.append(c)
            } else {
                pendingHyphen = true
            }
        }
        var out = s.toString()
        if (out.length > 40) out = out.substring(0, 40)
        return out.trim('-')
    }

    private fun appendJsonString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")
                '\\' -> sb.append("\\\\")
                '/' -> sb.append("\\/")
                '\b' -> sb.append("\\b")
                '' -> sb.append("\\f")
                '\n' -> sb.append("\\n")
                '\r' -> sb.append("\\r")
                '\t' -> sb.append("\\t")
                else ->
                    if (c < ' ') sb.append("\\u%04x".format(c.code))
                    else sb.append(c)
            }
        }
        sb.append('"')
    }
}

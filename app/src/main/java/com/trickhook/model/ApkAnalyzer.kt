package com.trickhook.model

/**
 * Binary AXML (AndroidManifest.xml) parser + APK zip helpers.
 * Pure Kotlin — no external dependencies.
 */

/**
 * One deep-link data spec off an intent-filter: the external entry points a
 * scheme://host:port/path URL reaches. Any field may be blank — a filter that
 * only declares android:scheme matches every host under it — and [path] carries
 * the kind of match (path / prefix / pattern) it came from so an analyst is not
 * misled into reading a prefix as an exact path.
 */
data class DeepLink(
    val scheme: String,
    val host: String,
    val port: String,
    val path: String,
    val pathKind: String,   // path | prefix | pattern | ""
    val mimeType: String
) {
    /** A compact scheme://host[:port]/path rendering for the row, honest about blanks. */
    fun display(): String {
        val sb = StringBuilder()
        if (scheme.isNotEmpty()) sb.append(scheme).append("://") else sb.append("*://")
        sb.append(if (host.isNotEmpty()) host else "*")
        if (port.isNotEmpty()) sb.append(':').append(port)
        if (path.isNotEmpty()) {
            if (!path.startsWith("/")) sb.append('/')
            sb.append(path)
        }
        return sb.toString()
    }
}

/** An app-declared (custom) permission — a `<permission>` the manifest defines. */
data class CustomPermission(
    val name: String,
    val protectionLevel: String
)

data class ApkComponent(
    val type: String,          // activity | service | receiver | provider
    val name: String,
    val exported: Boolean?,
    val actions: List<String>,
    val categories: List<String>,
    val authorities: String? = null,
    val permission: String? = null,        // android:permission guarding it, if any
    val deepLinks: List<DeepLink> = emptyList()
)

data class ManifestInfo(
    val ok: Boolean,
    val packageName: String,
    val versionName: String,
    val versionCode: String,
    val minSdk: String,
    val targetSdk: String,
    val appLabel: String,
    val appIcon: String,
    val debuggable: Boolean?,
    val permissions: List<String>,
    val activities: List<ApkComponent>,
    val services: List<ApkComponent>,
    val receivers: List<ApkComponent>,
    val providers: List<ApkComponent>,
    val usesLibraries: List<String>,
    val rawXml: String,
    val allowBackup: Boolean? = null,
    val customPermissions: List<CustomPermission> = emptyList()
)

data class ApkResourceEntry(val path: String, val size: Long, val isImage: Boolean, val isXml: Boolean)

object ApkAnalyzer {

    // ---- common android: attr resource IDs (from frameworks/base) ----
    private val ATTR_NAMES = mapOf(
        0x01010000L to "theme",
        0x01010001L to "label",
        0x01010002L to "icon",
        0x01010003L to "name",
        0x01010006L to "permission",
        0x01010007L to "author",
        0x01010009L to "protectionLevel",
        0x0101000eL to "enabled",
        0x0101000fL to "debuggable",
        0x01010010L to "exported",
        0x01010011L to "process",
        0x01010017L to "description",
        0x01010018L to "authorities",
        0x0101001bL to "grantUriPermissions",
        0x0101001dL to "launchMode",
        0x0101001eL to "screenOrientation",
        0x0101001fL to "configChanges",
        // intent-filter <data> — the deep-link URL pieces. These resource ids
        // are the stable public android.R.attr values; a modern AAPT2 manifest
        // also carries the names in its string pool, and the reader below falls
        // back to whichever of the two is present.
        0x01010026L to "mimeType",
        0x01010027L to "scheme",
        0x01010028L to "host",
        0x01010029L to "port",
        0x0101002aL to "path",
        0x0101002bL to "pathPrefix",
        0x0101002cL to "pathPattern",
        0x0101020cL to "minSdkVersion",
        0x0101021bL to "versionCode",
        0x0101021cL to "versionName",
        0x01010270L to "targetSdkVersion",
        0x01010280L to "allowBackup",
        0x0101031cL to "extractNativeLibs",
        0x01010477L to "requestLegacyExternalStorage"
    )

    fun attrName(resId: Long, stringPool: List<String>): String {
        ATTR_NAMES[resId]?.let { return "android:$it" }
        // resource map order: attr index maps into string pool via resource-map chunk
        return "0x${String.format("%08X", resId)}"
    }

    // ======================================================= AXML parse ==
    fun parseManifest(axml: ByteArray): ManifestInfo {
        var packageName = ""
        var versionName = ""
        var versionCode = ""
        var minSdk = ""
        var targetSdk = ""
        var appLabel = ""
        var appIcon = ""
        var debuggable: Boolean? = null
        var allowBackup: Boolean? = null
        val permissions = mutableListOf<String>()
        val customPermissions = mutableListOf<CustomPermission>()
        val activities = mutableListOf<ApkComponent>()
        val services = mutableListOf<ApkComponent>()
        val receivers = mutableListOf<ApkComponent>()
        val providers = mutableListOf<ApkComponent>()
        val usesLibraries = mutableListOf<String>()

        var pool: List<String> = emptyList()
        var resMap: List<Long> = emptyList()
        val xml = StringBuilder()
        val stack = ArrayDeque<Pair<String, MutableMap<String, String>>>()   // element name -> attrs
        val openTags = ArrayDeque<String>()

        fun attrKey(name: String, nsIdx: Int, resIdSuffix: Long): String {
            // android ns attrs resolved via resource map; others raw
            return if (name.isNotEmpty()) name else "attr_$resIdSuffix"
        }

        try {
            var off = 0
            // top-level: find string pool + resource map + walk XML chunks
            while (off + 8 <= axml.size) {
                val type = u16(axml, off)
                val headerSize = u16(axml, off + 2)
                val size = i32(axml, off + 4).toLong() and 0xFFFFFFFFL
                if (size <= 0 || off + size > axml.size) break
                // RES_XML_TYPE (0x0003) is a WRAPPER chunk: its size covers the whole
                // document — descend into children by header size, do not skip whole file
                if (type == 0x0003) { off += headerSize; continue }

                when (type) {
                    0x0001 -> pool = parseStringPool(axml, off, size.toInt())
                    0x0180 -> {
                        // resource map: after header, attr resource ids
                        val n = ((size - headerSize) / 4).toInt()
                        resMap = List(n) { k ->
                            i32(axml, off + headerSize + k * 4).toLong() and 0xFFFFFFFFL
                        }
                    }
                    0x0102 -> {
                        // start element
                        val body = off + 8
                        // line(4) comment(4) ns(4) name(4) attrStart(2) attrSize(2)
                        // attrCount(2) idIdx(2) classIdx(2) styleIdx(2)
                        val nameIdx = i32(axml, body + 12)
                        val attrStart = u16(axml, body + 16)
                        val attrSize = u16(axml, body + 18)
                        val attrCount = u16(axml, body + 20)
                        val name = pool.getOrNull(nameIdx) ?: "?"
                        val attrs = linkedMapOf<String, String>()

                        for (k in 0 until attrCount) {
                            // The attribute array begins at the end of the 20-byte
                            // attrExt, which itself starts at body+8 (off+16): the
                            // node header is 8, then line(4) and comment(4). So the
                            // base is body + 8 + attributeStart, NOT body +
                            // attributeStart — the latter lands 8 bytes early, in
                            // the middle of attrExt, and reads the namespace string
                            // for every value.
                            val aOff = body + 8 + attrStart + k * attrSize
                            if (aOff + 20 > axml.size) break
                            val aNs = i32(axml, aOff)
                            val aNameIdx = i32(axml, aOff + 4)
                            val aRaw = i32(axml, aOff + 8)
                            val dataType = axml[aOff + 15].toInt() and 0xFF
                            val data = i32(axml, aOff + 16)
                            val key = pool.getOrNull(aNameIdx) ?: "?$aNameIdx"
                            val value = when {
                                aRaw >= 0 -> pool.getOrNull(aRaw) ?: ""
                                dataType == 0x03 -> pool.getOrNull(data) ?: ""  // STRING via typed value (rawValue stripped)
                                dataType == 0x12 -> (data != 0).toString()      // BOOLEAN
                                dataType == 0x10 -> data.toString()             // INT_DEC
                                dataType == 0x11 -> "0x${String.format("%08X", data)}" // INT_HEX
                                else -> "@${String.format("%08X", data)}"       // REFERENCE
                            }
                            // resolve android: attr full names via resource map
                            val isAndroid = aNs != -1
                            val resolved = if (isAndroid && aNameIdx in resMap.indices) {
                                val resId = resMap[aNameIdx]
                                val known = ATTR_NAMES[resId]
                                if (known != null) "android:$known"
                                else "android:$key(0x${String.format("%08X", resId)})"
                            } else key
                            attrs[resolved] = value
                        }

                        // pretty XML
                        val indent = "    ".repeat(minOf(stack.size, 8))
                        xml.append(indent).append("<").append(name)
                        attrs.forEach { (k, v) -> xml.append("\n${indent}    ${esc(k)}=\"${esc(v)}\"") }
                        xml.append("/>\n")

                        stack.addLast(name to attrs)
                        openTags.addLast(name)

                        // structured extraction
                        val a = attrs
                        fun attr(sub: String): String? =
                            a["android:$sub"] ?: a[sub]
                        when (name) {
                            "manifest" -> {
                                packageName = a["package"] ?: ""
                                versionName = attr("versionName") ?: ""
                                versionCode = attr("versionCode") ?: ""
                            }
                            "uses-sdk" -> {
                                minSdk = attr("minSdkVersion") ?: ""
                                targetSdk = attr("targetSdkVersion") ?: ""
                            }
                            "uses-permission", "uses-permission-sdk-23" ->
                                attr("name")?.let { permissions.add(it) }
                            "permission" -> attr("name")?.let {
                                customPermissions.add(
                                    CustomPermission(it, attr("protectionLevel") ?: "normal")
                                )
                            }
                            "uses-library" -> attr("name")?.let { usesLibraries.add(it) }
                            "application" -> {
                                appLabel = attr("label") ?: ""
                                appIcon = attr("icon") ?: ""
                                debuggable = attr("debuggable")?.toBooleanStrictOrNull()
                                allowBackup = attr("allowBackup")?.toBooleanStrictOrNull()
                            }
                            "activity", "activity-alias" -> activities.add(
                                ApkComponent("activity", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList(), permission = attr("permission")))
                            "service" -> services.add(
                                ApkComponent("service", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList(), permission = attr("permission")))
                            "receiver" -> receivers.add(
                                ApkComponent("receiver", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList(), permission = attr("permission")))
                            "provider" -> providers.add(
                                ApkComponent("provider", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList(), attr("authorities"),
                                    permission = attr("permission")))
                        }
                    }
                    0x0103 -> {
                        // end element
                        if (openTags.isNotEmpty()) openTags.removeLast()
                        if (stack.isNotEmpty()) stack.removeLast()
                    }
                    0x0104 -> {
                        // text node: body line(4) comment(4) data(4)
                        val dataIdx = i32(axml, off + 16)
                        val text = pool.getOrNull(dataIdx) ?: ""
                        if (text.isNotBlank()) {
                            val indent = "    ".repeat(minOf(stack.size, 8))
                            xml.append(indent).append(esc(text.trim())).append("\n")
                        }
                    }
                }
                off += size.toInt()
            }

            // second pass: fill intent-filters into the last component
            // (handled below via parseIntentFilters on raw walking — simplified:
            // we re-walk here because filters follow component declarations)
        } catch (e: Exception) {
            return ManifestInfo(false, "", "", "", "", "", "", "", null,
                emptyList(), emptyList(), emptyList(), emptyList(), emptyList(),
                emptyList(), "AXML parse error: ${e.message}")
        }

        // Second pass: actions, categories and <data> deep links belong to
        // intent-filters that FOLLOW their component's declaration, so they are
        // collected once the whole tree is known and merged back by name.
        val filters = collectIntentFilters(axml, pool, resMap)
        fun enrich(list: List<ApkComponent>): List<ApkComponent> = list.map { c ->
            c.copy(
                actions = filters.actions[c.name]?.distinct() ?: emptyList(),
                categories = filters.categories[c.name]?.distinct() ?: emptyList(),
                deepLinks = filters.deepLinks[c.name]?.distinct() ?: emptyList()
            )
        }
        return ManifestInfo(
            ok = packageName.isNotEmpty() || pool.isNotEmpty(),
            packageName = packageName,
            versionName = versionName, versionCode = versionCode,
            minSdk = minSdk, targetSdk = targetSdk,
            appLabel = appLabel, appIcon = appIcon, debuggable = debuggable,
            permissions = permissions,
            activities = enrich(activities), services = enrich(services),
            receivers = enrich(receivers), providers = enrich(providers),
            usesLibraries = usesLibraries,
            rawXml = xml.toString(),
            allowBackup = allowBackup,
            customPermissions = customPermissions
        )
    }

    /** What one walk of the intent-filters found, keyed by the owning component's android:name. */
    private class FilterData(
        val actions: Map<String, List<String>>,
        val categories: Map<String, List<String>>,
        val deepLinks: Map<String, List<DeepLink>>
    )

    private val COMPONENT_TAGS =
        setOf("activity", "activity-alias", "service", "receiver", "provider")

    /** How many scheme x host x path combinations one filter may expand to. */
    private const val MAX_LINKS_PER_FILTER = 32

    /**
     * Walk the XML a second time and gather, per component (keyed by its
     * android:name), the actions and categories of its intent-filters and the
     * <data> deep links they carry.
     *
     * action, category and data are START elements (chunk type 0x0102) that come
     * AFTER their component's own start tag — an earlier version read them as
     * CDATA (0x0104) and so never saw one — so this is a stateful walk that
     * tracks the component and the intent-filter it is currently inside. Android
     * merges every <data> in one filter for matching, so the scheme/host/path
     * pieces are accumulated across the filter and expanded into concrete
     * scheme://host/path links (bounded) when the filter closes.
     */
    private fun collectIntentFilters(
        axml: ByteArray, pool: List<String>, resMap: List<Long>
    ): FilterData {
        val actionsBy = mutableMapOf<String, MutableList<String>>()
        val catsBy = mutableMapOf<String, MutableList<String>>()
        val linksBy = mutableMapOf<String, MutableList<DeepLink>>()

        var component: String? = null
        var inFilter = false
        val curActions = mutableListOf<String>()
        val curCats = mutableListOf<String>()
        val curSchemes = LinkedHashSet<String>()
        val curHosts = LinkedHashSet<String>()
        val curPorts = LinkedHashSet<String>()
        val curPaths = ArrayList<Pair<String, String>>()   // value, kind
        val curMimes = LinkedHashSet<String>()

        fun resetFilter() {
            curActions.clear(); curCats.clear()
            curSchemes.clear(); curHosts.clear(); curPorts.clear()
            curPaths.clear(); curMimes.clear()
        }

        // One element's attributes as bare android names -> string value. Prefer
        // the pool name (AAPT2 keeps them), else resolve the resource-id map.
        fun attrsOf(body: Int): Map<String, String> {
            val out = HashMap<String, String>()
            if (body + 22 > axml.size) return out
            val attrStart = u16(axml, body + 16)
            val attrSize = u16(axml, body + 18)
            val attrCount = u16(axml, body + 20)
            for (k in 0 until attrCount) {
                // body + 8 + attributeStart: the attribute array follows the
                // 20-byte attrExt that starts at body+8. See the main pass.
                val aOff = body + 8 + attrStart + k * attrSize
                if (aOff + 20 > axml.size) break
                val aNameIdx = i32(axml, aOff + 4)
                val aRaw = i32(axml, aOff + 8)
                val dataType = axml[aOff + 15].toInt() and 0xFF
                val data = i32(axml, aOff + 16)
                val name = pool.getOrNull(aNameIdx)?.takeIf { it.isNotEmpty() }
                    ?: resMap.getOrNull(aNameIdx)?.let { ATTR_NAMES[it] }
                    ?: continue
                val value = when {
                    aRaw >= 0 -> pool.getOrNull(aRaw) ?: ""
                    dataType == 0x03 -> pool.getOrNull(data) ?: ""   // STRING via typed value
                    else -> data.toString()
                }
                out[name] = value
            }
            return out
        }

        fun flushFilter() {
            val c = component ?: return
            if (curActions.isNotEmpty())
                actionsBy.getOrPut(c) { mutableListOf() }.addAll(curActions)
            if (curCats.isNotEmpty())
                catsBy.getOrPut(c) { mutableListOf() }.addAll(curCats)
            val hasData = curSchemes.isNotEmpty() || curHosts.isNotEmpty() ||
                curPaths.isNotEmpty() || curMimes.isNotEmpty()
            if (!hasData) return
            val schemes = if (curSchemes.isEmpty()) listOf("") else curSchemes.toList()
            val hosts = if (curHosts.isEmpty()) listOf("") else curHosts.toList()
            val paths = if (curPaths.isEmpty()) listOf("" to "") else curPaths.toList()
            val port = curPorts.firstOrNull() ?: ""
            val mime = curMimes.firstOrNull() ?: ""
            val links = linksBy.getOrPut(c) { mutableListOf() }
            var made = 0
            build@ for (s in schemes) for (h in hosts) for ((pv, pk) in paths) {
                links.add(DeepLink(s, h, port, pv, pk, mime))
                if (++made >= MAX_LINKS_PER_FILTER) break@build
            }
        }

        try {
            var off = 0
            while (off + 8 <= axml.size) {
                val type = u16(axml, off)
                val headerSize = u16(axml, off + 2)
                val size = i32(axml, off + 4).toLong() and 0xFFFFFFFFL
                if (size <= 0 || off + size > axml.size) break
                if (type == 0x0003) { off += headerSize; continue }
                when (type) {
                    0x0102 -> {
                        val body = off + 8
                        val name = pool.getOrNull(i32(axml, body + 12)) ?: ""
                        when {
                            name in COMPONENT_TAGS -> component = attrsOf(body)["name"]
                            name == "intent-filter" -> { inFilter = true; resetFilter() }
                            inFilter && name == "action" ->
                                attrsOf(body)["name"]?.takeIf { it.isNotEmpty() }?.let { curActions.add(it) }
                            inFilter && name == "category" ->
                                attrsOf(body)["name"]?.takeIf { it.isNotEmpty() }?.let { curCats.add(it) }
                            inFilter && name == "data" -> {
                                val a = attrsOf(body)
                                a["scheme"]?.takeIf { it.isNotEmpty() }?.let { curSchemes.add(it) }
                                a["host"]?.takeIf { it.isNotEmpty() }?.let { curHosts.add(it) }
                                a["port"]?.takeIf { it.isNotEmpty() }?.let { curPorts.add(it) }
                                a["mimeType"]?.takeIf { it.isNotEmpty() }?.let { curMimes.add(it) }
                                val p = a["path"]; val pp = a["pathPrefix"]; val pr = a["pathPattern"]
                                when {
                                    !p.isNullOrEmpty() -> curPaths.add(p to "path")
                                    !pp.isNullOrEmpty() -> curPaths.add(pp to "prefix")
                                    !pr.isNullOrEmpty() -> curPaths.add(pr to "pattern")
                                }
                            }
                        }
                    }
                    0x0103 -> {
                        val name = pool.getOrNull(i32(axml, off + 8 + 12)) ?: ""
                        when {
                            name == "intent-filter" -> { flushFilter(); inFilter = false; resetFilter() }
                            name in COMPONENT_TAGS -> component = null
                        }
                    }
                }
                off += size.toInt()
            }
        } catch (_: Exception) { }

        return FilterData(actionsBy, catsBy, linksBy)
    }

    // ------------------------------------------------------- string pool --
    private fun parseStringPool(data: ByteArray, off: Int, size: Int): List<String> {
        val stringCount = u32(data, off + 8).toInt()
        val flags = u32(data, off + 16)
        val stringsStart = u32(data, off + 20).toInt()
        val utf8 = (flags and 0x100L) != 0L
        val out = mutableListOf<String>()
        var p = off + 28
        for (i in 0 until stringCount) {
            val strOff = off + stringsStart + u32(data, p + i * 4).toInt()
            if (strOff >= data.size) { out.add(""); continue }
            out.add(if (utf8) readUtf8(data, strOff) else readUtf16(data, strOff))
        }
        return out
    }

    private fun readUtf16(d: ByteArray, off: Int): String {
        var p = off
        var len = u16(d, p).toInt()
        if (len and 0x8000 != 0) {          // high bit: extended length
            len = ((len and 0x7FFF) shl 16) or u16(d, p + 2).toInt()
            p += 2
        }
        p += 2
        val sb = StringBuilder(len)
        for (i in 0 until len) {
            val idx = p + i * 2
            if (idx + 1 >= d.size) break
            // append(Char), never append(Int): a UTF-16 code unit is a Char, and
            // append(Int) would write the code point's DECIMAL DIGITS instead —
            // turning "com" into "99111109". Each unit stands for itself, so a
            // surrogate pair lands as its two units, which is a valid String.
            sb.append(u16(d, idx).toChar())
        }
        return sb.toString()
    }

    private fun readUtf8(d: ByteArray, off: Int): String {
        var p = off
        var charLen = d[p].toInt() and 0xFF
        p += 1
        if (charLen and 0x80 != 0) {
            charLen = ((charLen and 0x7F) shl 8) or (d[p].toInt() and 0xFF)
            p += 1
        }
        var byteLen = d[p].toInt() and 0xFF
        p += 1
        if (byteLen and 0x80 != 0) {
            byteLen = ((byteLen and 0x7F) shl 8) or (d[p].toInt() and 0xFF)
            p += 1
        }
        if (p + byteLen > d.size) byteLen = d.size - p
        return String(d, p, maxOf(byteLen, 0), Charsets.UTF_8)
    }

    private fun u16(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)) and 0xFFFF
    private fun u32(b: ByteArray, o: Int): Long =
        (b[o].toLong() and 0xFF) or ((b[o + 1].toLong() and 0xFF) shl 8) or
        ((b[o + 2].toLong() and 0xFF) shl 16) or ((b[o + 3].toLong() and 0xFF) shl 24)
    private fun i32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8) or
        ((b[o + 2].toInt() and 0xFF) shl 16) or ((b[o + 3].toInt() and 0xFF) shl 24)

    private fun esc(s: String) = s
        .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace("\"", "&quot;")
}

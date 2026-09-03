package com.sakore.studio.model

/**
 * Binary AXML (AndroidManifest.xml) parser + APK zip helpers.
 * Pure Kotlin — no external dependencies.
 */

data class ApkComponent(
    val type: String,          // activity | service | receiver | provider
    val name: String,
    val exported: Boolean?,
    val actions: List<String>,
    val categories: List<String>,
    val authorities: String? = null
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
    val rawXml: String
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
        0x0101020cL to "minSdkVersion",
        0x0101021bL to "versionCode",
        0x0101021cL to "versionName",
        0x01010270L to "targetSdkVersion",
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
        val permissions = mutableListOf<String>()
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
                            val aOff = body + attrStart + k * attrSize
                            if (aOff + 20 > axml.size) break
                            val aNs = i32(axml, aOff)
                            val aNameIdx = i32(axml, aOff + 4)
                            val aRaw = i32(axml, aOff + 8)
                            val dataType = axml[aOff + 15].toInt() and 0xFF
                            val data = i32(axml, aOff + 16)
                            val key = pool.getOrNull(aNameIdx) ?: "?$aNameIdx"
                            val value = when {
                                aRaw >= 0 -> pool.getOrNull(aRaw) ?: ""
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
                            "uses-permission" -> attr("name")?.let { permissions.add(it) }
                            "uses-library" -> attr("name")?.let { usesLibraries.add(it) }
                            "application" -> {
                                appLabel = attr("label") ?: ""
                                appIcon = attr("icon") ?: ""
                                val dbg = attr("debuggable")
                                debuggable = dbg?.toBooleanStrictOrNull()
                            }
                            "activity", "activity-alias" -> activities.add(
                                ApkComponent("activity", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList()))
                            "service" -> services.add(
                                ApkComponent("service", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList()))
                            "receiver" -> receivers.add(
                                ApkComponent("receiver", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList()))
                            "provider" -> providers.add(
                                ApkComponent("provider", attr("name") ?: "?",
                                    attr("exported")?.toBooleanStrictOrNull(),
                                    emptyList(), emptyList(), attr("authorities")))
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

        val (acts2, svc2, rcv2) = fillIntentFilters(axml, pool, activities, services, receivers)
        return ManifestInfo(
            ok = packageName.isNotEmpty() || pool.isNotEmpty(),
            packageName = packageName,
            versionName = versionName, versionCode = versionCode,
            minSdk = minSdk, targetSdk = targetSdk,
            appLabel = appLabel, appIcon = appIcon, debuggable = debuggable,
            permissions = permissions,
            activities = acts2, services = svc2, receivers = rcv2,
            providers = providers,
            usesLibraries = usesLibraries,
            rawXml = xml.toString()
        )
    }

    private fun fillIntentFilters(
        axml: ByteArray, pool: List<String>,
        activities: List<ApkComponent>,
        services: List<ApkComponent>,
        receivers: List<ApkComponent>
    ): Triple<List<ApkComponent>, List<ApkComponent>, List<ApkComponent>> {
        val actionsByComponent = mutableMapOf<String, MutableList<String>>()
        val categoriesByComponent = mutableMapOf<String, MutableList<String>>()
        var currentComponent: String? = null
        var inFilter = false
        val curActions = mutableListOf<String>()
        val curCats = mutableListOf<String>()

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
                        val nameIdx = i32(axml, body + 12)
                        val attrCount = u16(axml, body + 20)
                        val name = pool.getOrNull(nameIdx) ?: "?"
                        if (name in setOf("activity", "service", "receiver", "provider")) {
                            // find android:name attr
                            val attrStart = u16(axml, body + 16)
                            val attrSize = u16(axml, body + 18)
                            var compName: String? = null
                            for (k in 0 until attrCount) {
                                val aOff = body + attrStart + k * attrSize
                                val aNameIdx = i32(axml, aOff + 4)
                                val aRaw = i32(axml, aOff + 8)
                                val aData = i32(axml, aOff + 16)
                                val key = pool.getOrNull(aNameIdx) ?: ""
                                if (key == "name") {
                                    compName = if (aRaw >= 0) pool.getOrNull(aRaw)
                                               else pool.getOrNull(aData) ?: "?"
                                }
                            }
                            currentComponent = compName
                        } else if (name == "intent-filter") {
                            inFilter = true; curActions.clear(); curCats.clear()
                        }
                    }
                    0x0103 -> {
                        val body = off + 8
                        val nameIdx = i32(axml, body + 12)
                        val name = pool.getOrNull(nameIdx) ?: "?"
                        when (name) {
                            "intent-filter" -> {
                                inFilter = false
                                val c = currentComponent
                                if (c != null && (curActions.isNotEmpty() || curCats.isNotEmpty())) {
                                    actionsByComponent.getOrPut(c) { mutableListOf() }
                                        .addAll(curActions)
                                    categoriesByComponent.getOrPut(c) { mutableListOf() }
                                        .addAll(curCats)
                                }
                            }
                            "activity", "service", "receiver", "provider" -> currentComponent = null
                        }
                    }
                    0x0104 -> {
                        val body = off + 8
                        val nameIdx = i32(axml, body + 12)
                        val name = pool.getOrNull(nameIdx) ?: "?"
                        if (inFilter && (name == "action" || name == "category")) {
                            val attrStart = u16(axml, body + 16)
                            val attrSize = u16(axml, body + 18)
                            val attrCount = u16(axml, body + 20)
                            for (k in 0 until attrCount) {
                                val aOff = body + attrStart + k * attrSize
                                val aRaw = i32(axml, aOff + 8)
                                val aData = i32(axml, aOff + 16)
                                val v = (if (aRaw >= 0) pool.getOrNull(aRaw)
                                        else pool.getOrNull(aData)) ?: continue
                                if (name == "action") curActions.add(v) else curCats.add(v)
                            }
                        }
                    }
                }
                off += size.toInt()
            }
        } catch (_: Exception) { }

        fun enrich(list: List<ApkComponent>) = list.map { c ->
            c.copy(actions = actionsByComponent[c.name]?.distinct() ?: emptyList(),
                   categories = categoriesByComponent[c.name]?.distinct() ?: emptyList())
        }
        return Triple(enrich(activities), enrich(services), enrich(receivers))
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
            sb.append(((u16(d, idx).toInt())))
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

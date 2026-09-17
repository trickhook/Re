package com.trickhook.model

import org.json.JSONObject

data class ApkEntry(val name: String, val size: Long)
data class ConsoleLine(val ts: Long, val level: String, val msg: String)

data class Section(val name: String, val type: String, val flags: String, val addr: Long, val offset: Long, val size: Long)
data class Segment(val type: String, val flags: String, val vaddr: Long, val offset: Long, val filesz: Long, val memsz: Long)
data class FuncInfo(val addr: Long, val size: Long, val name: String, val from: String,
                    val demangled: String? = null, val nCallees: Int = 0, val nCallers: Int = 0)
data class FoundStr(val addr: Long, val value: String)
data class SymbolInfo(val name: String, val addr: Long)
data class DexClassInfo(val name: String, val superName: String)
data class DexMethodInfo(val clazz: String, val name: String, val proto: String, val codeOff: Long)

data class AnalysisMeta(
    val ok: Boolean,
    val error: String?,
    val format: String,
    val name: String,
    val arch: String,
    val entry: Long,
    val base: Long,
    val sizeBytes: Long,
    val truncated: Boolean,
    val loadMs: Int,
    val backend: String,
    val disassemblable: Boolean,
    val sections: List<Section>,
    val segments: List<Segment>,
    val functions: List<FuncInfo>,
    val strings: List<FoundStr>,
    val imports: List<SymbolInfo>,
    val exports: List<SymbolInfo>,
    val needed: List<String>,
    val soName: String,
    val dexClasses: List<DexClassInfo>,
    val dexMethods: List<DexMethodInfo>,
    val callEdges: List<CallEdge>,
    val notes: List<String>,
    /** Edges the engine FOUND. `callEdges` itself is capped at 12000 by Engine.cpp. */
    val callEdgesTotal: Int = 0,
    /** Raw call sites behind those edges, before the per-pair merge. */
    val callSitesTotal: Int = 0,
    /**
     * Functions the engine DISCOVERED. [functions] holds the first page of
     * them -- 12000 -- and the rest arrive through
     * [com.trickhook.engine.NativeBridge.nativeFunctionPage]. Never assume
     * `functions.size` is the answer to "how many functions".
     */
    val functionsTotal: Int = 0,
    /** Where [functions] starts. Always 0 from `analyze`; a page says its own. */
    val functionsOffset: Int = 0,
    /** How many rows [functions] arrived with. Grows as pages are appended. */
    val functionsCount: Int = 0,
    /** Rows whose name looked mangled and that the demangler could not read. */
    val demangleFailed: Int = 0,
    /** Strings the engine holds; [strings] is the first 3000 of them. */
    val stringsTotal: Int = 0,
    /**
     * References the xref map KEPT, and the number the scan SAW. When these
     * differ -- 200,000 of 1,323,435 on a large library -- every nCallers,
     * every nCallees and every xref count derived from the map is a floor
     * rather than a count. [xrefsAreFloors] is the one place that is decided.
     */
    val xrefsStored: Int = 0,
    val xrefsTotal: Int = 0,
    /** DEX class and method counts out of the header, exact. */
    val dexClassesTotal: Int = 0,
    val dexMethodsTotal: Int = 0
) {
    /** Functions the engine found but this object has not been handed yet. */
    val functionsPending: Int get() = (functionsTotal - functions.size).coerceAtLeast(0)

    /**
     * True when the reference map dropped what it could not hold, which makes
     * every count taken from it a floor. Read it before printing a bare
     * nCallers/nCallees anywhere.
     */
    val xrefsAreFloors: Boolean get() = xrefsStored in 1 until xrefsTotal
}

/**
 * One caller-callee pair.
 *
 * [from] is the start address of the CALLING FUNCTION, not the address of the
 * call instruction -- that is [site]. They used to be the same field, which is
 * why `groupBy { it.from }` and `functionAt(e.from)` never matched anything.
 * Anything that wants to show WHERE the call is must read [callSite].
 */
data class CallEdge(
    val from: Long,
    val to: Long,
    val fromName: String,
    val toName: String,
    val kind: String,
    /** Lowest call-site address behind this pair; 0 from an engine without the field. */
    val site: Long = 0L,
    /** How many call instructions this single edge stands for. At least 1. */
    val sites: Int = 1
) {
    /** The call instruction's address, falling back to [from] if the engine sent none. */
    val callSite: Long get() = if (site != 0L) site else from
}

data class AsmLine(val addr: Long, val bytes: String, val mnem: String, val ops: String, val comment: String = "")
data class CfgBlock(val id: Int, val start: Long, val end: Long, val nInstr: Int, val succ: List<Int>)
data class Xref(val from: Long, val to: Long, val type: String)

/**
 * One site that references a DATA address (a string or datum), mapped to the
 * function that contains it. [from] is the referencing instruction; [funcAddr]
 * is its containing function's start, or 0 when the site is outside every known
 * function; [funcName] is that function's raw symbol and [funcDisplay] its
 * demangled form (equal to [funcName] when nothing demangled).
 */
data class XrefSite(
    val from: Long,
    val funcAddr: Long,
    val funcName: String,
    val funcDisplay: String,
    val type: String
)

/**
 * The functions that reference one address — the answer to "who uses this
 * string?". Unlike [FunctionDetail]'s xrefs, which are a function's own, this
 * is keyed on any target address, so a string or datum that belongs to no
 * function still has an answer. [targetKind] is "string", "data" or "code";
 * [value] is the string's text when the target is one. [refs] is capped:
 * [total] is the honest count and [shown] (== refs.size) how many rows came
 * back. Engine side: Engine::xrefsTo, via [com.trickhook.engine.NativeBridge.nativeXrefsTo].
 */
data class AddressXrefs(
    val ok: Boolean,
    val error: String?,
    val target: Long,
    val targetKind: String,
    val value: String?,
    val total: Int,
    val shown: Int,
    val refs: List<XrefSite>
)

/**
 * One detection from the anti-analysis scan. A category-under-a-function
 * finding, or ([funcAddr] == 0) an unattributed hit on a string that nothing
 * references. [confidence] is "high", "medium" or "low"; [evidence] is the
 * representative matched token and [tokens] every distinct token that folded
 * into the row, so nothing is hidden behind it. [source] is "string", "name" or
 * "mixed"; [site] is the instruction to jump to — a referencing site for a
 * string match, the function start for a name match. [stringAddr]/[value]
 * describe the string when one drove the match (0 / null otherwise).
 * [funcDisplay] is the demangled name, equal to [funcName] when nothing
 * demangled. Engine side: Engine::detect, via
 * [com.trickhook.engine.NativeBridge.nativeDetect].
 */
data class Detection(
    val category: String,
    val confidence: String,
    val funcAddr: Long,
    val funcName: String,
    val funcDisplay: String,
    val evidence: String,
    val tokens: List<String>,
    val source: String,
    val site: Long,
    val stringAddr: Long,
    val value: String?,
    val hits: Int
)

/**
 * The whole anti-analysis scan of the open binary — the answer to "what
 * security / anti-analysis routines are in here?". [counts] is the per-category
 * total over the whole result; [detections] is capped, with [total] the honest
 * count and [shown] (== detections.size) how many rows came back.
 * [unattributed] counts the detections with no containing function. Engine
 * side: Engine::detect, via [com.trickhook.engine.NativeBridge.nativeDetect].
 */
data class DetectionResult(
    val ok: Boolean,
    val error: String?,
    val total: Int,
    val shown: Int,
    val unattributed: Int,
    val counts: Map<String, Int>,
    val detections: List<Detection>
)

data class IrStats(val stmts: Int, val whiles: Int, val ifs: Int, val gotos: Int, val calls: Int)

data class FunctionDetail(
    val ok: Boolean,
    val error: String?,
    val addr: Long,
    val name: String,
    val displayName: String,
    val size: Long,
    val from: String,
    val backend: String,
    val arch: String,
    val pseudoMode: String,
    val irStats: IrStats?,
    val asm: List<AsmLine>,
    val pseudo: String,
    val blocks: List<CfgBlock>,
    val xrefsIn: List<Xref>,
    val xrefsOut: List<Xref>,
    /** Call-graph degrees: one per calling/called FUNCTION, not per site. */
    val nCallees: Int = 0,
    val nCallers: Int = 0,
    /**
     * Reference SITES the engine counted. `xrefsIn` / `xrefsOut` are capped at
     * 64 rows for the sheet, so these are the only honest totals -- without
     * them a hot function with 561 callers renders as a flat 64.
     */
    val xrefsInTotal: Int = 0,
    val xrefsOutTotal: Int = 0,
    /** Bytes the engine actually disassembled into [asm]. */
    val asmBytes: Int = 0,
    /**
     * The listing stops before the end of the function -- the engine's asm
     * window filled, or the body runs past the end of the file. What is on
     * screen is not the whole function, and the panel has to say so.
     */
    val asmTruncated: Boolean = false,
    /** Basic blocks the CFG pass found; [blocks] is the first 512 of them. */
    val blocksTotal: Int = 0
)

data class DebugEvent(
    val n: Int,
    val nr: Long,
    val syscall: String,
    val ip: Long,
    val args: List<Long>,
    val ret: Long,
    val regs: Map<String, Long>
)

data class DebugResult(val ok: Boolean, val error: String?, val events: List<DebugEvent>)

private fun hx(s: String?): Long {
    if (s == null) return 0
    return if (s.startsWith("0x")) s.substring(2).toLongOrNull(16) ?: 0L else s.toLongOrNull(16) ?: 0L
}

/**
 * One `functions` element. `analyze`'s first page and `functions(offset,count)`
 * come out of the same emitter in Engine.cpp, so they are read here by the same
 * code -- a paged row cannot drift from a first-page row in either direction.
 */
private fun funcRow(s: JSONObject): FuncInfo = FuncInfo(
    hx(s.optString("addr")), s.optLong("size"), s.optString("name"), s.optString("from"),
    s.optString("demangled").ifEmpty { null },
    s.optInt("nCallees"), s.optInt("nCallers")
)

/** One `callEdges` / `edges` element. Both parsers read the same shape. */
private fun callEdge(e: JSONObject): CallEdge = CallEdge(
    from = hx(e.optString("from")), to = hx(e.optString("to")),
    fromName = e.optString("fromName"), toName = e.optString("toName"),
    kind = e.optString("kind"),
    site = hx(e.optString("site")),
    sites = e.optInt("sites", 1).coerceAtLeast(1)
)

fun parseMeta(json: String): AnalysisMeta {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return AnalysisMeta(
            ok = false, error = o.optString("error", "analysis failed"), format = "", name = "",
            arch = "", entry = 0, base = 0, sizeBytes = 0, truncated = false, loadMs = 0,
            backend = "", disassemblable = false, sections = emptyList(), segments = emptyList(),
            functions = emptyList(), strings = emptyList(), imports = emptyList(), exports = emptyList(),
            needed = emptyList(), soName = "", dexClasses = emptyList(), dexMethods = emptyList(),
            callEdges = emptyList(), notes = emptyList()
        )
    }
    val sections = o.optJSONArray("sections")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            Section(s.optString("name"), s.optString("type"), s.optString("flags"),
                hx(s.optString("addr")), s.optLong("offset"), s.optLong("size"))
        }
    } ?: emptyList()
    val segments = o.optJSONArray("segments")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            Segment(s.optString("type"), s.optString("flags"), hx(s.optString("vaddr")),
                s.optLong("offset"), s.optLong("filesz"), s.optLong("memsz"))
        }
    } ?: emptyList()
    val functions = o.optJSONArray("functions")?.let { arr ->
        (0 until arr.length()).map { i -> funcRow(arr.getJSONObject(i)) }
    } ?: emptyList()
    val strings = o.optJSONArray("strings")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            FoundStr(hx(s.optString("addr")), s.optString("value"))
        }
    } ?: emptyList()
    val imports = o.optJSONArray("imports")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            SymbolInfo(s.optString("name"), hx(s.optString("addr")))
        }
    } ?: emptyList()
    val exports = o.optJSONArray("exports")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            SymbolInfo(s.optString("name"), hx(s.optString("addr")))
        }
    } ?: emptyList()
    val needed = o.optJSONArray("needed")?.let { arr ->
        (0 until arr.length()).map { arr.optString(it) }
    } ?: emptyList()
    val dexClasses = o.optJSONArray("dexClasses")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            DexClassInfo(s.optString("name"), s.optString("super"))
        }
    } ?: emptyList()
    val dexMethods = o.optJSONArray("dexMethods")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            DexMethodInfo(s.optString("clazz"), s.optString("name"), s.optString("proto"), s.optLong("codeOff"))
        }
    } ?: emptyList()
    val notes = o.optJSONArray("notes")?.let { arr ->
        (0 until arr.length()).map { arr.optString(it) }
    } ?: emptyList()

    return AnalysisMeta(
        ok = true, error = null,
        format = o.optString("format"), name = o.optString("name"), arch = o.optString("arch"),
        entry = hx(o.optString("entry")), base = hx(o.optString("base")),
        sizeBytes = o.optLong("sizeBytes"), truncated = o.optBoolean("truncated"),
        loadMs = o.optInt("loadMs"), backend = o.optString("backend"),
        disassemblable = o.optBoolean("disassemblable"),
        sections = sections, segments = segments, functions = functions, strings = strings,
        imports = imports, exports = exports, needed = needed, soName = o.optString("soName"),
        dexClasses = dexClasses, dexMethods = dexMethods,
        callEdges = o.optJSONArray("callEdges")?.let { arr ->
            (0 until arr.length()).map { i -> callEdge(arr.getJSONObject(i)) }
        } ?: emptyList(),
        notes = notes,
        callEdgesTotal = o.optInt("callEdgesTotal"),
        callSitesTotal = o.optInt("callSitesTotal"),
        // maxOf against the array length throughout: an engine built before
        // these fields sends none of them, and a zero total beside a non-empty
        // list would read as "nothing found" for every one of these panels.
        functionsTotal = maxOf(o.optInt("functionsTotal"), functions.size),
        functionsOffset = o.optInt("functionsOffset"),
        functionsCount = maxOf(o.optInt("functionsCount"), functions.size),
        demangleFailed = o.optInt("demangleFailed"),
        stringsTotal = maxOf(o.optInt("stringsTotal"), strings.size),
        xrefsStored = o.optInt("xrefsStored"),
        xrefsTotal = o.optInt("xrefsTotal"),
        dexClassesTotal = maxOf(o.optInt("dexClassesTotal"), dexClasses.size),
        dexMethodsTotal = maxOf(o.optInt("dexMethodsTotal"), dexMethods.size)
    )
}

/**
 * One page of the function list, from
 * [com.trickhook.engine.NativeBridge.nativeFunctionPage].
 *
 * [count] is what the engine really sent after its own clamp, NOT what was
 * asked for: a walk advances by this, or it skips rows. [count] of 0 with
 * [ok] true is the end of the walk and not a failure.
 */
data class FunctionPage(
    val ok: Boolean,
    val error: String?,
    val functionsTotal: Int,
    val offset: Int,
    val count: Int,
    val functions: List<FuncInfo>,
    val demangleFailed: Int
)

/**
 * Rows here are emitted by the engine's one function-row emitter, the same one
 * `analyze` uses, so a paged row cannot drift from a first-page row -- and
 * this reads them with the same code for the same reason.
 */
fun parseFunctionPage(json: String): FunctionPage {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return FunctionPage(false, o.optString("error", "function page failed"), 0, 0, 0, emptyList(), 0)
    }
    val functions = o.optJSONArray("functions")?.let { arr ->
        (0 until arr.length()).map { i -> funcRow(arr.getJSONObject(i)) }
    } ?: emptyList()
    return FunctionPage(
        ok = true, error = null,
        functionsTotal = maxOf(o.optInt("functionsTotal"), functions.size),
        offset = o.optInt("offset"),
        // The array is the ground truth for what arrived; `count` is the
        // engine saying the same thing. Trusting a count larger than the array
        // would walk a loop straight past rows it never received.
        count = minOf(o.optInt("count"), functions.size),
        functions = functions,
        demangleFailed = o.optInt("demangleFailed")
    )
}

fun parseDetail(json: String): FunctionDetail {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return FunctionDetail(false, o.optString("error", "detail failed"), 0, "", "",
            0, "", "", "", "", null, emptyList(), "", emptyList(), emptyList(), emptyList())
    }
    val asm = o.optJSONArray("asm")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            AsmLine(hx(s.optString("a")), s.optString("b"), s.optString("m"), s.optString("o"),
                s.optString("c"))
        }
    } ?: emptyList()
    val blocks = o.optJSONArray("blocks")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            CfgBlock(s.optInt("id"), hx(s.optString("start")), hx(s.optString("end")),
                s.optInt("nInstr"),
                s.optJSONArray("succ")?.let { sa -> (0 until sa.length()).map { sa.optInt(it) } } ?: emptyList())
        }
    } ?: emptyList()
    val xin = o.optJSONArray("xrefsIn")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i); Xref(hx(s.optString("from")), hx(s.optString("to")), s.optString("type"))
        }
    } ?: emptyList()
    val xout = o.optJSONArray("xrefsOut")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i); Xref(hx(s.optString("from")), hx(s.optString("to")), s.optString("type"))
        }
    } ?: emptyList()
    val irStats = o.optJSONObject("irStats")?.let {
        IrStats(it.optInt("stmts"), it.optInt("whiles"), it.optInt("ifs"),
            it.optInt("gotocs"), it.optInt("calls"))
    }
    return FunctionDetail(
        ok = true, error = null, addr = hx(o.optString("addr")), name = o.optString("name"),
        displayName = o.optString("displayName").ifEmpty { o.optString("name") },
        size = o.optLong("size"), from = o.optString("from"), backend = o.optString("backend"),
        arch = o.optString("arch"), pseudoMode = o.optString("pseudoMode"),
        irStats = irStats, asm = asm, pseudo = o.optString("pseudo"),
        blocks = blocks, xrefsIn = xin, xrefsOut = xout,
        nCallees = o.optInt("nCallees"), nCallers = o.optInt("nCallers"),
        xrefsInTotal = o.optInt("xrefsInTotal"), xrefsOutTotal = o.optInt("xrefsOutTotal"),
        asmBytes = o.optInt("asmBytes"),
        asmTruncated = o.optBoolean("asmTruncated"),
        blocksTotal = maxOf(o.optInt("blocksTotal"), blocks.size)
    )
}

/**
 * Read the engine's `xrefsTo` answer. `refs` is the ground truth for what
 * arrived; `total` is the engine's honest count (>= refs.size when the 500-row
 * cap dropped some), and `shown` is trusted only as far as the array actually
 * carries, so a walk never steps past rows it never received -- the same rule
 * [parseFunctionPage] applies to `count`.
 */
fun parseAddressXrefs(json: String): AddressXrefs {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return AddressXrefs(false, o.optString("error", "xrefs failed"), 0, "", null, 0, 0, emptyList())
    }
    val refs = o.optJSONArray("refs")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            XrefSite(
                from = hx(s.optString("from")),
                funcAddr = hx(s.optString("funcAddr")),
                funcName = s.optString("funcName"),
                funcDisplay = s.optString("funcDisplay").ifEmpty { s.optString("funcName") },
                type = s.optString("type")
            )
        }
    } ?: emptyList()
    return AddressXrefs(
        ok = true, error = null,
        target = hx(o.optString("target")),
        targetKind = o.optString("targetKind"),
        value = if (o.has("value")) o.optString("value") else null,
        total = maxOf(o.optInt("total"), refs.size),
        shown = minOf(o.optInt("shown"), refs.size),
        refs = refs
    )
}

/**
 * Read the engine's `detect` answer, the same way [parseAddressXrefs] reads
 * `xrefsTo`: `detections` is the ground truth for what arrived, `total` the
 * engine's honest count (>= detections.size when the row cap dropped some), and
 * `shown` trusted only as far as the array actually carries.
 */
fun parseDetections(json: String): DetectionResult {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return DetectionResult(
            false, o.optString("error", "detect failed"), 0, 0, 0, emptyMap(), emptyList()
        )
    }
    val dets = o.optJSONArray("detections")?.let { arr ->
        (0 until arr.length()).map { i ->
            val d = arr.getJSONObject(i)
            val toks = d.optJSONArray("tokens")?.let { ta ->
                (0 until ta.length()).map { ta.optString(it) }
            } ?: emptyList()
            Detection(
                category = d.optString("category"),
                confidence = d.optString("confidence"),
                funcAddr = hx(d.optString("funcAddr")),
                funcName = d.optString("funcName"),
                funcDisplay = d.optString("funcDisplay").ifEmpty { d.optString("funcName") },
                evidence = d.optString("evidence"),
                tokens = toks,
                source = d.optString("source"),
                site = hx(d.optString("site")),
                stringAddr = hx(d.optString("stringAddr")),
                value = if (d.has("value")) d.optString("value") else null,
                hits = d.optInt("hits")
            )
        }
    } ?: emptyList()
    val counts = LinkedHashMap<String, Int>()
    o.optJSONObject("counts")?.let { co ->
        val keys = co.keys()
        while (keys.hasNext()) {
            val k = keys.next()
            counts[k] = co.optInt(k)
        }
    }
    return DetectionResult(
        ok = true, error = null,
        total = maxOf(o.optInt("total"), dets.size),
        shown = minOf(o.optInt("shown"), dets.size),
        unattributed = o.optInt("unattributed"),
        counts = counts,
        detections = dets
    )
}

// ---------------- DEX / smali ----------------

/**
 * One decoded Dalvik instruction, from Engine::dexSmali. [off] is the dex byte
 * offset of the instruction, [unit] its code-unit index within the method,
 * [bytes] its code units in hex, [mnem] + [ops] the smali (with index operands
 * resolved to names), and [comment] the raw pool tag or the absolute branch
 * target.
 */
data class SmaliLine(
    val off: Long,
    val unit: Int,
    val bytes: String,
    val mnem: String,
    val ops: String,
    val comment: String
)

/**
 * One DEX method decoded to smali, from
 * [com.trickhook.engine.NativeBridge.nativeDexSmali]. [addr] is the method's
 * codeOff. [truncated] means the decode stopped at the line cap or the code item
 * ran short, so [lines] is not the whole method. [nCallers] / [nCallees] are the
 * call-graph degrees, the same numbers the function list shows for this method.
 */
data class SmaliMethod(
    val ok: Boolean,
    val error: String?,
    val addr: Long,
    val clazz: String,
    val classShort: String,
    val method: String,
    val proto: String,
    val name: String,
    val registers: Int,
    val ins: Int,
    val outs: Int,
    val tries: Int,
    val insnsUnits: Int,
    val insnBytes: Int,
    val nCallers: Int,
    val nCallees: Int,
    val total: Int,
    val shown: Int,
    val truncated: Boolean,
    val lines: List<SmaliLine>
)

fun parseSmali(json: String): SmaliMethod {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return SmaliMethod(
            false, o.optString("error", "smali failed"), 0, "", "", "", "", "",
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, false, emptyList()
        )
    }
    val lines = o.optJSONArray("smali")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            SmaliLine(
                hx(s.optString("off")), s.optInt("unit"), s.optString("bytes"),
                s.optString("mnem"), s.optString("ops"), s.optString("comment")
            )
        }
    } ?: emptyList()
    return SmaliMethod(
        ok = true, error = null, addr = hx(o.optString("addr")),
        clazz = o.optString("class"), classShort = o.optString("classShort"),
        method = o.optString("method"), proto = o.optString("proto"), name = o.optString("name"),
        registers = o.optInt("registers"), ins = o.optInt("ins"), outs = o.optInt("outs"),
        tries = o.optInt("tries"), insnsUnits = o.optInt("insnsUnits"),
        insnBytes = o.optInt("insnBytes"),
        nCallers = o.optInt("nCallers"), nCallees = o.optInt("nCallees"),
        total = maxOf(o.optInt("total"), lines.size),
        shown = minOf(o.optInt("shown"), lines.size),
        truncated = o.optBoolean("truncated"), lines = lines
    )
}

/**
 * One page of a DEX string-pool search, from
 * [com.trickhook.engine.NativeBridge.nativeDexStrings]. [rows] carry each
 * matched string with its pool index as the address. [total] is matches over the
 * whole pool the loader read; [poolRead] < [poolTotal] means the loader capped
 * the pool, so a search reaches [poolRead] of [poolTotal] string_ids.
 */
data class DexStringsPage(
    val ok: Boolean,
    val error: String?,
    val query: String,
    val total: Int,
    val offset: Int,
    val shown: Int,
    val poolRead: Int,
    val poolTotal: Int,
    val rows: List<FoundStr>
)

fun parseDexStrings(json: String): DexStringsPage {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return DexStringsPage(
            false, o.optString("error", "dex strings failed"), "", 0, 0, 0, 0, 0, emptyList()
        )
    }
    val rows = o.optJSONArray("strings")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            FoundStr(hx(s.optString("addr")), s.optString("value"))
        }
    } ?: emptyList()
    return DexStringsPage(
        ok = true, error = null, query = o.optString("query"),
        total = maxOf(o.optInt("total"), rows.size),
        offset = o.optInt("offset"),
        shown = minOf(o.optInt("shown"), rows.size),
        poolRead = o.optInt("poolRead"), poolTotal = o.optInt("poolTotal"),
        rows = rows
    )
}

/** One end of a DEX method-xref edge: the other method, and the invoke site. */
data class DexXrefEdge(val addr: Long, val name: String, val site: Long, val sites: Int)

/**
 * DEX method xrefs from
 * [com.trickhook.engine.NativeBridge.nativeDexMethodXrefs] — who invokes a
 * method ([callers]) and what it invokes ([callees]), surfaced from the call
 * graph the engine already built at analysis time rather than a fresh scan.
 * [callersTotal] / [calleesTotal] are the honest counts; the lists are capped.
 */
data class DexMethodXrefs(
    val ok: Boolean,
    val error: String?,
    val addr: Long,
    val name: String,
    val callersTotal: Int,
    val callers: List<DexXrefEdge>,
    val calleesTotal: Int,
    val callees: List<DexXrefEdge>
)

fun parseDexMethodXrefs(json: String): DexMethodXrefs {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return DexMethodXrefs(
            false, o.optString("error", "dex xrefs failed"), 0, "", 0, emptyList(), 0, emptyList()
        )
    }
    fun edges(key: String): List<DexXrefEdge> = o.optJSONArray(key)?.let { arr ->
        (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i)
            DexXrefEdge(
                hx(e.optString("addr")), e.optString("name"),
                hx(e.optString("site")), e.optInt("sites", 1)
            )
        }
    } ?: emptyList()
    val callers = edges("callers")
    val callees = edges("callees")
    return DexMethodXrefs(
        ok = true, error = null, addr = hx(o.optString("addr")), name = o.optString("name"),
        callersTotal = maxOf(o.optInt("callersTotal"), callers.size), callers = callers,
        calleesTotal = maxOf(o.optInt("calleesTotal"), callees.size), callees = callees
    )
}

fun parseDebug(json: String): DebugResult {
    val o = JSONObject(json)
    val ok = o.optBoolean("ok", false)
    val events = o.optJSONArray("events")?.let { arr ->
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            DebugEvent(
                n = s.optInt("n"), nr = s.optLong("nr"), syscall = s.optString("syscall"),
                ip = hx(s.optString("ip")),
                args = s.optJSONArray("args")?.let { aa -> (0 until aa.length()).map { hx(aa.optString(it)) } } ?: emptyList(),
                ret = hx(s.optString("ret")),
                regs = s.keys().asSequence().filter { it != "n" && it != "nr" && it != "syscall" && it != "ip" && it != "args" && it != "ret" }
                    .associateWith { hx(s.optString(it)) }
            )
        }
    } ?: emptyList()
    return DebugResult(ok, o.optString("error", "").ifEmpty { null }, events)
}

// ---------------- v2 parsers ----------------

data class CallGraphNode(val addr: Long, val name: String)
data class CallGraphData(
    val ok: Boolean,
    val error: String?,
    val edges: List<CallEdge>,
    val funcs: List<CallGraphNode>,
    /**
     * The address this graph was BUILT for; 0 means the whole binary. Engine.cpp
     * now really filters on it, so a focused answer holds only the edges that
     * touch that one function and can stand in for no other view.
     */
    val focus: Long = 0L,
    /** Edges that passed the focus filter. `edges` is capped at 4000 for the canvas. */
    val edgesTotal: Int = 0,
    /**
     * Functions the engine DISCOVERED in the binary, which is no longer the
     * length of a capped list: it used to be both, so a 12,631-function
     * library printed "4000 of 4000". `funcs` is the first 4000 of them.
     */
    val funcsTotal: Int = 0
)

fun parseCallGraph(json: String): CallGraphData {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return CallGraphData(false, o.optString("error", "no call graph"), emptyList(), emptyList())
    }
    val edges = o.optJSONArray("edges")?.let { arr ->
        (0 until arr.length()).map { i -> callEdge(arr.getJSONObject(i)) }
    } ?: emptyList()
    val funcs = o.optJSONArray("funcs")?.let { arr ->
        (0 until arr.length()).map { i ->
            val f = arr.getJSONObject(i)
            CallGraphNode(hx(f.optString("addr")), f.optString("name"))
        }
    } ?: emptyList()
    return CallGraphData(
        true, null, edges, funcs,
        focus = hx(o.optString("focus")),
        edgesTotal = o.optInt("edgesTotal"), funcsTotal = o.optInt("funcsTotal")
    )
}

data class DbgBp(val addr: Long, val hits: Int, val enabled: Boolean)
data class DbgEvent(val type: String, val addr: Long, val pc: Long, val sig: Int, val code: Int)
data class DbgThread(val tid: Long, val name: String)

/**
 * One row of the attach picker: a running process of an installed app. [pid],
 * [uid] and [name] (the process name from /proc) come from the engine's `ps`
 * op; [label] is the human app name the app side resolves from [uid] with
 * PackageManager, falling back to [name] when the package cannot be resolved.
 */
data class DbgProc(val pid: Long, val uid: Int, val name: String, val label: String)

data class DbgState(
    val ok: Boolean,
    val error: String?,
    val state: String,
    val pid: Long,
    val arch: String,
    val regs: Map<String, Long>,
    val bps: List<DbgBp>,
    val threads: List<DbgThread>,
    val memData: String,       // hex string
    val memAddr: Long,
    val memLen: Long,
    val events: List<DbgEvent>,
    /**
     * The answer carried a `bps` array at all. `bp_list` is the one op that
     * reports the breakpoint set, and it legitimately reports an empty one
     * after the last breakpoint is deleted -- so an empty list is not the same
     * answer as no answer, and the merge needs to tell them apart.
     */
    val hasBps: Boolean = false,
    /**
     * Events the session's ring buffer threw away since the last poll. It
     * drops 500 at a time at 2000 and used to say nothing, so a session that
     * ate 500 stops showed one that never happened beside one it ate.
     */
    val eventsDropped: Int = 0
)

fun parseDbg(json: String): DbgState {
    val o = JSONObject(json)
    val ok = o.optBoolean("ok", false)
    val regs = mutableMapOf<String, Long>()
    for (k in o.keys()) {
        val v = o.optString(k)
        if (v.startsWith("0x") && k != "ok") {
            val lv = v.removePrefix("0x").toLongOrNull(16)
            if (lv != null && k != "arch" && k != "state" && k != "error" && k != "type" &&
                k != "data" && k != "name") regs[k] = lv
        }
    }
    val bps = o.optJSONArray("bps")?.let { arr ->
        (0 until arr.length()).map { i ->
            val b = arr.getJSONObject(i)
            DbgBp(hx(b.optString("addr")), b.optInt("hits"), b.optBoolean("enabled"))
        }
    } ?: emptyList()
    val threads = o.optJSONArray("threads")?.let { arr ->
        (0 until arr.length()).map { i ->
            val t = arr.getJSONObject(i)
            DbgThread(t.optLong("tid"), t.optString("name"))
        }
    } ?: emptyList()
    val events = o.optJSONArray("events")?.let { arr ->
        (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i)
            DbgEvent(e.optString("type"), hx(e.optString("addr")), hx(e.optString("pc")),
                e.optInt("sig"), e.optInt("code"))
        }
    } ?: emptyList()
    return DbgState(
        ok = ok,
        hasBps = o.optJSONArray("bps") != null,
        error = o.optString("error", "").ifEmpty { null },
        state = o.optString("state", "none"),
        pid = o.optLong("pid"),
        arch = o.optString("arch"),
        regs = regs,
        bps = bps,
        threads = threads,
        memData = o.optString("data", ""),
        memAddr = hx(o.optString("addr", "0x0")),
        memLen = o.optLong("len"),
        events = events,
        eventsDropped = o.optInt("eventsDropped")
    )
}

// ------------------------------------------------------ produce-file export --

/**
 * How far the running export has got, from `nativeExportProgress`. Lock-free
 * on the engine side, so it answers WHILE `nativeExportSource` holds the
 * engine mutex -- which is the only time it means anything.
 *
 * After a run ends the numbers stay at their final values with [running]
 * false, so one last poll sees the result rather than zeroes.
 */
data class ExportProgress(
    val running: Boolean,
    val done: Int,
    val total: Int,
    val failed: Int,
    val cancelling: Boolean
)

fun parseExportProgress(json: String): ExportProgress {
    val o = JSONObject(json)
    return ExportProgress(
        running = o.optBoolean("running"),
        done = o.optInt("done"),
        total = o.optInt("total"),
        failed = o.optInt("failed"),
        cancelling = o.optBoolean("cancelling")
    )
}

/**
 * What one `nativeExportSource` run produced.
 *
 * [failed] is not an error state. A function the decompiler refuses gets its
 * banner and a marker in the file where a reader will see it and the run
 * carries on, so 64 failures out of 5,363 is a run that SUCCEEDED -- before
 * this, one refusal ended the export.
 *
 * [cancelled] means the user stopped it. The file on disk is valid and says
 * in its own trailer where it stops.
 */
data class ExportResult(
    val ok: Boolean,
    val error: String?,
    val functions: Int,
    val failed: Int,
    val total: Int,
    val cancelled: Boolean,
    val bytes: Long
)

fun parseExportResult(json: String): ExportResult {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return ExportResult(false, o.optString("error", "export failed"), 0, 0, 0, false, 0L)
    }
    return ExportResult(
        ok = true, error = null,
        functions = o.optInt("functions"),
        failed = o.optInt("failed"),
        total = o.optInt("total"),
        cancelled = o.optBoolean("cancelled"),
        bytes = o.optLong("bytes")
    )
}

data class PluginEffect(val op: String, val addr: Long, val value: String)
data class ScriptResult(
    val ok: Boolean,
    val error: String?,
    val line: Int,
    val log: String,
    val effects: List<PluginEffect>
)

fun parseScriptResult(json: String): ScriptResult {
    val o = JSONObject(json)
    val effects = o.optJSONArray("effects")?.let { arr ->
        (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i)
            PluginEffect(e.optString("op"), hx(e.optString("addr")),
                e.optString("name").ifEmpty { e.optString("text").ifEmpty { e.optString("label") } })
        }
    } ?: emptyList()
    return ScriptResult(
        ok = o.optBoolean("ok", false),
        error = o.optString("error", "").ifEmpty { null },
        line = o.optInt("line"),
        log = o.optString("log", ""),
        effects = effects
    )
}

data class PluginDef(
    val id: String,
    val name: String,
    val version: String,
    val author: String,
    val description: String,
    val script: String
)

// ---------------- binary diff ----------------

/**
 * One CHANGED function: a pair matched across the two binaries whose normalized
 * instruction streams differ. [similarity] is the fraction of normalized
 * instructions the two bodies share (0..1); lower means more changed.
 */
data class DiffChangedPair(
    val nameA: String, val addrA: Long,
    val nameB: String, val addrB: Long,
    val similarity: Double
)

/** One added / removed function: a name and an address in its own binary. */
data class DiffEntry(val name: String, val addr: Long)

/**
 * Honest totals beside the capped lists. [changed]/[added]/[removed] are the
 * true counts; the arrays in [DiffResult] carry the first [DiffResult].counts
 * `*Shown` of them. [identicalExact] are byte-identical bodies; [identicalFingerprint]
 * are functions whose bytes differ but whose normalized instruction stream is
 * unchanged — a relocated-but-unchanged function, NOT a change.
 */
data class DiffCounts(
    val aFuncs: Int, val bFuncs: Int,
    val identical: Int, val identicalExact: Int, val identicalFingerprint: Int,
    val changed: Int, val changedShown: Int,
    val added: Int, val addedShown: Int,
    val removed: Int, val removedShown: Int,
    val nameMatched: Int, val fingerprintMatched: Int, val structuralMatched: Int,
    val listCap: Int
)

/**
 * A whole-binary diff, from [com.trickhook.engine.NativeBridge.nativeDiff]. A is
 * the binary that was open; B the one it was compared against. Every function is
 * identical, changed, added (B only) or removed (A only).
 */
data class DiffResult(
    val ok: Boolean,
    val error: String?,
    val aName: String,
    val bName: String,
    val aArch: String,
    val bArch: String,
    val identical: Int,
    val changed: List<DiffChangedPair>,
    val added: List<DiffEntry>,
    val removed: List<DiffEntry>,
    val counts: DiffCounts,
    val notes: List<String>
)

fun parseDiff(json: String): DiffResult {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return DiffResult(
            false, o.optString("error", "diff failed"), "", "", "", "",
            0, emptyList(), emptyList(), emptyList(),
            DiffCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0), emptyList()
        )
    }
    val changed = o.optJSONArray("changed")?.let { arr ->
        (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i)
            DiffChangedPair(
                e.optString("nameA"), hx(e.optString("addrA")),
                e.optString("nameB"), hx(e.optString("addrB")),
                e.optDouble("similarity", 0.0)
            )
        }
    } ?: emptyList()
    val added = o.optJSONArray("added")?.let { arr ->
        (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i); DiffEntry(e.optString("name"), hx(e.optString("addr")))
        }
    } ?: emptyList()
    val removed = o.optJSONArray("removed")?.let { arr ->
        (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i); DiffEntry(e.optString("name"), hx(e.optString("addr")))
        }
    } ?: emptyList()
    val c = o.optJSONObject("counts")
    val counts = DiffCounts(
        aFuncs = c?.optInt("aFuncs") ?: 0,
        bFuncs = c?.optInt("bFuncs") ?: 0,
        identical = c?.optInt("identical") ?: o.optInt("identical"),
        identicalExact = c?.optInt("identicalExact") ?: 0,
        identicalFingerprint = c?.optInt("identicalFingerprint") ?: 0,
        changed = maxOf(c?.optInt("changed") ?: 0, changed.size),
        changedShown = c?.optInt("changedShown") ?: changed.size,
        added = maxOf(c?.optInt("added") ?: 0, added.size),
        addedShown = c?.optInt("addedShown") ?: added.size,
        removed = maxOf(c?.optInt("removed") ?: 0, removed.size),
        removedShown = c?.optInt("removedShown") ?: removed.size,
        nameMatched = c?.optInt("nameMatched") ?: 0,
        fingerprintMatched = c?.optInt("fingerprintMatched") ?: 0,
        structuralMatched = c?.optInt("structuralMatched") ?: 0,
        listCap = c?.optInt("listCap") ?: 0
    )
    val notes = o.optJSONArray("notes")?.let { arr ->
        (0 until arr.length()).map { arr.optString(it) }
    } ?: emptyList()
    return DiffResult(
        ok = true, error = null,
        aName = o.optString("aName"), bName = o.optString("bName"),
        aArch = o.optString("aArch"), bArch = o.optString("bArch"),
        identical = o.optInt("identical"),
        changed = changed, added = added, removed = removed,
        counts = counts, notes = notes
    )
}

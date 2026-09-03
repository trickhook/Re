package com.sakore.studio.model

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
    val notes: List<String>
)

data class CallEdge(val from: Long, val to: Long, val fromName: String, val toName: String, val kind: String)

data class AsmLine(val addr: Long, val bytes: String, val mnem: String, val ops: String, val comment: String = "")
data class CfgBlock(val id: Int, val start: Long, val end: Long, val nInstr: Int, val succ: List<Int>)
data class Xref(val from: Long, val to: Long, val type: String)

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
    val xrefsOut: List<Xref>
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
        (0 until arr.length()).map { i ->
            val s = arr.getJSONObject(i)
            FuncInfo(
                hx(s.optString("addr")), s.optLong("size"), s.optString("name"), s.optString("from"),
                s.optString("demangled").ifEmpty { null },
                s.optInt("nCallees"), s.optInt("nCallers")
            )
        }
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
            (0 until arr.length()).map { i ->
                val e = arr.getJSONObject(i)
                CallEdge(hx(e.optString("from")), hx(e.optString("to")),
                    e.optString("fromName"), e.optString("toName"), e.optString("kind"))
            }
        } ?: emptyList(),
        notes = notes
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
        blocks = blocks, xrefsIn = xin, xrefsOut = xout
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
    val funcs: List<CallGraphNode>
)

fun parseCallGraph(json: String): CallGraphData {
    val o = JSONObject(json)
    if (!o.optBoolean("ok", false)) {
        return CallGraphData(false, o.optString("error", "no call graph"), emptyList(), emptyList())
    }
    val edges = o.optJSONArray("edges")?.let { arr ->
        (0 until arr.length()).map { i ->
            val e = arr.getJSONObject(i)
            CallEdge(hx(e.optString("from")), hx(e.optString("to")),
                e.optString("fromName"), e.optString("toName"), e.optString("kind"))
        }
    } ?: emptyList()
    val funcs = o.optJSONArray("funcs")?.let { arr ->
        (0 until arr.length()).map { i ->
            val f = arr.getJSONObject(i)
            CallGraphNode(hx(f.optString("addr")), f.optString("name"))
        }
    } ?: emptyList()
    return CallGraphData(true, null, edges, funcs)
}

data class DbgBp(val addr: Long, val hits: Int, val enabled: Boolean)
data class DbgEvent(val type: String, val addr: Long, val pc: Long, val sig: Int, val code: Int)
data class DbgThread(val tid: Long, val name: String)
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
    val events: List<DbgEvent>
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
        events = events
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

package com.trickhook.mcp

import com.trickhook.engine.NativeBridge
import com.trickhook.model.AnalysisMeta
import com.trickhook.model.CallEdge
import com.trickhook.model.FuncInfo
import com.trickhook.model.FunctionDetail
import com.trickhook.model.parseDetail
import com.trickhook.ui.parseAddr
import com.trickhook.ui.xrefRows
import com.trickhook.vm.StudioViewModel
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.locks.ReentrantLock

/**
 * The tool surface an MCP client sees, and the only way into this app from the
 * outside.
 *
 * Two rules shape every tool in here.
 *
 * ONE: nothing takes a filesystem path. Every tool works on the binary the user
 * has already opened in the app, through the ViewModel and the JNI bridge. A
 * client cannot name a file, cannot open one, and cannot reach anything the
 * person holding the phone has not already chosen to look at. There is
 * deliberately no `open_file` tool — opening goes through the app's SAF picker,
 * where a human is the one choosing.
 *
 * TWO: every list is bounded. A binary here routinely carries 1,300+ functions
 * and 12,000+ call edges; a tool that answers with all of them has spent a
 * client's whole context on data nobody read. Each list tool takes `offset` and
 * `limit`, and every list answer carries `total`, `count` and `nextOffset` so
 * the model can page deliberately instead of guessing.
 *
 * The three tools that write — [RENAME], [COMMENT], [BOOKMARK] — are separated
 * from the rest by [Tool.write] and are neither advertised nor callable unless
 * the user cleared read-only mode before starting the server. They write to
 * Nocturne's project database only; the binary on disk is never modified by
 * anything in this file.
 */
class McpTools(allowWrites: Boolean) {

    class Failure(message: String) : Exception(message)

    /** What one tool call produced: the JSON body, and a line for the sheet's log. */
    class Outcome(val body: JSONObject, val summary: String)

    private class Tool(
        val name: String,
        val title: String,
        val description: String,
        val schema: JSONObject,
        val write: Boolean,
        val handler: (JSONObject) -> Outcome
    )

    companion object {
        const val RENAME = "rename_function"
        const val COMMENT = "set_comment"
        const val BOOKMARK = "add_bookmark"

        /** Pseudo-C for one function, in characters. Well above any real function. */
        private const val PSEUDO_CAP = 60000

        /** Bytes one read_memory call may return. */
        private const val HEX_CAP = 4096

        /** Instructions one disassemble_function call may return. */
        private const val ASM_CAP = 400

        /**
         * One engine call at a time.
         *
         * The decompiler backend is a single global inside the engine — the
         * `backend` argument flips it and puts it back — and the native
         * analysis is shared mutable state. Serialising the MCP side means two
         * concurrent clients cannot interleave a flip with a decompile. The
         * app's own UI can still issue a call of its own; that is pre-existing
         * behaviour and not something this file can fix from here.
         */
        private val engineLock = ReentrantLock()

        private fun hx(v: Long): String = "0x" + java.lang.Long.toHexString(v)

        /** The key format ProjectDb and StudioViewModel use for annotations. */
        private fun annotationKey(addr: Long): String = "0x%08X".format(addr)
    }

    // ------------------------------------------------------------ schemas --

    private fun strProp(desc: String): JSONObject =
        JSONObject().put("type", "string").put("description", desc)

    private fun enumProp(desc: String, values: List<String>, def: String): JSONObject =
        JSONObject().put("type", "string").put("description", desc)
            .put("enum", JSONArray(values)).put("default", def)

    private fun intProp(desc: String, min: Int, max: Int, def: Int): JSONObject =
        JSONObject().put("type", "integer").put("description", desc)
            .put("minimum", min).put("maximum", max).put("default", def)

    private fun boolProp(desc: String, def: Boolean): JSONObject =
        JSONObject().put("type", "boolean").put("description", desc).put("default", def)

    private fun strListProp(desc: String): JSONObject =
        JSONObject().put("type", "array").put("description", desc)
            .put("items", JSONObject().put("type", "string"))

    private fun offsetProp(): JSONObject =
        JSONObject().put("type", "integer")
            .put("description", "Rows to skip. Pass the previous answer's nextOffset to continue.")
            .put("minimum", 0).put("default", 0)

    private fun limitProp(def: Int, max: Int): JSONObject =
        intProp("Rows to return. The answer carries total, count and nextOffset.", 1, max, def)

    private fun schema(required: List<String>, props: List<Pair<String, JSONObject>>): JSONObject {
        val p = JSONObject()
        for ((k, v) in props) p.put(k, v)
        val s = JSONObject().put("type", "object").put("properties", p)
        if (required.isNotEmpty()) s.put("required", JSONArray(required))
        s.put("additionalProperties", false)
        return s
    }

    private val addressProp = strProp(
        "Address in hex, with or without a 0x prefix (\"0x2a10\", \"2a10\"). " +
            "Take it from list_functions. An address inside a function body resolves " +
            "to the function that contains it, and the answer says so."
    )

    // ------------------------------------------------------------ session --

    private fun session(): StudioViewModel = McpRuntime.session
        ?: throw Failure(
            "Nocturne's analysis session is not open — its main screen has been closed on " +
                "the device. Reopen the app and the server picks the session back up."
        )

    private fun openMeta(): AnalysisMeta {
        val m = session().meta
            ?: throw Failure(
                "No binary is open in Nocturne. Open one on the device (overflow menu, " +
                    "\"Open binary…\"). For safety no tool here can open a file itself — " +
                    "the person holding the phone chooses what is exposed."
            )
        if (!m.ok) throw Failure(m.error ?: "the open file did not analyse")
        return m
    }

    private fun openPath(): String = session().currentPath
        ?: throw Failure("No binary is open in Nocturne.")

    // --------------------------------------------------------- arguments --

    private fun addressArg(args: JSONObject, name: String): Long {
        if (!args.has(name) || args.isNull(name)) throw Failure("`$name` is required.")
        val raw = args.get(name)
        if (raw is Number) return raw.toLong()
        val text = raw.toString()
        return parseAddr(text)
            ?: throw Failure("`$name` is not an address: \"$text\". Use hex, for example 0x2a10.")
    }

    private fun optionalAddress(args: JSONObject, name: String): Long? {
        if (!args.has(name) || args.isNull(name)) return null
        val text = args.get(name).toString()
        if (text.isBlank()) return null
        return addressArg(args, name)
    }

    private fun textArg(args: JSONObject, name: String, required: Boolean): String {
        if (!args.has(name) || args.isNull(name)) {
            if (required) throw Failure("`$name` is required.")
            return ""
        }
        return args.get(name).toString()
    }

    private fun intArg(args: JSONObject, name: String, def: Int, min: Int, max: Int): Int {
        if (!args.has(name) || args.isNull(name)) return def
        val v = args.optInt(name, def)
        return v.coerceIn(min, max)
    }

    private fun boolArg(args: JSONObject, name: String, def: Boolean): Boolean =
        if (!args.has(name) || args.isNull(name)) def else args.optBoolean(name, def)

    private fun enumArg(args: JSONObject, name: String, allowed: List<String>, def: String): String {
        val v = textArg(args, name, false).ifBlank { def }.lowercase()
        if (v !in allowed) {
            throw Failure("`$name` must be one of ${allowed.joinToString(", ")} — got \"$v\".")
        }
        return v
    }

    private class Window(val offset: Int, val limit: Int)

    private fun window(args: JSONObject, def: Int, max: Int) = Window(
        intArg(args, "offset", 0, 0, Int.MAX_VALUE),
        intArg(args, "limit", def, 1, max)
    )

    private fun <T> slice(all: List<T>, w: Window): List<T> {
        if (w.offset >= all.size) return emptyList()
        return all.subList(w.offset, minOf(all.size, w.offset + w.limit))
    }

    /** The same four fields on every list answer, so the model learns them once. */
    private fun paginate(out: JSONObject, total: Int, w: Window, count: Int) {
        out.put("total", total)
        out.put("offset", w.offset)
        out.put("count", count)
        val next = w.offset + count
        if (next < total) out.put("nextOffset", next) else out.put("nextOffset", JSONObject.NULL)
    }

    // ------------------------------------------------------------ engine --

    // One-entry memo of the last per-function analysis. A client normally asks
    // for the disassembly, the pseudo-C and the xrefs of the same address in a
    // row, and each of those is the same `nativeFunction` pass — several
    // seconds of Ghidra for the third time in a row otherwise. Keyed on path,
    // address and backend, so it can never answer for the wrong one.
    private var memoKey = ""
    private var memoValue: FunctionDetail? = null

    /**
     * Analyse one function. Must be called with [engineLock] held.
     *
     * A non-current backend is selected for the duration and put back in a
     * `finally`, which is the same dance StudioViewModel.loadAlternatePseudo
     * does for its comparison column: the engine keeps exactly one backend
     * selection for the whole process.
     */
    private fun functionDetail(addr: Long, backend: String): FunctionDetail {
        val vm = session()
        val path = openPath()
        val wanted = when (backend) {
            "ghidra" -> "ghidra"
            "ir" -> "ir"
            else -> vm.decompiler
        }
        if (wanted == "ghidra" && !vm.sleighReady) {
            throw Failure(
                "The Ghidra backend is not available on this device — the SLEIGH " +
                    "specifications are not installed" +
                    (if (vm.decompilerNote.isNotBlank()) " (${vm.decompilerNote})" else "") +
                    ". Pass backend=\"ir\" to use the built-in lifter."
            )
        }
        val key = "$path|$addr|$wanted"
        val hit = memoValue
        if (key == memoKey && hit != null) return hit
        val current = vm.decompiler
        val d = if (wanted == current) {
            parseDetail(NativeBridge.nativeFunction(path, addr))
        } else {
            NativeBridge.nativeSetDecompiler(wanted)
            try {
                parseDetail(NativeBridge.nativeFunction(path, addr))
            } finally {
                NativeBridge.nativeSetDecompiler(current)
            }
        }
        if (!d.ok) throw Failure(d.error ?: "the engine could not analyse ${hx(addr)}")
        memoKey = key
        memoValue = d
        return d
    }

    /** A function start for [addr], following containment, or a clear failure. */
    private fun resolveFunction(addr: Long): FuncInfo {
        val vm = session()
        openMeta()
        vm.functionAt(addr)?.let { return it }
        vm.functionContaining(addr)?.let { return it }
        throw Failure(
            "No function at or containing ${hx(addr)}. list_functions gives the addresses " +
                "the engine actually found."
        )
    }

    private fun effectiveName(addr: Long): String = session().effectiveFuncName(addr)

    // ------------------------------------------------------------- tools --

    private val tools: List<Tool> = buildList {
        add(Tool(
            "analysis_overview", "Analysis overview",
            "What Nocturne knows about the binary that is open in the app right now: " +
                "format, architecture, entry point, load base, size, the decompiler backend " +
                "in use, its sections and segments, and the totals for functions, strings, " +
                "imports, exports and call edges. Call this first — every other tool works on " +
                "this same open binary, and nothing here can open a file. Takes no arguments.",
            schema(emptyList(), emptyList()), false
        ) { overview() })

        add(Tool(
            "list_functions", "List functions",
            "List or search the functions the engine found. `query` is a case-insensitive " +
                "substring matched against the symbol name, the demangled name and any name " +
                "recorded in this project. Paginated: this binary can hold well over a " +
                "thousand functions, so read `total` and page with `offset` rather than " +
                "raising `limit`. Each row's `address` is what disassemble_function, " +
                "decompile_function, xrefs, call_graph and emulate_function take.",
            schema(
                emptyList(),
                listOf(
                    "query" to strProp("Case-insensitive substring of the function name. Omit for all."),
                    "sort" to enumProp(
                        "Row order. `callers` and `callees` sort by call-graph degree, " +
                            "descending — the quickest way to the functions that matter.",
                        listOf("address", "name", "size", "callers", "callees"), "address"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { listFunctions(it) })

        add(Tool(
            "list_strings", "List strings",
            "Strings the engine recovered, with the address each was found at. `query` is a " +
                "case-insensitive substring of the string itself. Paginated. Values longer " +
                "than 240 characters are cut and the row says so.",
            schema(
                emptyList(),
                listOf(
                    "query" to strProp("Case-insensitive substring to match. Omit for all."),
                    "minLength" to intProp("Drop strings shorter than this.", 1, 4096, 1),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { listStrings(it) })

        add(Tool(
            "list_symbols", "List imports and exports",
            "The binary's imports (what it calls out to — libc, JNI, syscall wrappers) or its " +
                "exports (what it offers callers). `kind` picks which. Paginated.",
            schema(
                listOf("kind"),
                listOf(
                    "kind" to enumProp("Which table to read.", listOf("imports", "exports"), "imports"),
                    "query" to strProp("Case-insensitive substring of the symbol name."),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { listSymbols(it) })

        add(Tool(
            "disassemble_function", "Disassemble a function",
            "Disassemble one function: address, raw bytes, mnemonic, operands and the engine's " +
                "auto-comment per instruction, plus any comment recorded in this project at " +
                "that address. Long functions are paginated by instruction — at most " +
                "$ASM_CAP per call.",
            schema(
                listOf("address"),
                listOf(
                    "address" to addressProp,
                    "offset" to offsetProp(),
                    "limit" to limitProp(200, ASM_CAP)
                )
            ), false
        ) { disassemble(it) })

        add(Tool(
            "decompile_function", "Decompile a function",
            "Decompile one function to pseudo-C. `backend`: `current` uses whatever the user " +
                "has selected in the app; `ghidra` is the p-code decompiler — slower, with " +
                "types and structure; `ir` is the built-in lifter — faster, rougher, gotos " +
                "and raw registers. A backend other than `current` is selected for this one " +
                "call and put back afterwards. Ghidra can take several seconds on a large " +
                "function. Output is capped at $PSEUDO_CAP characters.",
            schema(
                listOf("address"),
                listOf(
                    "address" to addressProp,
                    "backend" to enumProp(
                        "Which decompiler to run for this call.",
                        listOf("current", "ghidra", "ir"), "current"
                    )
                )
            ), false
        ) { decompile(it) })

        add(Tool(
            "xrefs", "Cross-references",
            "Who references a function (`in`), and what it references (`out`). Each row gives " +
                "the referencing address, the function that address belongs to, the reference " +
                "type, and the address to follow next. Answers come from the engine's " +
                "per-function analysis where it has one and from the whole-binary call graph " +
                "otherwise — the same rule the app's own xref sheet follows, so the two can " +
                "never disagree. Note this runs the same engine pass as decompile_function; " +
                "call_graph is the cheaper tool for walking many functions. Paginated.",
            schema(
                listOf("address"),
                listOf(
                    "address" to addressProp,
                    "direction" to enumProp(
                        "`in` is callers, `out` is callees.",
                        listOf("in", "out", "both"), "both"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(50, 200)
                )
            ), false
        ) { xrefs(it) })

        add(Tool(
            "call_graph", "Walk the call graph",
            "Walk the call graph around one function, or — with no `address` — report the " +
                "busiest functions in the binary. The whole graph runs to twelve thousand " +
                "edges here, which is useless in a transcript, so this answers with a bounded " +
                "neighbourhood: `depth` hops out from `address`, stopping at `limit` " +
                "functions. Each edge carries `sites`, how many distinct call instructions it " +
                "stands for. Reads the call-graph index built at analysis time, so it is " +
                "cheap and can be called repeatedly.",
            schema(
                emptyList(),
                listOf(
                    "address" to strProp(
                        "Function to walk out from, in hex. Omit for a whole-binary summary " +
                            "of the most-connected functions."
                    ),
                    "direction" to enumProp(
                        "Which way to walk from `address`.",
                        listOf("callers", "callees", "both"), "both"
                    ),
                    "depth" to intProp("Hops out from `address`.", 1, 4, 2),
                    "limit" to intProp("Maximum functions to return.", 1, 200, 60)
                )
            ), false
        ) { callGraph(it) })

        add(Tool(
            "read_memory", "Read bytes",
            "Read raw bytes of the open file as hex and as printable ASCII. Give either " +
                "`address` — a virtual address, translated through the section table for ELF " +
                "and PE — or `offset`, a byte offset into the file. Nocturne holds the first " +
                "8 MiB of the open file in memory and this reads only from that: it takes no " +
                "path and opens nothing. At most $HEX_CAP bytes per call.",
            schema(
                emptyList(),
                listOf(
                    "address" to strProp("Virtual address in hex. Use this or `offset`, not both."),
                    "offset" to intProp("Byte offset into the file.", 0, Int.MAX_VALUE, 0),
                    "length" to intProp("Bytes to read.", 1, HEX_CAP, 256)
                )
            ), false
        ) { readMemory(it) })

        add(Tool(
            "emulate_function", "Emulate a function",
            "Run one function under the engine's p-code emulator and report what it wrote to " +
                "memory. This is the tool for a decode or decrypt routine: pass an output " +
                "buffer as `buf:64`, run, and read the bytes back out of the `memory` array. " +
                "Arguments are positional and land in the target's argument registers — " +
                "`0x1` a plain scalar or an address inside the binary, `buf:N` N zeroed bytes " +
                "whose address is passed, `hex:aabbcc` a block holding those bytes, " +
                "`str:hello` the same but NUL-terminated. Every run is bounded by an " +
                "instruction budget, a wall clock, a page cap and a cap on stubbed imports, " +
                "and `stop` says which bound ended it. `approximate: true` means something " +
                "was modelled as zero that might not be, so treat the memory as plausible " +
                "rather than certain. This is the only tool that executes the analysed " +
                "binary's own instructions, and it does so inside the emulator — nothing is " +
                "run on the device's CPU.",
            schema(
                listOf("entry"),
                listOf(
                    "entry" to strProp("Function to run, in hex."),
                    "args" to strListProp(
                        "Positional arguments: \"0x1\", \"buf:64\", \"hex:aabbcc\", \"str:hello\"."
                    ),
                    "regs" to strListProp("Raw register overrides applied last, as \"x9=0x40\"."),
                    "write" to strListProp("Memory to place before the run, as \"0x4a100=aabb\"."),
                    "read" to strListProp("Extra windows to read back at exit, as \"0x4a100:64\"."),
                    "stopAt" to strProp("Halt before executing this address, in hex."),
                    "maxInstr" to intProp("Instruction budget.", 1000, 2000000, 200000),
                    "timeoutMs" to intProp("Wall clock for the run.", 100, 10000, 3000),
                    "maxPages" to intProp("4 KiB pages the run may dirty.", 16, 8192, 1024),
                    "maxCalls" to intProp("Stubbed imports it may call.", 16, 65536, 4096),
                    "strictUserops" to boolProp(
                        "Stop at the first p-code operation modelled as zero instead of noting it.",
                        false
                    )
                )
            ), false
        ) { emulate(it) })

        add(Tool(
            "list_annotations", "List project annotations",
            "What has been recorded against the open project: renames, comments, bookmarks " +
                "and notes, in address order. Read this before renaming anything, so you do " +
                "not overwrite work the user has already done. Paginated.",
            schema(
                emptyList(),
                listOf(
                    "kind" to enumProp(
                        "Which annotations to return.",
                        listOf("all", "renames", "comments", "bookmarks", "notes"), "all"
                    ),
                    "offset" to offsetProp(),
                    "limit" to limitProp(100, 200)
                )
            ), false
        ) { listAnnotations(it) })

        // ---- writes -------------------------------------------------------
        // Advertised only when the user cleared read-only mode before starting
        // the server. They write to Nocturne's SQLite project database through
        // the same ViewModel calls the app's own UI uses, so a client's rename
        // is undoable, exportable and visible exactly like a typed one. The
        // binary on disk is not touched by any of them.
        add(Tool(
            RENAME, "Rename a function",
            "Give a function a name. The name is stored in Nocturne's project database " +
                "against the address and appears everywhere in the app, in exports and in the " +
                "IDAPython/IDC scripts. The binary on disk is never modified. `address` must " +
                "be a function start — list_functions gives them.",
            schema(
                listOf("address", "name"),
                listOf(
                    "address" to addressProp,
                    "name" to strProp("The new name. Keep it to what the function does.")
                )
            ), true
        ) { rename(it) })

        add(Tool(
            COMMENT, "Comment an address",
            "Store a comment against an address in the open project. An empty `text` removes " +
                "the comment. Stored in Nocturne's project database; the binary on disk is " +
                "never modified.",
            schema(
                listOf("address", "text"),
                listOf(
                    "address" to addressProp,
                    "text" to strProp("The comment. An empty string removes the one that is there.")
                )
            ), true
        ) { comment(it) })

        add(Tool(
            BOOKMARK, "Bookmark an address",
            "Bookmark an address with a label so the user finds it in the app's bookmarks " +
                "list. Stored in Nocturne's project database; the binary on disk is never " +
                "modified.",
            schema(
                listOf("address", "label"),
                listOf(
                    "address" to addressProp,
                    "label" to strProp("Short label for the bookmark.")
                )
            ), true
        ) { bookmark(it) })
    }

    /** The tools this server will actually honour, read-only mode applied. */
    private val exposed: List<Tool> =
        if (allowWrites) tools else tools.filterNot { it.write }

    fun names(): List<String> = exposed.map { it.name }

    fun listJson(): JSONArray {
        val out = JSONArray()
        for (t in exposed) {
            val annotations = JSONObject()
                .put("title", t.title)
                .put("readOnlyHint", !t.write)
                .put("destructiveHint", false)
                .put("idempotentHint", true)
                .put("openWorldHint", false)
            out.put(
                JSONObject()
                    .put("name", t.name)
                    .put("title", t.title)
                    .put("description", t.description)
                    .put("inputSchema", t.schema)
                    .put("annotations", annotations)
            )
        }
        return out
    }

    fun has(name: String): Boolean = exposed.any { it.name == name }

    /** True for a tool this build knows but this server is not exposing. */
    fun hiddenByReadOnly(name: String): Boolean =
        tools.any { it.name == name } && exposed.none { it.name == name }

    /**
     * Run one tool. Blocking on purpose: the caller is already on
     * `Dispatchers.IO`, the engine calls below are blocking JNI, and the
     * project database is SQLite.
     */
    fun invoke(name: String, args: JSONObject): Outcome {
        val tool = exposed.firstOrNull { it.name == name }
            ?: throw Failure("No tool named \"$name\" is exposed by this server.")
        engineLock.lock()
        try {
            return tool.handler(args)
        } finally {
            engineLock.unlock()
        }
    }

    // ------------------------------------------------------- tool bodies --

    private fun overview(): Outcome {
        val vm = session()
        val m = openMeta()
        val out = JSONObject()
        out.put("name", m.name)
        out.put("format", m.format)
        out.put("arch", m.arch)
        out.put("entry", hx(m.entry))
        out.put("base", hx(m.base))
        out.put("sizeBytes", m.sizeBytes)
        out.put("truncated", m.truncated)
        out.put("loadMs", m.loadMs)
        out.put("engineBackend", m.backend)
        out.put("disassemblable", m.disassemblable)
        if (m.soName.isNotEmpty()) out.put("soName", m.soName)
        out.put("neededLibraries", JSONArray(m.needed))
        out.put(
            "addressing",
            if (m.format == "ELF" || m.format == "PE") "virtual addresses"
            else "file offsets — this format is read as a flat file, so an address is an offset"
        )

        val counts = JSONObject()
        counts.put("functions", m.functions.size)
        counts.put("strings", m.strings.size)
        counts.put("imports", m.imports.size)
        counts.put("exports", m.exports.size)
        counts.put("sections", m.sections.size)
        counts.put("segments", m.segments.size)
        counts.put("callEdges", m.callEdges.size)
        counts.put("callEdgesFound", maxOf(m.callEdgesTotal, m.callEdges.size))
        counts.put("callSites", m.callSitesTotal)
        if (m.dexClasses.isNotEmpty()) counts.put("dexClasses", m.dexClasses.size)
        if (m.dexMethods.isNotEmpty()) counts.put("dexMethods", m.dexMethods.size)
        out.put("counts", counts)

        val sections = JSONArray()
        for (s in m.sections.take(64)) {
            sections.put(
                JSONObject().put("name", s.name).put("type", s.type).put("flags", s.flags)
                    .put("address", hx(s.addr)).put("fileOffset", s.offset).put("size", s.size)
            )
        }
        out.put("sections", sections)

        val segments = JSONArray()
        for (s in m.segments.take(32)) {
            segments.put(
                JSONObject().put("type", s.type).put("flags", s.flags)
                    .put("vaddr", hx(s.vaddr)).put("fileOffset", s.offset)
                    .put("fileSize", s.filesz).put("memSize", s.memsz)
            )
        }
        out.put("segments", segments)

        val dec = JSONObject()
            .put("selected", vm.decompiler)
            .put("ghidraAvailable", vm.sleighReady)
        if (vm.decompilerNote.isNotBlank()) dec.put("note", vm.decompilerNote)
        out.put("decompiler", dec)

        val project = JSONObject()
            .put("renames", vm.renames.size)
            .put("comments", vm.comments.size)
            .put("bookmarks", vm.bookmarks.size)
            .put("notes", vm.notes().size)
            .put("writable", exposed.any { it.write })
        out.put("project", project)

        val mf = vm.manifest
        if (mf != null && mf.ok) {
            out.put(
                "androidManifest",
                JSONObject()
                    .put("package", mf.packageName)
                    .put("versionName", mf.versionName)
                    .put("versionCode", mf.versionCode)
                    .put("minSdk", mf.minSdk)
                    .put("targetSdk", mf.targetSdk)
                    .put("debuggable", mf.debuggable ?: JSONObject.NULL)
                    .put("permissions", JSONArray(mf.permissions))
                    .put("activities", mf.activities.size)
                    .put("services", mf.services.size)
                    .put("receivers", mf.receivers.size)
                    .put("providers", mf.providers.size)
            )
        }
        if (m.notes.isNotEmpty()) out.put("engineNotes", JSONArray(m.notes))

        return Outcome(
            out,
            "${m.name} · ${m.format} ${m.arch} · ${m.functions.size} functions"
        )
    }

    private fun listFunctions(args: JSONObject): Outcome {
        val m = openMeta()
        val q = textArg(args, "query", false).trim()
        val sort = enumArg(args, "sort", listOf("address", "name", "size", "callers", "callees"), "address")

        var rows = m.functions
        if (q.isNotEmpty()) {
            rows = rows.filter { f ->
                f.name.contains(q, true) ||
                    (f.demangled?.contains(q, true) == true) ||
                    effectiveName(f.addr).contains(q, true)
            }
        }
        rows = when (sort) {
            // xor with the sign bit is unsigned order: a top-bit-set address is
            // a high address, not a negative one.
            "address" -> rows.sortedBy { it.addr xor Long.MIN_VALUE }
            "name" -> rows.sortedBy { effectiveName(it.addr).lowercase() }
            "size" -> rows.sortedByDescending { it.size }
            "callers" -> rows.sortedByDescending { it.nCallers }
            else -> rows.sortedByDescending { it.nCallees }
        }

        val w = window(args, 50, 200)
        val page = slice(rows, w)
        val arr = JSONArray()
        for (f in page) {
            val name = effectiveName(f.addr)
            val row = JSONObject()
                .put("address", hx(f.addr))
                .put("name", name)
                .put("size", f.size)
                .put("source", f.from)
                .put("callers", f.nCallers)
                .put("callees", f.nCallees)
            if (f.name.isNotEmpty() && f.name != name) row.put("originalName", f.name)
            f.demangled?.takeIf { it.isNotBlank() }?.let { row.put("demangled", it) }
            arr.put(row)
        }
        val out = JSONObject().put("functions", arr)
        paginate(out, rows.size, w, page.size)
        if (q.isNotEmpty()) out.put("query", q)
        val note = if (q.isEmpty()) "" else " matching \"$q\""
        return Outcome(out, "${page.size} of ${rows.size}" + note)
    }

    private fun listStrings(args: JSONObject): Outcome {
        val m = openMeta()
        val q = textArg(args, "query", false).trim()
        val minLength = intArg(args, "minLength", 1, 1, 4096)
        var rows = m.strings
        if (minLength > 1) rows = rows.filter { it.value.length >= minLength }
        if (q.isNotEmpty()) rows = rows.filter { it.value.contains(q, true) }
        val w = window(args, 50, 200)
        val page = slice(rows, w)
        val arr = JSONArray()
        for (s in page) {
            val row = JSONObject().put("address", hx(s.addr))
            if (s.value.length > 240) {
                row.put("value", s.value.take(240)).put("truncated", true)
                    .put("length", s.value.length)
            } else {
                row.put("value", s.value)
            }
            arr.put(row)
        }
        val out = JSONObject().put("strings", arr)
        paginate(out, rows.size, w, page.size)
        if (q.isNotEmpty()) out.put("query", q)
        val note = if (q.isEmpty()) "" else " matching \"$q\""
        return Outcome(out, "${page.size} of ${rows.size}" + note)
    }

    private fun listSymbols(args: JSONObject): Outcome {
        val m = openMeta()
        val kind = enumArg(args, "kind", listOf("imports", "exports"), "imports")
        val q = textArg(args, "query", false).trim()
        var rows = if (kind == "imports") m.imports else m.exports
        if (q.isNotEmpty()) rows = rows.filter { it.name.contains(q, true) }
        val w = window(args, 50, 200)
        val page = slice(rows, w)
        val arr = JSONArray()
        for (s in page) {
            arr.put(JSONObject().put("name", s.name).put("address", hx(s.addr)))
        }
        val out = JSONObject().put("kind", kind).put("symbols", arr)
        paginate(out, rows.size, w, page.size)
        return Outcome(out, "$kind: ${page.size} of ${rows.size}")
    }

    private fun disassemble(args: JSONObject): Outcome {
        val vm = session()
        val asked = addressArg(args, "address")
        val fn = resolveFunction(asked)
        val d = functionDetail(fn.addr, "current")
        val w = window(args, 200, ASM_CAP)
        val page = slice(d.asm, w)
        val arr = JSONArray()
        for (line in page) {
            val row = JSONObject()
                .put("address", hx(line.addr))
                .put("bytes", line.bytes)
                .put("mnemonic", line.mnem)
                .put("operands", line.ops)
            if (line.comment.isNotEmpty()) row.put("autoComment", line.comment)
            vm.comments[annotationKey(line.addr)]?.let { row.put("comment", it) }
            arr.put(row)
        }
        val out = JSONObject()
            .put("function", hx(fn.addr))
            .put("name", effectiveName(fn.addr))
            .put("size", fn.size)
            .put("arch", d.arch)
            .put("blocks", d.blocks.size)
            .put("instructions", arr)
        if (asked != fn.addr) {
            out.put("note", "${hx(asked)} is inside this function, which starts at ${hx(fn.addr)}.")
        }
        paginate(out, d.asm.size, w, page.size)
        return Outcome(out, "${effectiveName(fn.addr)} · ${page.size} of ${d.asm.size} instructions")
    }

    private fun decompile(args: JSONObject): Outcome {
        val asked = addressArg(args, "address")
        val backend = enumArg(args, "backend", listOf("current", "ghidra", "ir"), "current")
        val fn = resolveFunction(asked)
        val d = functionDetail(fn.addr, backend)
        val out = JSONObject()
            .put("function", hx(fn.addr))
            .put("name", effectiveName(fn.addr))
            .put("engineName", d.displayName)
            .put("size", d.size)
            .put("backend", d.backend)
            .put("arch", d.arch)
            .put("pseudoMode", d.pseudoMode)
            .put("blocks", d.blocks.size)
            .put("callers", maxOf(d.nCallers, d.xrefsInTotal))
            .put("callees", maxOf(d.nCallees, d.xrefsOutTotal))
        d.irStats?.let {
            out.put(
                "irStats",
                JSONObject().put("statements", it.stmts).put("whiles", it.whiles)
                    .put("ifs", it.ifs).put("gotos", it.gotos).put("calls", it.calls)
            )
        }
        val text = d.pseudo
        if (text.length > PSEUDO_CAP) {
            out.put("pseudoC", text.take(PSEUDO_CAP))
            out.put("truncated", true)
            out.put("totalCharacters", text.length)
        } else {
            out.put("pseudoC", text)
            out.put("truncated", false)
        }
        if (asked != fn.addr) {
            out.put("note", "${hx(asked)} is inside this function, which starts at ${hx(fn.addr)}.")
        }
        return Outcome(out, "${effectiveName(fn.addr)} · ${d.backend} · ${text.length} chars")
    }

    private fun xrefs(args: JSONObject): Outcome {
        val asked = addressArg(args, "address")
        val direction = enumArg(args, "direction", listOf("in", "out", "both"), "both")
        val fn = resolveFunction(asked)
        val vm = session()
        val d = functionDetail(fn.addr, "current")
        val out = JSONObject()
            .put("function", hx(fn.addr))
            .put("name", effectiveName(fn.addr))
        val w = window(args, 50, 200)
        var shown = 0
        var total = 0
        if (direction == "in" || direction == "both") {
            val rows = xrefRows(vm, d, true)
            val page = slice(rows, w)
            out.put("incoming", xrefArray(page))
            out.put("incomingTotal", maxOf(rows.size, vm.xrefInCount(d)))
            shown += page.size
            total += rows.size
        }
        if (direction == "out" || direction == "both") {
            val rows = xrefRows(vm, d, false)
            val page = slice(rows, w)
            out.put("outgoing", xrefArray(page))
            out.put("outgoingTotal", maxOf(rows.size, vm.xrefOutCount(d)))
            shown += page.size
            total += rows.size
        }
        paginate(out, total, w, shown)
        return Outcome(out, "${effectiveName(fn.addr)} · $direction · $shown of $total")
    }

    private fun xrefArray(rows: List<com.trickhook.ui.XrefRow>): JSONArray {
        val arr = JSONArray()
        for (r in rows) {
            val row = JSONObject()
                .put("site", hx(r.site))
                .put("name", r.label)
                .put("type", r.type)
            row.put("address", if (r.target != null) hx(r.target) else JSONObject.NULL)
            if (r.note.isNotEmpty()) row.put("note", r.note)
            arr.put(row)
        }
        return arr
    }

    private fun callGraph(args: JSONObject): Outcome {
        val vm = session()
        val m = openMeta()
        val limit = intArg(args, "limit", 60, 1, 200)
        val root = optionalAddress(args, "address")

        if (root == null) {
            val hubs = m.functions
                .sortedByDescending { it.nCallers + it.nCallees }
                .take(limit)
            val arr = JSONArray()
            for (f in hubs) {
                arr.put(
                    JSONObject().put("address", hx(f.addr)).put("name", effectiveName(f.addr))
                        .put("callers", f.nCallers).put("callees", f.nCallees)
                        .put("size", f.size)
                )
            }
            val out = JSONObject()
                .put("scope", "whole binary")
                .put("functionsTotal", m.functions.size)
                .put("callEdgesFound", maxOf(m.callEdgesTotal, m.callEdges.size))
                .put("callSitesTotal", m.callSitesTotal)
                .put("busiestFunctions", arr)
                .put(
                    "note",
                    "The whole graph is too large to return. Pass `address` to walk a " +
                        "neighbourhood of one function."
                )
            return Outcome(out, "whole binary · ${hubs.size} busiest of ${m.functions.size}")
        }

        val fn = resolveFunction(root)
        val direction = enumArg(args, "direction", listOf("callers", "callees", "both"), "both")
        val depth = intArg(args, "depth", 2, 1, 4)

        val seen = LinkedHashMap<Long, Int>()
        val edgeKeys = HashSet<String>()
        val edges = ArrayList<CallEdge>()
        seen[fn.addr] = 0
        var frontier = listOf(fn.addr)
        var hop = 0
        var capped = false
        while (hop < depth && frontier.isNotEmpty() && !capped) {
            val next = ArrayList<Long>()
            for (addr in frontier) {
                val touching = ArrayList<CallEdge>()
                if (direction == "callers" || direction == "both") touching.addAll(vm.callersOf(addr))
                if (direction == "callees" || direction == "both") touching.addAll(vm.calleesOf(addr))
                for (e in touching) {
                    val key = "${e.from}>${e.to}"
                    if (edgeKeys.add(key)) edges.add(e)
                    val other = if (e.from == addr) e.to else e.from
                    if (!seen.containsKey(other)) {
                        if (seen.size >= limit) { capped = true; break }
                        seen[other] = hop + 1
                        next.add(other)
                    }
                }
                if (capped) break
            }
            frontier = next
            hop += 1
        }

        val nodes = JSONArray()
        for ((addr, d) in seen) {
            val info = vm.functionAt(addr)
            val node = JSONObject()
                .put("address", hx(addr))
                .put("name", effectiveName(addr))
                .put("depth", d)
            if (info != null) {
                node.put("callers", info.nCallers).put("callees", info.nCallees)
                    .put("size", info.size).put("source", info.from)
            } else {
                node.put("note", "referenced but not a function the engine mapped")
            }
            nodes.put(node)
        }
        val edgeArr = JSONArray()
        for (e in edges) {
            edgeArr.put(
                JSONObject()
                    .put("from", hx(e.from))
                    .put("to", hx(e.to))
                    .put("fromName", effectiveName(e.from))
                    .put("toName", if (vm.functionAt(e.to) != null) effectiveName(e.to) else e.toName)
                    .put("kind", e.kind.ifEmpty { "call" })
                    .put("site", hx(e.callSite))
                    .put("sites", e.sites)
            )
        }
        val out = JSONObject()
            .put("root", hx(fn.addr))
            .put("rootName", effectiveName(fn.addr))
            .put("direction", direction)
            .put("depth", depth)
            .put("functions", nodes)
            .put("edges", edgeArr)
            .put("truncated", capped)
        if (capped) {
            out.put(
                "note",
                "Stopped at the $limit-function cap before the walk finished. Raise `limit` " +
                    "or lower `depth`."
            )
        }
        return Outcome(out, "${effectiveName(fn.addr)} · ${seen.size} functions, ${edges.size} edges")
    }

    private fun readMemory(args: JSONObject): Outcome {
        val vm = session()
        val m = openMeta()
        val bytes = vm.hexData
            ?: throw Failure("Nocturne is not holding the open file's bytes — reopen the binary.")
        val length = intArg(args, "length", 256, 1, HEX_CAP)
        val virtual = optionalAddress(args, "address")
        val offset: Long
        var note = ""
        if (virtual != null) {
            val mapped = if (m.format == "ELF" || m.format == "PE") vm.fileOffsetOf(virtual) else virtual
            offset = mapped ?: throw Failure(
                "${hx(virtual)} is not inside any mapped section of this binary, so it has no " +
                    "place in the file. analysis_overview lists the sections and their address ranges."
            )
            if (m.format != "ELF" && m.format != "PE") {
                note = "This format is read as a flat file, so the address was used as a file offset."
            }
        } else {
            offset = args.optLong("offset", -1L)
            if (offset < 0) throw Failure("Give either `address` or `offset`.")
        }
        if (offset >= bytes.size) {
            throw Failure(
                "Offset ${offset} is past the ${bytes.size} bytes Nocturne holds" +
                    (if (m.sizeBytes > bytes.size) " (the first 8 MiB of a ${m.sizeBytes}-byte file)" else "") +
                    "."
            )
        }
        val start = offset.toInt()
        val end = minOf(bytes.size, start + length)
        val hex = StringBuilder((end - start) * 2)
        val ascii = StringBuilder(end - start)
        for (i in start until end) {
            val b = bytes[i].toInt() and 0xFF
            hex.append("0123456789abcdef"[b ushr 4])
            hex.append("0123456789abcdef"[b and 0xF])
            ascii.append(if (b in 0x20..0x7E) b.toChar() else '.')
        }
        val out = JSONObject()
            .put("fileOffset", start)
            .put("length", end - start)
            .put("hex", hex.toString())
            .put("ascii", ascii.toString())
            .put("bytesHeld", bytes.size)
        if (virtual != null) out.put("address", hx(virtual))
        if (note.isNotEmpty()) out.put("note", note)
        return Outcome(out, "${end - start} bytes at file offset $start")
    }

    private fun emulate(args: JSONObject): Outcome {
        val path = openPath()
        openMeta()
        val entry = addressArg(args, "entry")
        val request = JSONObject()
        request.put("entry", hx(entry))
        joinList(args, "args")?.let { request.put("args", it) }
        joinList(args, "regs")?.let { request.put("regs", it) }
        joinList(args, "write")?.let { request.put("write", it) }
        joinList(args, "read")?.let { request.put("read", it) }
        optionalAddress(args, "stopAt")?.let { request.put("stopAt", hx(it)) }
        request.put("maxInstr", intArg(args, "maxInstr", 200000, 1000, 2000000))
        request.put("timeoutMs", intArg(args, "timeoutMs", 3000, 100, 10000))
        request.put("maxPages", intArg(args, "maxPages", 1024, 16, 8192))
        request.put("maxCalls", intArg(args, "maxCalls", 4096, 16, 65536))
        request.put("strictUserops", if (boolArg(args, "strictUserops", false)) 1 else 0)

        val raw = NativeBridge.nativeEmulate(path, request.toString())
        val parsed = try {
            JSONObject(raw)
        } catch (e: Exception) {
            throw Failure("The emulator answered with something that is not JSON: ${raw.take(300)}")
        }
        val out = JSONObject()
        for (k in listOf(
            "ok", "stop", "detail", "approximate", "instructions", "ms", "backend",
            "retReg", "ret", "dirtyBytes", "memoryTruncated", "callsTotal"
        )) {
            if (parsed.has(k)) out.put(k, parsed.get(k))
        }
        parsed.optJSONObject("limits")?.let { out.put("limits", it) }
        out.put("entry", hx(entry))
        copyArray(parsed, out, "args", 32, 0)
        copyArray(parsed, out, "regs", 64, 0)
        copyArray(parsed, out, "memory", 24, 8192)
        copyArray(parsed, out, "dirtyRanges", 64, 0)
        copyArray(parsed, out, "calls", 80, 0)
        copyArray(parsed, out, "userops", 40, 0)
        copyArray(parsed, out, "tail", 64, 0)
        val stop = parsed.optString("stop", "?")
        val ok = parsed.optBoolean("ok", false)
        val ran = if (ok) "" else " (did not complete)"
        return Outcome(out, "${hx(entry)} · $stop" + ran)
    }

    /** ';'-joined list for the flat emulator request, or null when absent. */
    private fun joinList(args: JSONObject, name: String): String? {
        if (!args.has(name) || args.isNull(name)) return null
        val v = args.get(name)
        val parts = ArrayList<String>()
        if (v is JSONArray) {
            for (i in 0 until v.length()) {
                val s = v.optString(i, "").trim()
                if (s.isNotEmpty()) parts.add(s)
            }
        } else {
            val s = v.toString().trim()
            if (s.isNotEmpty()) parts.add(s)
        }
        return if (parts.isEmpty()) null else parts.joinToString(";")
    }

    /**
     * Copy one array from the engine's answer, capped at [rows] elements and,
     * when [textCap] is non-zero, with each element's long string fields cut to
     * that many characters. A 1 MiB memory dump helps nobody read a transcript.
     */
    private fun copyArray(from: JSONObject, to: JSONObject, name: String, rows: Int, textCap: Int) {
        val src = from.optJSONArray(name) ?: return
        val dst = JSONArray()
        val n = minOf(src.length(), rows)
        for (i in 0 until n) {
            val item = src.opt(i)
            if (item is JSONObject && textCap > 0) {
                val copy = JSONObject()
                for (k in item.keys()) {
                    val value = item.get(k)
                    if (value is String && value.length > textCap) {
                        copy.put(k, value.take(textCap))
                        copy.put(k + "Truncated", true)
                    } else {
                        copy.put(k, value)
                    }
                }
                dst.put(copy)
            } else {
                dst.put(item)
            }
        }
        to.put(name, dst)
        if (src.length() > n) to.put(name + "Truncated", src.length() - n)
    }

    private fun listAnnotations(args: JSONObject): Outcome {
        val vm = session()
        openMeta()
        val kind = enumArg(
            args, "kind", listOf("all", "renames", "comments", "bookmarks", "notes"), "all"
        )
        val w = window(args, 100, 200)
        val out = JSONObject()
        var shown = 0
        var total = 0
        if (kind == "all" || kind == "renames") {
            val rows = vm.renames.entries
                .map { Pair(parseAddr(it.key) ?: 0L, it.value) }
                .sortedBy { it.first xor Long.MIN_VALUE }
            val page = slice(rows, w)
            val arr = JSONArray()
            for ((addr, name) in page) {
                arr.put(
                    JSONObject().put("address", hx(addr)).put("name", name)
                        .put("originalName", vm.functionAt(addr)?.name ?: JSONObject.NULL)
                )
            }
            out.put("renames", arr); shown += page.size; total += rows.size
        }
        if (kind == "all" || kind == "comments") {
            val rows = vm.comments.entries
                .map { Pair(parseAddr(it.key) ?: 0L, it.value) }
                .sortedBy { it.first xor Long.MIN_VALUE }
            val page = slice(rows, w)
            val arr = JSONArray()
            for ((addr, text) in page) {
                arr.put(JSONObject().put("address", hx(addr)).put("text", text))
            }
            out.put("comments", arr); shown += page.size; total += rows.size
        }
        if (kind == "all" || kind == "bookmarks") {
            val rows = vm.bookmarks
            val page = slice(rows, w)
            val arr = JSONArray()
            for (b in page) {
                arr.put(JSONObject().put("address", b.addr).put("label", b.label))
            }
            out.put("bookmarks", arr); shown += page.size; total += rows.size
        }
        if (kind == "all" || kind == "notes") {
            val rows = vm.notes()
            val page = slice(rows, w)
            val arr = JSONArray()
            for (n in page) {
                arr.put(JSONObject().put("title", n.title).put("body", n.body))
            }
            out.put("notes", arr); shown += page.size; total += rows.size
        }
        paginate(out, total, w, shown)
        return Outcome(out, "$kind · $shown of $total")
    }

    // ------------------------------------------------------------ writes --
    // These call the same ViewModel entry points the app's own UI calls, so a
    // rename from a client lands in ProjectDb, shows up in every panel, exports
    // to IDA and is rolled into the app's own undo — it is indistinguishable
    // from one typed on the device, which is the point.
    //
    // They run on the socket's IO thread rather than the main thread: SQLite is
    // file I/O and does not belong on the main thread, and the Compose snapshot
    // state these touch is safe to write from any thread — the recomposition it
    // schedules lands on the main thread by itself.

    private fun rename(args: JSONObject): Outcome {
        val vm = session()
        val ctx = McpService.appContextOrNull()
            ?: throw Failure("The server is not running, so there is nothing to write with.")
        openMeta()
        val asked = addressArg(args, "address")
        val name = textArg(args, "name", true).trim()
        if (name.isEmpty()) throw Failure("`name` cannot be empty.")
        if (name.length > 200) throw Failure("`name` is longer than 200 characters.")
        val fn = vm.functionAt(asked)
            ?: throw Failure(
                "${hx(asked)} is not a function start. Rename the function that contains it " +
                    "instead — disassemble_function reports which one that is."
            )
        val before = effectiveName(fn.addr)
        vm.renameFunction(ctx, fn.addr, name)
        val out = JSONObject()
            .put("address", hx(fn.addr))
            .put("previousName", before)
            .put("name", name)
            .put("storedIn", "Nocturne project database — the binary on disk is unchanged")
        return Outcome(out, "${hx(fn.addr)} $before -> $name")
    }

    private fun comment(args: JSONObject): Outcome {
        val vm = session()
        val ctx = McpService.appContextOrNull()
            ?: throw Failure("The server is not running, so there is nothing to write with.")
        openMeta()
        val addr = addressArg(args, "address")
        val text = textArg(args, "text", true)
        if (text.length > 4000) throw Failure("`text` is longer than 4000 characters.")
        vm.addComment(ctx, addr, text)
        val out = JSONObject()
            .put("address", hx(addr))
            .put("removed", text.isBlank())
            .put("text", text)
        val verb = if (text.isBlank()) " comment removed" else " commented"
        return Outcome(out, hx(addr) + verb)
    }

    private fun bookmark(args: JSONObject): Outcome {
        val vm = session()
        val ctx = McpService.appContextOrNull()
            ?: throw Failure("The server is not running, so there is nothing to write with.")
        openMeta()
        val addr = addressArg(args, "address")
        val label = textArg(args, "label", true).trim()
        if (label.isEmpty()) throw Failure("`label` cannot be empty.")
        if (label.length > 200) throw Failure("`label` is longer than 200 characters.")
        vm.addBookmark(ctx, addr, label)
        return Outcome(
            JSONObject().put("address", hx(addr)).put("label", label),
            "${hx(addr)} bookmarked as \"$label\""
        )
    }
}

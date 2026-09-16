package com.trickhook.vm

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.trickhook.data.Bookmark
import com.trickhook.data.Note
import com.trickhook.data.ProjectDb
import com.trickhook.data.RecentProject
import com.trickhook.engine.NativeBridge
import com.trickhook.model.ApkEntry
import com.trickhook.model.ApkResourceEntry
import com.trickhook.model.AnalysisMeta
import com.trickhook.model.CallEdge
import com.trickhook.model.CallGraphData
import com.trickhook.model.ConsoleLine
import com.trickhook.model.DbgState
import com.trickhook.model.DebugResult
import com.trickhook.model.FuncInfo
import com.trickhook.model.FunctionDetail
import com.trickhook.model.ManifestInfo
import com.trickhook.model.PluginDef
import com.trickhook.model.Section
import com.trickhook.model.ApkAnalyzer
import com.trickhook.model.parseCallGraph
import com.trickhook.model.parseDbg
import com.trickhook.model.parseDebug
import com.trickhook.model.parseDetail
import com.trickhook.model.parseMeta
import com.trickhook.model.parseScriptResult
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.File
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.ZipFile

/**
 * Destinations are grouped so navigation fits a phone. Thirteen tabs in one
 * scrolling strip meant the list could never be seen at once; the drawer shows
 * the groups, and the strip under the header only carries the current one.
 */
enum class TabGroup(val title: String) {
    CODE("Code"),
    EXPLORE("Explore"),
    ANALYZE("Analyze"),
    OUTPUT("Output")
}

enum class Tab(val title: String, val group: TabGroup) {
    ASSEMBLY("Assembly", TabGroup.CODE),
    PSEUDO("Pseudo-C", TabGroup.CODE),
    GRAPH("Graph", TabGroup.CODE),
    CALLGRAPH("Call graph", TabGroup.CODE),
    FUNCTIONS("Functions", TabGroup.EXPLORE),
    STRINGS("Strings", TabGroup.EXPLORE),
    HEX("Hex", TabGroup.EXPLORE),
    MAP("Map", TabGroup.EXPLORE),
    APK("APK", TabGroup.ANALYZE),
    DEBUGGER("Debugger", TabGroup.ANALYZE),
    PLUGINS("Plugins", TabGroup.OUTPUT),
    CONSOLE("Console", TabGroup.OUTPUT);

    companion object {
        fun of(group: TabGroup): List<Tab> = entries.filter { it.group == group }
    }
}

enum class DbgMode { NONE, TRACE, SESSION }

/** How many places back the chevron can walk before the oldest is dropped. */
private const val NAV_LIMIT = 64

/** One step of the back stack: where the user was before a jump. */
data class NavEntry(val tab: Tab, val addr: Long?)

/**
 * A single transient message. The console is only visible on one of twelve
 * tabs, so every failure used to be silent; this is what the host screen
 * shows in a snackbar. [id] is a counter, not a timestamp, so two identical
 * messages in the same millisecond still count as two toasts.
 */
data class Toast(
    val id: Long,
    val level: String,
    val msg: String,
    val actionLabel: String? = null,
    val action: (() -> Unit)? = null
)

class StudioViewModel : ViewModel() {

    var meta by mutableStateOf<AnalysisMeta?>(null); private set
    var busy by mutableStateOf(false); private set
    var detailBusy by mutableStateOf(false); private set
    // What the engine is doing right now, and for how long. The Ghidra
    // backend can spend several seconds on a large function and every UI
    // spinner without a number looks the same as a hang; a phase and an
    // elapsed millisecond count are what tell you the engine is alive.
    var decompilePhase by mutableStateOf(""); private set
    var decompileTargetName by mutableStateOf(""); private set
    var decompileStartMs by mutableStateOf(0L); private set
    var currentPath by mutableStateOf<String?>(null); private set
    var hexData by mutableStateOf<ByteArray?>(null); private set
    var apkEntries by mutableStateOf<List<ApkEntry>>(emptyList()); private set
    var apkResources by mutableStateOf<List<ApkResourceEntry>>(emptyList()); private set
    var selectedFunc by mutableStateOf<Long?>(null); private set
    var detail by mutableStateOf<FunctionDetail?>(null); private set
    var tab by mutableStateOf(Tab.ASSEMBLY)
    var darkTheme by mutableStateOf(true)

    /**
     * What the app as a whole is doing, for the header progress line.
     * "" means idle. Distinct from [decompilePhase], which is only about the
     * decompiler: opening, exporting, call-graph building and plugin runs all
     * happen off the Pseudo-C tab and were invisible before.
     */
    var globalPhase by mutableStateOf("")

    // ------------------------------------------------------ hoisted panel state --
    // Every one of these used to be a `remember` inside a panel, so it died on
    // each tab switch: scroll position, filter text and graph transform all
    // reset when you looked at something else and came back.
    var asmIndex by mutableStateOf(0)
    var asmOffset by mutableStateOf(0)
    var hexIndex by mutableStateOf(0)
    var funcQuery by mutableStateOf("")
    var stringQuery by mutableStateOf("")
    /** functions | imports | exports */
    var symbolsMode by mutableStateOf("functions")
    /** 0 sections, 1 segments */
    var mapMode by mutableStateOf(0)
    var apkMode by mutableStateOf(0)
    var traceStep by mutableStateOf(-1)
    var pluginSelected by mutableStateOf("")
    var graphScale by mutableStateOf(1f)
    var graphPanX by mutableStateOf(0f)
    var graphPanY by mutableStateOf(0f)

    // -------------------------------------------------------- backend compare --
    var compareBackends by mutableStateOf(false)
    /** The other backend's pseudo-C for the current function, when asked for. */
    var pseudoAlt by mutableStateOf<String?>(null); private set
    var pseudoAltBusy by mutableStateOf(false); private set

    // ---------------------------------------------------------------- toasts --
    // Declared above `init`, which logs: property initializers run in
    // declaration order and log() now feeds notify().
    var toast by mutableStateOf<Toast?>(null); private set
    private val toastSeq = AtomicLong(0L)

    // ------------------------------------------------------------ cross-panel --
    /** An address another panel asked us to reveal; the panel consumes it. */
    var gotoAddr by mutableStateOf<Long?>(null); private set
    var graphZoomReq by mutableStateOf(1f)
    var graphFitReq by mutableStateOf(false)

    // legacy syscall trace
    var debugResult by mutableStateOf<DebugResult?>(null); private set
    var debugRunning by mutableStateOf(false); private set

    // v2: call graph
    var callGraph by mutableStateOf<CallGraphData?>(null); private set
    var callGraphBusy by mutableStateOf(false); private set

    // v2: interactive debugger session
    var dbgMode by mutableStateOf(DbgMode.NONE)
    var dbgState by mutableStateOf<DbgState?>(null); private set
    var dbgEvents by mutableStateOf<List<Pair<String, String>>>(emptyList()); private set
    var dbgBusy by mutableStateOf(false); private set
    var dbgMem by mutableStateOf<Pair<Long, String>?>(null); private set
    var dbgStack by mutableStateOf<Pair<Long, String>?>(null); private set

    // v2: plugins
    var plugins by mutableStateOf<List<PluginDef>>(emptyList()); private set
    var pluginOutput by mutableStateOf<String>(""); private set
    var pluginRunning by mutableStateOf(false); private set
    /** Name and effect count of the last run, for the result header. */
    var lastPluginName by mutableStateOf(""); private set
    var lastPluginEffects by mutableStateOf(0); private set
    var lastPluginOk by mutableStateOf(true); private set
    /** True while the last plugin run can still be rolled back. */
    var lastPluginUndoable by mutableStateOf(false); private set

    // v2: APK manifest
    var manifest by mutableStateOf<ManifestInfo?>(null); private set

    // v2: project database
    var projectId by mutableStateOf<Long>(-1); private set
    val renames = mutableStateMapOf<String, String>()
    val comments = mutableStateMapOf<String, String>()
    var bookmarks by mutableStateOf<List<Bookmark>>(emptyList()); private set
    var recents by mutableStateOf<List<RecentProject>>(emptyList()); private set

    // v2: AI assistant

    val console = mutableStateListOf<ConsoleLine>()
    private var apkFile: File? = null
    private var db: ProjectDb? = null

    fun database(context: Context): ProjectDb {
        if (db == null) db = ProjectDb(context.applicationContext)
        return db!!
    }

    init {
        log("INFO", "Nocturne ready — engine loaded (IR decompiler, call graph, debugger, plugins)")
    }

    fun log(level: String, msg: String) {
        console.add(ConsoleLine(System.currentTimeMillis(), level, msg))
        if (console.size > 800) console.removeRange(0, 200)
        // Only failures surface as a toast. There are dozens of INFO/OK call
        // sites and turning those into snackbars makes the screen unusable.
        if (level == "WARN" || level == "ERROR") notify(level, msg)
    }

    /**
     * Raise a transient message. The id is a counter rather than a clock so
     * that the same text twice in a row is still two distinct toasts — a
     * timestamp collides at millisecond resolution and the second one is
     * silently swallowed by the snackbar host.
     */
    fun notify(level: String, msg: String, actionLabel: String? = null, action: (() -> Unit)? = null) {
        toast = Toast(toastSeq.incrementAndGet(), level, msg, actionLabel, action)
    }

    fun dismissToast() { toast = null }

    // ------------------------------------------------------------ recents --
    fun refreshRecents(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            val list = database(context).recentProjects()
            withContext(Dispatchers.Main) { recents = list }
        }
    }

    // ------------------------------------------------------------ open file --
    fun openUri(context: Context, uri: Uri) = viewModelScope.launch {
        busy = true
        globalPhase = "Opening"
        try {
            withContext(Dispatchers.IO) {
                val name = queryName(context, uri) ?: "binary.bin"
                val dst = File(context.cacheDir, "current_$name")
                context.contentResolver.openInputStream(uri)?.use { ins ->
                    dst.outputStream().use { ins.copyTo(it) }
                } ?: throw IllegalStateException("Cannot open input stream")
                log("INFO", "Opened '$name' (${humanSize(dst.length())})")
                val head = dst.inputStream().use { ins ->
                    val b = ByteArray(2)
                    val n = ins.read(b)
                    n >= 2 && b[0] == 'P'.code.toByte() && b[1] == 'K'.code.toByte()
                }
                if (head) openApk(dst, name) else loadFile(dst, name)
                refreshRecents(context)
            }
        } catch (e: Exception) {
            log("ERROR", e.message ?: "open failed")
        } finally {
            busy = false
            globalPhase = ""
        }
    }

    fun openRecent(context: Context, rp: RecentProject) = viewModelScope.launch {
        busy = true
        globalPhase = "Opening ${rp.name}"
        try {
            withContext(Dispatchers.IO) {
                val f = File(rp.path)
                if (!f.exists()) { log("ERROR", "Cached binary missing — fur faylka markale"); return@withContext }
                if (rp.format == "APK") openApk(f, rp.name) else loadFile(f, rp.name)
            }
        } finally { busy = false; globalPhase = "" }
    }

    private fun openApk(file: File, name: String) {
        apkFile = file
        ZipFile(file).use { zf ->
            val entries = zf.entries().asSequence()
                .filter { !it.isDirectory }
                .map { ApkEntry(it.name, it.size) }
                .toList()
            apkEntries = entries.filter { it.name.endsWith(".dex") || it.name.endsWith(".so") }
            apkResources = entries
                .filter { it.name.startsWith("res/") || it.name.startsWith("assets/") }
                .take(400)
                .map { ApkResourceEntry(
                    it.name, it.size,
                    it.name.endsWith(".png") || it.name.endsWith(".webp") ||
                        it.name.endsWith(".jpg") || it.name.endsWith(".gif"),
                    it.name.endsWith(".xml")) }
            log("INFO", "APK '$name': ${apkEntries.size} dex/so · ${apkResources.size} resources")

            // parse binary manifest (guarded — must never kill dex extraction)
            try {
                val mfEntry = zf.getEntry("AndroidManifest.xml")
                if (mfEntry != null) {
                    val bytes = zf.getInputStream(mfEntry).use { it.readBytes() }
                    val mi = ApkAnalyzer.parseManifest(bytes)
                    manifest = mi
                    if (mi.ok) {
                        log("OK", "Manifest: ${mi.packageName} v${mi.versionName}(${mi.versionCode}) · " +
                            "${mi.permissions.size} permissions · ${mi.activities.size} activities · " +
                            "${mi.services.size} services")
                    } else log("WARN", "Manifest parse failed: ${mi.rawXml}")
                } else log("WARN", "No AndroidManifest.xml in APK")
            } catch (e: Exception) {
                log("ERROR", "Manifest read failed: ${e.message}")
            }
        }

        // register project
        db?.let { d ->
            projectId = d.upsertProject(file.absolutePath, name, "APK", "")
            syncProjectAnnotations()
        }

        val dex = apkEntries.firstOrNull { it.name == "classes.dex" }
            ?: apkEntries.firstOrNull { it.name.endsWith(".dex") }
        if (dex != null) extractApkEntry(dex) else log("WARN", "No .dex found in APK")
    }

    fun openApkEntry(entry: ApkEntry) = viewModelScope.launch {
        busy = true
        try {
            withContext(Dispatchers.IO) { extractApkEntry(entry) }
        } finally {
            busy = false
        }
    }

    private fun extractApkEntry(entry: ApkEntry) {
        val apk = apkFile ?: return
        ZipFile(apk).use { zf ->
            val zentry = zf.getEntry(entry.name) ?: run {
                log("ERROR", "Entry not found: ${entry.name}")
                return
            }
            val safe = entry.name.replace(Regex("[^A-Za-z0-9._-]"), "_")
            val dst = File(apk.parentFile, "apk_$safe")
            zf.getInputStream(zentry).use { ins -> dst.outputStream().use { ins.copyTo(it) } }
            log("INFO", "Extracted ${entry.name} (${humanSize(dst.length())})")
            loadFile(dst, entry.name.substringAfterLast('/'))
        }
    }

    private fun loadFile(file: File, name: String) {
        // Restored rather than cleared: an APK walks openApk -> extractApkEntry
        // -> loadFile, and the outer phase should survive the inner one.
        val outerPhase = globalPhase
        globalPhase = "Analyzing $name"
        try {
            currentPath = file.absolutePath
            val cap = 8L * 1024 * 1024
            hexData = file.inputStream().use { ins ->
                val buf = ByteArray(minOf(file.length(), cap).toInt())
                var off = 0
                while (off < buf.size) {
                    val r = ins.read(buf, off, buf.size - off)
                    if (r < 0) break
                    off += r
                }
                if (off < buf.size) buf.copyOf(off) else buf
            }
            val m = parseMeta(NativeBridge.nativeAnalyze(file.absolutePath))
            if (m.ok) {
                meta = m
                reindex()
                log(
                    "OK",
                    "${m.format} · ${m.arch.ifEmpty { "-" }} · ${m.functions.size} functions · " +
                        "${m.callEdges.size} call edges · ${m.strings.size} strings · backend: ${m.backend.ifEmpty { "-" }}"
                )
                m.notes.forEach { log("INFO", it) }
                selectedFunc = null
                detail = null
                pseudoAlt = null
                resetPanelState()
                db?.let { d ->
                    projectId = d.upsertProject(file.absolutePath, name, m.format, m.arch)
                    syncProjectAnnotations()
                }
                callGraph = null
                if (m.functions.isNotEmpty()) selectFunction(m.functions[0].addr)
                else if (m.format == "DEX") tab = Tab.STRINGS else tab = Tab.ASSEMBLY
            } else {
                log("ERROR", m.error ?: "analysis failed")
            }
        } finally {
            globalPhase = outerPhase
        }
    }

    /**
     * A new binary invalidates every hoisted scroll position, filter and
     * graph transform; the modes (which are preferences, not positions) stay.
     */
    private fun resetPanelState() {
        asmIndex = 0; asmOffset = 0; hexIndex = 0
        funcQuery = ""; stringQuery = ""
        traceStep = -1
        graphScale = 1f; graphPanX = 0f; graphPanY = 0f
        graphZoomReq = 1f; graphFitReq = false
        gotoAddr = null
        clearHistory()
        lastPluginUndoable = false
        pluginUndo = null
    }

    // ------------------------------------------------- project annotations --
    private fun syncProjectAnnotations() {
        val d = db ?: return
        if (projectId < 0) return
        renames.clear(); renames.putAll(d.renames(projectId))
        comments.clear(); comments.putAll(d.comments(projectId))
        bookmarks = d.bookmarks(projectId)
        refreshNotes(d)
    }

    /** Make sure there is a project row to hang annotations off. */
    private fun ensureProject(d: ProjectDb) {
        if (projectId < 0 && currentPath != null) {
            projectId = d.upsertProject(currentPath!!, meta?.name ?: "binary", meta?.format, meta?.arch)
        }
    }

    fun renameFunction(context: Context, addr: Long, newName: String) {
        val d = database(context)
        if (projectId < 0 && currentPath != null) {
            projectId = d.upsertProject(currentPath!!, meta?.name ?: "binary", meta?.format, meta?.arch)
        }
        val key = "0x%08X".format(addr)
        val old = functionAt(addr)?.name
        d.rename(projectId, key, old, newName)
        renames[key] = newName
        log("OK", "Renamed ${old ?: key} → $newName")
        // Refresh detail to pick up the new name in pseudo-C. selectFunction
        // deliberately does NOT push navigation history, so renaming in place
        // never lands a bogus entry on the back stack.
        selectedFunc?.let { if (it == addr) selectFunction(addr) }
    }

    fun addComment(context: Context, addr: Long, text: String) {
        val d = database(context)
        if (projectId < 0 && currentPath != null) {
            projectId = d.upsertProject(currentPath!!, meta?.name ?: "binary", meta?.format, meta?.arch)
        }
        val key = "0x%08X".format(addr)
        if (text.isBlank()) { d.deleteComment(projectId, key); comments.remove(key) }
        else { d.comment(projectId, key, text); comments[key] = text }
        log("OK", "Comment ${if (text.isBlank()) "removed" else "saved"} @ $key")
    }

    fun addBookmark(context: Context, addr: Long, label: String) {
        val d = database(context)
        if (projectId < 0 && currentPath != null) {
            projectId = d.upsertProject(currentPath!!, meta?.name ?: "binary", meta?.format, meta?.arch)
        }
        d.bookmark(projectId, "0x%08X".format(addr), label)
        bookmarks = d.bookmarks(projectId)
        log("OK", "Bookmark '$label' @ ${"0x%08X".format(addr)}")
    }

    fun removeBookmark(context: Context, id: Long) {
        database(context).deleteBookmark(id)
        bookmarks = database(context).bookmarks(projectId)
    }

    fun removeComment(context: Context, addr: Long) {
        val key = "0x%08X".format(addr)
        if (projectId >= 0) database(context).deleteComment(projectId, key)
        comments.remove(key)
        log("OK", "Comment removed @ $key")
    }

    // --------------------------------------------------------------- notes --
    // Held in state rather than queried per call: a panel reads this during
    // composition, so it has to be cheap AND it has to change when a note is
    // added, or the list would sit there stale.
    private var notesCache by mutableStateOf<List<Note>>(emptyList())
    private var notesCacheFor = -2L

    /** Free-form notes for the open project. Empty until a binary is opened. */
    fun notes(context: Context): List<Note> {
        if (projectId < 0) return emptyList()
        if (notesCacheFor != projectId) refreshNotes(database(context))
        return notesCache
    }

    private fun refreshNotes(d: ProjectDb) {
        notesCache = if (projectId < 0) emptyList() else d.notes(projectId)
        notesCacheFor = projectId
    }

    /**
     * The first line becomes the title and the rest the body, which is what
     * the notes table is shaped for; a single-line note has an empty body.
     */
    fun addNote(context: Context, text: String) {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return
        val d = database(context)
        ensureProject(d)
        if (projectId < 0) {
            log("WARN", "Open a binary before writing notes")
            return
        }
        val title = trimmed.lineSequence().first().take(80)
        val body = trimmed.removePrefix(title).trim()
        d.note(projectId, title, body)
        refreshNotes(d)
        log("OK", "Note saved")
    }

    fun deleteNote(context: Context, id: Long) {
        val d = database(context)
        d.deleteNote(id)
        refreshNotes(d)
        log("OK", "Note deleted")
    }

    // ------------------------------------------------------------ navigation --
    // A snapshot list, not an ArrayDeque: `canGoBack` is read during
    // composition and a plain field would never recompose, so the back
    // chevron would stay disabled forever.
    private val navStack = mutableStateListOf<NavEntry>()

    val canGoBack: Boolean get() = navStack.isNotEmpty()

    /**
     * Push where we are, then move. This is the ONLY writer of history:
     * [selectFunction] is also reached from restore paths and from the rename
     * self-refresh, and pushing there would fill the stack with places the
     * user never chose to visit.
     */
    fun navigateTo(tab: Tab? = null, addr: Long? = null) {
        val toTab = tab ?: this.tab
        val addrMoves = addr != null && addr != selectedFunc
        if (toTab == this.tab && !addrMoves) return
        if (navStack.size >= NAV_LIMIT) navStack.removeAt(0)
        navStack.add(NavEntry(this.tab, selectedFunc))
        this.tab = toTab
        if (addr != null && (addrMoves || detail == null)) selectFunction(addr)
    }

    /** Pop and restore. Restoring never pushes, so back is not a move. */
    fun back(): Boolean {
        if (navStack.isEmpty()) return false
        // removeAt(size-1), never removeLast(): on API 35 `MutableList.removeLast`
        // resolves to java.util.List.removeLast and throws NoSuchMethodError
        // on every device below it.
        val entry = navStack.removeAt(navStack.size - 1)
        tab = entry.tab
        if (entry.addr != null && (entry.addr != selectedFunc || detail == null)) selectFunction(entry.addr)
        return true
    }

    fun clearHistory() { navStack.clear() }

    // --------------------------------------------------------- goto requests --
    fun requestGoto(addr: Long) { gotoAddr = addr }

    /** Returns the pending address and clears it, so one request fires once. */
    fun consumeGoto(): Long? {
        val a = gotoAddr
        gotoAddr = null
        return a
    }

    // --------------------------------------------------------------- lookups --
    // Built once per analysis. A linear scan per composition over 1,300
    // functions and tens of thousands of call edges is what these replace.
    private var funcByAddr by mutableStateOf<Map<Long, FuncInfo>>(emptyMap())
    private var funcsByStart by mutableStateOf<List<FuncInfo>>(emptyList())
    private var funcStarts by mutableStateOf(LongArray(0))
    private var callersIndex by mutableStateOf<Map<Long, List<CallEdge>>>(emptyMap())
    private var calleesIndex by mutableStateOf<Map<Long, List<CallEdge>>>(emptyMap())
    private var mappedSections by mutableStateOf<List<Section>>(emptyList())

    /** Rebuild every lookup table. Call this at each site that assigns [meta]. */
    private fun reindex() {
        val m = meta
        if (m == null) {
            funcByAddr = emptyMap()
            funcsByStart = emptyList()
            funcStarts = LongArray(0)
            callersIndex = emptyMap()
            calleesIndex = emptyMap()
            mappedSections = emptyList()
            return
        }
        val sorted = m.functions.sortedBy { it.addr }
        funcsByStart = sorted
        funcStarts = LongArray(sorted.size) { sorted[it].addr }
        funcByAddr = m.functions.associateBy { it.addr }
        calleesIndex = m.callEdges.groupBy { it.from }
        callersIndex = m.callEdges.groupBy { it.to }
        // addr == 0 means the section is not mapped into the address space, so
        // it can never contain a virtual address.
        mappedSections = m.sections.filter { it.addr != 0L && it.size > 0L }.sortedBy { it.addr }
    }

    fun functionAt(addr: Long): FuncInfo? = funcByAddr[addr]

    /** The function whose body covers [addr], by binary search over starts. */
    fun functionContaining(addr: Long): FuncInfo? {
        val starts = funcStarts
        if (starts.isEmpty()) return null
        var i = starts.binarySearch(addr)
        if (i < 0) {
            i = -i - 2
            if (i < 0) return null
        }
        val f = funcsByStart[i]
        if (f.addr == addr) return f
        return if (f.size > 0L && addr < f.addr + f.size) f else null
    }

    /** Edges that call [addr]. Matched by address, never by name. */
    fun callersOf(addr: Long): List<CallEdge> = callersIndex[addr] ?: emptyList()

    fun calleesOf(addr: Long): List<CallEdge> = calleesIndex[addr] ?: emptyList()

    /**
     * Virtual address to offset in the file on disk. The hex view highlighted
     * the wrong bytes for every binary with a non-zero load address because it
     * used the VA directly.
     */
    fun fileOffsetOf(vaddr: Long): Long? {
        for (s in mappedSections) {
            if (vaddr >= s.addr && vaddr < s.addr + s.size) return s.offset + (vaddr - s.addr)
        }
        return null
    }

    fun effectiveFuncName(addr: Long): String {
        val key = "0x%08X".format(addr)
        return renames[key]
            ?: functionAt(addr)?.name
            ?: "sub_" + key.removePrefix("0x").lowercase()
    }

    // --------------------------------------------------------- function view --
    /**
     * Load one function. This never touches navigation history: it is called
     * from restore paths, from the rename self-refresh and from [navigateTo]
     * itself, and only [navigateTo] is allowed to push.
     */
    fun selectFunction(addr: Long) {
        val path = currentPath ?: return
        selectedFunc = addr
        // The comparison column belongs to the previous function.
        pseudoAlt = null
        viewModelScope.launch {
            detailBusy = true
            // The name comes from the last analysis; a stale one is better
            // than "—" while the new decompile is in flight, because the
            // point of the bar is to say what is being worked on.
            val fn = functionAt(addr)
            val label = fn?.demangled?.takeIf { it.isNotBlank() }
                ?: fn?.name?.takeIf { it.isNotBlank() }
                ?: "0x%X".format(addr)
            decompileTargetName = label
            decompilePhase = if (decompiler == "ghidra" && sleighReady)
                "Decompiling with Ghidra p-code" else "Lifting to IR"
            decompileStartMs = System.currentTimeMillis()
            try {
                val d = withContext(Dispatchers.IO) {
                    parseDetail(NativeBridge.nativeFunction(path, addr))
                }
                if (d.ok) {
                    detail = d
                    pseudoAlt = null
                } else log("WARN", d.error ?: "function detail failed")
            } catch (e: Exception) {
                log("ERROR", e.message ?: "detail error")
            } finally {
                detailBusy = false
                decompilePhase = ""
                decompileTargetName = ""
                decompileStartMs = 0L
            }
        }
    }

    // ------------------------------------------------------------ callgraph --
    fun loadCallGraph(focus: Long = 0) {
        val path = currentPath ?: return
        viewModelScope.launch {
            callGraphBusy = true
            globalPhase = "Building call graph"
            try {
                val g = withContext(Dispatchers.IO) {
                    parseCallGraph(NativeBridge.nativeCallGraph(path, focus))
                }
                if (g.ok) {
                    callGraph = g
                    log("OK", "Call graph: ${g.edges.size} edges, ${g.funcs.size} functions")
                } else log("WARN", g.error ?: "call graph failed")
            } catch (e: Exception) {
                log("ERROR", e.message ?: "callgraph error")
            } finally { callGraphBusy = false; globalPhase = "" }
        }
    }

    // ------------------------------------------------------------- projects --
    fun saveProject(context: Context, name: String) {
        try {
            val d = database(context)
            val path = currentPath ?: return
            val id = d.upsertProject(path, name, meta?.format, meta?.arch)
            projectId = id
            log("OK", "Project '$name' saved (SQLite id=$id)")
        } catch (e: Exception) {
            log("ERROR", "save failed: ${e.message}")
        }
    }

    fun listProjects(context: Context): List<RecentProject> = database(context).recentProjects(24)

    // ---------------------------------------------------------------- export --
    // IDA's "produce file": turn the analysis into a source listing on disk.

    var exportBusy by mutableStateOf(false); private set

    /** Default filename offered to the file picker for each export kind. */
    fun suggestedExportName(kind: String): String {
        val stem = (meta?.name ?: "binary").substringBeforeLast('.')
        return when (kind) {
            "c-one" -> (detail?.name?.takeIf { it.isNotBlank() } ?: "function") + ".c"
            "h-all" -> "$stem.h"
            "asm-all" -> "$stem.asm"
            else -> "$stem.c"
        }
    }

    fun mimeForExport(kind: String): String =
        if (kind == "asm-all") "text/plain" else "text/x-c"

    /**
     * The engine writes the listing to a private cache file, which is then
     * streamed to the document the user picked. Going through a file keeps a
     * whole-binary export — which can run to megabytes — out of the heap, and
     * means a failed write never leaves a half-written document behind.
     */
    fun exportSource(context: Context, uri: Uri, kind: String) {
        val path = currentPath
        if (path == null) { log("ERROR", "Nothing to export — open a binary first"); return }
        if (exportBusy) return
        exportBusy = true
        val backend = if (decompiler == "ghidra" && sleighReady) "Ghidra" else "IR lifter"
        val scope = when (kind) {
            "c-one" -> "function"; "h-all" -> "header stub"; "asm-all" -> "assembly listing"
            else -> "whole binary"
        }
        decompilePhase = "Exporting $scope · $backend"
        globalPhase = "Exporting"
        decompileTargetName = meta?.name ?: ""
        decompileStartMs = System.currentTimeMillis()
        viewModelScope.launch(Dispatchers.IO) {
            val tmp = File(context.cacheDir, "export.tmp")
            try {
                val addr = selectedFunc ?: 0L
                val status = NativeBridge.nativeExportSource(path, kind, addr, tmp.absolutePath)
                val ok = Regex("\"ok\"\\s*:\\s*true").containsMatchIn(status)
                if (!ok) {
                    val err = Regex("\"error\"\\s*:\\s*\"([^\"]*)\"")
                        .find(status)?.groupValues?.get(1) ?: "export failed"
                    log("ERROR", err)
                    return@launch
                }
                val produced = tmp.length()
                if (produced == 0L) {
                    log("ERROR", "The engine produced an empty listing — nothing written")
                    return@launch
                }
                var copied = 0L
                context.contentResolver.openOutputStream(uri, "wt")?.use { out ->
                    copied = tmp.inputStream().use { it.copyTo(out, 64 * 1024) }
                    out.flush()
                } ?: run {
                    log("ERROR", "Could not open the chosen file for writing")
                    return@launch
                }
                if (copied != produced) {
                    log("ERROR", "Short write: $copied of $produced bytes reached the file")
                    return@launch
                }
                val fns = Regex("\"functions\"\\s*:\\s*(\\d+)").find(status)?.groupValues?.get(1)
                val bytes = Regex("\"bytes\"\\s*:\\s*(\\d+)").find(status)?.groupValues?.get(1)?.toLongOrNull()
                val what = when (kind) {
                    "c-one" -> "function"
                    "h-all" -> "header"
                    "asm-all" -> "assembly listing"
                    else -> "source"
                }
                log("OK", "Exported $what" +
                        (fns?.let { " · $it functions" } ?: "") +
                        (bytes?.let { " · ${humanBytes(it)}" } ?: ""))
            } catch (e: Exception) {
                log("ERROR", "export failed: ${e.message}")
            } finally {
                tmp.delete()
                exportBusy = false
                withContext(Dispatchers.Main) {
                    decompilePhase = ""
                    decompileTargetName = ""
                    decompileStartMs = 0L
                    globalPhase = ""
                }
            }
        }
    }

    fun savePluginLog(context: Context, uri: Uri) {
        val text = pluginOutput
        if (text.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            try {
                context.contentResolver.openOutputStream(uri, "wt")?.use { out ->
                    out.write(text.toByteArray(Charsets.UTF_8))
                } ?: run { log("ERROR", "Could not open the chosen file"); return@launch }
                log("OK", "Plugin log saved · ${humanBytes(text.length.toLong())}")
            } catch (e: Exception) {
                log("ERROR", "saving the log failed: ${e.message}")
            }
        }
    }

    fun suggestedLogName(): String {
        val stem = lastPluginName.ifEmpty { "plugin" }
            .lowercase().replace(Regex("[^a-z0-9]+"), "-").trim('-')
        return "$stem-log.txt"
    }

    private fun humanBytes(n: Long): String = when {
        n >= 1024L * 1024 -> "%.1f MB".format(n / 1024.0 / 1024.0)
        n >= 1024L -> "%.0f KB".format(n / 1024.0)
        else -> "$n B"
    }

    // -------------------------------------------------------------- debugger --
    fun debugRun(argv: List<String>, maxEvents: Int) {
        if (debugRunning || argv.isEmpty()) return
        dbgMode = DbgMode.TRACE
        viewModelScope.launch {
            debugRunning = true
            try {
                val res = withContext(Dispatchers.IO) {
                    parseDebug(NativeBridge.nativeDebugRun(argv.joinToString("\n"), maxEvents))
                }
                debugResult = res
                if (res.ok) log("OK", "Syscall trace: ${res.events.size} events")
                else log("WARN", res.error ?: "trace ended without events")
            } catch (e: Exception) {
                log("ERROR", e.message ?: "debug error")
            } finally {
                debugRunning = false
            }
        }
    }

    fun debugStop() {
        NativeBridge.nativeDebugStop()
        if (dbgMode == DbgMode.SESSION) dbgCmd("kill")
    }

    // v2: interactive session
    fun dbgCmd(json: String, onDone: ((DbgState) -> Unit)? = null) {
        viewModelScope.launch {
            dbgBusy = true
            try {
                val s = withContext(Dispatchers.IO) { parseDbg(NativeBridge.nativeDbgCmd(json)) }
                if (s.ok) {
                    dbgState = s
                    if (s.events.isNotEmpty()) {
                        val lines = s.events.map { ev ->
                            when (ev.type) {
                                "breakpoint" -> "BP HIT @ ${"0x%X".format(ev.addr)}"
                                "exit" -> "process exited (code ${ev.code})"
                                "signal" -> "signal ${ev.sig} delivered"
                                "killed" -> "process killed (sig ${ev.sig})"
                                else -> "stopped @ ${"0x%X".format(ev.pc)}"
                            }
                        }
                        dbgEvents = dbgEvents + lines.map { Pair(now(), it) }
                        if (dbgEvents.size > 300) dbgEvents = dbgEvents.takeLast(300)
                    }
                    onDone?.invoke(s)
                } else log("WARN", s.error ?: "debugger command failed")
            } catch (e: Exception) {
                log("ERROR", e.message ?: "dbg error")
            } finally {
                dbgBusy = false
            }
        }
    }

    fun dbgSpawn(prog: String, args: String) {
        dbgMode = DbgMode.SESSION
        dbgEvents = emptyList()
        log("INFO", "Spawning $prog")
        dbgCmd("""{"op":"spawn","prog":"$prog","args":"${args.replace("\"", "\\\"").replace("\n", "\\n")}"}""")
    }

    fun dbgAttach(pid: Long) {
        dbgMode = DbgMode.SESSION
        dbgEvents = emptyList()
        log("INFO", "Attaching to pid $pid")
        dbgCmd("""{"op":"attach","pid":$pid}""")
    }

    fun dbgReadMem(addr: Long, len: Long = 256) {
        dbgCmd("""{"op":"read","addr":"0x${addr.toString(16)}","len":$len}""") { s ->
            if (s.ok && s.memData.isNotEmpty()) dbgMem = Pair(s.memAddr, s.memData)
        }
    }

    fun dbgReadStack() {
        dbgCmd("""{"op":"stack","len":256}""") { s ->
            if (s.ok && s.memData.isNotEmpty()) dbgStack = Pair(s.memAddr, s.memData)
        }
    }

    fun dbgAddBp(addr: Long) = dbgCmd("""{"op":"bp_add","addr":"0x${addr.toString(16)}"}""")
    fun dbgDelBp(addr: Long) = dbgCmd("""{"op":"bp_del","addr":"0x${addr.toString(16)}"}""")
    fun dbgCont() = dbgCmd("""{"op":"cont"}""")
    fun dbgStep() = dbgCmd("""{"op":"step"}""")
    fun dbgRegs() = dbgCmd("""{"op":"regs"}""")
    fun dbgThreads() = dbgCmd("""{"op":"threads"}""")
    fun dbgKill() {
        dbgCmd("""{"op":"kill"}""")
        dbgMode = DbgMode.NONE
        dbgState = null
    }

    fun dbgBpAtSelectedFunction() {
        val addr = selectedFunc ?: return
        dbgAddBp(addr)
        log("INFO", "Breakpoint at function entry ${"0x%X".format(addr)}")
    }

    private fun now(): String =
        java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US).format(java.util.Date())

    // ----------------------------------------------------------- decompiler --
    var decompiler by mutableStateOf("ghidra"); private set
    var decompilerBackend by mutableStateOf(""); private set
    var decompilerNote by mutableStateOf(""); private set
    var sleighReady by mutableStateOf(false); private set

    /**
     * Copy the SLEIGH specifications out of assets and hand the directory to
     * the engine. They are ~1.8 MB and never change for a given build, so a
     * version marker keeps this to a single pass on first run and after an
     * update.
     */
    fun installSleigh(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val names = context.assets.list("sleigh")?.toList().orEmpty()
                if (names.isEmpty()) {
                    log("WARN", "No SLEIGH specifications bundled — using the IR decompiler")
                    return@launch
                }
                val dir = File(context.filesDir, "sleigh").apply { mkdirs() }
                val stamp = try {
                    context.packageManager.getPackageInfo(context.packageName, 0).let {
                        "${it.versionName}-${names.size}"
                    }
                } catch (e: Exception) { "unknown-${names.size}" }
                val marker = File(dir, ".installed")
                if (marker.takeIf { it.exists() }?.readText() != stamp) {
                    var bytes = 0L
                    names.forEach { name ->
                        context.assets.open("sleigh/$name").use { ins ->
                            File(dir, name).outputStream().use { bytes += ins.copyTo(it) }
                        }
                    }
                    marker.writeText(stamp)
                    log("INFO", "SLEIGH specifications installed: ${names.size} files, " +
                        "${bytes / 1024} KB")
                }
                NativeBridge.nativeSetSleighDir(dir.absolutePath)
                NativeBridge.nativeSetDecompiler(decompiler)
                withContext(Dispatchers.Main) { sleighReady = true }
                refreshDecompilerStatus()
            } catch (e: Exception) {
                log("ERROR", "SLEIGH install: ${e.message}")
            }
        }
    }

    fun selectDecompiler(which: String) {
        decompiler = if (which == "ir") "ir" else "ghidra"
        NativeBridge.nativeSetDecompiler(decompiler)
        log("INFO", "Decompiler: " + if (decompiler == "ir") "built-in IR lifter" else "Ghidra p-code")
        refreshDecompilerStatus()
    }

    fun refreshDecompilerStatus() {
        viewModelScope.launch(Dispatchers.IO) {
            val json = try {
                NativeBridge.nativeDecompilerStatus(currentPath.orEmpty())
            } catch (e: Exception) { return@launch }
            try {
                val o = JSONObject(json)
                val backend = o.optString("backend")
                val note = o.optString("note")
                withContext(Dispatchers.Main) {
                    decompilerBackend = backend
                    decompilerNote = note
                }
            } catch (e: Exception) { /* status is advisory */ }
        }
    }

    // -------------------------------------------------------------- plugins --
    fun loadPlugins(context: Context) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val dir = File(context.filesDir, "plugins").apply { mkdirs() }
                // copy bundled samples on first run
                val marker = File(dir, ".bundled")
                if (!marker.exists()) {
                    context.assets.list("plugins")?.forEach { name ->
                        if (name.endsWith(".nocturneplugin")) {
                            context.assets.open("plugins/$name").use { ins ->
                                File(dir, name).outputStream().use { ins.copyTo(it) }
                            }
                            log("INFO", "Bundled plugin installed: $name")
                        }
                    }
                    marker.writeText("1")
                }
                val list = dir.listFiles { f -> f.name.endsWith(".nocturneplugin") }
                    ?.mapNotNull { f ->
                        try {
                            val o = JSONObject(f.readText())
                            PluginDef(
                                o.optString("id", f.nameWithoutExtension),
                                o.optString("name", f.nameWithoutExtension),
                                o.optString("version", "1.0"),
                                o.optString("author", "unknown"),
                                o.optString("description", ""),
                                o.optString("script", "")
                            )
                        } catch (e: Exception) { null }
                    } ?: emptyList()
                withContext(Dispatchers.Main) { plugins = list }
                log("INFO", "Plugins loaded: ${list.size}")
            } catch (e: Exception) {
                log("ERROR", "plugin load: ${e.message}")
            }
        }
    }

    fun runPlugin(context: Context, plugin: PluginDef) {
        if (pluginRunning) return
        pluginRunning = true
        pluginOutput = ""
        lastPluginName = plugin.name
        lastPluginEffects = 0
        lastPluginOk = true
        lastPluginUndoable = false
        pluginUndo = null
        globalPhase = "Running ${plugin.name}"
        // The undo action outlives this call and is held in VM state, so it
        // must not capture an Activity.
        val appCtx = context.applicationContext
        viewModelScope.launch {
            try {
                val res = withContext(Dispatchers.IO) {
                    parseScriptResult(NativeBridge.nativeScriptRun(plugin.script, currentPath ?: ""))
                }
                val sb = StringBuilder()
                var applied = 0
                if (res.ok) {
                    sb.appendLine("=== ${plugin.name} v${plugin.version} — OK ===")
                    sb.append(res.log)
                    // apply effects to project DB
                    val d = database(context)
                    if (projectId < 0 && currentPath != null) {
                        projectId = d.upsertProject(currentPath!!, meta?.name ?: "binary", meta?.format, meta?.arch)
                    }
                    // Every key this run is about to touch is snapshotted
                    // first, including "there was nothing here", so undo can
                    // put a hand-typed name back exactly as it was.
                    val priorRenames = LinkedHashMap<String, String?>()
                    val priorComments = LinkedHashMap<String, String?>()
                    val addedBookmarks = ArrayList<Long>()
                    for (fx in res.effects) {
                        val key = "0x%08X".format(fx.addr)
                        when (fx.op) {
                            "rename" -> {
                                if (!priorRenames.containsKey(key)) priorRenames[key] = renames[key]
                                d.rename(projectId, key, renames[key] ?: functionAt(fx.addr)?.name, fx.value)
                                renames[key] = fx.value
                            }
                            "comment" -> {
                                if (!priorComments.containsKey(key)) priorComments[key] = comments[key]
                                d.comment(projectId, key, fx.value)
                                comments[key] = fx.value
                            }
                            "bookmark" -> {
                                val rowId = d.bookmark(projectId, key, fx.value)
                                if (rowId >= 0) addedBookmarks.add(rowId)
                            }
                        }
                        sb.appendLine("  [${fx.op}] ${key} -> ${fx.value}")
                    }
                    bookmarks = d.bookmarks(projectId)
                    sb.appendLine("=== ${res.effects.size} effects applied ===")
                    applied = priorRenames.size + priorComments.size + addedBookmarks.size
                    if (applied > 0) {
                        pluginUndo = PluginUndo(projectId, plugin.name, priorRenames, priorComments, addedBookmarks)
                        lastPluginUndoable = true
                    }
                } else {
                    sb.appendLine("=== ${plugin.name} FAILED (line ${res.line}): ${res.error} ===")
                }
                pluginOutput = sb.toString()
                lastPluginOk = res.ok
                lastPluginEffects = res.effects.size
                log(if (res.ok) "OK" else "ERROR", "Plugin '${plugin.name}' ${if (res.ok) "finished" else "failed: ${res.error}"}")
                if (lastPluginUndoable) {
                    notify("OK", "${plugin.name}: $applied changes", "Undo") { undoLastPlugin(appCtx) }
                }
            } catch (e: Exception) {
                log("ERROR", e.message ?: "plugin error")
            } finally {
                pluginRunning = false
                globalPhase = ""
            }
        }
    }

    // ---------------------------------------------------------- plugin undo --
    /** What a plugin run overwrote. A null value means the key did not exist. */
    private data class PluginUndo(
        val projectId: Long,
        val pluginName: String,
        val renames: Map<String, String?>,
        val comments: Map<String, String?>,
        val bookmarkIds: List<Long>
    )

    private var pluginUndo: PluginUndo? = null

    /**
     * Put back everything the last plugin run changed, in the database and in
     * the live maps. Effects used to be irreversible and could quietly replace
     * a hand-typed function name.
     */
    fun undoLastPlugin(context: Context) {
        val u = pluginUndo ?: return
        val d = database(context)
        for ((key, prior) in u.renames) {
            if (prior == null) {
                d.deleteRename(u.projectId, key)
                renames.remove(key)
            } else {
                d.rename(u.projectId, key, null, prior)
                renames[key] = prior
            }
        }
        for ((key, prior) in u.comments) {
            if (prior == null) {
                d.deleteComment(u.projectId, key)
                comments.remove(key)
            } else {
                d.comment(u.projectId, key, prior)
                comments[key] = prior
            }
        }
        u.bookmarkIds.forEach { d.deleteBookmark(it) }
        if (u.projectId >= 0) bookmarks = d.bookmarks(u.projectId)
        val n = u.renames.size + u.comments.size + u.bookmarkIds.size
        pluginUndo = null
        lastPluginUndoable = false
        dismissToast()
        log("OK", "Undid ${u.pluginName} · $n change(s) restored")
        // Only re-read the open function when its own name was rolled back;
        // a decompile can take seconds and undo should feel instant.
        val sel = selectedFunc
        if (sel != null && u.renames.containsKey("0x%08X".format(sel))) selectFunction(sel)
    }

    // ------------------------------------------------------ backend compare --
    /**
     * Decompile the open function with the backend that is NOT selected, into
     * [pseudoAlt], leaving [decompiler] and [detail] alone. The engine keeps
     * one global backend selection, so it is flipped for the duration of the
     * call and flipped back in a finally.
     */
    fun loadAlternatePseudo() {
        val path = currentPath ?: return
        val d = detail ?: return
        if (pseudoAltBusy) return
        val other = if (decompiler == "ghidra") "ir" else "ghidra"
        if (other == "ghidra" && !sleighReady) {
            pseudoAlt = null
            log("WARN", "Ghidra backend unavailable — SLEIGH specifications are not installed")
            return
        }
        val addr = d.addr
        val current = decompiler
        viewModelScope.launch {
            pseudoAltBusy = true
            try {
                val alt = withContext(Dispatchers.IO) {
                    NativeBridge.nativeSetDecompiler(other)
                    try {
                        parseDetail(NativeBridge.nativeFunction(path, addr))
                    } finally {
                        NativeBridge.nativeSetDecompiler(current)
                    }
                }
                // Drop the result if the user moved to another function
                // while the other backend was working.
                if (detail?.addr == addr) {
                    if (alt.ok) {
                        pseudoAlt = alt.pseudo
                        log("INFO", "Comparison backend: " +
                            if (other == "ir") "built-in IR lifter" else "Ghidra p-code")
                    } else {
                        pseudoAlt = null
                        log("WARN", alt.error ?: "the other backend produced nothing")
                    }
                }
            } catch (e: Exception) {
                pseudoAlt = null
                log("ERROR", e.message ?: "comparison decompile failed")
            } finally {
                pseudoAltBusy = false
            }
        }
    }

    private fun localExplanation(d: FunctionDetail): String {
        val sb = StringBuilder()
        val calls = d.asm.mapNotNull { l ->
            val c = l.comment
            if ((l.mnem == "bl" || l.mnem == "call") && c.isNotEmpty()) c.substringBefore("  //") else null
        }.distinct()
        val loops = d.blocks.size
        val strings = d.asm.map { it.comment }.filter { it.startsWith("\"") }.distinct().take(5)
        val danger = calls.mapNotNull { n ->
            when {
                n.substringAfterLast('!').lowercase() in setOf("strcpy", "strcat", "sprintf", "gets") ->
                    "buffer overflow risk: $n (no bounds checking)"
                n.lowercase().contains("system") || n.lowercase().contains("exec") ->
                    "process execution: $n"
                n.lowercase().contains("dlopen") || n.lowercase().contains("dlsym") ->
                    "dynamic code loading: $n"
                n.lowercase() in setOf("mmap", "mprotect") -> "memory protection change: $n"
                else -> null
            }
        }
        val crypto = d.asm.any { l ->
            l.ops.contains("0x67452301") || l.ops.contains("0x9E3779B9") ||
                l.ops.contains("0x637C777F") || l.ops.contains("0x63") && l.mnem.startsWith("ldr")
        }

        sb.appendLine("## ${d.displayName.ifEmpty { d.name }} @ ${"0x%X".format(d.addr)}")
        sb.appendLine()
        sb.appendLine("Size ${d.size} bytes, ${d.asm.size} instructions, ${d.blocks.size} CFG blocks, ${d.irStats?.calls ?: 0} calls.")
        sb.appendLine()
        if (calls.isNotEmpty()) {
            sb.appendLine("### Calls (${calls.size})")
            calls.take(12).forEach { sb.appendLine(" • ${it.substringBefore('@')}") }
            sb.appendLine()
        }
        if (strings.isNotEmpty()) {
            sb.appendLine("### String references")
            strings.forEach { sb.appendLine(" • $it") }
            sb.appendLine()
        }
        if (danger.isNotEmpty()) {
            sb.appendLine("### Security notes")
            danger.forEach { sb.appendLine("  [!] $it") }
            sb.appendLine()
        }
        if (crypto) sb.appendLine("### Crypto hint: looks like hashing/crypto constants present.")
        if (loops > 3) sb.appendLine("### Control flow: ${d.irStats?.whiles ?: 0} loop(s), ${d.irStats?.ifs ?: 0} branch(es) — moderately complex logic.")
        sb.appendLine()
        sb.appendLine("### Summary (auto-generated, offline heuristics)")
        when {
            danger.isNotEmpty() && calls.size > 3 ->
                sb.appendLine("This function performs several operations including potentially sensitive calls (exec/dynamic loading/copying without bounds). Worth manual review of argument setup before each call.")
            calls.isEmpty() ->
                sb.appendLine("Leaf function: pure computation on registers/stack, no external calls. Return value comes from arithmetic on a0 (first argument).")
            calls.size <= 3 ->
                sb.appendLine("Small orchestration function: sets up arguments and calls ${calls.size} helper(s), then returns.")
            else ->
                sb.appendLine("Mid-level worker: loops over data and calls multiple helpers; likely parsing/processing routine.")
        }
        sb.appendLine()
        sb.appendLine("(Offline heuristic analysis — connect an LLM endpoint in AI settings for deeper explanation.)")
        return sb.toString()
    }

    // -------------------------------------------------------------- helpers --
    private fun queryName(context: Context, uri: Uri): String? =
        context.contentResolver.query(uri, null, null, null, null)?.use { c ->
            val idx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
            if (idx >= 0 && c.moveToFirst()) c.getString(idx) else null
        }

    private fun humanSize(n: Long): String {
        val kb = 1024.0
        return when {
            n >= kb * kb * kb -> "%.1f GB".format(n / (kb * kb * kb))
            n >= kb * kb -> "%.1f MB".format(n / (kb * kb))
            n >= kb -> "%.1f KB".format(n / kb)
            else -> "$n B"
        }
    }
}

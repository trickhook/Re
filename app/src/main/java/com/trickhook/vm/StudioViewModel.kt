package com.trickhook.vm

import android.content.Context
import android.net.Uri
import android.provider.OpenableColumns
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.trickhook.BuildConfig
import com.trickhook.data.Bookmark
import com.trickhook.data.Note
import com.trickhook.data.ProjectDb
import com.trickhook.data.RecentProject
import com.trickhook.engine.NativeBridge
import com.trickhook.mcp.McpRuntime
import com.trickhook.model.ApkEntry
import com.trickhook.model.ApkResourceEntry
import com.trickhook.model.AnalysisMeta
import com.trickhook.model.CallEdge
import com.trickhook.model.CallGraphData
import com.trickhook.model.ConsoleLine
import com.trickhook.model.DbgState
import com.trickhook.model.DbgThread
import com.trickhook.model.DebugResult
import com.trickhook.model.ExportProgress
import com.trickhook.model.ExportResult
import com.trickhook.model.FuncInfo
import com.trickhook.model.FunctionDetail
import com.trickhook.model.IdaAnnotations
import com.trickhook.model.IdaCommentRow
import com.trickhook.model.IdaExport
import com.trickhook.model.IdaMarkRow
import com.trickhook.model.IdaNameRow
import com.trickhook.model.ManifestInfo
import com.trickhook.model.PluginDef
import com.trickhook.model.Section
import com.trickhook.model.ApkAnalyzer
import com.trickhook.model.idaIdcScript
import com.trickhook.model.idaPythonScript
import com.trickhook.model.parseCallGraph
import com.trickhook.model.parseDbg
import com.trickhook.model.parseDebug
import com.trickhook.model.parseDetail
import com.trickhook.model.parseExportProgress
import com.trickhook.model.parseExportResult
import com.trickhook.model.parseFunctionPage
import com.trickhook.model.parseHexAddr
import com.trickhook.model.parseIdcAnnotations
import com.trickhook.model.parseMeta
import com.trickhook.model.parseScriptResult
import com.trickhook.shizuku.DbgBackend
import com.trickhook.shizuku.ShizukuGate
import com.trickhook.update.UpdateException
import com.trickhook.update.UpdateFailure
import com.trickhook.update.UpdateState
import com.trickhook.update.deleteUpdateApk
import com.trickhook.update.downloadApk
import com.trickhook.update.failInstallPermission
import com.trickhook.update.failNoInstaller
import com.trickhook.update.failUnexpected
import com.trickhook.update.fetchLatestRelease
import com.trickhook.update.freshUpdateApk
import com.trickhook.update.humanBytes
import com.trickhook.update.storeUpdateCheckOnLaunch
import com.trickhook.update.updateCheckOnLaunch
import com.trickhook.update.updateUserAgent
import com.trickhook.update.verifyDigest
import com.trickhook.update.verifySigning
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.cancelAndJoin
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

/**
 * How often a download may move the progress bar. A 64 KB read on a fast
 * connection fires hundreds of times a second, and each one would otherwise be
 * a hop to the main thread and a recomposition to draw a bar three pixels
 * further along.
 */
private const val UPDATE_PROGRESS_MS = 120L

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

/**
 * "5203 call edges", or "12000 of 31402 call edges" when Engine.cpp had to cap
 * the array. The cap is a rendering decision; the total is the measurement, and
 * the line printed on open is where a user learns the size of the analysis.
 */
private fun edgeCount(m: AnalysisMeta): String =
    if (m.callEdgesTotal > m.callEdges.size)
        "${m.callEdges.size} of ${m.callEdgesTotal} call edges"
    else "${m.callEdges.size} call edges"

/**
 * The same shape for the other three, which until now printed a floor as a
 * count. `functions` is one page of `functionsTotal`, `strings` stops at the
 * engine's cap, and both used to render as `list.size` with nothing beside it —
 * which is precisely the bug: 12,000 read as "this binary has 12,000
 * functions" when it has 98,022.
 */
private fun functionCount(m: AnalysisMeta): String =
    if (m.functionsTotal > m.functions.size)
        "${m.functions.size} of ${m.functionsTotal} functions"
    else "${m.functions.size} functions"

private fun stringCount(m: AnalysisMeta): String =
    if (m.stringsTotal > m.strings.size)
        "${m.strings.size} of ${m.stringsTotal} strings"
    else "${m.strings.size} strings"

/**
 * How many functions one [StudioViewModel.loadMoreFunctions] press asks for.
 * The engine clamps anything above 20000 and reports what it really sent, so
 * this is the largest page that is never silently cut.
 */
private const val FUNCTION_PAGE = 20_000L

/**
 * A guard on the "load the rest" walk, not a cap on the answer: it bounds a
 * loop whose termination depends on the engine answering `count:0`, so a bug
 * or a future engine that keeps answering cannot spin forever. At 20,000 a
 * page this allows 4,000,000 functions, which no real binary approaches.
 */
private const val FUNCTION_PAGE_LIMIT = 200

/**
 * How often the export progress is read. The export runs for minutes and the
 * numbers it moves are whole functions, so four reads a second is already more
 * than the eye needs and far less than one JNI call is worth worrying about.
 */
private const val EXPORT_POLL_MS = 250L

/** What the user was asked for, in the words the sheet and the console share. */
fun exportScopeNoun(kind: String): String = when (kind) {
    "c-one" -> "function"
    "h-all" -> "header stub"
    "asm-all" -> "assembly listing"
    else -> "decompiled source"
}

/**
 * One sentence for a finished export.
 *
 * Failures are not an error state and the wording must not imply they are: a
 * function the decompiler refuses is given its banner and a marker in the file
 * where a reader will see it, and the run carries on. 5,299 written with 64
 * marked is a run that SUCCEEDED — before the engine change, one refusal ended
 * the whole export.
 *
 * A cancelled run is the same: the file is valid, it says in its own trailer
 * where it stops, and nothing already written was lost.
 */
fun exportSummary(kind: String, r: ExportResult): String {
    val what = exportScopeNoun(kind)
    val head =
        if (r.cancelled) "Stopped after ${r.functions} of ${r.total} functions — the file is complete up to there and says so"
        else "Exported $what · ${r.functions} functions"
    val marked =
        if (r.failed > 0) " · ${r.failed} could not be decompiled and are marked in the file" else ""
    val size = if (r.bytes > 0) " · ${humanBytes(r.bytes)}" else ""
    return head + marked + size
}

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
    /**
     * Which function [asmIndex]/[asmOffset] were measured in. The listing panel
     * must not restore a scroll position taken from a 4,000-instruction function
     * into a 20-instruction one; [selectFunction] keeps this in step.
     */
    var asmIndexFor by mutableStateOf<Long?>(null)
    /**
     * HexPanel's own save/restore slot: a ROW index, whose meaning depends on
     * the bytes-per-row the panel picked for the current screen width. Nothing
     * outside HexPanel may write it — to send the hex view somewhere, use
     * [requestHexGoto], which speaks in file offsets.
     */
    var hexIndex by mutableStateOf(0)
    var funcQuery by mutableStateOf("")
    var stringQuery by mutableStateOf("")
    /** functions | imports | exports */
    var symbolsMode by mutableStateOf("functions")
    /** 0 sections, 1 segments */
    var mapMode by mutableStateOf(0)
    var apkMode by mutableStateOf(0)
    var traceStep by mutableStateOf(-1)
    /**
     * Which function [traceStep] counts instructions in. [traceStep] is an
     * index into a listing exactly like [asmIndex], and a bounds check cannot
     * catch a stale one: step 5 of a 4,000-instruction body is a perfectly
     * legal index into a 40-instruction body and points at an arbitrary line
     * of it. [selectFunction] keeps this in step, and the listing panel
     * compares before it trusts the number.
     */
    var traceStepFor by mutableStateOf<Long?>(null)
    // Float-specialised: pan and zoom write these on every pointer frame, and
    // a boxed Float per frame per axis is three allocations a frame.
    var graphScale by mutableFloatStateOf(1f)
    var graphPanX by mutableFloatStateOf(0f)
    var graphPanY by mutableFloatStateOf(0f)

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

    // --------------------------------------------------------------- updates --
    // The in-app updater. Nothing here runs by itself: [checkForUpdate] is
    // reached from the overflow menu and the command palette, and on launch
    // only when [updateOnLaunch] has been switched on by hand. This is the only
    // feature in the app that uses the network at all.
    var updateState by mutableStateOf<UpdateState>(UpdateState.Idle); private set

    /**
     * Download progress, held apart from [updateState] on purpose: it moves
     * several times a second, and folding it into the state object would
     * rebuild the whole sheet on every tick.
     */
    var updateBytes by mutableLongStateOf(0L); private set
    var updateTotal by mutableLongStateOf(0L); private set

    /** The opt-in launch check. Off until someone says otherwise. */
    var updateOnLaunch by mutableStateOf(false); private set

    /** Whatever the updater has in flight — one check or one download, never both. */
    private var updateJob: Job? = null

    // ------------------------------------------------------------ cross-panel --
    /** An address another panel asked us to reveal; the panel consumes it. */
    var gotoAddr by mutableStateOf<Long?>(null); private set
    /**
     * A FILE OFFSET the hex view has been asked to reveal — not a row index.
     * HexPanel measures its bytes-per-row (8, 16 or 32) from the screen width,
     * so a row index computed by the caller means different bytes on different
     * devices; only the panel can turn an offset into a row.
     */
    var hexGotoOffset by mutableStateOf<Long?>(null)
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
    /**
     * The thread list from the last `threads` command, held apart from
     * [dbgState] on purpose: the 400 ms session poll replaces dbgState
     * wholesale, so an answer that only lived there was gone before it could be
     * drawn — which is why the panel had to catch it in local state instead.
     * Nothing on the poll path writes this. Settable so the panel can hide the
     * list again.
     */
    var dbgThreads by mutableStateOf<List<DbgThread>>(emptyList())

    /**
     * Which process the ptrace session runs in.
     *
     * [DbgBackend.LOCAL] is the default and is exactly what the debugger has
     * always done — the engine in this process, which needs root or a
     * debuggable target. The Shizuku backends put the same engine in a process
     * running as shell or root, where an imported sample can actually be made
     * executable and run. Read on the caller's thread before each command, so
     * a backend switch mid-flight cannot send one command to two places.
     */
    var dbgBackend by mutableStateOf(DbgBackend.LOCAL); private set

    /**
     * True while a sample is being pushed into /data/local/tmp. WHERE it ended
     * up is [com.trickhook.shizuku.ShizukuGate.stagedPath] and not a copy of it
     * here: the gate is the only thing that learns the staged file is gone when
     * the privileged process dies, and two fields that can disagree about
     * whether an executable is sitting in a world-visible directory is exactly
     * the wrong place for a second source of truth.
     */
    var dbgStaging by mutableStateOf(false); private set

    // v2: plugins
    var plugins by mutableStateOf<List<PluginDef>>(emptyList()); private set
    var pluginOutput by mutableStateOf<String>(""); private set
    var pluginRunning by mutableStateOf(false); private set
    /** Name of the last run, for the result header. */
    var lastPluginName by mutableStateOf(""); private set
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
    /**
     * The package the open file came out of, or null when the open file is not
     * from one. Public and observable because the APK tab reads it during
     * composition to know which archive its resource rows can be read back
     * from: `currentPath` is the EXTRACTED classes.dex, so opening the archive
     * by that path failed on every entry and blamed the entry for it.
     * Only this class may write it.
     */
    var apkFile by mutableStateOf<File?>(null); private set
    private var db: ProjectDb? = null

    fun database(context: Context): ProjectDb {
        if (db == null) db = ProjectDb(context.applicationContext)
        return db!!
    }

    init {
        log("INFO", "Nocturne ready — engine loaded (IR decompiler, call graph, debugger, plugins)")
        // The MCP control port, when the user turns it on, drives THIS session:
        // the binary that is open here, the annotations recorded here. Nothing
        // is started by registering — McpRuntime only learns where the analysis
        // lives, so its tools can answer "nothing is open" instead of guessing.
        //
        // This is not an AI feature. Nocturne holds no model client and no API
        // key; com.trickhook.mcp is the far end of a wire whose other end is an
        // assistant running on somebody's own computer.
        McpRuntime.attach(this)
    }

    /**
     * The analysis session is over, which means the Activity was finished for
     * real. Handing that to McpRuntime lets it take a running control port down
     * with it: a listener with nothing to analyse and no screen to read its
     * token off is a port open for no reason.
     */
    override fun onCleared() {
        McpRuntime.detach(this)
        super.onCleared()
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
                if (!f.exists()) {
                    log("ERROR", "Cached binary missing — open the file again: ${rp.path}")
                    return@withContext
                }
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
        projectId = db?.upsertProject(file.absolutePath, name, "APK", "") ?: -1L
        syncProjectAnnotations()

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
            loadFile(dst, entry.name.substringAfterLast('/'), fromApk = true)
        }
    }

    /**
     * Everything the APK tab shows about the open package. Cleared together,
     * because a manifest without its entry list is a half-truth about which
     * file is open.
     */
    private fun clearApkState() {
        apkFile = null
        apkEntries = emptyList()
        apkResources = emptyList()
        manifest = null
    }

    /**
     * [fromApk] marks the one caller that is part of an APK open —
     * [extractApkEntry], which hands this the .dex or .so it just pulled OUT of
     * the package. Every other caller is opening something the package knows
     * nothing about, and the APK tab's contents then describe a file that is no
     * longer open.
     */
    private fun loadFile(file: File, name: String, fromApk: Boolean = false) {
        // Restored rather than cleared: an APK walks openApk -> extractApkEntry
        // -> loadFile, and the outer phase should survive the inner one.
        val outerPhase = globalPhase
        globalPhase = "Analyzing $name"
        try {
            currentPath = file.absolutePath
            // Before the analysis, not after it: the moment currentPath moves,
            // the previous package's manifest, components and resources are
            // about a file that is not open any more — and that is just as true
            // when the new file fails to analyse. Opening a plain .so after an
            // APK used to leave the whole APK tab standing.
            if (!fromApk) clearApkState()
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
                    "${m.format} · ${m.arch.ifEmpty { "-" }} · " + functionCount(m) + " · " +
                        edgeCount(m) + " · " + stringCount(m) +
                        " · backend: ${m.backend.ifEmpty { "-" }}"
                )
                m.notes.forEach { log("INFO", it) }
                selectedFunc = null
                detail = null
                pseudoAlt = null
                resetPanelState()
                projectId = db?.upsertProject(file.absolutePath, name, m.format, m.arch) ?: -1L
                syncProjectAnnotations()
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
        asmIndex = 0; asmOffset = 0; asmIndexFor = null; hexIndex = 0
        funcQuery = ""; stringQuery = ""
        traceStep = -1; traceStepFor = null
        graphScale = 1f; graphPanX = 0f; graphPanY = 0f
        graphZoomReq = 1f; graphFitReq = false
        gotoAddr = null; hexGotoOffset = null
        clearHistory()
        lastPluginUndoable = false
        pluginUndo = null
    }

    // ------------------------------------------------- project annotations --
    /**
     * Load every annotation for the open project in one pass, including the
     * notes — those used to be fetched lazily from inside composition, which
     * put a SQLite open on the main thread.
     *
     * With no database or no project row the caches are emptied rather than
     * left alone: keeping them would show the PREVIOUS binary's renames,
     * comments and notes against the new one.
     */
    private fun syncProjectAnnotations() {
        val d = db
        if (d == null || projectId < 0) {
            renames.clear()
            comments.clear()
            bookmarks = emptyList()
            notesCache = emptyList()
            return
        }
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
    // Held in state and loaded off the main thread. The annotations sheet reads
    // this list during composition, so reading it must never open SQLite; the
    // load happens in syncProjectAnnotations(), which already runs on the IO
    // dispatcher every time a project is opened.
    private var notesCache by mutableStateOf<List<Note>>(emptyList())

    /**
     * Free-form notes for the open project. A pure state read — safe to call
     * from composition — that recomposes when a note is added or deleted.
     */
    fun notes(): List<Note> = notesCache

    private fun refreshNotes(d: ProjectDb) {
        notesCache = if (projectId < 0) emptyList() else d.notes(projectId)
    }

    /**
     * The first line becomes the title and the rest the body, which is what
     * the notes table is shaped for; a single-line note has an empty body.
     */
    fun addNote(context: Context, text: String) {
        val trimmed = text.trim()
        if (trimmed.isEmpty()) return
        viewModelScope.launch(Dispatchers.IO) {
            val d = database(context)
            ensureProject(d)
            if (projectId < 0) {
                log("WARN", "Open a binary before writing notes")
                return@launch
            }
            val title = trimmed.lineSequence().first().take(80)
            val body = trimmed.removePrefix(title).trim()
            d.note(projectId, title, body)
            refreshNotes(d)
            log("OK", "Note saved")
        }
    }

    fun deleteNote(context: Context, id: Long) {
        viewModelScope.launch(Dispatchers.IO) {
            val d = database(context)
            d.deleteNote(id)
            refreshNotes(d)
            log("OK", "Note deleted")
        }
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

    /** Ask the hex view to reveal [offset], counted from the start of the file. */
    fun requestHexGoto(offset: Long) { hexGotoOffset = offset.coerceAtLeast(0L) }

    /** Returns the pending file offset and clears it, so one request fires once. */
    fun consumeHexGoto(): Long? {
        val o = hexGotoOffset
        hexGotoOffset = null
        return o
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
        //
        // NOBITS (.bss, .tbss) passes both of those tests and still occupies
        // ZERO bytes on disk: its sh_offset conventionally points at wherever
        // the next section begins. Translating a .bss address through it hands
        // back a confident file offset into unrelated data, which is worse than
        // returning null. MapSectionRow already refuses to jump for the same
        // reason; the guard had simply never reached this shared helper.
        mappedSections = m.sections
            .filter { it.addr != 0L && it.size > 0L && it.type != "NOBITS" }
            .sortedBy { it.addr }
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
     * How many references come IN to [d]. One definition, called from every
     * panel: the same function used to read "refs in 0" on one tab and "3 in"
     * on another because four call sites each had their own rule.
     *
     * The engine fills xrefsIn only for functions it disassembled, so an empty
     * list means "not analysed", not "nobody calls this" — the call-graph index
     * answers that case.
     *
     * `xrefsInTotal` is what the engine COUNTED; `xrefsIn` is the first 64 of
     * them, which is all a bottom sheet can use. The total is the number, and
     * the sheet says how many of it it is showing — before this, the hot
     * function at 0x11149C reported 64 references when it has 561. `maxOf`
     * because an engine built before the field sends no total at all.
     */
    fun xrefInCount(d: FunctionDetail): Int =
        if (d.xrefsIn.isNotEmpty()) maxOf(d.xrefsInTotal, d.xrefsIn.size)
        else callersOf(d.addr).size

    /** How many references go OUT of [d]. Counterpart to [xrefInCount]. */
    fun xrefOutCount(d: FunctionDetail): Int =
        if (d.xrefsOut.isNotEmpty()) maxOf(d.xrefsOutTotal, d.xrefsOut.size)
        else calleesOf(d.addr).size

    /**
     * True when EVERY reference count in the app is a floor rather than a
     * count.
     *
     * The engine's xref map stops at 200,000 references, and on a real library
     * it held 200,000 of 1,323,435 — 85% dropped. Storing them all was measured
     * and costs 737 MB against 294 MB, so the cap stays; what changes is that
     * it now says so, and every screen that prints a number taken from that map
     * has to say so too. [xrefInCount], [xrefOutCount], `nCallers`, `nCallees`
     * and the call-graph index all come off it.
     *
     * The UI reads it through `floorCount`, which is what turns 561 into
     * "561+", and `xrefFloorNote`, which is the one sentence that says why.
     */
    val xrefsAreFloors: Boolean get() = meta?.xrefsAreFloors == true

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

    // ------------------------------------------------------- function paging --
    /**
     * `analyze` hands back the first 12,000 functions and says how many there
     * are; these two walk the rest. One page at a time or all of them, because
     * "the rest" of a 200,000-function binary is a minute of engine time and
     * the user should be the one who decides to spend it.
     */
    var funcPageBusy by mutableStateOf(false); private set

    /** Rows loaded while [funcPageBusy], for the footer's own progress line. */
    var funcPageLoaded by mutableStateOf(0); private set

    /**
     * Append the next page of functions, or every remaining page when [all].
     *
     * The loop advances by the RETURNED count, never by what was asked for: the
     * engine clamps a request above 20,000 and says what it really sent, so
     * advancing by the request would step straight over rows. A page that comes
     * back empty is the end of the walk and not a failure.
     *
     * Appending only ever adds to the END of a list that is already in
     * ascending address order, so nothing on screen moves and no scroll
     * position is invalidated.
     */
    fun loadMoreFunctions(all: Boolean = false) {
        val path = currentPath ?: return
        val m0 = meta ?: return
        if (funcPageBusy) return
        if (m0.functionsPending == 0) return
        // A page takes the engine mutex, and the export holds it for minutes.
        // Queuing behind it would look exactly like a hang, and the user has
        // no way to tell which of the two they are waiting on.
        if (exportBusy) {
            log("WARN", "An export has the engine. Load the rest once it has finished.")
            return
        }
        funcPageBusy = true
        funcPageLoaded = 0
        globalPhase = if (all) "Loading all functions" else "Loading functions"
        viewModelScope.launch {
            var added = 0
            var failure: String? = null
            try {
                // The whole walk runs off the main thread, append and reindex
                // included: reindex() sorts the list it is handed, and at
                // 98,022 functions that is not a main-thread sort. Snapshot
                // state is safe to write from here — loadFile already assigns
                // `meta` and reindexes from this same dispatcher.
                withContext(Dispatchers.IO) {
                    var pages = 0
                    while (true) {
                        // Re-read inside the loop: `meta` is what the append
                        // writes to, so the offset has to come from the object
                        // that is actually there now rather than from a
                        // snapshot taken before the previous page landed.
                        val m = meta ?: break
                        if (m.functions.size >= m.functionsTotal) break
                        val offset = m.functions.size.toLong()
                        val page = parseFunctionPage(
                            NativeBridge.nativeFunctionPage(path, offset, FUNCTION_PAGE)
                        )
                        if (!page.ok) { failure = page.error ?: "function page failed"; break }
                        // An empty page is how the engine says "past the end".
                        if (page.count == 0 || page.functions.isEmpty()) break
                        // Between the request and the answer the user may have
                        // opened another binary. Dropping the page is the only
                        // correct move: these rows belong to a file that is no
                        // longer open.
                        val cur = meta
                        if (cur == null || currentPath != path) break
                        meta = cur.copy(
                            functions = cur.functions + page.functions,
                            functionsTotal = maxOf(cur.functionsTotal, page.functionsTotal),
                            functionsCount = cur.functionsCount + page.count,
                            demangleFailed = cur.demangleFailed + page.demangleFailed
                        )
                        reindex()
                        added += page.count
                        funcPageLoaded = added
                        pages++
                        if (!all) break
                        if (pages >= FUNCTION_PAGE_LIMIT) {
                            failure = "stopped after $pages pages — the engine kept answering"
                            break
                        }
                    }
                }
            } catch (e: Exception) {
                failure = e.message ?: "function page error"
            } finally {
                funcPageBusy = false
                funcPageLoaded = 0
                globalPhase = ""
            }
            val m = meta
            // Copied into a val first: `failure` is a local captured and
            // written by the closure above, and Kotlin will not smart-cast one
            // of those to String no matter how the null check is spelled.
            val err = failure
            when {
                err != null -> log("ERROR", err)
                added == 0 -> log("INFO", "No more functions — the list is complete")
                m != null -> log(
                    "OK",
                    "Loaded $added more · " + functionCount(m) +
                        (if (m.functionsPending == 0) " · complete" else "")
                )
                else -> log("OK", "Loaded $added more functions")
            }
        }
    }

    // --------------------------------------------------------- function view --
    /**
     * Load one function. This never touches navigation history: it is called
     * from restore paths, from the rename self-refresh and from [navigateTo]
     * itself, and only [navigateTo] is allowed to push.
     */
    fun selectFunction(addr: Long) {
        val path = currentPath ?: return
        // A scroll position measured in one function means nothing in another:
        // restoring row 3,800 of a 4,000-instruction body into a 20-instruction
        // one opened the listing at its end. Only a real move resets it, so the
        // rename self-refresh (same address) still keeps your place.
        if (selectedFunc != addr) {
            asmIndex = 0
            asmOffset = 0
            // traceStep indexes the same listing, so it dies with the position
            // it was counted in. The panel's bounds check cannot see this: a
            // step inside the new function's range is wrong, not out of range.
            traceStep = -1
        }
        asmIndexFor = addr
        traceStepFor = addr
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
                    // Both arrays are capped by Engine.cpp and both totals
                    // come back beside them, so neither number is the cap
                    // wearing a measurement's clothes.
                    val eOf = if (g.edgesTotal > g.edges.size) " of ${g.edgesTotal}" else ""
                    val fOf = if (g.funcsTotal > g.funcs.size) " of ${g.funcsTotal}" else ""
                    log("OK", "Call graph: ${g.edges.size}$eOf edges, ${g.funcs.size}$fOf functions")
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

    // ---------------------------------------------------------------- export --
    // IDA's "produce file": turn the analysis into a source listing on disk.

    var exportBusy by mutableStateOf(false); private set

    /**
     * What the running export is doing, polled off `nativeExportProgress`.
     *
     * Held apart from [exportBusy] because it ticks several times a second for
     * minutes, and because the export is the one operation in the app that
     * blocks every other native call for its whole run: without a number
     * moving on screen the app is indistinguishable from a hang.
     *
     * Non-null from the moment an export starts until the sheet is dismissed,
     * so the final figures survive the run and can be read afterwards.
     */
    var exportProgress by mutableStateOf<ExportProgress?>(null); private set

    /** What the finished run produced, or null while one is still in flight. */
    var exportResult by mutableStateOf<ExportResult?>(null); private set

    /** Which of c-one / c-all / h-all / asm-all is running. "" when none is. */
    var exportKindRunning by mutableStateOf(""); private set

    /** Wall clock for the run, so a long export can show its own elapsed time. */
    var exportStartMs by mutableLongStateOf(0L); private set

    /** True once [stopExport] has been called and before the run notices. */
    var exportStopping by mutableStateOf(false); private set

    /** The poll timer. Cancelled when the run ends, never outlives it. */
    private var exportPollJob: Job? = null

    /**
     * Ask the export to stop.
     *
     * `nativeExportStop` is lock-free, which is the only reason this can be
     * called at all: the export holds the engine mutex for its whole run, so
     * anything that took the mutex would answer after the export was over.
     *
     * Cancellation is checked between functions, so the run does not end on
     * this line — it ends at the next function boundary, and what it has
     * already written stays written.
     */
    fun stopExport() {
        if (!exportBusy || exportStopping) return
        exportStopping = true
        try {
            NativeBridge.nativeExportStop()
            log("INFO", "Stopping the export — it finishes the function it is on")
        } catch (e: Throwable) {
            log("ERROR", "Could not stop the export: ${e.message}")
        }
    }

    /**
     * Put the progress panel away. The run, if one is still going, is NOT
     * affected: this only clears what is on screen.
     */
    fun dismissExportProgress() {
        if (exportBusy) return
        exportProgress = null
        exportResult = null
        exportKindRunning = ""
        exportStartMs = 0L
    }

    /**
     * Poll `nativeExportProgress` on a timer for as long as the run lasts.
     *
     * Main thread on purpose: the call is lock-free and cheap, and hopping to
     * IO for it would put it behind the export on the very dispatcher the
     * export is occupying.
     */
    private fun startExportPoll() {
        exportPollJob?.cancel()
        exportPollJob = viewModelScope.launch {
            while (exportBusy) {
                val tick = try {
                    parseExportProgress(NativeBridge.nativeExportProgress())
                } catch (e: Throwable) {
                    // A progress read that throws is not worth ending the
                    // export over; the run reports itself when it finishes.
                    null
                }
                if (tick == null) break
                // The engine raises its own running flag a moment after
                // exportBusy goes up here, and until it does the counters still
                // hold the PREVIOUS run's final figures. Showing those would be
                // a progress bar counting somebody else's work.
                if (tick.running) exportProgress = tick
                delay(EXPORT_POLL_MS)
            }
            // One last read after the flag drops: the engine leaves the final
            // figures in place with running:false, so this is the result rather
            // than a stale tick from halfway through.
            try {
                exportProgress = parseExportProgress(NativeBridge.nativeExportProgress())
            } catch (e: Throwable) {
                // Keep whatever the last successful poll saw.
            }
        }
    }

    /** Default filename offered to the file picker for each export kind. */
    fun suggestedExportName(kind: String): String {
        val stem = (meta?.name ?: "binary").substringBeforeLast('.')
        return when (kind) {
            "c-one" -> (detail?.name?.takeIf { it.isNotBlank() } ?: "function") + ".c"
            "h-all" -> "$stem.h"
            "asm-all" -> "$stem.asm"
            "ida-py" -> "$stem-nocturne.py"
            "ida-idc" -> "$stem-nocturne.idc"
            else -> "$stem.c"
        }
    }

    fun mimeForExport(kind: String): String = when (kind) {
        "asm-all" -> "text/plain"
        "ida-py" -> "text/x-python"
        // No registered type for IDC, and text/plain is what makes a picker
        // offer every folder rather than none.
        "ida-idc" -> "text/plain"
        else -> "text/x-c"
    }

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
        // The two IDA kinds are written here rather than by the engine: what
        // they carry is the annotation database, which the engine has never
        // seen. Everything else about the export — the picker, the busy flag,
        // the phase line — stays the same.
        if (kind == "ida-py" || kind == "ida-idc") {
            val model = idaExportModel()
            if (model == null || model.total == 0) {
                log("WARN", "Nothing to send to IDA yet — rename a function, write a comment or drop a bookmark first")
                return
            }
            exportIdaScript(context, uri, kind, model)
            return
        }
        exportBusy = true
        exportStopping = false
        exportResult = null
        exportKindRunning = kind
        exportStartMs = System.currentTimeMillis()
        // Seeded rather than left null, so the sheet opens with a line of text
        // instead of a blank while the first poll is still 250 ms away.
        exportProgress = ExportProgress(running = true, done = 0, total = 0, failed = 0, cancelling = false)
        val backend = if (decompiler == "ghidra" && sleighReady) "Ghidra" else "IR lifter"
        val scope = when (kind) {
            "c-one" -> "function"; "h-all" -> "header stub"; "asm-all" -> "assembly listing"
            else -> "whole binary"
        }
        decompilePhase = "Exporting $scope · $backend"
        globalPhase = "Exporting"
        decompileTargetName = meta?.name ?: ""
        decompileStartMs = System.currentTimeMillis()
        startExportPoll()
        viewModelScope.launch(Dispatchers.IO) {
            val tmp = File(context.cacheDir, "export.tmp")
            try {
                val addr = selectedFunc ?: 0L
                // Blocking, for minutes on a large binary, and holding the
                // engine mutex the whole time. Nothing else native can answer
                // until it returns except the progress and stop calls, which
                // are lock-free precisely so that they can.
                val res = parseExportResult(
                    NativeBridge.nativeExportSource(path, kind, addr, tmp.absolutePath)
                )
                exportResult = res
                if (!res.ok) {
                    log("ERROR", res.error ?: "export failed")
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
                log(if (res.cancelled) "WARN" else "OK", exportSummary(kind, res))
            } catch (e: Exception) {
                log("ERROR", "export failed: ${e.message}")
            } finally {
                tmp.delete()
                exportBusy = false
                withContext(Dispatchers.Main) {
                    exportStopping = false
                    decompilePhase = ""
                    decompileTargetName = ""
                    decompileStartMs = 0L
                    globalPhase = ""
                }
            }
        }
    }

    // --------------------------------------------------------- IDA Pro bridge --
    // Triage on the phone, the deep work at the desk, and the names flow both
    // ways. IDA itself is nowhere near this: what crosses is a text script the
    // user runs in their own licensed copy, and a text file it can write back.

    /** How many project notes the script header carries before it stops listing. */
    private val idaNotesInHeader = 20

    /**
     * The user's own work, in address order, ready for the script generator.
     *
     * Built on the caller's thread because [renames], [comments] and
     * [bookmarks] are Compose state that the UI thread owns; the generator
     * itself is pure and runs on IO.
     */
    private fun idaExportModel(): IdaExport? {
        val m = meta ?: return null
        // Sorting by the address XOR the sign bit is the unsigned order: an
        // address with the top bit set is a high address, not a negative one.
        val nameRows = renames.mapNotNull { (key, value) ->
            val addr = parseHexAddr(key)
            if (addr == null) null else IdaNameRow(addr, value, functionAt(addr)?.name)
        }.sortedBy { it.addr xor Long.MIN_VALUE }
        val commentRows = comments.mapNotNull { (key, value) ->
            val addr = parseHexAddr(key)
            if (addr == null) null else IdaCommentRow(addr, value)
        }.sortedBy { it.addr xor Long.MIN_VALUE }
        val markRows = bookmarks.mapNotNull { b ->
            val addr = parseHexAddr(b.addr)
            if (addr == null) null else IdaMarkRow(addr, b.label)
        }.sortedBy { it.addr xor Long.MIN_VALUE }

        val all = notes()
        val noteLines = ArrayList<String>()
        for (n in all.take(idaNotesInHeader)) {
            noteLines.add(if (n.body.isBlank()) n.title else n.title + " - " + n.body)
        }
        if (all.size > idaNotesInHeader) {
            noteLines.add("(" + (all.size - idaNotesInHeader) + " more notes, not listed)")
        }

        // ELF and PE addresses are virtual; a DEX "function" is a code_item
        // offset in the file, and Mach-O/raw never get past the hex view, so
        // their addresses are offsets too.
        val virtualAddresses = m.format == "ELF" || m.format == "PE"
        return IdaExport(
            binaryName = m.name,
            format = m.format,
            arch = m.arch,
            base = m.base,
            fileOffsets = !virtualAddresses,
            names = nameRows,
            comments = commentRows,
            marks = markRows,
            notes = noteLines,
            stamp = java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
                .format(java.util.Date())
        )
    }

    private fun exportIdaScript(context: Context, uri: Uri, kind: String, model: IdaExport) {
        exportBusy = true
        val idc = kind == "ida-idc"
        decompilePhase = "Writing " + (if (idc) "IDC" else "IDAPython") + " script"
        globalPhase = "Exporting"
        decompileTargetName = model.binaryName
        decompileStartMs = System.currentTimeMillis()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                val text = if (idc) idaIdcScript(model) else idaPythonScript(model)
                val bytes = text.toByteArray(Charsets.UTF_8)
                var written = false
                context.contentResolver.openOutputStream(uri, "wt")?.use { out ->
                    out.write(bytes)
                    out.flush()
                    written = true
                }
                if (!written) {
                    log("ERROR", "Could not open the chosen file for writing")
                    return@launch
                }
                log(
                    "OK",
                    "Exported " + (if (idc) "IDC" else "IDAPython") + " script · " +
                        "${model.names.size} names · ${model.comments.size} comments · " +
                        "${model.marks.size} bookmarks · ${humanBytes(bytes.size.toLong())}"
                )
            } catch (e: Exception) {
                log("ERROR", "export failed: ${e.message}")
            } finally {
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

    var importBusy by mutableStateOf(false); private set

    /**
     * Read an IDA-produced file and put what it holds into this project.
     *
     * The file is IDA's "File > Produce file > Dump database to IDC file";
     * [parseIdcAnnotations] says why that one and not a .map or a listing. It
     * is streamed rather than read whole, because a database dump of a real
     * binary is tens of megabytes and this is a phone.
     */
    fun importIdaAnnotations(context: Context, uri: Uri) {
        if (meta == null) { log("ERROR", "Open a binary before importing from IDA"); return }
        if (importBusy) return
        importBusy = true
        globalPhase = "Reading IDA annotations"
        viewModelScope.launch {
            try {
                val parsed = withContext(Dispatchers.IO) {
                    context.contentResolver.openInputStream(uri)?.use { ins ->
                        ins.bufferedReader().useLines { lines -> parseIdcAnnotations(lines) }
                    }
                }
                if (parsed == null) log("ERROR", "Could not read the chosen file")
                else applyIdaAnnotations(context, parsed)
            } catch (e: Exception) {
                log("ERROR", "IDA import failed: ${e.message}")
            } finally {
                importBusy = false
                globalPhase = ""
            }
        }
    }

    /** How many of [p]'s addresses mean something in this binary, shifted by [delta]. */
    private fun scoreIdaDelta(p: IdaAnnotations, delta: Long): Int {
        var hits = 0
        for (a in p.names.keys) if (functionAt(a + delta) != null) hits++
        for (a in p.comments.keys) if (functionContaining(a + delta) != null) hits++
        for (a in p.marks.keys) if (functionContaining(a + delta) != null) hits++
        return hits
    }

    /**
     * Apply an IDA file through the ordinary annotation paths, so everything
     * lands in ProjectDb and shows up wherever a rename or a comment already
     * shows up.
     *
     * Every address is checked against this binary first. A name that matches
     * nothing here is counted and reported rather than written: a silent
     * partial import is the kind of answer that looks like it worked.
     */
    private fun applyIdaAnnotations(context: Context, p: IdaAnnotations) {
        val m = meta ?: return
        if (p.total == 0) {
            log(
                "ERROR",
                "No names or comments in that file. Nocturne reads IDA's " +
                    "\"File > Produce file > Dump database to IDC file\" output" +
                    (if (p.unreadable > 0) " — ${p.unreadable} line(s) looked right but could not be read" else "")
            )
            return
        }
        // The same question the exported script asks, asked in reverse: IDA's
        // addresses are IDA's. Try no shift, and the shift the file's own
        // segment table implies, and keep whichever lands on real functions.
        val deltas = ArrayList<Long>()
        deltas.add(0L)
        val seg = p.lowestSegment
        if (seg != null && m.base != seg) deltas.add(m.base - seg)
        var delta = 0L
        var best = -1
        for (d in deltas) {
            val score = scoreIdaDelta(p, d)
            if (score > best) { best = score; delta = d }
        }
        if (best <= 0) {
            log(
                "ERROR",
                "None of the ${p.total} addresses in that file exist in this binary — " +
                    "nothing was changed. Is it the same file, loaded at the same address?"
            )
            return
        }
        if (delta != 0L) {
            val shift = if (delta < 0) "-0x%X".format(-delta) else "0x%X".format(delta)
            log("INFO", "That file's addresses are $shift away from this binary's; applied with that shift")
        }

        var namesApplied = 0
        var namesReplaced = 0
        var namesSame = 0
        var namesMissing = 0
        var namesInside = 0
        var cmtApplied = 0
        var cmtSame = 0
        var cmtMissing = 0
        var markApplied = 0
        var markSame = 0
        var markMissing = 0

        // One transaction around the lot. Each rename and comment still goes
        // through its own public path — this only stops SQLite from committing
        // (and fsyncing) once per row, which for a symbolised binary is
        // thousands of commits on the main thread. It also makes the import
        // all-or-nothing rather than half-applied if something throws.
        val sql = database(context).writableDatabase
        var committed = false
        sql.beginTransaction()
        try {
            for ((addr0, name) in p.names) {
                val addr = addr0 + delta
                if (functionAt(addr) == null) {
                    namesMissing++
                    if (functionContaining(addr) != null) namesInside++
                    continue
                }
                // effectiveFuncName covers both cases that are not a change:
                // this project already renamed it that, or the engine read the
                // very same name out of the symbol table.
                if (effectiveFuncName(addr) == name) { namesSame++; continue }
                if (renames["0x%08X".format(addr)] != null) namesReplaced++
                renameFunction(context, addr, name)
                namesApplied++
            }

            for ((addr0, text) in p.comments) {
                val addr = addr0 + delta
                if (!knownAddress(addr)) { cmtMissing++; continue }
                if (comments["0x%08X".format(addr)] == text) { cmtSame++; continue }
                addComment(context, addr, text)
                cmtApplied++
            }

            for ((addr0, label) in p.marks) {
                val addr = addr0 + delta
                if (!knownAddress(addr)) { markMissing++; continue }
                val key = "0x%08X".format(addr)
                // addBookmark always inserts, so re-importing the same file
                // would otherwise stack up duplicates.
                if (bookmarks.any { it.addr == key && it.label == label }) { markSame++; continue }
                addBookmark(context, addr, label)
                markApplied++
            }
            sql.setTransactionSuccessful()
            committed = true
        } finally {
            sql.endTransaction()
            // A rollback leaves the in-memory maps ahead of the database, so
            // re-read rather than leave the screen describing rows that are no
            // longer there.
            if (!committed) syncProjectAnnotations()
        }

        log(
            "INFO",
            "IDA file: ${p.lines} lines · names $namesApplied applied, $namesSame already matched, " +
                "$namesMissing unmatched · comments $cmtApplied applied, $cmtSame already matched, " +
                "$cmtMissing unmatched · bookmarks $markApplied added, $markSame already there, " +
                "$markMissing unmatched"
        )
        if (namesReplaced > 0) {
            log("INFO", "$namesReplaced of the applied names replaced a name typed here")
        }
        if (namesInside > 0) {
            log("INFO", "$namesInside of the unmatched names point inside a function rather than at its start")
        }
        if (p.dummySkipped > 0) {
            log("INFO", "${p.dummySkipped} name(s) IDA had generated for itself (sub_…, loc_…) were skipped")
        }
        if (p.unreadable > 0) {
            log("INFO", "${p.unreadable} line(s) named a call we read but could not be parsed")
        }
        val applied = namesApplied + cmtApplied + markApplied
        val missed = namesMissing + cmtMissing + markMissing
        log(
            if (missed > 0) "WARN" else "OK",
            "Imported from IDA: $applied applied, ${namesSame + cmtSame + markSame} already matched" +
                (if (missed > 0) ", $missed with no address in this binary" else "")
        )
    }

    /** True when [addr] is somewhere this binary actually has: a function or a mapped section. */
    private fun knownAddress(addr: Long): Boolean =
        functionAt(addr) != null || functionContaining(addr) != null || fileOffsetOf(addr) != null

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
        // Was dbgCmd("kill") — a bare word, not JSON. The engine's parser read
        // it as an empty object, matched no op and answered nothing, so this
        // branch has never stopped a session. It stayed invisible because the
        // Stop button is only enabled during a legacy trace, where dbgMode is
        // TRACE. Across a Binder it would not have stayed invisible.
        if (dbgMode == DbgMode.SESSION) dbgKill()
    }

    /**
     * Fold one command's answer into the session state instead of replacing it.
     *
     * Every op answers with only the fields it is about: `poll` carries the
     * state, the pid and the events but no registers; `regs` carries the
     * registers and the arch but no state; `stack`, `read` and `bp_list` carry
     * neither. Overwriting [dbgState] with the last answer is why the screen
     * flipped between STOPPED and NONE twice a second while a process sat at a
     * breakpoint, why Continue and Step were disabled on every other flip, and
     * why the register strip blanked itself at the moment the registers
     * arrived. The debugger screen worked around it with a private accumulator;
     * the state belongs here, where every reader gets the same answer.
     *
     * The discriminators are fields that only the real answer carries. `arch`
     * marks a register set: parseDbg files every top-level 0x value as a
     * register, so the lone "addr" that `read` and `bp_add` echo back would
     * otherwise replace all of them. `hasBps` marks the breakpoint set, so
     * deleting the last breakpoint stays an empty list rather than reading as
     * "this answer said nothing about breakpoints".
     */
    private fun mergeDbg(prev: DbgState?, s: DbgState): DbgState {
        // "none" is what parseDbg reports for an answer with no state field at
        // all, which is most of them. It is not news that the session ended.
        val st = if (s.state.isNotEmpty() && s.state != "none") s.state else prev?.state ?: "none"
        val hasRegs = s.arch.isNotEmpty()
        return s.copy(
            state = st,
            pid = if (s.pid != 0L) s.pid else prev?.pid ?: 0L,
            arch = if (hasRegs) s.arch else prev?.arch ?: "",
            // Registers belong to a stop. While the process runs they are a
            // lie, and the last stop's values would be worse than none at all.
            regs = when {
                st == "running" || st == "exited" -> emptyMap()
                hasRegs -> s.regs
                else -> prev?.regs ?: emptyMap()
            },
            bps = if (s.hasBps) s.bps else prev?.bps ?: emptyList()
        )
    }

    /**
     * One command to whichever backend is live.
     *
     * [DbgBackend.LOCAL] is the JNI call this has always been. The Shizuku
     * backends put the identical JSON across a Binder into a process running as
     * shell or root — same protocol, same parser, same event log. The transport
     * never throws: a dead binder comes back as `{"ok":false,"error":...}` and
     * is reported like any other failed command.
     *
     * Blocking; only [dbgCmd] calls it, and only from Dispatchers.IO.
     */
    private fun dbgSend(backend: DbgBackend, json: String): String =
        if (backend == DbgBackend.LOCAL) NativeBridge.nativeDbgCmd(json) else ShizukuGate.cmd(json)

    /**
     * Point the debugger at a different process. Any live session is killed
     * first: a session belongs to the backend that started it, and carrying the
     * pid, registers and breakpoints of one over to the other would describe a
     * process that the new backend cannot even see.
     */
    fun selectDbgBackend(backend: DbgBackend) {
        if (backend == dbgBackend) return
        // Shell and root are the SAME privileged process, relabelled once
        // Shizuku says which uid it runs as. Killing a session for that would
        // throw away a live tracee because a caption changed.
        val sameProcess = backend.privileged && dbgBackend.privileged
        if (!sameProcess) {
            if (dbgMode == DbgMode.SESSION) dbgKill()
            dbgClearStaged()
        }
        dbgBackend = backend
        log("INFO", "Debugger backend: ${backend.label}")
    }

    // v2: interactive session
    fun dbgCmd(json: String, onDone: ((DbgState) -> Unit)? = null) {
        // Read on the caller's thread, not inside the coroutine: the 400 ms
        // poll outlives a backend switch, and a command must go where it was
        // aimed when it was issued.
        val backend = dbgBackend
        // A privileged backend whose process has gone answers EVERY command
        // with an error, and the session poll sends four of them every 400 ms.
        // Since a failed command is now a toast, that is a toast twice a second
        // for as long as the tab is open — so the session ends here, once, with
        // one line saying why, instead.
        if (backend.privileged && !ShizukuGate.ready) {
            if (dbgMode == DbgMode.SESSION) {
                dbgMode = DbgMode.NONE
                clearDbgSessionViews()
                log("WARN", "The privileged debugger is not connected. Session ended.")
            }
            return
        }
        viewModelScope.launch {
            dbgBusy = true
            try {
                val s = withContext(Dispatchers.IO) { parseDbg(dbgSend(backend, json)) }
                if (s.ok) {
                    dbgState = mergeDbg(dbgState, s)
                    // The event ring drops 500 at a time at 2000 and used to
                    // say nothing, so a session that ate 500 stops showed one
                    // that never happened beside one it ate. The gap goes in
                    // the log IN ORDER, before the events that survived it,
                    // because that is where the missing ones were.
                    if (s.eventsDropped > 0) {
                        dbgEvents = dbgEvents +
                            Pair(now(), "— ${s.eventsDropped} earlier events dropped, the ring was full —")
                    }
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
        dbgClearStaged()
        clearDbgSessionViews()
        log("INFO", "Spawning $prog")
        dbgCmd("""{"op":"spawn","prog":"$prog","args":"${args.replace("\"", "\\\"").replace("\n", "\\n")}"}""")
    }

    fun dbgAttach(pid: Long) {
        dbgMode = DbgMode.SESSION
        dbgEvents = emptyList()
        dbgClearStaged()
        clearDbgSessionViews()
        log("INFO", "Attaching to pid $pid")
        dbgCmd("""{"op":"attach","pid":$pid}""")
    }

    /**
     * Copy the open file into /data/local/tmp through the privileged process,
     * make it executable, and spawn it under ptrace.
     *
     * This is the whole reason the Shizuku backend exists. The app cannot do
     * any part of it: since Android 10 app_data_file carries no execute
     * permission, so an imported sample cannot be execve'd by this process at
     * all, at any path, however it was chmod'ed. The privileged process runs as
     * shell, /data/local/tmp is shell_data_file, and shell may execute there
     * and ptrace its own child. That is the gdbserver workflow.
     *
     * The bytes cross the Binder rather than being read from a path, because a
     * shell-uid process cannot read this app's data directory.
     */
    fun dbgSpawnStaged(args: String) {
        if (dbgStaging) return
        val backend = dbgBackend
        if (!backend.canStage) {
            log("WARN", "The in-process backend cannot run a file from app storage.")
            return
        }
        val path = currentPath
        if (path == null) {
            log("WARN", "No file is open to run.")
            return
        }
        viewModelScope.launch {
            dbgStaging = true
            globalPhase = "Staging"
            try {
                val res = withContext(Dispatchers.IO) { ShizukuGate.stageSample(File(path)) }
                if (!res.ok) {
                    log("ERROR", "Staging failed: ${res.note}")
                    return@launch
                }
                val arch = res.machine.ifEmpty { "unknown" }
                log("OK", "Staged to ${res.path} ($arch)")
                dbgMode = DbgMode.SESSION
                dbgEvents = emptyList()
                clearDbgSessionViews()
                val escaped = args.replace("\"", "\\\"").replace("\n", "\\n")
                dbgCmd("""{"op":"spawn","prog":"${res.path}","args":"$escaped"}""")
            } catch (e: Exception) {
                log("ERROR", e.message ?: "staging error")
            } finally {
                dbgStaging = false
                globalPhase = ""
            }
        }
    }

    /**
     * Delete the staged sample. Called whenever a session ends, so the tmp
     * directory does not accumulate executables — the privileged service also
     * sweeps on connect and on teardown, because a crash reaches neither of the
     * tidy paths.
     */
    private fun dbgClearStaged() {
        if (!dbgBackend.privileged) return
        // Off the main thread: this is a Binder call into a process that may be
        // sitting in waitpid. It is a no-op when nothing is staged.
        viewModelScope.launch {
            withContext(Dispatchers.IO) { ShizukuGate.unstage() }
        }
    }

    /**
     * Bytes, stack, threads and the merged session state all belong to one
     * process; none survive it. [dbgState] is in here because it now
     * ACCUMULATES — a new session that inherited the old one's registers and
     * breakpoints would be describing a process that no longer exists.
     */
    private fun clearDbgSessionViews() {
        dbgMem = null
        dbgStack = null
        dbgThreads = emptyList()
        dbgState = null
    }

    /**
     * Read [len] bytes at [addr] into [dbgMem], which is what the MEMORY
     * hexdump draws. An empty answer is reported rather than ignored: leaving
     * the previous dump on screen made a failed read look like a successful one
     * at the new address.
     */
    fun dbgReadMem(addr: Long, len: Long = 256) {
        dbgCmd("""{"op":"read","addr":"0x${addr.toString(16)}","len":$len}""") { s ->
            if (s.memData.isNotEmpty()) dbgMem = Pair(s.memAddr, s.memData)
            else log("WARN", "No memory readable at ${"0x%X".format(addr)}")
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

    /**
     * Ask for the live thread list and keep the answer in [dbgThreads], where
     * the poll cannot overwrite it. Renamed from `dbgThreads()`, which had no
     * callers because its answer was unreachable.
     */
    fun dbgRefreshThreads() = dbgCmd("""{"op":"threads"}""") { s -> dbgThreads = s.threads }

    fun dbgKill() {
        dbgCmd("""{"op":"kill"}""")
        dbgMode = DbgMode.NONE
        clearDbgSessionViews()
        // The staged executable goes with the process it was staged for.
        // Leaving one behind in a directory every shell process on the device
        // can reach is untidy at best.
        dbgClearStaged()
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
    var decompilerNote by mutableStateOf(""); private set
    var sleighReady by mutableStateOf(false); private set

    /**
     * Copy the SLEIGH specifications out of assets and hand the directory to
     * the engine. They are ~3.2 MB and never change for a given build, so a
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
                // Only the note is kept: the backend name was written here and
                // read nowhere, while every screen that shows a backend takes
                // it from `decompiler`/`detail.backend`.
                val note = JSONObject(json).optString("note")
                withContext(Dispatchers.Main) { decompilerNote = note }
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

    // -------------------------------------------------------------- updates --
    /**
     * Read the launch preference and clear any APK a previous run left behind.
     *
     * A pending download at startup is always stale: either it installed — in
     * which case this process is the new build — or it was abandoned. Nothing
     * may reuse it either way, because nothing would re-verify it, so it goes.
     */
    fun loadUpdatePrefs(context: Context) {
        val app = context.applicationContext
        viewModelScope.launch {
            val on = withContext(Dispatchers.IO) { updateCheckOnLaunch(app) }
            // Tested back on the main thread, where [updateJob] is the only
            // thing that writes it: a download started while this preference
            // was being read off disk must not have its file deleted underneath
            // it. In practice this runs before the first frame, but the check
            // costs nothing and the failure it prevents is silent.
            if (updateJob == null) withContext(Dispatchers.IO) { deleteUpdateApk(app) }
            updateOnLaunch = on
            if (on && updateState is UpdateState.Idle) checkForUpdate(app, manual = false)
        }
    }

    /**
     * Turn the launch-time check on or off. Named `apply…` rather than `set…`
     * because `var updateOnLaunch` already compiles to `setUpdateOnLaunch`.
     */
    fun applyUpdateOnLaunch(context: Context, on: Boolean) {
        updateOnLaunch = on
        val app = context.applicationContext
        viewModelScope.launch(Dispatchers.IO) { storeUpdateCheckOnLaunch(app, on) }
        log(
            "INFO",
            if (on) "Update check on launch: on — Nocturne will ask GitHub once per start"
            else "Update check on launch: off — updates are checked only when you ask"
        )
    }

    /**
     * Raised by the overflow menu and the command palette. A result already in
     * hand is kept rather than re-fetched: GitHub allows 60 unauthenticated
     * requests an hour and opening a sheet is not a reason to spend one.
     */
    fun openUpdates(context: Context) {
        when (updateState) {
            is UpdateState.Idle, is UpdateState.Failed -> checkForUpdate(context, manual = true)
            else -> Unit
        }
    }

    /**
     * Ask GitHub what the latest release is and compare it with this build.
     *
     * [manual] is the difference between a question the user asked and one the
     * launch preference asked on their behalf: a failure they asked for goes to
     * the toast channel, a failure they did not goes to the console only. A
     * tool that shouts about a network call it made on its own initiative is
     * worse than one that stays quiet about it.
     */
    fun checkForUpdate(context: Context, manual: Boolean) {
        if (updateJob?.isActive == true) return
        val app = context.applicationContext
        updateState = UpdateState.Checking
        updateBytes = 0L
        updateTotal = 0L
        updateJob = viewModelScope.launch {
            try {
                val rel = fetchLatestRelease(
                    BuildConfig.UPDATE_REPO,
                    BuildConfig.UPDATE_MANIFEST_ASSET,
                    updateUserAgent(BuildConfig.VERSION_NAME)
                )
                val mine = BuildConfig.VERSION_CODE.toLong()
                if (rel.versionCode <= mine) {
                    updateState = UpdateState.UpToDate(BuildConfig.VERSION_NAME, mine)
                    if (manual) log("OK", "Nocturne ${BuildConfig.VERSION_NAME} is the newest published build")
                } else {
                    updateState = UpdateState.Available(rel)
                    log(
                        "INFO",
                        "Update available: Nocturne ${rel.versionName} · ${humanBytes(rel.apkSize)}"
                    )
                }
            } catch (e: UpdateException) {
                updateState = UpdateState.Failed(e.failure, null)
                reportUpdateFailure(e.failure, manual)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                val failure = failUnexpected(e.message)
                updateState = UpdateState.Failed(failure, null)
                reportUpdateFailure(failure, manual)
            }
        }
    }

    /**
     * Fetch the release APK into app-private storage and put it through both
     * verification checks before anyone is offered a button that installs it.
     *
     * The order is the whole point. The file is written, then hashed off the
     * disk, then its signing certificate is read off the disk, and only then
     * does [UpdateState.Ready] appear. A file that fails either check is
     * deleted before the message about it is raised, so there is never a moment
     * where a rejected APK is sitting on the device with a story attached.
     */
    fun downloadUpdate(context: Context) {
        val standing = updateState
        val rel = when (standing) {
            is UpdateState.Available -> standing.rel
            is UpdateState.Failed -> standing.rel
            else -> null
        } ?: return
        if (updateJob?.isActive == true) return
        val app = context.applicationContext
        updateBytes = 0L
        updateTotal = rel.apkSize
        updateState = UpdateState.Downloading(rel)
        updateJob = viewModelScope.launch {
            try {
                val dest = withContext(Dispatchers.IO) { freshUpdateApk(app) }
                var lastTick = 0L
                downloadApk(rel, dest, updateUserAgent(BuildConfig.VERSION_NAME)) { got, total ->
                    val now = System.currentTimeMillis()
                    if (got >= total || now - lastTick >= UPDATE_PROGRESS_MS) {
                        lastTick = now
                        withContext(Dispatchers.Main) {
                            updateBytes = got
                            updateTotal = total
                        }
                    }
                }

                // Check 2 of 3: the digest of the bytes that actually landed.
                updateState = UpdateState.Verifying(rel, "SHA-256")
                val digestFailure = withContext(Dispatchers.IO) { verifyDigest(dest, rel) }
                if (digestFailure != null) {
                    discardUpdate(app)
                    throw UpdateException(digestFailure)
                }

                // Check 3 of 3: who signed it, against who signed us.
                updateState = UpdateState.Verifying(rel, "signing certificate")
                val signingFailure = withContext(Dispatchers.IO) { verifySigning(app, dest, rel) }
                if (signingFailure != null) {
                    discardUpdate(app)
                    throw UpdateException(signingFailure)
                }

                updateState = UpdateState.Ready(rel, dest.absolutePath)
                log("OK", "Update verified — SHA-256 and signing certificate both match")
            } catch (e: UpdateException) {
                updateState = UpdateState.Failed(e.failure, rel)
                log("ERROR", e.failure.title)
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                discardUpdate(app)
                val failure = failUnexpected(e.message)
                updateState = UpdateState.Failed(failure, rel)
                log("ERROR", failure.title)
            }
        }
    }

    /**
     * Stop a download or a verification and take the partial file with it.
     *
     * The delete runs in a fresh coroutine after the old job has actually
     * stopped: issuing it from inside the cancelled job would race the stream
     * that is still being written.
     */
    fun cancelUpdateDownload(context: Context) {
        val job = updateJob ?: return
        val standing = updateState
        val rel = when (standing) {
            is UpdateState.Downloading -> standing.rel
            is UpdateState.Verifying -> standing.rel
            else -> null
        }
        updateBytes = 0L
        updateState = if (rel != null) UpdateState.Available(rel) else UpdateState.Idle
        val app = context.applicationContext
        // The cleanup becomes the job in flight. Without that, Download pressed
        // immediately after Cancel would start writing a new file while this
        // coroutine was still waiting to delete the old one — and delete the
        // new one instead.
        updateJob = viewModelScope.launch {
            job.cancelAndJoin()
            discardUpdate(app)
        }
        log("INFO", "Update download cancelled — the partial file was deleted")
    }

    /** The sheet pressed Install and Android has not granted the permission for it. */
    fun updateInstallBlocked() {
        log("WARN", failInstallPermission().title)
    }

    /**
     * Nothing on this device answered a request to install a package. Rare —
     * a stripped or managed image — but it throws out of `launch()`, and an
     * uncaught ActivityNotFoundException there would take the app down at the
     * last step of a flow that had otherwise gone perfectly.
     */
    fun updateNoInstaller() {
        val standing = updateState
        val rel = if (standing is UpdateState.Ready) standing.rel else null
        val failure = failNoInstaller()
        updateState = UpdateState.Failed(failure, rel)
        log("ERROR", failure.title)
    }

    /**
     * Anything else that went wrong at the moment of hand-over — a FileProvider
     * that cannot serve the path, a SecurityException on the grant. There is no
     * way to exercise this from a build machine, so it is caught rather than
     * trusted: a crash on the last press of a flow that had gone perfectly is
     * the worst possible place to find out.
     */
    fun updateHandoverFailed(message: String?) {
        val standing = updateState
        val rel = if (standing is UpdateState.Ready) standing.rel else null
        val failure = failUnexpected(message)
        updateState = UpdateState.Failed(failure, rel)
        log("ERROR", failure.title)
    }

    /**
     * The system installer came back. On a successful replace this process is
     * usually killed before the result ever arrives, so a success here is a
     * bonus rather than something the flow depends on; a dismissal leaves the
     * verified APK in place so the button still works.
     */
    fun updateInstallerReturned(ok: Boolean) {
        if (ok) {
            updateState = UpdateState.Idle
            log("OK", "The installer accepted the update")
        } else {
            // RESULT_CANCELED means they backed out; RESULT_FIRST_USER means the
            // platform refused it. Neither installed anything, and neither is
            // worth a toast — the sheet is still open behind the installer with
            // the verified APK ready to try again.
            log("INFO", "The installer did not complete — nothing was installed")
        }
    }

    private fun reportUpdateFailure(failure: UpdateFailure, manual: Boolean) {
        if (manual) log("ERROR", failure.title) else log("INFO", "Update check: ${failure.title}")
    }

    /** NonCancellable so a rejected or cancelled APK is still removed. */
    private suspend fun discardUpdate(app: Context) {
        withContext(NonCancellable + Dispatchers.IO) { deleteUpdateApk(app) }
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

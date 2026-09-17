package com.trickhook.ui

import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab
import com.trickhook.vm.TabGroup

data class Command(
    val title: String,
    val subtitle: String = "",
    val shortcut: String = "",
    val action: () -> Unit
)

// global overlay state
var showPalette by mutableStateOf(false)
var showSearch by mutableStateOf(false)
var showGoto by mutableStateOf(false)
var showShortcutsHelp by mutableStateOf(false)

/** Raised from the Pseudo-C bar, the overflow menu and the command palette. */
var showExportSheet by mutableStateOf(false)

/**
 * The progress panel for a running "produce file" export.
 *
 * Raised automatically when an export starts, and again by tapping the export
 * bar while one is running. Dismissing it does NOT stop the export — the
 * header's phase line and the bar both keep saying the run is alive, and this
 * comes back on a tap.
 */
var showExportProgress by mutableStateOf(false)

/** Raised from the overflow menu and the command palette. */
var showUpdateSheet by mutableStateOf(false)

/**
 * Raised from the overflow menu and the command palette, which is the file
 * invariant StudioApp states: everything in the overflow is reachable here too.
 *
 * The row below deliberately carries no state in its label, so the palette's
 * `remember` keys do not need to grow for it — whether the server is up is the
 * sheet's business, not this list's.
 */
var showMcpSheet by mutableStateOf(false)

/**
 * How many hits of one kind the search dialog draws before it stops and says
 * how many more there are. The number itself matters far less than the fact
 * that the header always prints "{shown} of {total}": the old dialog capped
 * every group silently, so a query matching six functions and a query matching
 * three hundred drew exactly the same six rows.
 */
private const val HITS_PER_GROUP = 6

/**
 * StudioApp's key handler maps Ctrl+1..Ctrl+9 onto the first nine tabs and
 * nothing onto the rest, so only the first nine may advertise a number.
 * The palette used to print Ctrl+10/11/12 for Debugger, Plugins and Console,
 * which no key event can ever produce.
 */
private const val NUMBERED_TABS = 9

/** ApkPanel's section switcher order: manifest, components, permissions, dex, libs, resources. */
private const val APK_MODE_DEX = 3

@Composable
fun CommandPaletteOverlay(vm: StudioViewModel, openFile: () -> Unit, importIda: () -> Unit) {
    val ide = LocalIde.current
    val ctx = androidx.compose.ui.platform.LocalContext.current

    if (showPalette) {
        Dialog(
            onDismissRequest = { showPalette = false },
            properties = DialogProperties(usePlatformDefaultWidth = false)
        ) {
            Surface(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 40.dp, vertical = 80.dp)
                    .border(1.dp, ide.borderStrong, MaterialTheme.shapes.medium),
                color = ide.panel,
                shape = MaterialTheme.shapes.medium,
                tonalElevation = 8.dp
            ) {
                var query by remember { mutableStateOf("") }
                val requester = remember { FocusRequester() }
                LaunchedEffect(Unit) { requester.requestFocus() }

                // Keyed on cheap scalars, never on `vm.meta` itself: AnalysisMeta is a
                // data class holding tens of thousands of elements, so using it as a
                // remember key runs a deep equals on every keystroke.
                // Every piece of state a command's LABEL or PRESENCE depends on
                // has to be a key here, or the row keeps the wording it was
                // built with: `compareBackends` is in the list because the
                // comparison row says what it will do next, not what is on.
                val commands = remember(
                    vm.plugins.size, vm.tab, vm.meta != null, vm.decompiler, vm.canGoBack,
                    vm.compareBackends,
                    // Both of these change a row's PRESENCE and its wording:
                    // "load the remaining 86,022" is a different row from
                    // "load the remaining 66,022", and the stop row exists only
                    // while an export is actually running.
                    vm.exportBusy, vm.meta?.functionsPending ?: 0
                ) {
                    buildList {
                        add(Command("Open file (APK/ELF/EXE/DEX)", "pick a binary to analyse", "Ctrl+O", openFile))
                        add(Command(
                            "Open native lib from installed app",
                            "reads an installed app's own split APKs — no root, no reinstall", ""
                        ) { showInstalledApps = true })
                        add(Command(
                            "Load bundled test target",
                            "a crackme to analyse and defeat · running it needs a Shizuku backend",
                            ""
                        ) { vm.openBundledSample(ctx) })
                        add(Command("Go to address…", "resolve a virtual address and jump there", "Ctrl+G") { showGoto = true })
                        add(Command(
                            "Search everywhere",
                            "functions · disassembly · pseudo-C · strings · symbols · sections · DEX",
                            "Ctrl+F"
                        ) { showSearch = true })
                        if (vm.canGoBack) {
                            add(Command("Back", "return to where you jumped from", "") { vm.back() })
                        }
                        add(Command("Save project", "persist renames, comments, bookmarks", "Ctrl+S") { vm.saveProject(ctx, vm.meta?.name ?: "project") })
                        add(Command("Toggle dark/light theme", "", "Ctrl+T") { vm.darkTheme = !vm.darkTheme })
                        add(Command("Load call graph", "whole binary", "") { vm.loadCallGraph(0) })

                        // The graph's zoom and fit live in the ViewModel exactly
                        // so something outside the panel can drive them, and
                        // until now nothing did: two consumers, no producer.
                        // The values match the panel's own toolbar buttons.
                        if (vm.meta != null) {
                            add(Command(
                                "Fit graph to screen",
                                "frame the whole control-flow graph", ""
                            ) {
                                vm.navigateTo(tab = Tab.GRAPH)
                                vm.graphFitReq = true
                            })
                            add(Command("Zoom in on the graph", "control-flow graph", "") {
                                vm.navigateTo(tab = Tab.GRAPH)
                                vm.graphZoomReq = 1.25f
                            })
                            add(Command("Zoom out on the graph", "control-flow graph", "") {
                                vm.navigateTo(tab = Tab.GRAPH)
                                vm.graphZoomReq = 0.8f
                            })
                        }

                        // The decompiler backend was reachable only from the top-bar
                        // overflow menu. Only the backend you are NOT on is offered,
                        // so the row says what it will do rather than what is on.
                        if (vm.decompiler != "ghidra") {
                            add(Command(
                                "Decompiler: Ghidra p-code",
                                "slower, better output · re-decompiles the open function", ""
                            ) {
                                vm.selectDecompiler("ghidra")
                                vm.detail?.let { vm.selectFunction(it.addr) }
                            })
                        }
                        if (vm.decompiler != "ir") {
                            add(Command(
                                "Decompiler: built-in IR lifter",
                                "faster, rougher output · re-decompiles the open function", ""
                            ) {
                                vm.selectDecompiler("ir")
                                vm.detail?.let { vm.selectFunction(it.addr) }
                            })
                        }

                        // Same idiom as the two rows above: the label is what
                        // this will DO, so it has to be rebuilt when the flag
                        // moves — hence `compareBackends` in the remember keys.
                        add(
                            if (vm.compareBackends) Command(
                                "Stop comparing decompiler backends",
                                "show one backend's output again", ""
                            ) { vm.compareBackends = false }
                            else Command(
                                "Compare decompiler backends",
                                "Ghidra p-code and the IR lifter, side by side", ""
                            ) {
                                vm.compareBackends = true
                                vm.navigateTo(tab = Tab.PSEUDO)
                            }
                        )

                        vm.plugins.forEach { p ->
                            add(Command("Run plugin: ${p.name}", p.description, "") { vm.runPlugin(ctx, p) })
                        }

                        // navigateTo, not `vm.tab =`, so the back chevron can walk
                        // out of a jump the palette made.
                        Tab.entries.forEachIndexed { i, t ->
                            add(Command(
                                "Go to tab: ${t.title}",
                                t.group.title,
                                if (i < NUMBERED_TABS) "Ctrl+${i + 1}" else ""
                            ) { vm.navigateTo(tab = t) })
                        }
                        TabGroup.entries.forEach { g ->
                            val tabs = Tab.of(g)
                            val first = tabs.firstOrNull()
                            if (first != null) {
                                add(Command(
                                    "Go to group: ${g.title}",
                                    tabs.joinToString(" · ") { it.title }, ""
                                ) { vm.navigateTo(tab = first) })
                            }
                        }

                        add(Command("Keyboard shortcuts help", "", "F1") { showShortcutsHelp = true })
                        add(Command(
                            "MCP server",
                            "let an AI client on your computer drive Nocturne's analysis", ""
                        ) { showMcpSheet = true })
                        add(Command(
                            "Check for updates",
                            "compare this build against the latest release on GitHub", ""
                        ) {
                            showUpdateSheet = true
                            vm.openUpdates(ctx)
                        })
                        // The export holds the engine mutex for minutes, so the
                        // one control that still works during it has to be
                        // reachable from the place that is always reachable.
                        if (vm.exportBusy) {
                            add(Command(
                                "Stop the running export",
                                "it finishes the function it is on and leaves a valid file", ""
                            ) {
                                showExportProgress = true
                                vm.stopExport()
                            })
                            add(Command(
                                "Watch the running export",
                                "progress, failures and the stop control", ""
                            ) { showExportProgress = true })
                        }
                        val pending = vm.meta?.functionsPending ?: 0
                        if (pending > 0 && !vm.exportBusy) {
                            add(Command(
                                "Load the remaining $pending functions",
                                "the analysis carries one page; this walks the rest", ""
                            ) {
                                vm.navigateTo(tab = Tab.FUNCTIONS)
                                vm.loadMoreFunctions(all = true)
                            })
                        }
                        if (vm.meta != null) {
                            // Not while one is running: the sheet opens a file
                            // picker for an export exportSource would refuse.
                            if (!vm.exportBusy) add(Command(
                                "Export source or an IDA script",
                                "pseudo-C, header, listing — or your names as .py / .idc", ""
                            ) { showExportSheet = true })
                            add(Command(
                                "Import from IDA…",
                                "names and comments out of an IDC database dump", "",
                                importIda
                            ))
                        }
                    }
                }
                val filtered = if (query.isBlank()) commands
                else commands.filter {
                    it.title.contains(query, ignoreCase = true) ||
                        it.subtitle.contains(query, ignoreCase = true) ||
                        it.shortcut.contains(query, ignoreCase = true)
                }

                Column {
                    OutlinedTextField(
                        value = query,
                        onValueChange = { query = it },
                        placeholder = { Text("Type a command… (Ctrl+K)", color = ide.dim) },
                        singleLine = true,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(12.dp)
                            .focusRequester(requester)
                            .semantics { contentDescription = "Filter commands" },
                        textStyle = TextStyle(fontSize = Type.body, color = ide.text)
                    )
                    if (filtered.isEmpty()) {
                        EmptyPanel(
                            "No command matches “$query”",
                            "${commands.size} commands are available. Clear the box to see them all."
                        )
                    } else {
                        LazyColumn(Modifier.heightIn(max = 360.dp)) {
                            items(filtered.size) { i ->
                                val c = filtered[i]
                                Row(
                                    Modifier
                                        .fillMaxWidth()
                                        .clickable(role = Role.Button) {
                                            showPalette = false
                                            c.action()
                                        }
                                        .sizeIn(minHeight = 48.dp)
                                        .padding(horizontal = 12.dp, vertical = 8.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Column(Modifier.weight(1f)) {
                                        Text(c.title, color = ide.text, fontSize = Type.body, fontFamily = Mono)
                                        if (c.subtitle.isNotEmpty()) {
                                            Text(
                                                c.subtitle, color = ide.dim2, fontSize = Type.caption,
                                                maxLines = 1, overflow = TextOverflow.Ellipsis
                                            )
                                        }
                                    }
                                    if (c.shortcut.isNotEmpty()) {
                                        Spacer(Modifier.width(8.dp))
                                        Text(c.shortcut, color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if (showGoto) {
        GotoDialog(vm) { showGoto = false }
    }

    if (showSearch) {
        GlobalSearchDialog(vm) { showSearch = false }
    }

    if (showShortcutsHelp) {
        AlertDialog(
            onDismissRequest = { showShortcutsHelp = false },
            containerColor = ide.panel,
            title = { Text("Keyboard shortcuts", color = ide.text, fontSize = Type.section) },
            text = {
                Column {
                    listOf(
                        "Ctrl+K" to "Command palette",
                        "Ctrl+F" to "Search everywhere",
                        "Ctrl+G" to "Go to address",
                        "Ctrl+O" to "Open file",
                        "Ctrl+S" to "Save project",
                        "Ctrl+T" to "Toggle theme",
                        "Ctrl+Tab" to "Next tab",
                        "Ctrl+1..9" to "Jump to one of the first nine tabs",
                        "F1" to "This help"
                    ).forEach { (k, v) ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(vertical = 2.dp)
                        ) {
                            Text(
                                k, color = ide.amber, fontSize = Type.label, fontFamily = Mono,
                                modifier = Modifier.widthIn(min = 92.dp)
                            )
                            Text(v, color = ide.text, fontSize = Type.label)
                        }
                    }
                    Spacer(Modifier.height(8.dp))
                    Text(
                        "There is no Ctrl+10 and up: Debugger, Plugins and Console have no " +
                            "number shortcut. Reach them with Ctrl+Tab or from the palette.",
                        color = ide.dim2, fontSize = Type.caption
                    )
                }
            },
            confirmButton = { TextButton(onClick = { showShortcutsHelp = false }) { Text("OK", color = ide.accent) } }
        )
    }
}

// ============================================================ Go to address ==

/**
 * Go-to-address used to write a file-scope global in GraphPanel that only the
 * Graph tab read, then call `selectFunction` on whatever raw address was typed
 * when no function matched — the engine returned not-ok, the failure went to
 * the console as a WARN nobody was looking at, and the previous function stayed
 * on screen. A typo and a successful jump looked identical.
 *
 * Now the destination is resolved and shown BEFORE the jump: Go is enabled only
 * when a real function covers the address, and an address that is in the file
 * but outside every function offers the hex view at its file offset instead.
 */
@Composable
private fun GotoDialog(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    var addrText by remember { mutableStateOf("") }
    val requester = remember { FocusRequester() }
    LaunchedEffect(Unit) { requester.requestFocus() }

    val parsed = parseAddr(addrText)
    val target = parsed?.let { vm.functionContaining(it) }
    val fileOffset = parsed?.let { vm.fileOffsetOf(it) }
    val parsedHex = parsed?.let { hexFmt(it) } ?: ""
    val intoFunc = if (parsed != null && target != null) parsed - target.addr else 0L
    // Identity, not the value: AnalysisMeta's equals walks every list it holds.
    val span = remember(System.identityHashCode(vm.meta)) {
        val fs = vm.meta?.functions.orEmpty()
        if (fs.isEmpty()) ""
        else "Functions span ${hexFmt(fs.minOf { it.addr })}–${hexFmt(fs.maxOf { it.addr + it.size })}"
    }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Go to address", color = ide.text, fontSize = Type.section) },
        text = {
            Column {
                OutlinedTextField(
                    value = addrText,
                    onValueChange = { addrText = it },
                    label = { Text("Address (hex, 0x optional)") },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(requester)
                        .semantics { contentDescription = "Virtual address to go to" },
                    textStyle = TextStyle(fontSize = Type.body, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(10.dp))
                when {
                    addrText.isBlank() -> Text(
                        span.ifEmpty { "No binary is open, so there is nowhere to go." },
                        color = ide.dim2, fontSize = Type.label, fontFamily = Mono
                    )
                    parsed == null -> Text(
                        "“${addrText.trim()}” is not a hexadecimal address.",
                        color = ide.red, fontSize = Type.label
                    )
                    target != null -> Text(
                        "${vm.effectiveFuncName(target.addr)} + 0x${intoFunc.toString(16)}" +
                            "  ·  ${hexFmt(target.addr)}",
                        color = ide.entry, fontSize = Type.label, fontFamily = Mono,
                        maxLines = 2, overflow = TextOverflow.Ellipsis
                    )
                    else -> Text(
                        "No function contains $parsedHex.",
                        color = ide.amber, fontSize = Type.label, fontFamily = Mono
                    )
                }
                if (parsed != null && target == null) {
                    // Bound to explicitly typed locals so the lambdas below never
                    // depend on a smart cast surviving into a closure.
                    val addr: Long = parsed
                    val off: Long? = fileOffset
                    if (off != null) {
                        val byteOffset: Long = off
                        // The hex panel does its own VA-to-offset conversion and
                        // knows how many bytes it is drawing per row, so it is
                        // handed the address, not a row index.
                        ActionRow("Show byte ${hexFmt(byteOffset)} in Hex") {
                            vm.navigateTo(tab = Tab.HEX)
                            vm.requestGoto(addr)
                            onDismiss()
                        }
                    } else {
                        Spacer(Modifier.height(4.dp))
                        Text(
                            "It falls outside every mapped section too, so it is not part of this file.",
                            color = ide.dim2, fontSize = Type.caption
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                enabled = target != null && parsed != null,
                onClick = {
                    val f = target
                    val addr = parsed
                    if (f != null && addr != null) {
                        // Stay where the user is when the current tab can show an
                        // address; otherwise the listing is the sane default.
                        val dest = if (vm.tab == Tab.GRAPH || vm.tab == Tab.PSEUDO) vm.tab else Tab.ASSEMBLY
                        vm.navigateTo(tab = dest, addr = f.addr)
                        // Pseudo-C has no line for an address to land on and never
                        // consumes the request; leaving one pending would make it
                        // fire on whichever panel opened next.
                        if (dest != Tab.PSEUDO) vm.requestGoto(addr)
                        onDismiss()
                    }
                }
            ) { Text("Go", color = if (target != null) ide.accent else ide.dim2) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = ide.dim) } }
    )
}

// ========================================================= Search everywhere ==

/** One result. [open] is null for a row that has nowhere to go, and such a row does not ripple. */
private class Hit(
    val label: String,
    val detail: String,
    val tint: Color,
    val open: (() -> Unit)? = null
)

private class HitGroup(
    val title: String,
    val note: String,
    val total: Int,
    val hits: List<Hit>,
    val showAllLabel: String = "",
    val showAll: (() -> Unit)? = null
)

/**
 * Resolve an address to the best place that can actually show it: the function
 * that contains it, else the bytes at its file offset, else nothing — and say
 * so rather than jumping somewhere arbitrary.
 *
 * `requestGoto` is only issued for tabs that consume it (Assembly, Hex, Graph);
 * leaving a pending address behind for a panel that ignores it would fire on
 * whichever panel opened next.
 */
private fun openAddress(vm: StudioViewModel, addr: Long) {
    val f = vm.functionContaining(addr)
    if (f != null) {
        vm.navigateTo(tab = Tab.ASSEMBLY, addr = f.addr)
        vm.requestGoto(addr)
        return
    }
    if (vm.fileOffsetOf(addr) != null) {
        // Hex converts the virtual address itself and knows its own row width.
        vm.navigateTo(tab = Tab.HEX)
        vm.requestGoto(addr)
        return
    }
    // log() raises the WARN toast itself; a second notify() here would double it.
    vm.log("WARN", "${hexFmt(addr)} is outside every mapped section — showing the memory map instead")
    vm.mapMode = 0
    vm.navigateTo(tab = Tab.MAP)
}

/** An import or export: its body when there is one, the symbol list otherwise. */
private fun openSymbol(vm: StudioViewModel, addr: Long, mode: String, query: String) {
    val f = if (addr != 0L) vm.functionContaining(addr) else null
    if (f != null) {
        vm.navigateTo(tab = Tab.ASSEMBLY, addr = f.addr)
        vm.requestGoto(addr)
    } else {
        vm.symbolsMode = mode
        vm.funcQuery = query
        vm.navigateTo(tab = Tab.FUNCTIONS)
    }
}

private fun openDex(vm: StudioViewModel) {
    vm.apkMode = APK_MODE_DEX
    vm.navigateTo(tab = Tab.APK)
}

/**
 * Everything the app can be asked about, in one pass. The four lists the old
 * dialog searched (functions, strings, comments, bookmarks) left out the two
 * things a reverse engineer greps first — the disassembly and the decompiled C
 * — plus the sections, the import and export tables and the DEX classes, all of
 * which are parsed into `meta` and were being carried around unread.
 */
private fun buildHits(vm: StudioViewModel, q: String, ide: IdeColors): List<HitGroup> {
    val out = ArrayList<HitGroup>()
    val meta = vm.meta ?: return out
    val detail = vm.detail

    fun <T> group(
        title: String,
        note: String,
        matches: List<T>,
        showAllLabel: String = "",
        showAll: (() -> Unit)? = null,
        row: (T) -> Hit
    ) {
        if (matches.isEmpty()) return
        out.add(
            HitGroup(
                title, note, matches.size,
                matches.take(HITS_PER_GROUP).map(row),
                showAllLabel,
                if (matches.size > HITS_PER_GROUP) showAll else null
            )
        )
    }

    val funcs = meta.functions.filter {
        it.name.contains(q, true) || vm.effectiveFuncName(it.addr).contains(q, true)
    }
    group(
        "FUNCTIONS", "", funcs,
        "Show all ${funcs.size} in Functions",
        {
            vm.symbolsMode = "functions"
            vm.funcQuery = q
            vm.navigateTo(tab = Tab.FUNCTIONS)
        }
    ) { f ->
        Hit(
            vm.effectiveFuncName(f.addr),
            "${hexFmt(f.addr)} · ${f.size} bytes · ${f.from}",
            ide.cyan
        ) { vm.navigateTo(tab = Tab.ASSEMBLY, addr = f.addr) }
    }

    // The engine's own annotations live in AsmLine.comment — resolved call
    // targets and string literals among them — so they are searched too.
    val asmHits = detail?.asm.orEmpty().filter {
        it.mnem.contains(q, true) || it.ops.contains(q, true) || it.comment.contains(q, true)
    }
    val scope = detail?.displayName?.takeIf { it.isNotBlank() }
        ?: detail?.name?.takeIf { it.isNotBlank() }
    group(
        "DISASSEMBLY",
        if (scope != null) "open function only — $scope" else "",
        asmHits
    ) { l ->
        Hit(
            "${l.mnem} ${l.ops}".trim(),
            hexFmt(l.addr) + (if (l.comment.isNotBlank()) "  ; ${l.comment}" else ""),
            ide.text
        ) {
            vm.navigateTo(tab = Tab.ASSEMBLY)
            vm.requestGoto(l.addr)
        }
    }

    val pseudo = detail?.pseudo.orEmpty()
    val pseudoHits: List<IndexedValue<String>> =
        if (pseudo.isBlank()) emptyList()
        else pseudo.lineSequence().withIndex().filter { it.value.contains(q, true) }.toList()
    group(
        "PSEUDO-C",
        if (scope != null) "open function only — $scope" else "",
        pseudoHits
    ) { line ->
        Hit(line.value.trim(), "line ${line.index + 1}", ide.text) {
            vm.navigateTo(tab = Tab.PSEUDO)
        }
    }

    val strs = meta.strings.filter { it.value.contains(q, true) }
    group(
        "STRINGS", "", strs,
        "Show all ${strs.size} in Strings",
        {
            vm.stringQuery = q
            vm.navigateTo(tab = Tab.STRINGS)
        }
    ) { s ->
        Hit("“${s.value.take(72)}”", hexFmt(s.addr), ide.text) { openAddress(vm, s.addr) }
    }

    val cmts = vm.comments.entries.filter {
        it.value.contains(q, true) || it.key.contains(q, true)
    }
    group("COMMENTS", "yours", cmts) { e ->
        Hit(e.value, e.key, ide.violet) { parseAddr(e.key)?.let { openAddress(vm, it) } }
    }

    val marks = vm.bookmarks.filter { it.label.contains(q, true) || it.addr.contains(q, true) }
    group("BOOKMARKS", "yours", marks) { b ->
        Hit(b.label, b.addr, ide.amber) { parseAddr(b.addr)?.let { openAddress(vm, it) } }
    }

    val imps = meta.imports.filter { it.name.contains(q, true) }
    group(
        "IMPORTS", "", imps,
        "Show all ${imps.size} in Functions",
        {
            vm.symbolsMode = "imports"
            vm.funcQuery = q
            vm.navigateTo(tab = Tab.FUNCTIONS)
        }
    ) { s ->
        Hit(
            s.name,
            if (s.addr != 0L) hexFmt(s.addr) else "resolved at load time · no address in this file",
            ide.text
        ) { openSymbol(vm, s.addr, "imports", q) }
    }

    // JNI bindings first: on an APK's native library they are what you are hunting for.
    val exps = meta.exports.filter { it.name.contains(q, true) }
        .sortedByDescending { it.name.startsWith("Java_") }
    group(
        "EXPORTS", "this file's attack surface", exps,
        "Show all ${exps.size} in Functions",
        {
            vm.symbolsMode = "exports"
            vm.funcQuery = q
            vm.navigateTo(tab = Tab.FUNCTIONS)
        }
    ) { s ->
        Hit(
            s.name,
            (if (s.name.startsWith("Java_")) "JNI entry point · " else "") + hexFmt(s.addr),
            ide.text
        ) { openSymbol(vm, s.addr, "exports", q) }
    }

    val secs = meta.sections.filter {
        it.name.contains(q, true) || it.type.contains(q, true) || it.flags.contains(q, true)
    }
    group(
        "SECTIONS", "", secs,
        "Show all ${secs.size} in Map",
        {
            vm.mapMode = 0
            vm.navigateTo(tab = Tab.MAP)
        }
    ) { s ->
        Hit(
            s.name,
            "${hexFmt(s.addr)} · ${s.size} bytes · ${s.type} ${s.flags}".trim(),
            ide.text
        ) {
            vm.mapMode = 0
            vm.navigateTo(tab = Tab.MAP)
        }
    }

    val dexClasses = meta.dexClasses.filter {
        it.name.contains(q, true) || it.superName.contains(q, true)
    }
    group(
        "DEX CLASSES", "", dexClasses,
        "Show all ${dexClasses.size} in APK", { openDex(vm) }
    ) { c ->
        Hit(c.name, "extends ${c.superName}", ide.text) { openDex(vm) }
    }

    val dexMethods = meta.dexMethods.filter {
        it.name.contains(q, true) || it.clazz.contains(q, true)
    }
    group(
        "DEX METHODS", "", dexMethods,
        "Show all ${dexMethods.size} in APK", { openDex(vm) }
    ) { m ->
        Hit("${m.clazz}.${m.name}", m.proto, ide.text) { openDex(vm) }
    }

    // DT_SONAME and DT_NEEDED: parsed on every ELF and displayed nowhere. There
    // is nothing in this file to jump to, so these rows do not pretend to be links.
    val libs = ArrayList<Hit>()
    if (meta.soName.isNotBlank() && meta.soName.contains(q, true)) {
        libs.add(Hit(meta.soName, "DT_SONAME · this file", ide.dim))
    }
    meta.needed.filter { it.contains(q, true) }.forEach {
        libs.add(Hit(it, "DT_NEEDED · loaded alongside this file", ide.dim))
    }
    if (libs.isNotEmpty()) {
        out.add(
            HitGroup(
                "SHARED LIBRARIES", "named in the dynamic section, not code in this file",
                libs.size, libs.take(HITS_PER_GROUP)
            )
        )
    }

    return out
}

@Composable
fun GlobalSearchDialog(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    var query by remember { mutableStateOf("") }
    val requester = remember { FocusRequester() }
    LaunchedEffect(Unit) { requester.requestFocus() }

    // Keyed rather than recomputed every frame: dexMethods alone can run to six
    // figures. The keys are identities and sizes, never the model objects —
    // AnalysisMeta and FunctionDetail are data classes whose equals walks every
    // list they hold, which would cost more than the search itself.
    val groups: List<HitGroup> = remember(
        query, System.identityHashCode(vm.meta), System.identityHashCode(vm.detail),
        vm.renames.size, vm.comments.size, vm.bookmarks.size, ide
    ) {
        if (query.length < 2) emptyList() else buildHits(vm, query, ide)
    }
    val total = groups.sumOf { it.total }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Search everywhere", color = ide.text, fontSize = Type.section) },
        text = {
            Column {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("code, strings, symbols, DEX…", color = ide.dim) },
                    singleLine = true,
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(requester)
                        .semantics { contentDescription = "Search the whole binary" },
                    textStyle = TextStyle(fontSize = Type.body, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(8.dp))
                when {
                    vm.meta == null -> EmptyPanel(
                        "Nothing is open yet.",
                        "Open an ELF, PE, DEX or APK and this searches its code, strings, symbols and sections."
                    )
                    query.length < 2 -> Hint(
                        "Type at least two characters.",
                        "Functions, the open function's disassembly and pseudo-C, strings, your comments and " +
                            "bookmarks, imports, exports, sections, DEX classes and methods."
                    )
                    groups.isEmpty() -> EmptyPanel(
                        "No matches for “$query”",
                        "Searched ${searchedSummary(vm)}. The disassembly and pseudo-C cover the open function only."
                    )
                    else -> {
                        val noun = if (total == 1) "match" else "matches"
                        val where = if (groups.size == 1) "category" else "categories"
                        Text(
                            "$total $noun in ${groups.size} $where",
                            color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                        )
                        Spacer(Modifier.height(4.dp))
                        LazyColumn(
                            Modifier
                                .fillMaxWidth()
                                .heightIn(max = 420.dp)
                        ) {
                            groups.forEach { g ->
                                item { GroupHeader(g) }
                                items(g.hits.size) { i -> HitRow(g.hits[i], onDismiss) }
                                val showAll = g.showAll
                                if (showAll != null) {
                                    item {
                                        ActionRow(g.showAllLabel) {
                                            showAll()
                                            onDismiss()
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close", color = ide.dim) } }
    )
}

/**
 * What the empty state is allowed to claim it looked through.
 *
 * Emphasis on ALLOWED. The palette searches the lists this app holds, and
 * three of those lists are pages of something larger — functions above all,
 * which arrive 12,000 at a time out of as many as 98,022. "searched 12000
 * functions" under a query that found nothing is a claim about the binary that
 * the app has not earned; "searched 12000 of 98022 functions" is the one it
 * has.
 */
private fun searchedSummary(vm: StudioViewModel): String {
    val m = vm.meta ?: return "nothing"
    val parts = ArrayList<String>()
    if (m.functions.isNotEmpty()) parts.add("${ofTotal(m.functions.size, m.functionsTotal)} functions")
    if (m.strings.isNotEmpty()) parts.add("${ofTotal(m.strings.size, m.stringsTotal)} strings")
    if (m.imports.isNotEmpty()) parts.add("${m.imports.size} imports")
    if (m.exports.isNotEmpty()) parts.add("${m.exports.size} exports")
    if (m.sections.isNotEmpty()) parts.add("${m.sections.size} sections")
    if (m.dexClasses.isNotEmpty())
        parts.add("${ofTotal(m.dexClasses.size, m.dexClassesTotal)} DEX classes")
    return if (parts.isEmpty()) "an empty analysis" else parts.joinToString(", ")
}

@Composable
private fun GroupHeader(g: HitGroup) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp)
            .padding(top = 10.dp, bottom = 2.dp)
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(
                g.title, color = ide.dim2, fontSize = Type.caption,
                fontWeight = FontWeight.Bold, fontFamily = Mono
            )
            Spacer(Modifier.weight(1f))
            // Never just the first six with nothing saying so.
            Text(
                if (g.total > g.hits.size) "${g.hits.size} of ${g.total}" else "${g.total}",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
            )
        }
        if (g.note.isNotEmpty()) {
            Text(g.note, color = ide.dim2, fontSize = Type.caption, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

@Composable
private fun HitRow(hit: Hit, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val open = hit.open
    var mod = Modifier.fillMaxWidth()
    if (open != null) {
        mod = mod.clickable(role = Role.Button) {
            open()
            onDismiss()
        }
    }
    Column(
        mod
            .sizeIn(minHeight = 48.dp)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            hit.label,
            color = if (open != null) hit.tint else ide.dim,
            fontSize = Type.mono, fontFamily = Mono,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        if (hit.detail.isNotEmpty()) {
            Text(
                hit.detail, color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
    }
}

/** A secondary action inside a dialog: bordered, because the border is its only edge. */
@Composable
private fun ActionRow(label: String, onClick: () -> Unit) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp)
            .border(1.dp, ide.borderStrong, RoundedCornerShape(6.dp))
            .clip(RoundedCornerShape(6.dp))
            .clickable(role = Role.Button, onClick = onClick)
            .sizeIn(minHeight = 48.dp)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            label, color = ide.text, fontSize = Type.label, fontFamily = Mono,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
    }
}

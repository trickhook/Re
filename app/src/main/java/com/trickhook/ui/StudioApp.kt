package com.trickhook.ui

import android.app.Activity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.foundation.Image
import androidx.compose.ui.draw.clip
import androidx.compose.ui.res.painterResource
import com.trickhook.R
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Grid4x4
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.TextFields
import com.trickhook.vm.TabGroup
import androidx.compose.material.icons.Icons
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Functions
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Laptop
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRowDefaults
import androidx.compose.material3.TabRowDefaults.tabIndicatorOffset
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDrawerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.view.WindowCompat
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab
import kotlinx.coroutines.launch

@Composable
fun StudioApp(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()

    val openLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { vm.openUri(ctx, it) }
    }
    val openFile = { openLauncher.launch(arrayOf("*/*")) }
    var showAbout by remember { mutableStateOf(false) }
    var showOverflow by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        vm.refreshRecents(ctx)
        vm.loadPlugins(ctx)
        vm.installSleigh(ctx)
    }
    LaunchedEffect(vm.darkTheme) {
        (ctx as? Activity)?.window?.let { w ->
            WindowCompat.getInsetsController(w, w.decorView).isAppearanceLightStatusBars = !vm.darkTheme
        }
    }

    // ---- keyboard shortcut handler ----
    val keyHandler = Modifier.onPreviewKeyEvent { e ->
        if (e.type == KeyEventType.KeyDown) {
            when {
                e.isCtrlPressed && e.key == Key.K -> { showPalette = !showPalette; true }
                e.isCtrlPressed && e.key == Key.F -> { showSearch = true; true }
                e.isCtrlPressed && e.key == Key.G -> { showGoto = true; true }
                e.isCtrlPressed && e.key == Key.O -> { openFile(); true }
                e.isCtrlPressed && e.key == Key.S -> { vm.saveProject(ctx, vm.meta?.name ?: "project"); true }
                e.isCtrlPressed && e.key == Key.T -> { vm.darkTheme = !vm.darkTheme; true }
                e.isCtrlPressed && e.key == Key.Tab -> {
                    val next = (vm.tab.ordinal + 1) % Tab.entries.size
                    vm.tab = Tab.entries[next]
                    true
                }
                e.isCtrlPressed && e.key.keyCode >= Key.One.keyCode &&
                    e.key.keyCode <= Key.Nine.keyCode -> {
                    val idx = (e.key.keyCode - Key.One.keyCode).toInt()
                    if (idx in 0 until Tab.entries.size) { vm.tab = Tab.entries[idx]; true } else false
                }
                e.key == Key.F1 -> { showShortcutsHelp = true; true }
                else -> false
            }
        } else false
    }

    ModalNavigationDrawer(
        modifier = keyHandler,
        drawerState = drawer,
        drawerContent = {
            Surface(modifier = Modifier.fillMaxWidth(0.86f), color = ide.panel) {
                ProjectDrawer(vm, onClose = { scope.launch { drawer.close() } }, openFile = openFile)
            }
        }
    ) {
        Column(Modifier.fillMaxSize().background(ide.bg)) {
            // ---- top bar ----
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(ide.panel)
                    .statusBarsPadding()
                    .height(52.dp)
                    .padding(horizontal = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                IconButton(onClick = { scope.launch { drawer.open() } }) {
                    Icon(Icons.Filled.Menu, contentDescription = "Project tree", tint = ide.text)
                }
                Column {
                    Text(
                        "Nocturne",
                        color = ide.text,
                        fontSize = 17.sp,
                        fontWeight = FontWeight.SemiBold,
                        letterSpacing = (-0.2).sp
                    )
                    Text(
                        "ELF · PE · DEX · APK",
                        color = ide.dim,
                        fontSize = 10.sp,
                        letterSpacing = 0.4.sp
                    )
                }
                Spacer(Modifier.weight(1f))
                // One tint for every control. Six icons in five colours read as
                // decoration; the accent is reserved for state and primary
                // actions. Secondary items move into the overflow — all of them
                // remain reachable from the command palette too.
                IconButton(onClick = { openFile() }) {
                    Icon(Icons.Filled.FolderOpen, contentDescription = "Open (Ctrl+O)", tint = ide.dim)
                }
                IconButton(onClick = { showSearch = true }) {
                    Icon(Icons.Filled.Search, contentDescription = "Search (Ctrl+F)", tint = ide.dim)
                }
                IconButton(onClick = { showPalette = true }) {
                    Icon(Icons.Filled.List, contentDescription = "Command palette (Ctrl+K)", tint = ide.dim)
                }
                Box {
                    IconButton(onClick = { showOverflow = true }) {
                        Icon(Icons.Filled.MoreVert, contentDescription = "More", tint = ide.dim)
                    }
                    DropdownMenu(
                        expanded = showOverflow,
                        onDismissRequest = { showOverflow = false },
                        containerColor = ide.panel2
                    ) {
                        DropdownMenuItem(
                            text = { Text("Export source…", color = ide.text, fontSize = 13.sp) },
                            leadingIcon = {
                                Icon(Icons.Filled.FileDownload, null, tint = ide.dim,
                                    modifier = Modifier.size(18.dp))
                            },
                            enabled = vm.meta != null,
                            onClick = { showOverflow = false; showExportSheet = true }
                        )
                        DropdownMenuItem(
                            text = { Text("Save project", color = ide.text, fontSize = 13.sp) },
                            leadingIcon = {
                                Icon(Icons.Filled.Save, null, tint = ide.dim,
                                    modifier = Modifier.size(18.dp))
                            },
                            enabled = vm.meta != null,
                            onClick = {
                                showOverflow = false
                                vm.saveProject(ctx, vm.meta?.name ?: "project")
                            }
                        )
                        DropdownMenuItem(
                            text = {
                                Column {
                                    Text(
                                        if (vm.decompiler == "ghidra") "Decompiler: Ghidra"
                                        else "Decompiler: built-in IR",
                                        color = ide.text, fontSize = 13.sp
                                    )
                                    Text(
                                        if (vm.decompiler == "ghidra")
                                            "p-code, types and structure — slower"
                                        else "fast lifter, gotos and raw registers",
                                        color = ide.dim, fontSize = 10.sp
                                    )
                                }
                            },
                            leadingIcon = {
                                Icon(Icons.Filled.Memory, null, tint = ide.dim,
                                    modifier = Modifier.size(18.dp))
                            },
                            onClick = {
                                showOverflow = false
                                vm.setDecompiler(if (vm.decompiler == "ghidra") "ir" else "ghidra")
                                vm.detail?.let { vm.selectFunction(it.addr) }
                            }
                        )
                        DropdownMenuItem(
                            text = {
                                Text(if (vm.darkTheme) "Light theme" else "Dark theme",
                                    color = ide.text, fontSize = 13.sp)
                            },
                            leadingIcon = {
                                Icon(
                                    if (vm.darkTheme) Icons.Filled.LightMode else Icons.Filled.DarkMode,
                                    null, tint = ide.dim, modifier = Modifier.size(18.dp)
                                )
                            },
                            onClick = { showOverflow = false; vm.darkTheme = !vm.darkTheme }
                        )
                        DropdownMenuItem(
                            text = { Text("Shortcuts", color = ide.text, fontSize = 13.sp) },
                            leadingIcon = {
                                Icon(Icons.Filled.Keyboard, null, tint = ide.dim,
                                    modifier = Modifier.size(18.dp))
                            },
                            onClick = { showOverflow = false; showShortcutsHelp = true }
                        )
                        DropdownMenuItem(
                            text = { Text("About", color = ide.text, fontSize = 13.sp) },
                            leadingIcon = {
                                Icon(Icons.Filled.Info, null, tint = ide.dim,
                                    modifier = Modifier.size(18.dp))
                            },
                            onClick = { showOverflow = false; showAbout = true }
                        )
                    }
                }
            }

            if (vm.meta == null) {
                EmptyState(vm, onOpen = openFile)
            } else {
                // Only the current group rides the strip — four items at most,
                // so it never scrolls. Switching group happens in the drawer.
                val groupTabs = Tab.of(vm.tab.group)
                ScrollableTabRow(
                    selectedTabIndex = groupTabs.indexOf(vm.tab).coerceAtLeast(0),
                    edgePadding = 16.dp,
                    containerColor = ide.bg,
                    contentColor = ide.text,
                    divider = { HorizontalDivider(color = ide.border) },
                    indicator = { positions ->
                        val i = groupTabs.indexOf(vm.tab)
                        if (i in positions.indices) {
                            TabRowDefaults.SecondaryIndicator(
                                Modifier.tabIndicatorOffset(positions[i]),
                                height = 2.dp,
                                color = ide.accent
                            )
                        }
                    }
                ) {
                    groupTabs.forEach { t ->
                        val selected = vm.tab == t
                        Tab(
                            selected = selected,
                            onClick = { vm.tab = t },
                            text = {
                                Text(
                                    t.title,
                                    fontSize = 13.sp,
                                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                                    color = if (selected) ide.text else ide.dim
                                )
                            }
                        )
                    }
                }
                Box(Modifier.weight(1f)) {
                    when (vm.tab) {
                        Tab.ASSEMBLY -> AssemblyPanel(vm)
                        Tab.PSEUDO -> DecompilePanel(vm)
                        Tab.GRAPH -> GraphPanel(vm)
                        Tab.CALLGRAPH -> CallGraphPanel(vm)
                        Tab.FUNCTIONS -> FunctionsPanel(vm)
                        Tab.STRINGS -> StringsPanel(vm)
                        Tab.HEX -> HexPanel(vm)
                        Tab.MAP -> MapPanel(vm)
                        Tab.APK -> ApkPanel(vm)
                        Tab.DEBUGGER -> DebuggerPanel(vm)
                        Tab.PLUGINS -> PluginsPanel(vm)
                        Tab.CONSOLE -> ConsolePanel(vm)
                    }
                }
            }
        }
    }

    CommandPaletteOverlay(vm, openFile)

    if (showAbout) AboutDialog(onDismiss = { showAbout = false })
    // Two contracts so the picker gets a sensible mime per shape; both are
    // registered here, where they survive the sheet being dismissed.
    var exportKind by remember { mutableStateOf("c-all") }
    val saveSource = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/x-c")
    ) { uri -> if (uri != null) vm.exportSource(ctx, uri, exportKind) }
    val saveText = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri -> if (uri != null) vm.exportSource(ctx, uri, exportKind) }

    if (showExportSheet && vm.meta != null) {
        ExportSheet(
            vm,
            onPick = { k ->
                exportKind = k
                showExportSheet = false
                val name = vm.suggestedExportName(k)
                if (vm.mimeForExport(k) == "text/plain") saveText.launch(name)
                else saveSource.launch(name)
            },
            onDismiss = { showExportSheet = false }
        )
    }
}

// ------------------------------------------------------------- empty state --
@Composable
private fun EmptyState(vm: StudioViewModel, onOpen: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    Box(Modifier.fillMaxSize().background(ide.bg)) {
        Box(
            Modifier
                .offset(x = (-70).dp, y = 20.dp)
                .size(320.dp)
                .background(
                    Brush.radialGradient(listOf(ide.accent.copy(alpha = 0.13f), Color.Transparent)),
                    CircleShape
                )
        )
        Box(
            Modifier
                .align(Alignment.TopEnd)
                .offset(x = 80.dp, y = 120.dp)
                .size(240.dp)
                .background(
                    Brush.radialGradient(listOf(ide.violet.copy(alpha = 0.09f), Color.Transparent)),
                    CircleShape
                )
        )

        // Top-aligned rather than centred: centring left roughly a third of the
        // screen empty above the wordmark and another gap below it, and pushed
        // the recent list off the first screen.
        Column(
            Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
        ) {
            Column(
                Modifier.fillMaxWidth().padding(horizontal = 20.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Spacer(Modifier.height(24.dp))
                Image(
                    painter = painterResource(R.drawable.nocturne_mark),
                    contentDescription = null,
                    modifier = Modifier
                        .size(96.dp)
                        .clip(RoundedCornerShape(26.dp))
                )
                Spacer(Modifier.height(16.dp))
                Text(
                    "Nocturne", color = ide.text, fontSize = 32.sp,
                    fontWeight = FontWeight.Light, letterSpacing = (-1.1).sp
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "Interactive disassembler & decompiler",
                    color = ide.dim, fontSize = 12.sp
                )
                Spacer(Modifier.height(16.dp))
                ArchChips()
                Spacer(Modifier.height(20.dp))

                Box(
                    Modifier
                        .fillMaxWidth()
                        .height(48.dp)
                        .shadow(16.dp, RoundedCornerShape(13.dp), clip = false,
                            ambientColor = ide.accent, spotColor = ide.accent)
                        .background(
                            if (vm.busy) ide.accent.copy(alpha = 0.45f) else ide.accent,
                            RoundedCornerShape(13.dp)
                        )
                        .clickable(enabled = !vm.busy) { onOpen() },
                    contentAlignment = Alignment.Center
                ) {
                    if (vm.busy) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(
                                color = Color(0xFF14020A),
                                modifier = Modifier.size(16.dp), strokeWidth = 2.dp
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                "Analyzing\u2026", color = Color(0xFF14020A),
                                fontSize = 14.sp, fontWeight = FontWeight.SemiBold
                            )
                        }
                    } else {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Icon(
                                Icons.Filled.FolderOpen, contentDescription = null,
                                tint = Color(0xFF14020A), modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(9.dp))
                            Text(
                                "Open a binary", color = Color(0xFF14020A),
                                fontSize = 14.5.sp, fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }

                Spacer(Modifier.height(10.dp))
                Text(
                    "Ctrl+K palette   ·   Ctrl+F search   ·   F1 shortcuts",
                    color = ide.dim.copy(alpha = 0.55f), fontSize = 10.sp, fontFamily = Mono
                )
            }

            // Recents belong on the first screen, not only behind the drawer —
            // reopening the last binary is the most common way in.
            if (vm.recents.isNotEmpty()) {
                Spacer(Modifier.height(22.dp))
                Row(
                    Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, bottom = 8.dp),
                    verticalAlignment = Alignment.Bottom
                ) {
                    Text(
                        "RECENT", color = ide.dim, fontSize = 10.sp,
                        fontWeight = FontWeight.Medium, letterSpacing = 1.sp
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "${vm.recents.size}",
                        color = ide.dim.copy(alpha = 0.6f), fontSize = 10.sp, fontFamily = Mono
                    )
                }
                Column(Modifier.padding(horizontal = 16.dp)) {
                    vm.recents.take(4).forEach { rp ->
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(vertical = 3.dp)
                                .border(1.dp, ide.border, RoundedCornerShape(11.dp))
                                .background(ide.panel, RoundedCornerShape(11.dp))
                                .clickable { vm.openRecent(ctx, rp) }
                                .padding(horizontal = 13.dp, vertical = 11.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                fileIcon(rp.format), contentDescription = null,
                                tint = ide.dim, modifier = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(11.dp))
                            Text(
                                rp.name, color = ide.text, fontSize = 12.5.sp,
                                fontFamily = Mono, maxLines = 1,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                rp.format.ifEmpty { "RAW" },
                                color = ide.dim.copy(alpha = 0.7f), fontSize = 9.5.sp,
                                fontFamily = Mono
                            )
                        }
                    }
                }
            } else {
                Spacer(Modifier.height(22.dp))
                Text(
                    ".so    .dex    .exe    .apk",
                    color = ide.dim.copy(alpha = 0.45f), fontSize = 11.sp, fontFamily = Mono,
                    modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center
                )
            }

            Spacer(Modifier.height(18.dp))
            ConsoleCard(vm)
            Spacer(Modifier.height(16.dp))
        }
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ArchChips() {
    val ide = LocalIde.current
    // Colour ranks them: what the IR decompiler lifts, what only disassembles.
    val chips = listOf(
        "ARM64" to ide.violet, "ARM/Thumb" to ide.violet,
        "x86-64" to ide.cyan, "x86" to ide.cyan,
        "MIPS" to ide.dim, "PowerPC" to ide.dim,
        "SPARC" to ide.dim, "SystemZ" to ide.dim, "m68k" to ide.dim
    )
    FlowRow(
        horizontalArrangement = Arrangement.spacedBy(6.dp, Alignment.CenterHorizontally),
        verticalArrangement = Arrangement.spacedBy(6.dp)
    ) {
        chips.forEach { (label, tint) ->
            Text(
                label,
                color = tint, fontSize = 10.sp, fontFamily = Mono,
                modifier = Modifier
                    .border(1.dp, ide.border, RoundedCornerShape(999.dp))
                    .padding(horizontal = 10.dp, vertical = 5.dp)
            )
        }
    }
}

@Composable
private fun ConsoleCard(vm: StudioViewModel) {
    val ide = LocalIde.current
    Column(
        Modifier
            .padding(horizontal = 16.dp)
            .fillMaxWidth()
            .border(1.dp, ide.border, RoundedCornerShape(14.dp))
            .background(ide.panel, RoundedCornerShape(14.dp))
    ) {
        Row(
            Modifier.fillMaxWidth().padding(start = 14.dp, end = 14.dp, top = 11.dp, bottom = 9.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(Modifier.size(6.dp).background(ide.amber, CircleShape))
            Spacer(Modifier.width(8.dp))
            Text(
                "CONSOLE", color = ide.dim, fontSize = 10.sp,
                fontWeight = FontWeight.Medium, letterSpacing = 1.sp,
                modifier = Modifier.weight(1f)
            )
            Text(
                "${vm.plugins.size} plugins",
                color = ide.dim.copy(alpha = 0.6f), fontSize = 9.sp, fontFamily = Mono
            )
        }
        Column(Modifier.padding(start = 14.dp, end = 14.dp, bottom = 13.dp)) {
            vm.console.takeLast(2).forEach { line ->
                Row {
                    Text(
                        "[${line.level.lowercase()}] ",
                        color = levelColor(line.level, ide), fontSize = 10.sp, fontFamily = Mono
                    )
                    Text(
                        line.msg, color = ide.dim, fontSize = 10.sp,
                        fontFamily = Mono, lineHeight = 15.sp, maxLines = 2
                    )
                }
            }
        }
    }
}

// ----------------------------------------------------------------- drawer --
@Composable
private fun ProjectDrawer(vm: StudioViewModel, onClose: () -> Unit, openFile: () -> Unit) {
    val ide = LocalIde.current
    val meta = vm.meta
    val ctx = LocalContext.current
    LazyColumn(Modifier.fillMaxSize().background(ide.panel)) {
        item {
            Column(Modifier.fillMaxWidth().background(ide.panel2).padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        meta?.let { fileIcon(it.format) } ?: Icons.Filled.FolderOpen,
                        contentDescription = null, tint = ide.accent,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        meta?.name ?: "No file", color = ide.text, fontSize = 15.sp,
                        fontWeight = FontWeight.Bold
                    )
                }
                Spacer(Modifier.height(4.dp))
                KeyValue("Format", "${meta?.format ?: "-"} · ${meta?.arch ?: "-"}")
                KeyValue(
                    "Entry / Base",
                    "${meta?.entry?.let { hexFmt(it) } ?: "-"} / ${meta?.base?.let { hexFmt(it) } ?: "-"}"
                )
                KeyValue("Size", "${meta?.sizeBytes ?: 0} bytes")
                KeyValue("Disassembler", meta?.backend?.ifEmpty { "-" } ?: "-")
                KeyValue("Pseudo-C", vm.detail?.pseudoMode ?: "-")
            }
            HorizontalDivider(color = ide.border)
        }

        // Navigation lives here now: every destination visible at once,
        // grouped, instead of thirteen tabs behind a horizontal scroll.
        TabGroup.entries.forEach { group ->
            item { SectionTitle(group.title) }
            items(Tab.of(group).size) { i ->
                val t = Tab.of(group)[i]
                val active = vm.tab == t
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(if (active) ide.accent.copy(alpha = 0.10f) else Color.Transparent)
                        .clickable { vm.tab = t; onClose() }
                        .padding(horizontal = 12.dp, vertical = 9.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(tabIcon(t), if (active) ide.accent else ide.dim, 16.dp)
                    Text(
                        t.title,
                        color = if (active) ide.accent else ide.text,
                        fontSize = 13.sp,
                        fontWeight = if (active) FontWeight.SemiBold else FontWeight.Normal,
                        modifier = Modifier.weight(1f)
                    )
                    if (active) {
                        Box(Modifier.size(5.dp).background(ide.accent, CircleShape))
                    }
                }
            }
        }
        item { Spacer(Modifier.height(6.dp)); HorizontalDivider(color = ide.border) }

        // RECENT PROJECTS
        if (vm.recents.isNotEmpty()) {
            item { SectionTitle("Recent projects (${vm.recents.size})") }
            items(minOf(vm.recents.size, 8)) { i ->
                val rp = vm.recents[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable {
                            vm.openRecent(ctx, rp)
                            onClose()
                        }
                        .padding(horizontal = 12.dp, vertical = 5.dp)
                ) {
                    RowIcon(fileIcon(rp.format), ide.dim, 13.dp)
                    Text(
                        rp.name, color = ide.cyan, fontSize = 12.sp, fontFamily = Mono,
                        maxLines = 1, modifier = Modifier.weight(1f)
                    )
                    Text(rp.format.ifEmpty { "RAW" }, color = ide.dim, fontSize = 9.5.sp, fontFamily = Mono)
                }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // BOOKMARKS
        if (vm.bookmarks.isNotEmpty()) {
            item { SectionTitle("Bookmarks (${vm.bookmarks.size})") }
            items(minOf(vm.bookmarks.size, 10)) { i ->
                val b = vm.bookmarks[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable {
                            val a = b.addr.removePrefix("0x").toLongOrNull(16) ?: 0L
                            val f = meta?.functions?.filter { it.addr <= a }?.maxByOrNull { it.addr }
                            if (f != null) vm.selectFunction(f.addr)
                            onClose()
                        }
                        .padding(horizontal = 12.dp, vertical = 4.dp)
                ) {
                    RowIcon(Icons.Filled.Star, ide.amber, 13.dp)
                    Text(b.label, color = ide.text, fontSize = 12.sp, maxLines = 1, modifier = Modifier.weight(1f))
                    Text(b.addr, color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // APK CONTENTS
        if (vm.apkEntries.isNotEmpty()) {
            item { SectionTitle("APK contents (${vm.apkEntries.size})") }
            items(minOf(vm.apkEntries.size, 40)) { i ->
                val e = vm.apkEntries[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable { vm.openApkEntry(e); onClose() }
                        .padding(horizontal = 12.dp, vertical = 5.dp)
                ) {
                    RowIcon(
                        if (e.name.endsWith(".apk")) Icons.Filled.Android
                        else if (e.name.endsWith(".so")) Icons.Filled.Memory
                        else Icons.Filled.Description,
                        ide.dim, 13.dp
                    )
                    Text(e.name, color = ide.cyan, fontSize = 11.sp, fontFamily = Mono, maxLines = 1, modifier = Modifier.weight(1f))
                    Text("${e.size}", color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // FUNCTIONS with icons
        item { SectionTitle("Functions (${meta?.functions?.size ?: 0})") }
        if (meta != null && meta.functions.isNotEmpty()) {
            items(minOf(meta.functions.size, 150)) { i ->
                val f = meta.functions[i]
                val display = vm.renames["0x%08X".format(f.addr)] ?: f.name
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable {
                            vm.selectFunction(f.addr)
                            onClose()
                        }
                        .padding(horizontal = 12.dp, vertical = 5.dp)
                ) {
                    val isRenamed = vm.renames.containsKey("0x%08X".format(f.addr))
                    RowIcon(
                        if (f.from == "import") Icons.Filled.ArrowDownward
                        else if (isRenamed) Icons.Filled.DriveFileRenameOutline
                        else Icons.Filled.Functions,
                        if (isRenamed) ide.amber else ide.dim, 13.dp
                    )
                    Text(
                        display,
                        color = if (f.addr == vm.selectedFunc) ide.accent else ide.text,
                        fontSize = 12.sp, fontFamily = Mono,
                        modifier = Modifier.weight(1f), maxLines = 1
                    )
                    Text(hexFmt(f.addr), color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // IMPORTS
        item { SectionTitle("Imports (${meta?.imports?.size ?: 0})") }
        if (meta != null && meta.imports.isNotEmpty()) {
            items(minOf(meta.imports.size, 60)) { i ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(Icons.Filled.ArrowDownward, ide.dim, 12.dp)
                    Text(
                        meta.imports[i].name,
                        color = ide.dim, fontSize = 11.sp, fontFamily = Mono, maxLines = 1
                    )
                }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // SECTIONS
        item { SectionTitle("Sections (${meta?.sections?.size ?: 0})") }
        if (meta != null && meta.sections.isNotEmpty()) {
            items(minOf(meta.sections.size, 60)) { i ->
                val s = meta.sections[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable { vm.tab = Tab.MAP; onClose() }
                        .padding(horizontal = 12.dp, vertical = 3.dp)
                ) {
                    RowIcon(
                        if (s.flags.contains("X")) Icons.Filled.Code
                        else if (s.flags.contains("W")) Icons.Filled.Edit
                        else Icons.Filled.Storage,
                        ide.dim, 12.dp
                    )
                    Text(s.name.ifEmpty { "(unnamed)" }, color = ide.text, fontSize = 11.sp, fontFamily = Mono, maxLines = 1)
                    Spacer(Modifier.weight(1f))
                    Text("${s.flags} · ${s.size}", color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                }
            }
        }
        item {
            Spacer(Modifier.height(12.dp))
            Text(
                "Ctrl+K — command palette · Ctrl+F — search",
                color = ide.dim, fontSize = 10.sp, fontFamily = Mono,
                modifier = Modifier.padding(12.dp)
            )
            Spacer(Modifier.height(24.dp))
        }
    }
}

private fun tabIcon(t: Tab): ImageVector = when (t) {
    Tab.ASSEMBLY  -> Icons.Filled.Code
    Tab.PSEUDO    -> Icons.Filled.DataObject
    Tab.GRAPH     -> Icons.Filled.AccountTree
    Tab.CALLGRAPH -> Icons.Filled.Hub
    Tab.FUNCTIONS -> Icons.Filled.Functions
    Tab.STRINGS   -> Icons.Filled.TextFields
    Tab.HEX       -> Icons.Filled.Grid4x4
    Tab.MAP       -> Icons.Filled.Layers
    Tab.APK       -> Icons.Filled.Android
    Tab.DEBUGGER  -> Icons.Filled.BugReport
    Tab.PLUGINS   -> Icons.Filled.Extension
    Tab.CONSOLE   -> Icons.Filled.Terminal
}

private fun fileIcon(format: String?): ImageVector = when (format) {
    "APK" -> Icons.Filled.Android
    "ELF" -> Icons.Filled.Memory
    "PE" -> Icons.Filled.DesktopWindows
    "DEX" -> Icons.Filled.DataObject
    "MachO" -> Icons.Filled.Laptop
    else -> Icons.Filled.InsertDriveFile
}

@Composable
fun SectionTitle(text: String) {
    val ide = LocalIde.current
    Text(
        text.uppercase(),
        color = ide.dim,
        fontSize = 10.sp,
        fontWeight = FontWeight.Medium,
        letterSpacing = 1.sp,
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 12.dp, end = 12.dp, top = 18.dp, bottom = 6.dp)
    )
}

// ---------------------------------------------------------------- dialogs --
@Composable
private fun AboutDialog(onDismiss: () -> Unit) {
    val ide = LocalIde.current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Nocturne v2.0", color = ide.accent) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                Text("Reverse-engineering studio for ELF, PE, DEX and APK binaries.", color = ide.text, fontSize = 12.sp)
                Spacer(Modifier.height(8.dp))
                KeyValue("Engine", "C++17 NDK · Capstone 4.0.2 + built-in fallback")
                KeyValue(
                    "Architectures",
                    "ARM64 · ARM/Thumb · x86 · x86-64 · MIPS · PowerPC · SPARC · SystemZ · m68k · TI C6000 (LE + BE)"
                )
                KeyValue("Decompiler", "ASM → IR → Pseudo-C (typed vars, while/if, calls w/ args)")
                KeyValue("Analysis", "call graph · PLT/GOT/IAT resolution · demangler · auto-comments")
                KeyValue("Project DB", "SQLite: renames, comments, bookmarks, notes, recents")
                KeyValue("Debugger", "ptrace session: spawn/attach, breakpoints, regs, memory, stack, threads")
                KeyValue("Plugins", "NocturneScript interpreter + bundled sample plugins")
                Spacer(Modifier.height(8.dp))
                Text(
                    "The debugger needs a rooted or debuggable device; SELinux may still deny ptrace. " +
                        "Pseudo-C is a real IR pipeline, not a full decompiler — no vtable or exception recovery.",
                    color = ide.amber, fontSize = 10.5.sp, lineHeight = 14.sp
                )
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("OK", color = ide.accent) } }
    )
}

package com.trickhook.ui

import android.app.Activity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.WindowInsetsSides
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.imePadding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.offset
import androidx.compose.foundation.layout.only
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Comment
import androidx.compose.material.icons.filled.DarkMode
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material.icons.filled.Functions
import androidx.compose.material.icons.filled.Grid4x4
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.InsertDriveFile
import androidx.compose.material.icons.filled.Keyboard
import androidx.compose.material.icons.filled.Laptop
import androidx.compose.material.icons.filled.Layers
import androidx.compose.material.icons.filled.LightMode
import androidx.compose.material.icons.filled.List
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Menu
import androidx.compose.material.icons.filled.MoreHoriz
import androidx.compose.material.icons.filled.MoreVert
import androidx.compose.material.icons.filled.Notes
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material.icons.filled.TextFields
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DrawerValue
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalNavigationDrawer
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.ScrollableTabRow
import androidx.compose.material3.Snackbar
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.SnackbarResult
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
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.input.key.KeyEventType
import androidx.compose.ui.input.key.isCtrlPressed
import androidx.compose.ui.input.key.isShiftPressed
import androidx.compose.ui.input.key.key
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.input.key.type
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.core.view.WindowCompat
import com.trickhook.R
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab
import com.trickhook.vm.TabGroup
import kotlinx.coroutines.launch

/**
 * Two radii, not five. `Card` is anything that frames a group of rows; `Control`
 * is anything you press. The home screen used to show 11dp, 13dp and 14dp side
 * by side at the same width, which reads as a mistake rather than a distinction.
 */
private val CardShape = RoundedCornerShape(14.dp)
private val ControlShape = RoundedCornerShape(10.dp)

@Composable
fun StudioApp(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val drawer = rememberDrawerState(DrawerValue.Closed)
    val scope = rememberCoroutineScope()
    val snackbarHost = remember { SnackbarHostState() }

    val openLauncher = rememberLauncherForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
        uri?.let { vm.openUri(ctx, it) }
    }
    val openFile = { openLauncher.launch(arrayOf("*/*")) }

    // rememberSaveable, not remember: rotating recreates the Activity, and these
    // four are the only pieces of screen state StudioApp still owns — everything
    // else moved onto the ViewModel, which survives a configuration change by
    // itself.
    var showAbout by rememberSaveable { mutableStateOf(false) }
    var showOverflow by rememberSaveable { mutableStateOf(false) }
    var showAnnotations by rememberSaveable { mutableStateOf(false) }
    var exportKind by rememberSaveable { mutableStateOf("c-all") }

    // Where the user was standing the last time they were in each group, so the
    // group rail returns you to it instead of always resetting to the first tab.
    val lastInGroup = remember { mutableStateMapOf<TabGroup, Tab>() }
    val landingFor: (TabGroup) -> Tab = { g -> lastInGroup[g] ?: Tab.of(g).first() }
    LaunchedEffect(vm.tab) { lastInGroup[vm.tab.group] = vm.tab }

    LaunchedEffect(Unit) {
        vm.refreshRecents(ctx)
        vm.loadPlugins(ctx)
        vm.installSleigh(ctx)
    }
    LaunchedEffect(vm.darkTheme) {
        (ctx as? Activity)?.window?.let { w ->
            val bars = WindowCompat.getInsetsController(w, w.decorView)
            bars.isAppearanceLightStatusBars = !vm.darkTheme
            // themes.xml no longer pins the bars to the dark background, so the
            // gesture pill is drawn over app content and has to follow the theme
            // as well — otherwise it is invisible in whichever theme it does not
            // match, which is exactly what used to happen in light mode.
            bars.isAppearanceLightNavigationBars = !vm.darkTheme
        }
    }

    // ---- the ViewModel's toast channel, hosted as a snackbar ----
    // Kept in a local so the colour survives the fade-out: vm.toast is cleared
    // the moment the snackbar is dismissed, and reading the level off it would
    // flicker the dot back to grey while the bar is still animating away.
    var toastLevel by remember { mutableStateOf("INFO") }
    LaunchedEffect(vm.toast?.id) {
        val t = vm.toast ?: return@LaunchedEffect
        toastLevel = t.level
        val result = snackbarHost.showSnackbar(
            message = t.msg,
            actionLabel = t.actionLabel,
            duration = if (t.actionLabel != null || t.level == "ERROR")
                SnackbarDuration.Long else SnackbarDuration.Short
        )
        if (result == SnackbarResult.ActionPerformed) t.action?.invoke()
        vm.dismissToast()
    }

    // ---- system Back ----
    // Back used to exit the app from any tab, mid-analysis. It now closes the
    // drawer if it is open and otherwise walks the ViewModel's navigation
    // history; when there is nothing left to pop the handler disables itself and
    // the system gets the press back, so Back still leaves the app at the root.
    BackHandler(enabled = drawer.isOpen || vm.canGoBack) {
        if (drawer.isOpen) scope.launch { drawer.close() } else vm.back()
    }

    // ---- keyboard shortcut handler ----
    val keyHandler = Modifier.onPreviewKeyEvent { e ->
        if (e.type == KeyEventType.KeyDown) {
            val isDigit = e.key.keyCode >= Key.One.keyCode && e.key.keyCode <= Key.Nine.keyCode
            // Key.keyCode is NOT the Android keycode: on Android a Key is built as
            // packInts(nativeKeyCode, 0), i.e. nativeKeyCode shl 32. So subtracting two
            // of them leaves the difference in the HIGH word and the low 32 bits at
            // zero — a plain .toInt() returned 0 for every digit, which is why Ctrl+1
            // through Ctrl+9 all selected the first tab. The range test above is fine,
            // since KEYCODE_1..KEYCODE_9 are contiguous and so is their packed form.
            val digit = ((e.key.keyCode - Key.One.keyCode) ushr 32).toInt()
            when {
                e.isCtrlPressed && e.key == Key.K -> { showPalette = !showPalette; true }
                e.isCtrlPressed && e.key == Key.F -> { showSearch = true; true }
                e.isCtrlPressed && e.key == Key.G -> { showGoto = true; true }
                e.isCtrlPressed && e.key == Key.O -> { openFile(); true }
                e.isCtrlPressed && e.key == Key.S -> { vm.saveProject(ctx, vm.meta?.name ?: "project"); true }
                e.isCtrlPressed && e.key == Key.T -> { vm.darkTheme = !vm.darkTheme; true }
                e.isCtrlPressed && e.key == Key.B -> { showAnnotations = true; true }
                e.isCtrlPressed && e.key == Key.Tab -> {
                    val next = (vm.tab.ordinal + 1) % Tab.entries.size
                    vm.navigateTo(Tab.entries[next])
                    true
                }
                // Ctrl+Shift+1..4 picks the group and lands on the tab you last
                // used inside it. Ctrl+1..9 keeps meaning "tab N", which is what
                // the command palette prints beside each entry.
                e.isCtrlPressed && e.isShiftPressed && isDigit -> {
                    val g = TabGroup.entries.getOrNull(digit)
                    if (g != null) { vm.navigateTo(landingFor(g)); true } else false
                }
                e.isCtrlPressed && isDigit -> {
                    val t = Tab.entries.getOrNull(digit)
                    if (t != null) { vm.navigateTo(t); true } else false
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
            Surface(
                modifier = Modifier.fillMaxWidth(0.86f).fillMaxHeight(),
                color = ide.panel
            ) {
                ProjectDrawer(
                    vm,
                    onClose = { scope.launch { drawer.close() } },
                    openFile = openFile,
                    onAnnotations = {
                        showAnnotations = true
                        scope.launch { drawer.close() }
                    }
                )
            }
        }
    ) {
        Box(Modifier.fillMaxSize().background(ide.bg)) {
            Column(
                Modifier
                    .fillMaxSize()
                    // Horizontal safe-drawing only. The BOTTOM inset belongs to
                    // whichever panel is on screen — they pad themselves with
                    // NavBarSpacer()/bottomInset() — and consuming it here would
                    // silently zero theirs out and double the gap.
                    .windowInsetsPadding(WindowInsets.safeDrawing.only(WindowInsetsSides.Horizontal))
            ) {
                // ---- top bar ----
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(ide.panel)
                        .statusBarsPadding()
                        .heightIn(min = 52.dp)
                        .padding(horizontal = 2.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    IconButton(onClick = { scope.launch { drawer.open() } }) {
                        Icon(Icons.Filled.Menu, contentDescription = "Project tree", tint = ide.text)
                    }
                    // Accent when there is somewhere to go, which is the file's
                    // own rule: the accent means state, not decoration.
                    IconButton(onClick = { vm.back() }, enabled = vm.canGoBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = "Back",
                            tint = if (vm.canGoBack) ide.accent else ide.dim2
                        )
                    }
                    Column(Modifier.weight(1f).padding(horizontal = 4.dp)) {
                        Text(
                            "Nocturne",
                            color = ide.text,
                            fontSize = Type.title,
                            fontWeight = FontWeight.SemiBold,
                            letterSpacing = (-0.2).sp,
                            maxLines = 1
                        )
                        // The subtitle is the one quiet line with room in it, so
                        // the engine's current phase borrows the slot. Opening,
                        // analyzing, exporting, call graphs and plugin runs all
                        // used to be invisible outside the Pseudo-C tab.
                        val phase = vm.globalPhase
                        Text(
                            if (phase.isEmpty()) "ELF · PE · DEX · APK" else phase,
                            color = if (phase.isEmpty()) ide.dim else ide.accent,
                            fontSize = Type.caption,
                            letterSpacing = if (phase.isEmpty()) 0.4.sp else 0.sp,
                            maxLines = 1
                        )
                    }
                    // One tint for every control. Six icons in five colours read
                    // as decoration; the accent is reserved for state and primary
                    // actions. Secondary items live in the overflow — all of them
                    // remain reachable from the command palette too.
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
                                text = { Text("Open binary…", color = ide.text, fontSize = Type.body) },
                                leadingIcon = {
                                    Icon(Icons.Filled.FolderOpen, null, tint = ide.dim,
                                        modifier = Modifier.size(18.dp))
                                },
                                trailingIcon = {
                                    Text("Ctrl+O", color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
                                },
                                onClick = { showOverflow = false; openFile() }
                            )
                            DropdownMenuItem(
                                text = { Text("Bookmarks & notes", color = ide.text, fontSize = Type.body) },
                                leadingIcon = {
                                    Icon(Icons.Filled.Star, null, tint = ide.dim,
                                        modifier = Modifier.size(18.dp))
                                },
                                onClick = { showOverflow = false; showAnnotations = true }
                            )
                            DropdownMenuItem(
                                text = { Text("Export source…", color = ide.text, fontSize = Type.body) },
                                leadingIcon = {
                                    Icon(Icons.Filled.FileDownload, null, tint = ide.dim,
                                        modifier = Modifier.size(18.dp))
                                },
                                enabled = vm.meta != null,
                                onClick = { showOverflow = false; showExportSheet = true }
                            )
                            DropdownMenuItem(
                                text = { Text("Save project", color = ide.text, fontSize = Type.body) },
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
                                            color = ide.text, fontSize = Type.body
                                        )
                                        Text(
                                            if (vm.decompiler == "ghidra")
                                                "p-code, types and structure — slower"
                                            else "fast lifter, gotos and raw registers",
                                            color = ide.dim, fontSize = Type.caption
                                        )
                                    }
                                },
                                leadingIcon = {
                                    Icon(Icons.Filled.Memory, null, tint = ide.dim,
                                        modifier = Modifier.size(18.dp))
                                },
                                onClick = {
                                    showOverflow = false
                                    vm.selectDecompiler(if (vm.decompiler == "ghidra") "ir" else "ghidra")
                                    vm.detail?.let { vm.selectFunction(it.addr) }
                                }
                            )
                            DropdownMenuItem(
                                text = {
                                    Text(if (vm.darkTheme) "Light theme" else "Dark theme",
                                        color = ide.text, fontSize = Type.body)
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
                                text = { Text("Shortcuts", color = ide.text, fontSize = Type.body) },
                                leadingIcon = {
                                    Icon(Icons.Filled.Keyboard, null, tint = ide.dim,
                                        modifier = Modifier.size(18.dp))
                                },
                                onClick = { showOverflow = false; showShortcutsHelp = true }
                            )
                            DropdownMenuItem(
                                text = { Text("About", color = ide.text, fontSize = Type.body) },
                                leadingIcon = {
                                    Icon(Icons.Filled.Info, null, tint = ide.dim,
                                        modifier = Modifier.size(18.dp))
                                },
                                onClick = { showOverflow = false; showAbout = true }
                            )
                        }
                    }
                }

                // A 2dp line under the header for everything the engine is doing:
                // opening, analyzing, exporting, building a call graph, running a
                // plugin. The phase text sits in the header subtitle above it.
                if (vm.globalPhase.isNotEmpty()) {
                    LinearProgressIndicator(
                        modifier = Modifier.fillMaxWidth().height(2.dp),
                        color = ide.accent,
                        trackColor = ide.accent.copy(alpha = 0.20f)
                    )
                }

                if (vm.meta == null) {
                    EmptyState(
                        vm,
                        onOpen = openFile,
                        onMoreRecents = { scope.launch { drawer.open() } }
                    )
                } else {
                    // One two-level control: the group rail sits on the header's
                    // own panel colour with no rule between them, and the strip
                    // below it drops onto the content background. Switching group
                    // used to be possible only from the drawer, and the strip
                    // never said which of the four you were standing in.
                    GroupRail(vm, onPick = { g -> vm.navigateTo(landingFor(g)) })
                    TabStrip(vm)
                    Box(Modifier.weight(1f).imePadding()) {
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

            // Floats over whatever panel is on screen, which is the point: the
            // console it mirrors is visible on one tab in twelve.
            SnackbarHost(
                hostState = snackbarHost,
                modifier = Modifier
                    .align(Alignment.BottomCenter)
                    .navigationBarsPadding()
                    .imePadding()
                    .padding(horizontal = 12.dp, vertical = 10.dp)
            ) { data ->
                val tint = levelColor(toastLevel, ide)
                val label = data.visuals.actionLabel
                if (label != null) {
                    Snackbar(
                        shape = ControlShape,
                        containerColor = ide.panel2,
                        contentColor = ide.text,
                        actionContentColor = tint,
                        action = {
                            TextButton(onClick = { data.performAction() }) {
                                Text(
                                    label, color = tint, fontSize = Type.label,
                                    fontWeight = FontWeight.SemiBold
                                )
                            }
                        }
                    ) { ToastBody(data.visuals.message, tint) }
                } else {
                    Snackbar(
                        shape = ControlShape,
                        containerColor = ide.panel2,
                        contentColor = ide.text
                    ) { ToastBody(data.visuals.message, tint) }
                }
            }
        }
    }

    CommandPaletteOverlay(vm, openFile)

    if (showAbout) AboutDialog(onDismiss = { showAbout = false })
    if (showAnnotations) AnnotationsSheet(vm, onDismiss = { showAnnotations = false })

    // Two contracts so the picker gets a sensible mime per shape; both are
    // registered here, where they survive the sheet being dismissed.
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

@Composable
private fun ToastBody(message: String, tint: Color) {
    val ide = LocalIde.current
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(Modifier.size(6.dp).background(tint, CircleShape))
        Spacer(Modifier.width(9.dp))
        Text(
            message, color = ide.text, fontSize = Type.label,
            lineHeight = 17.sp, maxLines = 3
        )
    }
}

// ------------------------------------------------------------- group rail --
/**
 * The first level of the tab control: which of the four groups you are in.
 * Eight of the twelve destinations used to be reachable only through the
 * hamburger, and nothing on screen ever named the group.
 */
@Composable
private fun GroupRail(vm: StudioViewModel, onPick: (TabGroup) -> Unit) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            .selectableGroup()
            .padding(horizontal = 8.dp, vertical = 3.dp),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        TabGroup.entries.forEach { g ->
            val on = vm.tab.group == g
            Box(
                Modifier
                    .weight(1f)
                    .heightIn(min = 28.dp)
                    .clip(ControlShape)
                    .background(if (on) ide.accent.copy(alpha = 0.14f) else Color.Transparent)
                    // borderStrong, not border: this outline is the only edge the
                    // chip has and it is something you press.
                    .border(1.dp, if (on) ide.accent else ide.borderStrong, ControlShape)
                    .selectable(selected = on, role = Role.Tab, onClick = { onPick(g) }),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    g.title.uppercase(),
                    color = if (on) ide.accent else ide.dim,
                    fontSize = Type.caption,
                    fontWeight = if (on) FontWeight.SemiBold else FontWeight.Medium,
                    letterSpacing = 0.8.sp,
                    maxLines = 1
                )
            }
        }
    }
}

/**
 * The second level: the tabs inside the current group, at most four, so it never
 * actually scrolls. Deliberately shorter than a stock Material tab row — the
 * group rail above it costs height and the two together have to stay cheap.
 */
@Composable
private fun TabStrip(vm: StudioViewModel) {
    val ide = LocalIde.current
    val groupTabs = Tab.of(vm.tab.group)
    val index = groupTabs.indexOf(vm.tab).coerceAtLeast(0)
    ScrollableTabRow(
        selectedTabIndex = index,
        edgePadding = 12.dp,
        containerColor = ide.bg,
        contentColor = ide.text,
        divider = { HorizontalDivider(color = ide.border) },
        indicator = { positions ->
            if (index in positions.indices) {
                TabRowDefaults.SecondaryIndicator(
                    Modifier.tabIndicatorOffset(positions[index]),
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
                onClick = { vm.navigateTo(t) },
                modifier = Modifier.heightIn(min = 36.dp),
                selectedContentColor = ide.text,
                unselectedContentColor = ide.dim
            ) {
                Text(
                    t.title,
                    fontSize = Type.body,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                    color = if (selected) ide.text else ide.dim,
                    maxLines = 1,
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp)
                )
            }
        }
    }
}

// ------------------------------------------------------------- empty state --
@Composable
private fun EmptyState(vm: StudioViewModel, onOpen: () -> Unit, onMoreRecents: () -> Unit) {
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
                .imePadding()
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
                    "Nocturne", color = ide.text, fontSize = Type.display,
                    fontWeight = FontWeight.Light, letterSpacing = (-1.1).sp
                )
                Spacer(Modifier.height(6.dp))
                Text(
                    "Interactive disassembler & decompiler",
                    color = ide.dim, fontSize = Type.label
                )
                Spacer(Modifier.height(16.dp))
                ArchChips()
                Spacer(Modifier.height(20.dp))

                // The only filled object on the screen, and the only one that
                // lifts. A 16dp accent-tinted shadow over an already saturated
                // accent fill read as bloom rather than elevation.
                Box(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .shadow(8.dp, ControlShape, clip = false)
                        .background(ide.accent, ControlShape)
                        .clickable(enabled = !vm.busy, role = Role.Button) { onOpen() },
                    contentAlignment = Alignment.Center
                ) {
                    if (vm.busy) {
                        Row(
                            Modifier.padding(vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            CircularProgressIndicator(
                                color = ide.onAccent,
                                modifier = Modifier.size(16.dp), strokeWidth = 2.dp
                            )
                            Spacer(Modifier.width(10.dp))
                            Text(
                                "Analyzing…", color = ide.onAccent,
                                fontSize = Type.section, fontWeight = FontWeight.SemiBold
                            )
                        }
                    } else {
                        Row(
                            Modifier.padding(vertical = 12.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Filled.FolderOpen, contentDescription = null,
                                tint = ide.onAccent, modifier = Modifier.size(18.dp)
                            )
                            Spacer(Modifier.width(9.dp))
                            Text(
                                "Open a binary", color = ide.onAccent,
                                fontSize = Type.section, fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                }

                Spacer(Modifier.height(10.dp))
                Text(
                    "Ctrl+K palette   ·   Ctrl+F search   ·   F1 shortcuts",
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                )
            }

            // Recents belong on the first screen, not only behind the drawer —
            // reopening the last binary is the most common way in. One panel
            // block with hairline rules, not four separately framed cards: the
            // group is one object and it should read as one.
            if (vm.recents.isNotEmpty()) {
                Spacer(Modifier.height(22.dp))
                Row(
                    Modifier.fillMaxWidth().padding(start = 20.dp, end = 20.dp, bottom = 8.dp),
                    verticalAlignment = Alignment.Bottom
                ) {
                    Text(
                        "RECENT", color = ide.dim, fontSize = Type.caption,
                        fontWeight = FontWeight.Medium, letterSpacing = 1.sp
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        "${vm.recents.size}",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                    )
                }
                val shown = vm.recents.take(4)
                Column(
                    Modifier
                        .padding(horizontal = 16.dp)
                        .fillMaxWidth()
                        .clip(CardShape)
                        .background(ide.panel)
                ) {
                    shown.forEachIndexed { i, rp ->
                        if (i > 0) HorizontalDivider(color = ide.border)
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable(role = Role.Button) { vm.openRecent(ctx, rp) }
                                .heightIn(min = 46.dp)
                                .padding(horizontal = 14.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                fileIcon(rp.format), contentDescription = null,
                                tint = ide.dim, modifier = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(11.dp))
                            Text(
                                rp.name, color = ide.text, fontSize = Type.mono,
                                fontFamily = Mono, maxLines = 1,
                                modifier = Modifier.weight(1f)
                            )
                            Text(
                                rp.format.ifEmpty { "RAW" },
                                color = ide.dim2, fontSize = Type.monoSmall,
                                fontFamily = Mono
                            )
                        }
                    }
                    if (vm.recents.size > shown.size) {
                        HorizontalDivider(color = ide.border)
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable(role = Role.Button) { onMoreRecents() }
                                .heightIn(min = 40.dp)
                                .padding(horizontal = 14.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Filled.MoreHoriz, contentDescription = null,
                                tint = ide.dim2, modifier = Modifier.size(16.dp)
                            )
                            Spacer(Modifier.width(11.dp))
                            Text(
                                "${vm.recents.size - shown.size} more in the project drawer",
                                color = ide.dim2, fontSize = Type.caption
                            )
                        }
                    }
                }
            } else {
                Spacer(Modifier.height(22.dp))
                Text(
                    ".so    .dex    .exe    .apk",
                    color = ide.dim2, fontSize = Type.label, fontFamily = Mono,
                    modifier = Modifier.fillMaxWidth(), textAlign = TextAlign.Center
                )
            }

            Spacer(Modifier.height(18.dp))
            ConsoleCard(vm)
            Spacer(Modifier.height(16.dp))
            // Real inset instead of a guessed 40dp spacer.
            NavBarSpacer()
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
                color = tint, fontSize = Type.caption, fontFamily = Mono,
                modifier = Modifier
                    // The pill has no fill, so this hairline is its only edge.
                    .border(1.dp, ide.borderStrong, RoundedCornerShape(999.dp))
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
            .border(1.dp, ide.borderStrong, CardShape)
            .background(ide.panel, CardShape)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(start = 14.dp, end = 14.dp, top = 11.dp, bottom = 9.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(Modifier.size(6.dp).background(ide.amber, CircleShape))
            Spacer(Modifier.width(8.dp))
            Text(
                "CONSOLE", color = ide.dim, fontSize = Type.caption,
                fontWeight = FontWeight.Medium, letterSpacing = 1.sp,
                modifier = Modifier.weight(1f)
            )
            Text(
                "${vm.plugins.size} plugins",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono
            )
        }
        Column(Modifier.padding(start = 14.dp, end = 14.dp, bottom = 13.dp)) {
            vm.console.takeLast(2).forEach { line ->
                Row {
                    Text(
                        "[${line.level.lowercase()}] ",
                        color = levelColor(line.level, ide), fontSize = Type.monoSmall, fontFamily = Mono
                    )
                    Text(
                        line.msg, color = ide.dim, fontSize = Type.monoSmall,
                        fontFamily = Mono, lineHeight = 15.sp, maxLines = 2
                    )
                }
            }
        }
    }
}

// ----------------------------------------------------------------- drawer --
@Composable
private fun ProjectDrawer(
    vm: StudioViewModel,
    onClose: () -> Unit,
    openFile: () -> Unit,
    onAnnotations: () -> Unit
) {
    val ide = LocalIde.current
    val meta = vm.meta
    val ctx = LocalContext.current
    LazyColumn(
        Modifier.fillMaxSize().background(ide.panel),
        contentPadding = bottomInset(12.dp)
    ) {
        // The drawer is full-bleed under edge-to-edge, so the header would
        // otherwise start behind the clock.
        item { Spacer(Modifier.statusBarsPadding()) }
        item {
            Column(Modifier.fillMaxWidth().background(ide.panel2).padding(12.dp)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        meta?.let { fileIcon(it.format) } ?: Icons.Filled.FolderOpen,
                        contentDescription = null, tint = ide.accent,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(Modifier.width(8.dp))
                    Text(
                        meta?.name ?: "No file", color = ide.text, fontSize = Type.section,
                        fontWeight = FontWeight.Bold, maxLines = 1
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

        item {
            DrawerAction(Icons.Filled.FolderOpen, "Open binary…", "Ctrl+O") {
                openFile(); onClose()
            }
            DrawerAction(
                Icons.Filled.Star,
                "Bookmarks & notes",
                "${vm.bookmarks.size} marked · ${vm.comments.size} commented"
            ) { onAnnotations() }
            HorizontalDivider(color = ide.border)
        }

        // Navigation lives here too: every destination visible at once, grouped.
        // The group rail under the header now reaches all of them in one tap as
        // well, so this is the index rather than the only way through.
        TabGroup.entries.forEach { group ->
            item { SectionTitle(group.title) }
            items(Tab.of(group).size) { i ->
                val t = Tab.of(group)[i]
                val active = vm.tab == t
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(if (active) ide.accent.copy(alpha = 0.10f) else Color.Transparent)
                        .selectable(selected = active, role = Role.Tab) {
                            vm.navigateTo(t); onClose()
                        }
                        .heightIn(min = 40.dp)
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(tabIcon(t), if (active) ide.accent else ide.dim, 16.dp)
                    Text(
                        t.title,
                        color = if (active) ide.accent else ide.text,
                        fontSize = Type.body,
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

        // Every list below is capped so the drawer stays scrollable. The counts
        // in the headers used to be the true totals while the list silently
        // stopped short, so each one now says what it is showing and offers the
        // panel that has the rest.
        if (vm.recents.isNotEmpty()) {
            val shown = minOf(vm.recents.size, 8)
            item { SectionTitle(countLabel("Recent projects", shown, vm.recents.size)) }
            items(shown) { i ->
                val rp = vm.recents[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(role = Role.Button) { vm.openRecent(ctx, rp); onClose() }
                        .heightIn(min = 36.dp)
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(fileIcon(rp.format), ide.dim, 13.dp)
                    Text(
                        rp.name, color = ide.cyan, fontSize = Type.mono, fontFamily = Mono,
                        maxLines = 1, modifier = Modifier.weight(1f)
                    )
                    Text(rp.format.ifEmpty { "RAW" }, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                }
            }
            if (vm.recents.size > shown) {
                item { MoreRow("${vm.recents.size - shown} older projects not listed") }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // BOOKMARKS
        if (vm.bookmarks.isNotEmpty()) {
            val shown = minOf(vm.bookmarks.size, 10)
            item { SectionTitle(countLabel("Bookmarks", shown, vm.bookmarks.size)) }
            items(shown) { i ->
                val b = vm.bookmarks[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(role = Role.Button) {
                            jumpToAddress(vm, b.addr)
                            onClose()
                        }
                        .heightIn(min = 36.dp)
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(Icons.Filled.Star, ide.amber, 13.dp)
                    Text(b.label, color = ide.text, fontSize = Type.mono, maxLines = 1, modifier = Modifier.weight(1f))
                    Text(b.addr, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                }
            }
            item {
                MoreRow(
                    if (vm.bookmarks.size > shown)
                        "${vm.bookmarks.size - shown} more · open Bookmarks & notes"
                    else "Review or delete in Bookmarks & notes"
                ) { onAnnotations() }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // APK CONTENTS
        if (vm.apkEntries.isNotEmpty()) {
            val shown = minOf(vm.apkEntries.size, 40)
            item { SectionTitle(countLabel("APK contents", shown, vm.apkEntries.size)) }
            items(shown) { i ->
                val e = vm.apkEntries[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(role = Role.Button) { vm.openApkEntry(e); onClose() }
                        .heightIn(min = 36.dp)
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(
                        if (e.name.endsWith(".apk")) Icons.Filled.Android
                        else if (e.name.endsWith(".so")) Icons.Filled.Memory
                        else Icons.Filled.Description,
                        ide.dim, 13.dp
                    )
                    Text(e.name, color = ide.cyan, fontSize = Type.mono, fontFamily = Mono, maxLines = 1, modifier = Modifier.weight(1f))
                    Text("${e.size}", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                }
            }
            if (vm.apkEntries.size > shown) {
                item {
                    MoreRow("${vm.apkEntries.size - shown} more · open the APK tab") {
                        vm.navigateTo(Tab.APK); onClose()
                    }
                }
            }
            item { HorizontalDivider(color = ide.border) }
        }
        // FUNCTIONS with icons
        if (meta != null && meta.functions.isNotEmpty()) {
            val shown = minOf(meta.functions.size, 150)
            item { SectionTitle(countLabel("Functions", shown, meta.functions.size)) }
            items(shown) { i ->
                val f = meta.functions[i]
                val display = vm.renames["0x%08X".format(f.addr)] ?: f.name
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(role = Role.Button) {
                            vm.navigateTo(addr = f.addr)
                            onClose()
                        }
                        .heightIn(min = 36.dp)
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
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
                        fontSize = Type.mono, fontFamily = Mono,
                        modifier = Modifier.weight(1f), maxLines = 1
                    )
                    Text(hexFmt(f.addr), color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                }
            }
            if (meta.functions.size > shown) {
                item {
                    MoreRow("${meta.functions.size - shown} more · search them in Functions") {
                        vm.symbolsMode = "functions"
                        vm.navigateTo(Tab.FUNCTIONS)
                        onClose()
                    }
                }
            }
            item { HorizontalDivider(color = ide.border) }
        } else {
            item { SectionTitle("Functions (0)") }
        }
        // IMPORTS
        if (meta != null && meta.imports.isNotEmpty()) {
            val shown = minOf(meta.imports.size, 60)
            item { SectionTitle(countLabel("Imports", shown, meta.imports.size)) }
            items(shown) { i ->
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 30.dp)
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(Icons.Filled.ArrowDownward, ide.dim, 13.dp)
                    Text(
                        meta.imports[i].name,
                        color = ide.dim, fontSize = Type.mono, fontFamily = Mono, maxLines = 1
                    )
                }
            }
            if (meta.imports.size > shown) {
                item {
                    MoreRow("${meta.imports.size - shown} more · open Functions, then Imports") {
                        vm.symbolsMode = "imports"
                        vm.navigateTo(Tab.FUNCTIONS)
                        onClose()
                    }
                }
            }
            item { HorizontalDivider(color = ide.border) }
        } else {
            item { SectionTitle("Imports (0)") }
        }
        // SECTIONS
        if (meta != null && meta.sections.isNotEmpty()) {
            val shown = minOf(meta.sections.size, 60)
            item { SectionTitle(countLabel("Sections", shown, meta.sections.size)) }
            items(shown) { i ->
                val s = meta.sections[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(role = Role.Button) { vm.navigateTo(Tab.MAP); onClose() }
                        .heightIn(min = 30.dp)
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    RowIcon(
                        if (s.flags.contains("X")) Icons.Filled.Code
                        else if (s.flags.contains("W")) Icons.Filled.Edit
                        else Icons.Filled.Storage,
                        ide.dim, 13.dp
                    )
                    Text(s.name.ifEmpty { "(unnamed)" }, color = ide.text, fontSize = Type.mono, fontFamily = Mono, maxLines = 1)
                    Spacer(Modifier.weight(1f))
                    Text("${s.flags} · ${s.size}", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                }
            }
            if (meta.sections.size > shown) {
                item {
                    MoreRow("${meta.sections.size - shown} more · open the Map tab") {
                        vm.navigateTo(Tab.MAP); onClose()
                    }
                }
            }
        } else {
            item { SectionTitle("Sections (0)") }
        }
        item {
            Spacer(Modifier.height(12.dp))
            Text(
                "Ctrl+K — command palette · Ctrl+F — search · Ctrl+B — annotations",
                color = ide.dim, fontSize = Type.caption, fontFamily = Mono,
                modifier = Modifier.padding(12.dp)
            )
        }
    }
}

/** "Functions · 150 of 4213" when capped, "Functions (412)" when it is all of them. */
private fun countLabel(name: String, shown: Int, total: Int): String =
    if (shown < total) "$name · $shown of $total" else "$name ($total)"

@Composable
private fun DrawerAction(icon: ImageVector, label: String, hint: String, onClick: () -> Unit) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClick = onClick)
            .heightIn(min = 44.dp)
            .padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(icon, ide.dim, 16.dp)
        Column(Modifier.weight(1f)) {
            Text(label, color = ide.text, fontSize = Type.body)
            Text(hint, color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1)
        }
    }
}

/** The honest tail of a capped list. Silence here reads as "that is all of it". */
@Composable
private fun MoreRow(text: String, onClick: (() -> Unit)? = null) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                if (onClick != null) Modifier.clickable(role = Role.Button, onClick = onClick)
                else Modifier
            )
            .heightIn(min = 34.dp)
            .padding(horizontal = 12.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(Icons.Filled.MoreHoriz, ide.dim2, 13.dp)
        Text(
            text,
            color = if (onClick != null) ide.cyan else ide.dim2,
            fontSize = Type.caption, maxLines = 1
        )
    }
}

/**
 * Jump to a "0x…" address string: select the function that contains it and ask
 * whichever panel lands next to reveal the exact line.
 */
private fun jumpToAddress(vm: StudioViewModel, addr: String) {
    val a = addr.removePrefix("0x").removePrefix("0X").toLongOrNull(16) ?: return
    vm.requestGoto(a)
    vm.navigateTo(Tab.ASSEMBLY, vm.functionContaining(a)?.addr)
}

// --------------------------------------------------- bookmarks / notes sheet --
/**
 * Everything the user has marked up in this binary, in one place. Bookmarks
 * could be created and never removed — `removeBookmark` had no caller at all —
 * comments were only visible under the line they annotate, and the notes table
 * the About dialog advertises had no UI whatsoever.
 *
 * Deliberately not a thirteenth tab: `Tab` lives in the ViewModel and is not
 * this file's to extend.
 */
@Composable
private fun AnnotationsSheet(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    var section by rememberSaveable { mutableStateOf(0) }
    var draft by rememberSaveable { mutableStateOf("") }
    val comments = vm.comments.entries.sortedBy { it.key }
    val notes = vm.notes(ctx)

    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier.fillMaxWidth(0.94f).fillMaxHeight(0.92f),
            color = ide.panel,
            shape = CardShape
        ) {
            Column(Modifier.fillMaxSize().imePadding()) {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(ide.panel2)
                        .heightIn(min = 48.dp)
                        .padding(start = 14.dp, end = 4.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        "ANNOTATIONS", color = ide.text, fontSize = Type.label,
                        fontWeight = FontWeight.Bold, letterSpacing = 1.sp,
                        modifier = Modifier.weight(1f)
                    )
                    IconButton(onClick = onDismiss) {
                        Icon(Icons.Filled.Close, contentDescription = "Close", tint = ide.dim)
                    }
                }
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(ide.panel2)
                        .selectableGroup()
                        .padding(start = 8.dp, end = 8.dp, bottom = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    val tabs = listOf(
                        "BOOKMARKS" to vm.bookmarks.size,
                        "COMMENTS" to comments.size,
                        "NOTES" to notes.size
                    )
                    tabs.forEachIndexed { i, (label, n) ->
                        val on = section == i
                        Box(
                            Modifier
                                .weight(1f)
                                .heightIn(min = 30.dp)
                                .clip(ControlShape)
                                .background(if (on) ide.accent.copy(alpha = 0.14f) else Color.Transparent)
                                .border(1.dp, if (on) ide.accent else ide.borderStrong, ControlShape)
                                .selectable(selected = on, role = Role.Tab) { section = i },
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                "$label $n",
                                color = if (on) ide.accent else ide.dim,
                                fontSize = Type.caption,
                                fontWeight = if (on) FontWeight.SemiBold else FontWeight.Medium,
                                maxLines = 1
                            )
                        }
                    }
                }
                HorizontalDivider(color = ide.border)

                Box(Modifier.weight(1f)) {
                    when (section) {
                        0 -> if (vm.bookmarks.isEmpty()) {
                            EmptyPanel(
                                "No bookmarks yet",
                                "Long-press a disassembly line and choose Bookmark to mark an address."
                            )
                        } else {
                            LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset()) {
                                items(vm.bookmarks.size) { i ->
                                    val b = vm.bookmarks[i]
                                    AnnotationRow(
                                        icon = Icons.Filled.Star,
                                        tint = ide.amber,
                                        title = b.label,
                                        sub = b.addr,
                                        onOpen = { jumpToAddress(vm, b.addr); onDismiss() },
                                        onDelete = { vm.removeBookmark(ctx, b.id) },
                                        deleteLabel = "Delete bookmark"
                                    )
                                }
                            }
                        }
                        1 -> if (comments.isEmpty()) {
                            EmptyPanel(
                                "No comments yet",
                                "Long-press a disassembly line to annotate it; every comment you write shows up here."
                            )
                        } else {
                            LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset()) {
                                items(comments.size) { i ->
                                    val e = comments[i]
                                    val a = e.key.removePrefix("0x").removePrefix("0X").toLongOrNull(16)
                                    val owner = a?.let { vm.functionContaining(it) }
                                    AnnotationRow(
                                        icon = Icons.Filled.Comment,
                                        tint = ide.cyan,
                                        title = e.value,
                                        sub = if (owner != null)
                                            "${e.key}  ·  ${vm.effectiveFuncName(owner.addr)}" else e.key,
                                        onOpen = { jumpToAddress(vm, e.key); onDismiss() },
                                        onDelete = { if (a != null) vm.removeComment(ctx, a) },
                                        deleteLabel = "Delete comment"
                                    )
                                }
                            }
                        }
                        else -> if (notes.isEmpty()) {
                            EmptyPanel(
                                "No notes yet",
                                "Free-text notes for this binary. The first line becomes the title."
                            )
                        } else {
                            LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset()) {
                                items(notes.size) { i ->
                                    val n = notes[i]
                                    AnnotationRow(
                                        icon = Icons.Filled.Notes,
                                        tint = ide.violet,
                                        title = n.title,
                                        sub = n.body.ifEmpty { "—" },
                                        onOpen = null,
                                        onDelete = { vm.deleteNote(ctx, n.id) },
                                        deleteLabel = "Delete note"
                                    )
                                }
                            }
                        }
                    }
                }

                if (section == 2) {
                    HorizontalDivider(color = ide.border)
                    Row(
                        Modifier.fillMaxWidth().background(ide.panel2).padding(8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        OutlinedTextField(
                            value = draft,
                            onValueChange = { draft = it },
                            placeholder = {
                                Text(
                                    "New note — first line is the title",
                                    color = ide.dim2, fontSize = Type.label
                                )
                            },
                            modifier = Modifier.weight(1f),
                            textStyle = TextStyle(fontSize = Type.label, color = ide.text),
                            maxLines = 3
                        )
                        Spacer(Modifier.width(8.dp))
                        IconButton(
                            onClick = { vm.addNote(ctx, draft); draft = "" },
                            enabled = draft.isNotBlank()
                        ) {
                            Icon(
                                Icons.Filled.Add, contentDescription = "Add note",
                                tint = if (draft.isNotBlank()) ide.accent else ide.dim2
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun AnnotationRow(
    icon: ImageVector,
    tint: Color,
    title: String,
    sub: String,
    onOpen: (() -> Unit)?,
    onDelete: () -> Unit,
    deleteLabel: String
) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                if (onOpen != null) Modifier.clickable(role = Role.Button, onClick = onOpen)
                else Modifier
            )
            .heightIn(min = 48.dp)
            .padding(start = 12.dp, end = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(icon, tint, 15.dp)
        Column(Modifier.weight(1f).padding(vertical = 6.dp)) {
            Text(title, color = ide.text, fontSize = Type.label, maxLines = 2)
            Text(sub, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1)
        }
        IconButton(onClick = onDelete) {
            Icon(
                Icons.Filled.Delete, contentDescription = deleteLabel,
                tint = ide.dim, modifier = Modifier.size(18.dp)
            )
        }
    }
    HorizontalDivider(color = ide.border)
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
        fontSize = Type.caption,
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
                Text("Reverse-engineering studio for ELF, PE, DEX and APK binaries.", color = ide.text, fontSize = Type.label)
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
                    color = ide.amber, fontSize = Type.caption, lineHeight = 14.sp
                )
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("OK", color = ide.accent) } }
    )
}

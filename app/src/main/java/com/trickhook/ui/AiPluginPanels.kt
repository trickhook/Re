package com.trickhook.ui

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.OpenInFull
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TextFields
import androidx.compose.material.icons.filled.TrendingUp
import androidx.compose.material.icons.filled.Undo
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.model.PluginDef
import com.trickhook.vm.StudioViewModel

// ========================================================== Plugins panel ==

/** The three NocturneScript builtins that write into the project. */
private val SCRIPT_WRITE_OPS = listOf(
    "rename" to "renames",
    "comment" to "comments",
    "bookmark" to "bookmarks"
)

/**
 * Which of the writing builtins a plugin's source actually calls. A run is the
 * only action in Nocturne that can destroy work the user typed by hand, so the
 * panel says up front what a script is able to touch instead of finding out
 * afterwards from the log. `##` starts a comment in NocturneScript, so the
 * commented-out half of a line never counts.
 */
private fun pluginWriteOps(script: String): List<String> {
    val code = script.lineSequence().joinToString("\n") { it.substringBefore("##") }
    return SCRIPT_WRITE_OPS
        .filter { (fn, _) -> Regex("(^|[^A-Za-z0-9_])${fn}\\s*\\(").containsMatchIn(code) }
        .map { it.second }
}

/** What a finished run actually wrote, read back out of its own log. */
private data class RunChanges(val renames: Int, val comments: Int, val bookmarks: Int) {
    val total: Int get() = renames + comments + bookmarks

    fun label(): String {
        val parts = ArrayList<String>(3)
        if (renames > 0) parts.add("$renames rename${plural(renames)}")
        if (comments > 0) parts.add("$comments comment${plural(comments)}")
        if (bookmarks > 0) parts.add("$bookmarks bookmark${plural(bookmarks)}")
        return if (parts.isEmpty()) "nothing changed" else parts.joinToString(" · ")
    }

    private fun plural(n: Int) = if (n == 1) "" else "s"
}

/** The effect lines the run appends look like `  [rename] 0x0000A1B0 -> foo`. */
private fun parseChanges(output: String): RunChanges {
    var renames = 0
    var comments = 0
    var bookmarks = 0
    for (line in output.lineSequence()) {
        val t = line.trim()
        val close = t.indexOf(']')
        if (!t.startsWith("[") || close < 0) continue
        when (t.substring(1, close)) {
            "rename" -> renames++
            "comment" -> comments++
            "bookmark" -> bookmarks++
        }
    }
    return RunChanges(renames, comments, bookmarks)
}

@Composable
fun PluginsPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    var showLog by remember { mutableStateOf(false) }
    var confirm by remember { mutableStateOf<PluginDef?>(null) }

    val changes = remember(vm.pluginOutput) { parseChanges(vm.pluginOutput) }
    val hasResult = vm.pluginOutput.isNotEmpty()
    // The result bar carries its own navigation-bar inset; when it is absent
    // the list has to carry it itself, or its last card hides behind the bar.
    val listBottom = bottomInset(20.dp).calculateBottomPadding()

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            Text(
                "NOCTURNESCRIPT", color = ide.dim, fontSize = Type.caption,
                fontWeight = FontWeight.Medium, letterSpacing = 1.sp
            )
            Spacer(Modifier.width(8.dp))
            Text(
                "${vm.plugins.size} installed",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
            )
        }
        if (vm.plugins.isEmpty()) {
            Box(
                Modifier.weight(1f).fillMaxWidth().background(ide.bg),
                contentAlignment = Alignment.Center
            ) {
                EmptyPanel(
                    "No plugins installed",
                    "Nocturne copies its bundled .nocturneplugin scripts into files/plugins the first time it starts. None were found there."
                )
            }
        } else {
            LazyColumn(
                Modifier.weight(1f).background(ide.bg),
                contentPadding = PaddingValues(
                    start = 16.dp, end = 16.dp, top = 8.dp,
                    bottom = if (hasResult) 20.dp else listBottom
                ),
                verticalArrangement = Arrangement.spacedBy(9.dp)
            ) {
                items(vm.plugins.size) { i ->
                    val p = vm.plugins[i]
                    val (icon, tint) = pluginIcon(p.id, ide)
                    val writes = remember(p.script) { pluginWriteOps(p.script) }
                    val running = vm.pluginRunning && vm.lastPluginName == p.name
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .border(1.dp, ide.borderStrong, RoundedCornerShape(13.dp))
                            .background(ide.panel, RoundedCornerShape(13.dp))
                            .padding(horizontal = 14.dp, vertical = 13.dp)
                    ) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            Box(
                                Modifier
                                    .size(28.dp)
                                    .background(tint.copy(alpha = 0.14f), RoundedCornerShape(8.dp)),
                                contentAlignment = Alignment.Center
                            ) {
                                Icon(icon, contentDescription = null, tint = tint,
                                    modifier = Modifier.size(15.dp))
                            }
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    p.name, color = ide.text, fontSize = Type.body,
                                    fontWeight = FontWeight.SemiBold
                                )
                                Text(
                                    if (writes.isEmpty()) "v${p.version} · read-only"
                                    else "v${p.version} · writes ${writes.joinToString(", ")}",
                                    color = if (writes.isEmpty()) ide.dim2 else ide.amber,
                                    fontSize = Type.monoSmall,
                                    fontFamily = Mono
                                )
                            }
                            Spacer(Modifier.width(8.dp))
                            // A 48dp target around a 32dp pill: the pill used
                            // to be the whole 30dp target.
                            Box(
                                Modifier
                                    .heightIn(min = 48.dp)
                                    .clickable(
                                        enabled = !vm.pluginRunning,
                                        role = Role.Button,
                                        onClickLabel = "Run ${p.name}"
                                    ) {
                                        if (writes.isEmpty()) {
                                            vm.runPlugin(ctx, p)
                                        } else {
                                            confirm = p
                                        }
                                    },
                                contentAlignment = Alignment.Center
                            ) {
                                Row(
                                    Modifier
                                        .then(
                                            if (vm.pluginRunning)
                                                Modifier.border(1.dp, ide.borderStrong, RoundedCornerShape(9.dp))
                                            else
                                                Modifier.background(
                                                    ide.accent.copy(alpha = 0.15f),
                                                    RoundedCornerShape(9.dp)
                                                )
                                        )
                                        .heightIn(min = 32.dp)
                                        .padding(horizontal = 15.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    if (running) {
                                        CircularProgressIndicator(
                                            modifier = Modifier.size(12.dp),
                                            color = ide.dim,
                                            strokeWidth = 1.5.dp
                                        )
                                        Spacer(Modifier.width(7.dp))
                                    }
                                    Text(
                                        if (running) "Running" else "Run",
                                        color = if (vm.pluginRunning) ide.dim2 else ide.accent,
                                        fontSize = Type.label, fontWeight = FontWeight.SemiBold
                                    )
                                }
                            }
                        }
                        if (p.description.isNotEmpty()) {
                            Spacer(Modifier.height(8.dp))
                            Text(
                                p.description, color = ide.dim, fontSize = Type.label,
                                lineHeight = 16.sp
                            )
                        }
                    }
                }
            }
        }
        // A fixed 200dp slab used to eat the bottom of the list and clip the
        // log mid-line. The result is a one-line bar now; the whole log opens
        // full-screen, where it can be read, copied or saved.
        if (hasResult) {
            Column(Modifier.fillMaxWidth().background(ide.panel)) {
                HorizontalDivider(color = ide.borderStrong)
                Row(
                    Modifier
                        .fillMaxWidth()
                        .heightIn(min = 56.dp)
                        .clickable(role = Role.Button, onClickLabel = "Open the full log") {
                            showLog = true
                        }
                        .padding(horizontal = 16.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Box(
                        Modifier
                            .size(7.dp)
                            .background(
                                when {
                                    !vm.lastPluginOk -> ide.red
                                    changes.total == 0 -> ide.dim
                                    else -> ide.entry
                                },
                                CircleShape
                            )
                    )
                    Spacer(Modifier.width(10.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            vm.lastPluginName.ifEmpty { "Plugin result" },
                            color = ide.text, fontSize = Type.label, fontWeight = FontWeight.Medium
                        )
                        // An empty run and a failed run used to read the same.
                        Text(
                            when {
                                !vm.lastPluginOk -> "failed — tap to read the error"
                                changes.total == 0 ->
                                    "ran clean · nothing changed · ${vm.pluginOutput.lineSequence().count()} lines"
                                else -> "wrote ${changes.label()}"
                            },
                            color = if (vm.lastPluginOk) ide.dim2 else ide.red,
                            fontSize = Type.caption, fontFamily = Mono
                        )
                    }
                    Icon(
                        Icons.Filled.OpenInFull, contentDescription = "Open full log",
                        tint = ide.accent, modifier = Modifier.size(17.dp)
                    )
                }
                // A toast is gone in four seconds; the one destructive action
                // in the app keeps its way back for as long as it is undoable.
                if (vm.lastPluginUndoable) UndoRow(vm, changes)
                NavBarSpacer()
            }
        }
    }

    val pending = confirm
    if (pending != null) {
        RunConfirmDialog(
            plugin = pending,
            writes = pluginWriteOps(pending.script),
            onDismiss = { confirm = null },
            onRun = {
                confirm = null
                vm.runPlugin(ctx, pending)
            }
        )
    }

    if (showLog) PluginLogSheet(vm) { showLog = false }
}

/** The visible, non-transient counterpart to the snackbar's Undo action. */
@Composable
private fun UndoRow(vm: StudioViewModel, changes: RunChanges) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clickable(role = Role.Button) { vm.undoLastPlugin(ctx) }
            .padding(horizontal = 16.dp, vertical = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.Undo, contentDescription = null, tint = ide.accent,
            modifier = Modifier.size(15.dp)
        )
        Spacer(Modifier.width(8.dp))
        Text(
            "Undo these changes", color = ide.accent, fontSize = Type.label,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.weight(1f))
        Text(
            changes.label(), color = ide.dim2, fontSize = Type.caption,
            fontFamily = Mono, maxLines = 1
        )
    }
}

/**
 * Asked before a plugin that can write runs. There is no dry run — the script
 * decides what it touches while it executes — so the honest preview is which
 * kinds of annotation it is able to overwrite, plus the promise of undo.
 */
@Composable
private fun RunConfirmDialog(
    plugin: PluginDef,
    writes: List<String>,
    onDismiss: () -> Unit,
    onRun: () -> Unit
) {
    val ide = LocalIde.current
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        icon = {
            Icon(
                Icons.Filled.Warning, contentDescription = null, tint = ide.amber,
                modifier = Modifier.size(20.dp)
            )
        },
        title = {
            Text(
                "Run ${plugin.name}?", color = ide.text, fontSize = Type.section,
                fontWeight = FontWeight.SemiBold
            )
        },
        text = {
            Column {
                Text(
                    "This plugin writes ${writes.joinToString(" and ")} into the project. " +
                        "Anything it finds at the same address is replaced — including a name you typed yourself.",
                    color = ide.dim, fontSize = Type.label, lineHeight = 18.sp
                )
                Spacer(Modifier.height(10.dp))
                Text(
                    "The whole run can be undone afterwards, from the result bar at the bottom of this panel.",
                    color = ide.dim2, fontSize = Type.label, lineHeight = 18.sp
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onRun) {
                Text("Run", color = ide.accent, fontSize = Type.label, fontWeight = FontWeight.SemiBold)
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("Cancel", color = ide.dim, fontSize = Type.label)
            }
        }
    )
}

/** Full-height reader for a plugin run: scrollable, copyable, savable. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PluginLogSheet(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val clip = LocalClipboardManager.current
    val changes = remember(vm.pluginOutput) { parseChanges(vm.pluginOutput) }
    val save = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri -> if (uri != null) vm.savePluginLog(ctx, uri) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp, bottom = 6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        vm.lastPluginName.ifEmpty { "Plugin result" },
                        color = ide.text, fontSize = Type.title, fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        if (vm.lastPluginOk) "finished · ${changes.label()}" else "failed",
                        color = if (vm.lastPluginOk) ide.dim2 else ide.red,
                        fontSize = Type.label, fontFamily = Mono
                    )
                }
                IconTarget(Icons.Filled.ContentCopy, "Copy log", ide.dim) {
                    clip.setText(AnnotatedString(vm.pluginOutput))
                    vm.log("OK", "Plugin log copied to the clipboard")
                }
                IconTarget(Icons.Filled.SaveAlt, "Save log", ide.accent) {
                    save.launch(vm.suggestedLogName())
                }
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(start = 20.dp, end = 12.dp, bottom = 10.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                StatChip("lines", "${vm.pluginOutput.lineSequence().count()}", ide.dim)
                StatChip("effects", "${vm.lastPluginEffects}", ide.cyan)
                if (changes.renames > 0) StatChip("renames", "${changes.renames}", ide.amber)
                if (changes.comments > 0) StatChip("comments", "${changes.comments}", ide.violet)
                if (changes.bookmarks > 0) StatChip("bookmarks", "${changes.bookmarks}", ide.cyan)
                if (!vm.lastPluginOk) StatChip("failed", ide.red)
                else if (changes.total == 0) StatChip("no changes", ide.dim2)
            }
            if (vm.lastPluginUndoable) UndoRow(vm, changes)
            HorizontalDivider(color = ide.border)
            val out = vm.pluginOutput
            if (out.isBlank()) {
                Box(Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    EmptyPanel(
                        "This run printed nothing",
                        "The script finished without a single log line and without touching the project. Nothing failed — there was simply nothing to report."
                    )
                }
            } else {
                SelectionContainer(Modifier.weight(1f).fillMaxWidth()) {
                    Text(
                        out,
                        color = ide.text, fontSize = Type.mono, fontFamily = Mono, lineHeight = 17.sp,
                        modifier = Modifier
                            .fillMaxSize()
                            .verticalScroll(rememberScrollState())
                            .horizontalScroll(rememberScrollState())
                            .padding(16.dp)
                    )
                }
            }
            NavBarSpacer()
        }
    }
}

/** A 48dp touch target around a 17dp glyph. */
@Composable
private fun IconTarget(icon: ImageVector, description: String, tint: Color, onClick: () -> Unit) {
    Box(
        Modifier
            .size(48.dp)
            .clickable(role = Role.Button, onClickLabel = description, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Icon(icon, contentDescription = description, tint = tint, modifier = Modifier.size(17.dp))
    }
}

/** Icon and tint per bundled plugin, falling back to a generic extension mark. */
private fun pluginIcon(id: String, ide: IdeColors): Pair<ImageVector, Color> = when (id) {
    "security-auditor"   -> Icons.Filled.Shield to ide.red
    "crypto-finder"      -> Icons.Filled.Lock to ide.amber
    "anti-debug-scanner" -> Icons.Filled.BugReport to ide.violet
    "jni-mapper"         -> Icons.Filled.Link to ide.cyan
    "xref-hotspots"      -> Icons.Filled.TrendingUp to ide.accent
    "attack-surface"     -> Icons.Filled.Public to ide.red
    "string-triage"      -> Icons.Filled.TextFields to ide.cyan
    "string-hunter"      -> Icons.Filled.Search to ide.cyan
    "arm-analyzer"       -> Icons.Filled.Memory to ide.violet
    "dex-helper"         -> Icons.Filled.DataObject to ide.amber
    else                 -> Icons.Filled.Extension to ide.dim
}

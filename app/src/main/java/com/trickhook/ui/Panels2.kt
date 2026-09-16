package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Functions
import androidx.compose.material.icons.filled.Grid4x4
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import com.trickhook.model.ConsoleLine
import com.trickhook.model.FoundStr
import com.trickhook.model.Section
import com.trickhook.model.Segment
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ============================================================== Strings ==
/**
 * A strings list exists to answer one question: where is this used? This one
 * used to answer it by appending a line to a console living in another tab.
 * Now a row is a destination: the function whose body covers the address if
 * there is one, otherwise the bytes themselves in the hex view. A row that can
 * reach neither is not clickable, because a ripple that leads nowhere is worse
 * than no ripple at all.
 */
@Composable
fun StringsPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val all = vm.meta?.strings ?: emptyList()
    val query = vm.stringQuery
    val filtered = remember(all, query) {
        if (query.isBlank()) all else all.filter { it.value.contains(query, ignoreCase = true) }
    }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { vm.stringQuery = it },
                label = { Text("Search strings") },
                singleLine = true,
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { vm.stringQuery = "" }) {
                            Icon(
                                Icons.Filled.Close,
                                contentDescription = "Clear the search",
                                tint = ide.dim
                            )
                        }
                    }
                },
                modifier = Modifier
                    .weight(1f)
                    .semantics { contentDescription = "Search strings" },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.width(8.dp))
            Text(
                if (query.isBlank()) "${all.size}" else "${filtered.size}/${all.size}",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
            )
        }
        when {
            all.isEmpty() -> EmptyPanel(
                "No strings",
                "Open a binary — the extracted strings from its data sections land here."
            )

            filtered.isEmpty() -> Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                EmptyPanel(
                    "No string matches \"$query\"",
                    "${all.size} strings in this binary, none containing that text."
                )
                TextButton(onClick = { vm.stringQuery = "" }) {
                    Text("Clear search", color = ide.accent, fontSize = Type.label)
                }
            }

            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(12.dp)) {
                items(filtered.size) { i -> StringsHitRow(vm, filtered[i]) }
            }
        }
    }
}

@Composable
private fun StringsHitRow(vm: StudioViewModel, s: FoundStr) {
    val ide = LocalIde.current
    // The containing function is a binary search and the file offset a walk of
    // the section table; both are indexed once per analysis on the ViewModel.
    val fn = vm.functionContaining(s.addr)
    val off = vm.fileOffsetOf(s.addr)
    val canJump = fn != null || off != null
    val where = when {
        fn != null -> "in ${vm.effectiveFuncName(fn.addr)}"
        off != null -> "no function · file @ ${hexFmt(off)}"
        else -> "no function · not mapped into the file"
    }
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                if (canJump) Modifier.clickable(
                    onClickLabel = if (fn != null) "Open in Assembly" else "Show the bytes in Hex",
                    role = Role.Button
                ) {
                    // navigateTo pushes the current place, so Back returns
                    // here; requestGoto puts the listing on this exact line
                    // rather than on the top of the function.
                    if (fn != null) {
                        vm.navigateTo(tab = Tab.ASSEMBLY, addr = fn.addr)
                        vm.requestGoto(s.addr)
                    } else if (off != null) {
                        panelJumpToHex(vm, off)
                    }
                } else Modifier
            )
            .heightIn(min = 48.dp)
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                s.value,
                color = if (canJump) ide.text else ide.dim,
                fontSize = Type.mono, fontFamily = Mono,
                maxLines = 2, overflow = TextOverflow.Ellipsis
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(hexFmt(s.addr), color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono)
                Spacer(Modifier.width(6.dp))
                Text(
                    where, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
        }
        Spacer(Modifier.width(6.dp))
        if (fn != null && off != null) {
            // The second destination: the raw bytes. Only worth its own button
            // when the tap itself is already spoken for by the code view.
            IconButton(onClick = { panelJumpToHex(vm, off) }) {
                Icon(
                    Icons.Filled.Grid4x4,
                    contentDescription = "Show the bytes in Hex",
                    tint = ide.dim,
                    modifier = Modifier.size(16.dp)
                )
            }
        } else if (off != null) {
            RowIcon(Icons.Filled.Grid4x4, ide.dim2, 14.dp, contentDescription = null)
        }
    }
}

/**
 * Put the hex view on a file offset and go there. The offset has to come from
 * [StudioViewModel.fileOffsetOf]: a virtual address used raw lands on the wrong
 * bytes for every binary with a non-zero load address, which is the same bug
 * that made the hex selection tint highlight the wrong range.
 */
private fun panelJumpToHex(vm: StudioViewModel, fileOffset: Long) {
    vm.hexIndex = (fileOffset / 16L).coerceAtLeast(0L).toInt()
    vm.navigateTo(tab = Tab.HEX)
}

// ============================================================ Functions ==
@Composable
fun FunctionsPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val all = vm.meta?.functions ?: emptyList()
    val query = vm.funcQuery
    // Not memoized: the match reads `renames`, and a rename that keeps the map
    // the same size would leave a remembered list stale while the name on the
    // row had already changed.
    val filtered = if (query.isBlank()) all else all.filter {
        it.name.contains(query, ignoreCase = true) ||
            (vm.renames["0x%08X".format(it.addr)] ?: "").contains(query, ignoreCase = true)
    }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { vm.funcQuery = it },
                label = { Text("Search functions") },
                singleLine = true,
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { vm.funcQuery = "" }) {
                            Icon(
                                Icons.Filled.Close,
                                contentDescription = "Clear the search",
                                tint = ide.dim
                            )
                        }
                    }
                },
                modifier = Modifier
                    .weight(1f)
                    .semantics { contentDescription = "Search functions" },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.width(8.dp))
            Text(
                if (query.isBlank()) "${all.size}" else "${filtered.size}/${all.size}",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
            )
        }
        when {
            all.isEmpty() -> EmptyPanel(
                "No functions",
                "Open a binary the engine can disassemble and its functions land here."
            )

            filtered.isEmpty() -> Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                EmptyPanel(
                    "No function matches \"$query\"",
                    "${all.size} functions in this binary, by name or by the name you gave it."
                )
                TextButton(onClick = { vm.funcQuery = "" }) {
                    Text("Clear search", color = ide.accent, fontSize = Type.label)
                }
            }

            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(12.dp)) {
                items(filtered.size) { i ->
                    val f = filtered[i]
                    val renamed = vm.renames["0x%08X".format(f.addr)]
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .clickable(
                                onClickLabel = "Open this function",
                                role = Role.Button
                            ) { vm.selectFunction(f.addr) }
                            .heightIn(min = 48.dp)
                            .padding(horizontal = 10.dp, vertical = 4.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RowIcon(
                            if (renamed != null) Icons.Filled.DriveFileRenameOutline
                            else Icons.Filled.Functions,
                            if (renamed != null) ide.amber else ide.dim, 13.dp,
                            contentDescription = if (renamed != null) "renamed" else null
                        )
                        Column(Modifier.weight(1f)) {
                            Text(
                                renamed ?: f.name,
                                color = if (f.addr == vm.selectedFunc) ide.accent else ide.text,
                                fontSize = Type.mono, fontFamily = Mono,
                                maxLines = 1, overflow = TextOverflow.Ellipsis
                            )
                            Text(
                                "${f.from} · ${f.size} bytes · ${f.nCallees} out / ${f.nCallers} in",
                                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                                maxLines = 1, overflow = TextOverflow.Ellipsis
                            )
                        }
                        Spacer(Modifier.width(6.dp))
                        Text(hexFmt(f.addr), color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono)
                    }
                }
            }
        }
    }
}

// ============================================================ Memory map ==
/**
 * Sections and segments. The rows used to lay out 414dp of fixed-dp columns
 * before the flags column even started, so on a phone the flags — the one
 * field that separates executable code from writable data — were not truncated
 * but absent, with nothing on screen to say so. The row is now the name over
 * a detail line, with the flags as an unweighted child that Row measures
 * before the name gets what is left — so R/W/X survives at 360dp, at any font
 * scale, and with a section name of any length.
 */
@Composable
fun MapPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta
    val sections = meta?.sections ?: emptyList()
    val segments = meta?.segments ?: emptyList()
    val segs = vm.mapMode == 1
    val rows = if (segs) segments.size else sections.size
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 6.dp)
                .selectableGroup(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            MapModeLabel("Sections", sections.size, !segs) { vm.mapMode = 0 }
            MapModeLabel("Segments", segments.size, segs) { vm.mapMode = 1 }
            Spacer(Modifier.weight(1f))
            Text(
                if (segs) "load map" else "section table",
                color = ide.dim2, fontSize = Type.caption, maxLines = 1
            )
        }
        when {
            meta == null -> EmptyPanel(
                "No binary open",
                "The section and segment tables come from the file header — open a file to read them."
            )

            rows == 0 -> EmptyPanel(
                if (segs) "No segments" else "No sections",
                if (segs) "This format has no program headers, so there is no load map to show."
                else "This file declares no section headers — try the segment view."
            )

            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(12.dp)) {
                items(rows) { i ->
                    if (segs) MapSegmentRow(vm, segments[i]) else MapSectionRow(vm, sections[i])
                }
            }
        }
    }
}

@Composable
private fun MapModeLabel(text: String, count: Int, selected: Boolean, onSelect: () -> Unit) {
    val ide = LocalIde.current
    Box(
        Modifier
            .heightIn(min = 48.dp)
            .selectable(selected = selected, role = Role.Tab, onClick = onSelect)
            .padding(horizontal = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            "$text ($count)",
            color = if (selected) ide.accent else ide.dim2,
            fontSize = Type.label,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            maxLines = 1
        )
    }
}

@Composable
private fun MapSectionRow(vm: StudioViewModel, s: Section) {
    val ide = LocalIde.current
    // NOBITS occupies no bytes on disk, so its offset points at whatever
    // follows it — jumping there would show the wrong bytes confidently.
    val hasBytes = s.type != "NOBITS" && s.size > 0L && s.offset > 0L
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                if (hasBytes) Modifier.clickable(
                    onClickLabel = "Show these bytes in Hex",
                    role = Role.Button
                ) { panelJumpToHex(vm, s.offset) } else Modifier
            )
            .heightIn(min = 48.dp)
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(
            mapFlagIcon(s.flags), mapFlagTint(s.flags, ide), 13.dp,
            contentDescription = mapFlagLabel(s.flags)
        )
        Column(Modifier.weight(1f)) {
            Text(
                s.name.ifEmpty { "(unnamed)" },
                color = ide.text, fontSize = Type.mono, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                "${s.type} · ${hexFmt(s.addr)} · ${s.size} B",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        Spacer(Modifier.width(8.dp))
        MapFlagsText(s.flags)
    }
}

@Composable
private fun MapSegmentRow(vm: StudioViewModel, s: Segment) {
    val ide = LocalIde.current
    val hasBytes = s.filesz > 0L
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                if (hasBytes) Modifier.clickable(
                    onClickLabel = "Show these bytes in Hex",
                    role = Role.Button
                ) { panelJumpToHex(vm, s.offset) } else Modifier
            )
            .heightIn(min = 48.dp)
            .padding(horizontal = 10.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(
            mapFlagIcon(s.flags), mapFlagTint(s.flags, ide), 13.dp,
            contentDescription = mapFlagLabel(s.flags)
        )
        Column(Modifier.weight(1f)) {
            Text(
                s.type, color = ide.amber, fontSize = Type.mono, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                "${hexFmt(s.vaddr)} · ${s.filesz} B file · ${s.memsz} B mem",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        Spacer(Modifier.width(8.dp))
        MapFlagsText(s.flags)
    }
}

/**
 * The flags string — "AX", "RWX", "-" — one character at a time, so the two
 * that change what a section IS are the only coloured ones. The field is a
 * plain String on the model, which is why this needs an AnnotatedString rather
 * than a colour parameter.
 */
@Composable
private fun MapFlagsText(flags: String) {
    val ide = LocalIde.current
    val text = buildAnnotatedString {
        for (c in flags) {
            val tint = when (c) {
                'X' -> ide.accent
                'W' -> ide.amber
                else -> ide.dim2
            }
            withStyle(
                SpanStyle(
                    color = tint,
                    fontWeight = if (c == 'X' || c == 'W') FontWeight.Bold else FontWeight.Normal
                )
            ) { append(c.toString()) }
        }
    }
    Text(
        text, fontSize = Type.mono, fontFamily = Mono, maxLines = 1,
        modifier = Modifier.widthIn(min = 36.dp)
    )
}

private fun mapFlagIcon(flags: String): ImageVector = when {
    flags.contains('X') -> Icons.Filled.Code
    flags.contains('W') -> Icons.Filled.Edit
    else -> Icons.Filled.Storage
}

private fun mapFlagTint(flags: String, ide: IdeColors): Color = when {
    flags.contains('X') -> ide.accent
    flags.contains('W') -> ide.amber
    else -> ide.dim2
}

private fun mapFlagLabel(flags: String): String = when {
    flags.contains('X') -> "executable"
    flags.contains('W') -> "writable"
    else -> "read-only"
}

// =============================================================== Console ==
/**
 * Every failure in the app reports here, on one tab of twelve. The snackbar
 * mirrors the newest one; this panel is the record, so it filters by level and
 * says which case it is in when it has nothing to show: empty, filtered empty,
 * or nothing has gone wrong.
 */
@Composable
fun ConsolePanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var level by rememberSaveable { mutableStateOf("ALL") }
    var confirmClear by remember { mutableStateOf(false) }
    val lines = vm.console
    val errors = lines.count { it.level == "ERROR" }
    val warns = lines.count { it.level == "WARN" }
    val filtered = if (level == "ALL") lines.toList() else lines.filter { it.level == level }
    val stamp = remember { SimpleDateFormat("HH:mm:ss", Locale.US) }

    Column(Modifier.fillMaxSize().background(ide.bg)) {
        PanelHeader(
            "Console",
            subtitle = when {
                lines.isEmpty() -> "nothing logged yet"
                errors + warns == 0 -> "${lines.size} lines · nothing has failed"
                else -> "${lines.size} lines"
            },
            trailing = {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    if (errors > 0) {
                        StatChip("ERR", "$errors", ide.red)
                        Spacer(Modifier.width(6.dp))
                    }
                    if (warns > 0) {
                        StatChip("WARN", "$warns", ide.amber)
                        Spacer(Modifier.width(6.dp))
                    }
                    TextButton(
                        onClick = { confirmClear = true },
                        enabled = lines.isNotEmpty()
                    ) { Text("Clear", color = ide.dim, fontSize = Type.label) }
                }
            }
        )
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel)
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = 6.dp)
                .selectableGroup(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            ConsoleLevelFilterChip("ALL", lines.size, level == "ALL", ide.text) { level = "ALL" }
            for (lv in listOf("INFO", "OK", "WARN", "ERROR")) {
                ConsoleLevelFilterChip(
                    lv, lines.count { it.level == lv }, level == lv, levelColor(lv, ide)
                ) { level = lv }
            }
        }
        when {
            lines.isEmpty() -> EmptyPanel(
                "Console empty",
                "Opening a file, decompiling and exporting all report here."
            )

            filtered.isEmpty() -> EmptyPanel(
                when (level) {
                    "ERROR" -> "No errors"
                    "WARN" -> "No warnings"
                    else -> "No $level lines"
                },
                "${lines.size} lines are hidden by the $level filter."
            )

            else -> {
                val state = rememberLazyListState()
                LaunchedEffect(filtered.size, level) {
                    if (filtered.isNotEmpty()) state.scrollToItem(filtered.size - 1)
                }
                LazyColumn(
                    Modifier.fillMaxSize(), state = state,
                    contentPadding = bottomInset(12.dp)
                ) {
                    items(filtered.size) { i -> ConsoleLineRow(filtered[i], stamp) }
                }
            }
        }
    }

    if (confirmClear) {
        AlertDialog(
            onDismissRequest = { confirmClear = false },
            containerColor = ide.panel,
            title = { Text("Clear the console?", color = ide.text, fontSize = Type.section) },
            text = {
                Text(
                    "${lines.size} lines go, including $errors errors and $warns warnings. " +
                        "The console is the only record of them.",
                    color = ide.dim, fontSize = Type.body
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    vm.console.clear()
                    vm.log("INFO", "Console cleared")
                    confirmClear = false
                }) { Text("Clear", color = ide.red) }
            },
            dismissButton = {
                TextButton(onClick = { confirmClear = false }) { Text("Keep", color = ide.dim) }
            }
        )
    }
}

@Composable
private fun ConsoleLevelFilterChip(
    level: String,
    count: Int,
    selected: Boolean,
    tint: Color,
    onSelect: () -> Unit
) {
    val ide = LocalIde.current
    Box(
        Modifier
            .heightIn(min = 48.dp)
            .selectable(selected = selected, role = Role.Tab, onClick = onSelect)
            .padding(horizontal = 3.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            "$level $count",
            color = if (selected) tint else ide.dim2,
            fontSize = Type.caption, fontFamily = Mono,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            maxLines = 1,
            modifier = Modifier
                .background(
                    if (selected) tint.copy(alpha = 0.12f) else Color.Transparent,
                    RoundedCornerShape(6.dp)
                )
                .border(
                    1.dp,
                    if (selected) ide.borderStrong else ide.border,
                    RoundedCornerShape(6.dp)
                )
                .padding(horizontal = 8.dp, vertical = 5.dp)
        )
    }
}

@Composable
private fun ConsoleLineRow(l: ConsoleLine, stamp: SimpleDateFormat) {
    val ide = LocalIde.current
    val tint = levelColor(l.level, ide)
    val wash = when (l.level) {
        "ERROR" -> ide.red.copy(alpha = 0.10f)
        "WARN" -> ide.amber.copy(alpha = 0.08f)
        else -> Color.Transparent
    }
    Row(
        Modifier
            .fillMaxWidth()
            .background(wash)
            .padding(horizontal = 10.dp, vertical = 3.dp)
    ) {
        Text(
            stamp.format(Date(l.ts)),
            color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
        )
        Spacer(Modifier.width(8.dp))
        Text(
            l.level, color = tint, fontSize = Type.monoSmall, fontFamily = Mono,
            fontWeight = FontWeight.Bold, maxLines = 1,
            modifier = Modifier.widthIn(min = 42.dp)
        )
        Spacer(Modifier.width(6.dp))
        Text(
            l.msg,
            color = if (l.level == "ERROR" || l.level == "WARN") tint else ide.text,
            fontSize = Type.mono, fontFamily = Mono,
            modifier = Modifier.weight(1f)
        )
    }
}

// ============================================================== Debugger ==
@Composable
fun LegacyTracerPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var args by remember { mutableStateOf("/system/bin/toybox echo hello-nocturne") }
    var maxEvents by remember { mutableStateOf("200") }
    Column(Modifier.fillMaxSize()) {
        PanelHeader(
            "Debugger — experimental ptrace",
            trailing = {
                if (vm.debugRunning) {
                    CircularProgressIndicator(color = ide.amber, modifier = Modifier.size(16.dp))
                }
            }
        )
        Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
            Text(
                "Program + args (newline-separated argv): /system/bin/* · SELinux wuxuu xannibi karaa (root/debuggable u baahan).",
                color = ide.amber, fontSize = Type.label
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = args,
                onValueChange = { args = it },
                label = { Text("argv") },
                singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .semantics { contentDescription = "Program and arguments" },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = maxEvents,
                    onValueChange = { maxEvents = it.filter { c -> c.isDigit() }.take(4) },
                    label = { Text("Max events") },
                    singleLine = true,
                    modifier = Modifier
                        .width(120.dp)
                        .semantics { contentDescription = "Maximum number of events" },
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = {
                        val argv = args.split('\n').map { it.trim() }.filter { it.isNotEmpty() }
                        vm.debugRun(argv, maxEvents.toIntOrNull() ?: 200)
                    },
                    enabled = !vm.debugRunning
                ) { Text("Run trace") }
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { vm.debugStop() }, enabled = vm.debugRunning) {
                    Text("Stop", color = ide.red)
                }
            }
        }
        val res = vm.debugResult
        if (res != null && !res.ok && res.error != null) {
            Text(
                "ERROR: ${res.error}",
                color = ide.red, fontSize = Type.mono, fontFamily = Mono,
                modifier = Modifier.padding(horizontal = 12.dp)
            )
        }
        val events = res?.events ?: emptyList()
        if (events.isEmpty()) {
            EmptyPanel(
                if (res?.ok == true) "No events" else "No trace yet",
                if (res?.ok == true) "The process ran and returned without a syscall the tracer caught."
                else "Give it an argv and run a trace — each syscall lands here as it happens."
            )
        } else {
            LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(12.dp)) {
                items(events.size) { i ->
                    val e = events[i]
                    Column(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 2.dp)) {
                        Text(
                            "#${e.n} ${e.syscall}(ret=${hexFmt(e.ret)})",
                            color = ide.text, fontSize = Type.mono, fontFamily = Mono
                        )
                        Text(
                            "   ip=${hexFmt(e.ip)} nr=${e.nr} args=[${e.args.joinToString(", ") { hexFmt(it) }}]",
                            color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 2
                        )
                    }
                }
            }
        }
    }
}

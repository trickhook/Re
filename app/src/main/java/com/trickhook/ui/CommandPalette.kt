package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab

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

@Composable
fun CommandPaletteOverlay(vm: StudioViewModel, openFile: () -> Unit) {
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
                    .padding(horizontal = 40.dp, vertical = 80.dp),
                color = ide.panel,
                shape = MaterialTheme.shapes.medium,
                tonalElevation = 8.dp
            ) {
                var query by remember { mutableStateOf("") }
                val requester = remember { FocusRequester() }
                LaunchedEffect(Unit) { requester.requestFocus() }

                val commands = remember(vm.plugins.size, vm.tab) {
                    buildList {
                        add(Command("Open file (APK/ELF/EXE/DEX)", "pick a binary to analyse", "Ctrl+O", openFile))
                        add(Command("Go to address…", "jump to a virtual address", "Ctrl+G") { showGoto = true })
                        add(Command("Search everywhere", "functions + strings + comments", "Ctrl+F") { showSearch = true })
                        add(Command("Save project", "persist renames, comments, bookmarks", "Ctrl+S") { vm.saveProject(ctx, vm.meta?.name ?: "project") })
                        add(Command("Toggle dark/light theme", "", "Ctrl+T") { vm.darkTheme = !vm.darkTheme })
                        add(Command("Load call graph", "whole binary", "") { vm.loadCallGraph(0) })
                        vm.plugins.forEach { p ->
                            add(Command("Run plugin: ${p.name}", p.description, "") { vm.runPlugin(ctx, p) })
                        }
                        Tab.entries.forEach { t ->
                            add(Command("Go to tab: ${t.title}", "", "Ctrl+${Tab.entries.indexOf(t) + 1}") { vm.tab = t })
                        }
                        add(Command("Keyboard shortcuts help", "", "F1") { showShortcutsHelp = true })
                        if (vm.meta != null) {
                            add(Command("Export decompiled source (.c / .h / .asm)",
                                "Whole binary, one function, header or listing", "") {
                                showExportSheet = true
                            })
                        }
                    }
                }
                val filtered = if (query.isBlank()) commands
                else commands.filter {
                    it.title.contains(query, ignoreCase = true) ||
                        it.subtitle.contains(query, ignoreCase = true)
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
                            .focusRequester(requester),
                        textStyle = TextStyle(fontSize = 14.sp, color = ide.text)
                    )
                    LazyColumn(Modifier.height(360.dp)) {
                        items(filtered.size) { i ->
                            val c = filtered[i]
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        showPalette = false
                                        c.action()
                                    }
                                    .padding(horizontal = 16.dp, vertical = 8.dp)
                            ) {
                                Column(Modifier.weight(1f)) {
                                    Text(c.title, color = ide.text, fontSize = 13.sp, fontFamily = Mono)
                                    if (c.subtitle.isNotEmpty())
                                        Text(c.subtitle, color = ide.dim, fontSize = 10.sp)
                                }
                                if (c.shortcut.isNotEmpty())
                                    Text(c.shortcut, color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                            }
                        }
                    }
                }
            }
        }
    }

    if (showGoto) {
        val addrState = remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { showGoto = false },
            containerColor = ide.panel,
            title = { Text("Go to address", color = ide.accent, fontSize = 14.sp) },
            text = {
                OutlinedTextField(
                    value = addrState.value,
                    onValueChange = { addrState.value = it },
                    label = { Text("Address (hex or 0x…)") },
                    singleLine = true,
                    textStyle = TextStyle(fontSize = 13.sp, fontFamily = Mono, color = ide.text)
                )
            },
            confirmButton = {
                TextButton(onClick = {
                    val raw = addrState.value.removePrefix("0x").removePrefix("0X")
                    raw.toLongOrNull(16)?.let { addr ->
                        gotoRequest = addr
                        // jump to the function containing the address
                        val f = vm.meta?.functions
                            ?.filter { it.addr <= addr }
                            ?.maxByOrNull { it.addr }
                        if (f != null && addr < f.addr + maxOf(f.size, 512)) {
                            vm.selectFunction(f.addr)
                        } else {
                            vm.selectFunction(addr)
                        }
                    }
                    showGoto = false
                }) { Text("Go", color = ide.accent) }
            },
            dismissButton = { TextButton(onClick = { showGoto = false }) { Text("Cancel", color = ide.dim) } }
        )
    }

    if (showSearch) {
        GlobalSearchDialog(vm) { showSearch = false }
    }

    if (showShortcutsHelp) {
        AlertDialog(
            onDismissRequest = { showShortcutsHelp = false },
            containerColor = ide.panel,
            title = { Text("Keyboard shortcuts", color = ide.accent, fontSize = 14.sp) },
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
                        "Ctrl+1..9" to "Jump to tab",
                        "F1" to "This help"
                    ).forEach { (k, v) ->
                        Row(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                            Text(k, color = ide.amber, fontSize = 12.sp, fontFamily = Mono, modifier = Modifier.width(110.dp))
                            Text(v, color = ide.text, fontSize = 12.sp)
                        }
                    }
                }
            },
            confirmButton = { TextButton(onClick = { showShortcutsHelp = false }) { Text("OK", color = ide.accent) } }
        )
    }
}

@Composable
fun GlobalSearchDialog(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    var query by remember { mutableStateOf("") }
    val requester = remember { FocusRequester() }
    LaunchedEffect(Unit) { requester.requestFocus() }

    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Search everywhere", color = ide.accent, fontSize = 14.sp) },
        text = {
            Column {
                OutlinedTextField(
                    value = query,
                    onValueChange = { query = it },
                    placeholder = { Text("functions · strings · comments · bookmarks", color = ide.dim) },
                    singleLine = true,
                    modifier = Modifier.focusRequester(requester),
                    textStyle = TextStyle(fontSize = 13.sp, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(8.dp))
                if (query.length >= 2) {
                    val meta = vm.meta
                    val funcs = meta?.functions
                        ?.filter { it.name.contains(query, true) ||
                            (vm.renames["0x%08X".format(it.addr)] ?: "").contains(query, true) }
                        ?.take(6) ?: emptyList()
                    val strs = meta?.strings
                        ?.filter { it.value.contains(query, true) }?.take(5) ?: emptyList()
                    val cmts = vm.comments.filter { it.value.contains(query, true) }.entries.take(5)
                    val marks = vm.bookmarks.filter { it.label.contains(query, true) }.take(5)

                    LazyColumn(Modifier.height(280.dp)) {
                        if (funcs.isNotEmpty()) item {
                            Text("FUNCTIONS", color = ide.dim, fontSize = 10.sp, fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(vertical = 4.dp))
                        }
                        items(funcs.size) { i ->
                            val f = funcs[i]
                            Text(
                                "${vm.renames["0x%08X".format(f.addr)] ?: f.name}  @ ${hexFmt(f.addr)}",
                                color = ide.cyan, fontSize = 12.sp, fontFamily = Mono,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { vm.selectFunction(f.addr); onDismiss() }
                                    .padding(vertical = 3.dp)
                            )
                        }
                        if (strs.isNotEmpty()) item {
                            Text("STRINGS", color = ide.dim, fontSize = 10.sp, fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(vertical = 4.dp))
                        }
                        items(strs.size) { i ->
                            val s = strs[i]
                            Text(
                                "${hexFmt(s.addr)}  \"${s.value.take(48)}\"",
                                color = ide.text, fontSize = 11.sp, fontFamily = Mono,
                                maxLines = 1,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable { vm.log("INFO", "String @ ${hexFmt(s.addr)}: ${s.value.take(60)}"); onDismiss() }
                                    .padding(vertical = 3.dp)
                            )
                        }
                        if (cmts.isNotEmpty()) item {
                            Text("COMMENTS", color = ide.dim, fontSize = 10.sp, fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(vertical = 4.dp))
                        }
                        items(cmts.size) { i ->
                            val (addr, text) = cmts[i]
                            Text(
                                "${addr}  ; $text",
                                color = ide.accent, fontSize = 11.sp, fontFamily = Mono, maxLines = 1,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        val a = addr.removePrefix("0x").toLongOrNull(16) ?: 0L
                                        val f = vm.meta?.functions?.filter { it.addr <= a }
                                            ?.maxByOrNull { it.addr }
                                        if (f != null) vm.selectFunction(f.addr)
                                        onDismiss()
                                    }
                                    .padding(vertical = 3.dp)
                            )
                        }
                        if (marks.isNotEmpty()) item {
                            Text("BOOKMARKS", color = ide.dim, fontSize = 10.sp, fontWeight = FontWeight.Bold,
                                modifier = Modifier.padding(vertical = 4.dp))
                        }
                        items(marks.size) { i ->
                            val b = marks[i]
                            Text(
                                "${b.addr}  ${b.label}",
                                color = ide.amber, fontSize = 11.sp, fontFamily = Mono,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        val a = b.addr.removePrefix("0x").toLongOrNull(16) ?: 0L
                                        val f = vm.meta?.functions?.filter { it.addr <= a }
                                            ?.maxByOrNull { it.addr }
                                        if (f != null) vm.selectFunction(f.addr)
                                        onDismiss()
                                    }
                                    .padding(vertical = 3.dp)
                            )
                        }
                        if (funcs.isEmpty() && strs.isEmpty() && cmts.isEmpty() && marks.isEmpty()) {
                            item { Text("No matches.", color = ide.dim, fontSize = 12.sp) }
                        }
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onDismiss) { Text("Close", color = ide.dim) } }
    )
}

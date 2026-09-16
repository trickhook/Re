package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab

// ============================================================== Strings ==
@Composable
fun StringsPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta
    Column(Modifier.fillMaxSize()) {
        var query by remember { mutableStateOf("") }
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search strings · raadi") },
                singleLine = true,
                modifier = Modifier.weight(1f),
                textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
            )
        }
        val all = meta?.strings ?: emptyList()
        val filtered = if (query.isBlank()) all else all.filter { it.value.contains(query, ignoreCase = true) }
        LazyColumn(Modifier.fillMaxSize()) {
            items(filtered.size) { i ->
                val s = filtered[i]
                Column(
                    Modifier
                        .fillMaxWidth()
                        .clickable { vm.log("INFO", "String @ ${hexFmt(s.addr)}: ${s.value.take(60)}") }
                        .padding(horizontal = 10.dp, vertical = 3.dp)
                ) {
                    Text(hexFmt(s.addr), color = ide.cyan, fontSize = 10.sp, fontFamily = Mono)
                    Text(s.value, color = ide.text, fontSize = 12.sp, fontFamily = Mono, maxLines = 2)
                }
            }
            item { Spacer(Modifier.height(40.dp)) }
        }
    }
}

// ============================================================ Functions ==
@Composable
fun FunctionsPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta
    Column(Modifier.fillMaxSize()) {
        var query by remember { mutableStateOf("") }
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search functions · raadi shaqo") },
                singleLine = true,
                modifier = Modifier.weight(1f),
                textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
            )
        }
        val all = meta?.functions ?: emptyList()
        val filtered = if (query.isBlank()) all else all.filter {
            it.name.contains(query, ignoreCase = true) ||
                (vm.renames["0x%08X".format(it.addr)] ?: "").contains(query, ignoreCase = true)
        }
        LazyColumn(Modifier.fillMaxSize()) {
            items(filtered.size) { i ->
                val f = filtered[i]
                val renamed = vm.renames["0x%08X".format(f.addr)]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable { vm.selectFunction(f.addr) }
                        .padding(horizontal = 10.dp, vertical = 5.dp)
                ) {
                    Text(
                        if (renamed != null) "✏" else "ƒ",
                        color = if (renamed != null) ide.amber else ide.dim,
                        fontSize = 12.sp, fontFamily = Mono,
                        modifier = Modifier.width(24.dp)
                    )
                    Column(Modifier.weight(1f)) {
                        Text(
                            renamed ?: f.name,
                            color = if (f.addr == vm.selectedFunc) ide.accent else ide.text,
                            fontSize = 12.sp, fontFamily = Mono, maxLines = 1
                        )
                        Text(
                            "${f.from} · ${f.size} bytes · ${f.nCallees}→ / ←${f.nCallers}",
                            color = ide.dim, fontSize = 10.sp, fontFamily = Mono
                        )
                    }
                    Text(hexFmt(f.addr), color = ide.cyan, fontSize = 11.sp, fontFamily = Mono)
                }
            }
            item { Spacer(Modifier.height(40.dp)) }
        }
    }
}

// ============================================================ Memory map ==
@Composable
fun MapPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta ?: return
    var showSegments by remember { mutableStateOf(true) }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            TextButton(onClick = { showSegments = true }) {
                Text(
                    "Segments",
                    color = if (showSegments) ide.accent else ide.dim,
                    fontWeight = if (showSegments) androidx.compose.ui.text.font.FontWeight.Bold else null
                )
            }
            TextButton(onClick = { showSegments = false }) {
                Text(
                    "Sections",
                    color = if (!showSegments) ide.accent else ide.dim,
                    fontWeight = if (!showSegments) androidx.compose.ui.text.font.FontWeight.Bold else null
                )
            }
            Spacer(Modifier.weight(1f))
            Text(
                if (showSegments) "Memory Map · Khariidadaha memory-ga"
                else "Section Table · Shaxda qaybaha",
                color = ide.dim, fontSize = 10.sp
            )
        }
        if (showSegments) {
            LazyColumn(Modifier.fillMaxSize()) {
                items(meta.segments.size) { i ->
                    val s = meta.segments[i]
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 4.dp)
                    ) {
                        Text(s.type, color = ide.amber, fontSize = 11.sp, fontFamily = Mono, modifier = Modifier.width(110.dp))
                        Text(hexFmt(s.vaddr), color = ide.cyan, fontSize = 11.sp, fontFamily = Mono, modifier = Modifier.width(100.dp))
                        Text("${s.filesz}", color = ide.text, fontSize = 11.sp, fontFamily = Mono, modifier = Modifier.width(90.dp))
                        Text(s.flags, color = ide.accent, fontSize = 11.sp, fontFamily = Mono)
                    }
                }
                item { Spacer(Modifier.height(40.dp)) }
            }
        } else {
            LazyColumn(Modifier.fillMaxSize()) {
                items(meta.sections.size) { i ->
                    val s = meta.sections[i]
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 4.dp)
                    ) {
                        Text(
                            s.name.ifEmpty { "(unnamed)" },
                            color = ide.text, fontSize = 11.sp, fontFamily = Mono,
                            modifier = Modifier.width(150.dp), maxLines = 1
                        )
                        Text(s.type, color = ide.dim, fontSize = 10.sp, fontFamily = Mono, modifier = Modifier.width(84.dp))
                        Text(hexFmt(s.addr), color = ide.cyan, fontSize = 11.sp, fontFamily = Mono, modifier = Modifier.width(96.dp))
                        Text("${s.size}", color = ide.text, fontSize = 11.sp, fontFamily = Mono, modifier = Modifier.width(84.dp))
                        Text(s.flags, color = ide.accent, fontSize = 11.sp, fontFamily = Mono)
                    }
                }
                item { Spacer(Modifier.height(40.dp)) }
            }
        }
    }
}

// =============================================================== Console ==
@Composable
fun ConsolePanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxSize().background(ide.bg)) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("Console · Console-ka Nocturne", color = ide.text, fontSize = 12.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
            Spacer(Modifier.weight(1f))
            TextButton(onClick = { vm.console.clear(); vm.log("INFO", "Console cleared") }) {
                Text("Clear", color = ide.dim)
            }
        }
        val state = rememberLazyListState()
        LaunchedEffect(vm.console.size) {
            if (vm.console.isNotEmpty()) state.scrollToItem(vm.console.size - 1)
        }
        LazyColumn(Modifier.fillMaxSize(), state = state) {
            items(vm.console.size) { i ->
                val l = vm.console[i]
                val time = java.text.SimpleDateFormat("HH:mm:ss", java.util.Locale.US)
                    .format(java.util.Date(l.ts))
                Text(
                    "[$time] [${l.level}] ${l.msg}",
                    color = levelColor(l.level, ide),
                    fontSize = 11.sp, fontFamily = Mono,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 10.dp, vertical = 1.dp)
                )
            }
            item { Spacer(Modifier.height(30.dp)) }
        }
    }
}

// ============================================================== Debugger ==
@Composable
fun LegacyTracerPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var args by remember { mutableStateOf("/system/bin/toybox echo hello-nocturne") }
    var maxEvents by remember { mutableStateOf("200") }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "Debugger (experimental ptrace) · Tijaabo",
                color = ide.text, fontSize = 12.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold
            )
            Spacer(Modifier.weight(1f))
            if (vm.debugRunning) CircularProgressIndicator(color = ide.amber, modifier = Modifier.size(16.dp))
        }
        Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
            Text(
                "Program + args (newline-separated argv): /system/bin/* · SELinux wuxuu xannibi karaa (root/debuggable u baahan).",
                color = ide.amber, fontSize = 11.sp
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = args,
                onValueChange = { args = it },
                label = { Text("argv") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = maxEvents,
                    onValueChange = { maxEvents = it.filter { c -> c.isDigit() }.take(4) },
                    label = { Text("Max events") },
                    singleLine = true,
                    modifier = Modifier.width(120.dp),
                    textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
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
                color = ide.red, fontSize = 12.sp, fontFamily = Mono,
                modifier = Modifier.padding(horizontal = 12.dp)
            )
        }
        val events = res?.events ?: emptyList()
        LazyColumn(Modifier.fillMaxSize()) {
            items(events.size) { i ->
                val e = events[i]
                Column(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 2.dp)) {
                    Text(
                        "#${e.n} ${e.syscall}(ret=${hexFmt(e.ret)})",
                        color = ide.accent, fontSize = 11.5.sp, fontFamily = Mono
                    )
                    Text(
                        "   ip=${hexFmt(e.ip)} nr=${e.nr} args=[${e.args.joinToString(", ") { hexFmt(it) }}]",
                        color = ide.dim, fontSize = 10.5.sp, fontFamily = Mono, maxLines = 2
                    )
                }
            }
            item {
                if (events.isEmpty() && res?.ok == true)
                    Text("(no events)", color = ide.dim, fontSize = 12.sp, modifier = Modifier.padding(12.dp))
                Spacer(Modifier.height(40.dp))
            }
        }
    }
}

package com.sakore.studio.ui

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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sakore.studio.vm.DbgMode
import com.sakore.studio.vm.StudioViewModel
import kotlinx.coroutines.delay

// ============================================================== Debugger ==
@Composable
fun DebuggerPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    var showSpawn by remember { mutableStateOf(false) }
    var showAttach by remember { mutableStateOf(false) }

    // poll debugger state while a session is live
    LaunchedEffect(vm.dbgMode) {
        while (vm.dbgMode == DbgMode.SESSION) {
            vm.dbgCmd("""{"op":"poll"}""")
            vm.dbgState?.let { s ->
                if (s.state == "stopped") {
                    vm.dbgRegs()
                    vm.dbgReadStack()
                }
            }
            delay(400)
        }
    }

    Column(Modifier.fillMaxSize()) {
        // toolbar
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 8.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "DEBUGGER",
                color = ide.text, fontSize = 12.sp,
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, fontFamily = Mono
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = { showSpawn = true }, enabled = !vm.dbgBusy) { Text("Spawn", fontSize = 11.sp) }
            Spacer(Modifier.width(4.dp))
            Button(onClick = { showAttach = true }, enabled = !vm.dbgBusy) { Text("Attach PID", fontSize = 11.sp) }
            Spacer(Modifier.weight(1f))
            val st = vm.dbgState?.state
            Text(
                st?.uppercase() ?: if (vm.dbgMode == DbgMode.TRACE) "TRACE MODE" else "NO SESSION",
                color = when (st) {
                    "stopped" -> ide.amber
                    "running" -> ide.accent
                    "exited" -> ide.dim
                    else -> ide.dim
                },
                fontSize = 11.sp, fontFamily = Mono
            )
            if (vm.dbgMode == DbgMode.SESSION) {
                Spacer(Modifier.width(6.dp))
                TextButton(onClick = { vm.dbgKill() }) { Text("Kill", color = ide.red, fontSize = 11.sp) }
            }
        }

        // session controls
        if (vm.dbgMode == DbgMode.SESSION) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(ide.panel)
                    .padding(horizontal = 8.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Button(onClick = { vm.dbgCont() }, enabled = vm.dbgState?.state == "stopped" && !vm.dbgBusy) {
                    Text("▶ Continue", fontSize = 11.sp)
                }
                Spacer(Modifier.width(4.dp))
                Button(onClick = { vm.dbgStep() }, enabled = vm.dbgState?.state == "stopped" && !vm.dbgBusy) {
                    Text("⏭ Step", fontSize = 11.sp)
                }
                Spacer(Modifier.width(4.dp))
                Button(onClick = { vm.dbgBpAtSelectedFunction() }, enabled = vm.selectedFunc != null) {
                    Text("BP @ func", fontSize = 11.sp)
                }
                Spacer(Modifier.width(4.dp))
                Button(onClick = { vm.dbgRegs() }, enabled = !vm.dbgBusy) { Text("Regs", fontSize = 11.sp) }
                Spacer(Modifier.width(4.dp))
                Button(onClick = { vm.dbgThreads() }, enabled = !vm.dbgBusy) { Text("Threads", fontSize = 11.sp) }
            }
            BpRow(vm)
            RegsRow(vm)
        }

        // body: legacy trace or session view
        when (vm.dbgMode) {
            DbgMode.TRACE -> TraceView(vm)
            DbgMode.SESSION -> SessionView(vm)
            DbgMode.NONE -> Hint(
                "Two debugger modes:\n" +
                    "  • Spawn/Attach — real ptrace session: breakpoints, registers, memory, stack, threads.\n" +
                    "  • (Old) syscall tracer — set program below and Run trace.",
                "ptrace wuxuu u baahan yahay root ama debuggable device — SELinux waxay xannibi karaa."
            )
        }
    }

    if (showSpawn) SpawnDialog(vm) { showSpawn = false }
    if (showAttach) AttachDialog(vm) { showAttach = false }
}

@Composable
private fun BpRow(vm: StudioViewModel) {
    val ide = LocalIde.current
    var addr by remember { mutableStateOf("") }
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            .padding(horizontal = 8.dp, vertical = 2.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        OutlinedTextField(
            value = addr, onValueChange = { addr = it },
            label = { Text("BP address (hex)", fontSize = 10.sp) },
            singleLine = true,
            modifier = Modifier.width(170.dp),
            textStyle = TextStyle(fontSize = 11.sp, fontFamily = Mono, color = ide.text)
        )
        TextButton(onClick = {
            addr.removePrefix("0x").toLongOrNull(16)?.let { vm.dbgAddBp(it); addr = "" }
        }) { Text("+ Add", fontSize = 11.sp) }
        vm.dbgState?.bps?.forEach { b ->
            Text(
                "● ${"0x%X".format(b.addr)}(${b.hits})",
                color = ide.red, fontSize = 10.5.sp, fontFamily = Mono,
                modifier = Modifier
                    .clickable { vm.dbgDelBp(b.addr) }
                    .padding(horizontal = 4.dp)
            )
        }
        Spacer(Modifier.weight(1f))
        Text("tap a BP to delete", color = ide.dim, fontSize = 9.sp)
    }
}

@Composable
private fun RegsRow(vm: StudioViewModel) {
    val ide = LocalIde.current
    val regs = vm.dbgState?.regs ?: return
    val ordered = listOf("pc", "sp", "lr", "fp", "a0", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15", "eflags", "pstate", "orig_rax", "cs")
    val shown = ordered.filter { regs.containsKey(it) }
    if (shown.isEmpty()) return
    Row(
        Modifier
            .fillMaxWidth()
            .horizontalScrollIfNeeded()
            .background(ide.panel)
            .padding(horizontal = 8.dp, vertical = 2.dp)
    ) {
        shown.take(20).forEach { r ->
            Column(Modifier.padding(horizontal = 6.dp)) {
                Text(r, color = ide.dim, fontSize = 9.sp, fontFamily = Mono)
                Text(
                    "0x%X".format(regs[r] ?: 0L),
                    color = if (r == "pc" || r == "rip") ide.amber else ide.cyan,
                    fontSize = 10.sp, fontFamily = Mono
                )
            }
        }
    }
}

private fun Modifier.horizontalScrollIfNeeded(): Modifier = this

@Composable
private fun SessionView(vm: StudioViewModel) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxSize()) {
        // memory + stack hex views
        val mem = vm.dbgMem
        val stack = vm.dbgStack
        if (mem != null) HexDump("MEMORY @ 0x%X".format(mem.first), mem.second, ide)
        if (stack != null) HexDump("STACK @ 0x%X".format(stack.first), stack.second, ide)
        // event log
        Text(
            "EVENT LOG",
            color = ide.dim, fontSize = 10.sp, fontFamily = Mono,
            modifier = Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 2.dp)
        )
        LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
            items(vm.dbgEvents.size) { i ->
                val (ts, msg) = vm.dbgEvents[vm.dbgEvents.size - 1 - i]
                Text(
                    "[$ts] $msg",
                    color = if (msg.startsWith("BP")) ide.red else
                        if (msg.startsWith("process exited")) ide.dim else ide.text,
                    fontSize = 11.sp, fontFamily = Mono,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 10.dp, vertical = 1.dp)
                )
            }
            item {
                Text(
                    "pid ${vm.dbgState?.pid ?: "-"} · ${vm.dbgState?.arch ?: "-"} — breakpoints/registers/memory update on stop",
                    color = ide.dim, fontSize = 9.5.sp, fontFamily = Mono,
                    modifier = Modifier.padding(10.dp)
                )
                Spacer(Modifier.height(30.dp))
            }
        }
    }
}

@Composable
private fun HexDump(title: String, hexData: String, ide: IdeColors) {
    Column(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
    ) {
        Text(
            title, color = ide.cyan, fontSize = 10.sp, fontFamily = Mono,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 1.dp)
        )
        val bytes = remember(hexData) {
            hexData.chunked(2).mapNotNull { it.toLongOrNull(16) }
        }
        val rows = (bytes.size + 15) / 16
        Column(Modifier.padding(horizontal = 10.dp)) {
            repeat(minOf(rows, 4)) { r ->
                val base = r * 16
                val line = buildString {
                    for (i in 0 until 16) {
                        if (base + i < bytes.size) append("%02X ".format(bytes[base + i]))
                    }
                }
                val ascii = buildString {
                    for (i in 0 until 16) {
                        if (base + i < bytes.size) {
                            val v = bytes[base + i].toInt()
                            append(if (v in 0x20..0x7E) v.toChar() else '.')
                        }
                    }
                }
                Text(
                    "$line $ascii",
                    color = ide.text, fontSize = 9.5.sp, fontFamily = Mono, maxLines = 1
                )
            }
        }
        Spacer(Modifier.height(2.dp))
    }
}

@Composable
private fun TraceView(vm: StudioViewModel) {
    val ide = LocalIde.current
    var args by remember { mutableStateOf("/system/bin/toybox echo hello-sako") }
    var maxEvents by remember { mutableStateOf("200") }
    Column {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
            Text(
                "Syscall tracer (legacy): logs every syscall of the child. Requires root/debuggable.",
                color = ide.amber, fontSize = 11.sp
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = args, onValueChange = { args = it },
                label = { Text("argv (newline-separated)") }, singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = maxEvents,
                    onValueChange = { maxEvents = it.filter { c -> c.isDigit() }.take(4) },
                    label = { Text("Max events") }, singleLine = true,
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

@Composable
private fun SpawnDialog(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    var prog by remember { mutableStateOf("/system/bin/toybox") }
    var args by remember { mutableStateOf("sleep 30") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Spawn process", color = ide.accent, fontSize = 14.sp) },
        text = {
            Column {
                OutlinedTextField(
                    value = prog, onValueChange = { prog = it },
                    label = { Text("Program path") }, singleLine = true,
                    textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = args, onValueChange = { args = it },
                    label = { Text("Arguments") }, singleLine = true,
                    textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Suggested: /system/bin/toybox sleep 30 — then BP @ func on a selected function.",
                    color = ide.dim, fontSize = 10.sp
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                vm.dbgSpawn(prog, args)
                onDismiss()
            }) { Text("Spawn", color = ide.accent) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = ide.dim) } }
    )
}

@Composable
private fun AttachDialog(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    var pid by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Attach to PID", color = ide.accent, fontSize = 14.sp) },
        text = {
            Column {
                OutlinedTextField(
                    value = pid, onValueChange = { pid = it.filter { c -> c.isDigit() } },
                    label = { Text("PID") }, singleLine = true,
                    textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Attach requires same-uid or root. Find PIDs via adb shell ps.",
                    color = ide.dim, fontSize = 10.sp
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                pid.toLongOrNull()?.let { vm.dbgAttach(it) }
                onDismiss()
            }) { Text("Attach", color = ide.accent) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = ide.dim) } }
    )
}

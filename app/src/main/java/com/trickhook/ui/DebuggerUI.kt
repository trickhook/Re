package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.trickhook.model.DbgThread
import com.trickhook.vm.DbgMode
import com.trickhook.vm.StudioViewModel
import kotlinx.coroutines.delay

// ============================================================== Debugger ==

/**
 * Material3's default button padding is 24dp per side on top of a 58dp minimum
 * width. Five default-padded buttons in one Row measured ~460dp of intrinsic
 * width against a 360-412dp phone, which is why "Threads" was drawn past the
 * right edge and could never be tapped. Every control on this screen uses this
 * compact padding instead, and the rows that hold them wrap.
 */
private val DbgBtnPad = PaddingValues(horizontal = 10.dp, vertical = 6.dp)

/** Every interactive target on this screen clears Material's 48dp minimum. */
private val TouchTarget = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DebuggerPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var showSpawn by remember { mutableStateOf(false) }
    var showAttach by remember { mutableStateOf(false) }
    // The threads op answers into DbgState.threads, but the poll below replaces
    // DbgState wholesale every 400ms, so the answer has to be caught here or it
    // is gone before it can be drawn.
    var threads by remember { mutableStateOf<List<DbgThread>>(emptyList()) }

    // poll debugger state while a session is live
    LaunchedEffect(vm.dbgMode) {
        threads = emptyList()
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
        // ---- header band: title on the left, live state on the right. Two
        // short items, so this is the one row here that cannot overflow.
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "DEBUGGER",
                color = ide.text, fontSize = Type.mono,
                fontWeight = FontWeight.Bold, fontFamily = Mono
            )
            Spacer(Modifier.weight(1f))
            val st = vm.dbgState?.state
            Text(
                st?.uppercase() ?: if (vm.dbgMode == DbgMode.TRACE) "TRACE MODE" else "NO SESSION",
                color = when (st) {
                    "stopped" -> ide.amber
                    "running" -> ide.entry
                    else -> ide.dim2
                },
                fontSize = Type.mono, fontFamily = Mono, maxLines = 1
            )
        }

        // ---- session lifecycle. FlowRow, not Row: at a large font scale even
        // two buttons and a Kill will not fit one line on a 360dp phone.
        FlowRow(
            modifier = Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Button(
                onClick = { showSpawn = true }, enabled = !vm.dbgBusy,
                contentPadding = DbgBtnPad
            ) { Text("Spawn", fontSize = Type.label) }
            Button(
                onClick = { showAttach = true }, enabled = !vm.dbgBusy,
                contentPadding = DbgBtnPad
            ) { Text("Attach", fontSize = Type.label) }
            if (vm.dbgMode == DbgMode.SESSION) {
                TextButton(onClick = { vm.dbgKill() }, contentPadding = DbgBtnPad) {
                    Text("Kill", color = ide.red, fontSize = Type.label)
                }
            }
        }

        // ---- execution controls. These are the five that used to run off the
        // edge; wrapping them is what makes Regs and Threads reachable at all.
        if (vm.dbgMode == DbgMode.SESSION) {
            val stopped = vm.dbgState?.state == "stopped" && !vm.dbgBusy
            FlowRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .background(ide.panel)
                    .padding(horizontal = 10.dp, vertical = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                Button(onClick = { vm.dbgCont() }, enabled = stopped, contentPadding = DbgBtnPad) {
                    Icon(
                        Icons.Filled.PlayArrow, contentDescription = null,
                        modifier = Modifier.size(14.dp)
                    )
                    Spacer(Modifier.width(4.dp))
                    Text("Continue", fontSize = Type.label)
                }
                Button(onClick = { vm.dbgStep() }, enabled = stopped, contentPadding = DbgBtnPad) {
                    Text("Step", fontSize = Type.label)
                }
                Button(
                    onClick = { vm.dbgBpAtSelectedFunction() },
                    enabled = vm.selectedFunc != null, contentPadding = DbgBtnPad
                ) { Text("BP @ func", fontSize = Type.label) }
                Button(onClick = { vm.dbgRegs() }, enabled = !vm.dbgBusy, contentPadding = DbgBtnPad) {
                    Text("Regs", fontSize = Type.label)
                }
                Button(
                    onClick = { vm.dbgCmd("""{"op":"threads"}""") { s -> threads = s.threads } },
                    enabled = !vm.dbgBusy, contentPadding = DbgBtnPad
                ) { Text("Threads", fontSize = Type.label) }
            }
            BpRow(vm)
            RegsRow(vm)
            ThreadsRow(threads) { threads = emptyList() }
        }

        // body: legacy trace or session view
        when (vm.dbgMode) {
            DbgMode.TRACE -> TraceView(vm)
            DbgMode.SESSION -> SessionView(vm)
            DbgMode.NONE -> Hint(
                "Two debugger modes:\n" +
                    "  • Spawn/Attach — real ptrace session: breakpoints, registers, memory, stack, threads.\n" +
                    "  • (Old) syscall tracer — set program below and Run trace.",
                "ptrace needs root or a debuggable process, and SELinux can refuse it even then."
            )
        }
    }

    if (showSpawn) SpawnDialog(vm) { showSpawn = false }
    if (showAttach) AttachDialog(vm) { showAttach = false }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun BpRow(vm: StudioViewModel) {
    val ide = LocalIde.current
    var addr by remember { mutableStateOf("") }
    val bps = vm.dbgState?.bps.orEmpty()
    Column(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            .padding(horizontal = 10.dp, vertical = 4.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = addr, onValueChange = { addr = it },
                label = { Text("BP address (hex)", fontSize = Type.caption) },
                singleLine = true,
                // weight, not a fixed 170dp: the field gives up whatever the
                // Add button needs instead of pushing it off the edge.
                modifier = Modifier
                    .weight(1f)
                    .semantics { contentDescription = "Breakpoint address in hexadecimal" },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.width(6.dp))
            TextButton(
                onClick = {
                    addr.removePrefix("0x").removePrefix("0X").toLongOrNull(16)
                        ?.let { vm.dbgAddBp(it); addr = "" }
                },
                enabled = addr.isNotBlank(),
                contentPadding = DbgBtnPad
            ) { Text("Add", fontSize = Type.label) }
        }
        if (bps.isEmpty()) {
            Text(
                "No breakpoints. Type a hex address above, or select a function and use BP @ func.",
                color = ide.dim2, fontSize = Type.caption,
                modifier = Modifier.padding(vertical = 4.dp)
            )
        } else {
            // Chips wrap instead of running off the edge — with two or more
            // breakpoints the old Row clipped them, and tapping one is still
            // the only way to delete it.
            FlowRow(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(6.dp)
            ) {
                bps.forEach { b ->
                    val label = "0x%X".format(b.addr)
                    Row(
                        TouchTarget
                            .clickable(
                                onClickLabel = "Delete breakpoint at $label",
                                role = Role.Button
                            ) { vm.dbgDelBp(b.addr) }
                            .padding(horizontal = 6.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Filled.Close, contentDescription = null,
                            tint = ide.red, modifier = Modifier.size(12.dp)
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            "$label (${b.hits})", color = ide.red,
                            fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun RegsRow(vm: StudioViewModel) {
    val ide = LocalIde.current
    val regs = vm.dbgState?.regs.orEmpty()
    val ordered = listOf("pc", "sp", "lr", "fp", "a0", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
        "r12", "r13", "r14", "r15", "eflags", "pstate", "orig_rax", "cs")
    val shown = ordered.filter { regs.containsKey(it) }
    // The ScrollState is hoisted here rather than hidden inside a Modifier
    // extension so the fade edges below can ask it what is still off-screen.
    val scroll = rememberScrollState()
    val fadeStart by remember { derivedStateOf { scroll.value > 0 } }
    val fadeEnd by remember { derivedStateOf { scroll.value < scroll.maxValue } }
    Box(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
    ) {
        if (shown.isEmpty()) {
            Text(
                "Registers appear when the process stops — hit a breakpoint, or Step.",
                color = ide.dim2, fontSize = Type.caption,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 6.dp)
            )
        } else {
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(scroll)
                    .padding(horizontal = 10.dp, vertical = 2.dp)
            ) {
                shown.forEach { r ->
                    Column(Modifier.padding(horizontal = 6.dp)) {
                        Text(r, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                        Text(
                            "0x%X".format(regs[r] ?: 0L),
                            color = if (r == "pc" || r == "rip") ide.amber else ide.cyan,
                            fontSize = Type.monoSmall, fontFamily = Mono
                        )
                    }
                }
            }
            // A control you cannot see is not reachable just because it can be
            // scrolled to. These say, in the only place the user is looking,
            // that the strip continues past the edge.
            if (fadeStart) {
                Box(
                    Modifier
                        .matchParentSize()
                        .background(Brush.horizontalGradient(0f to ide.panel, 0.08f to Color.Transparent))
                )
            }
            if (fadeEnd) {
                Box(
                    Modifier
                        .matchParentSize()
                        .background(Brush.horizontalGradient(0.92f to Color.Transparent, 1f to ide.panel))
                )
            }
        }
    }
}

/**
 * The Threads button used to fetch a thread list that nothing on screen ever
 * drew. It is captured in [DebuggerPanel] and rendered here.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ThreadsRow(threads: List<DbgThread>, onHide: () -> Unit) {
    if (threads.isEmpty()) return
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            .padding(horizontal = 10.dp, vertical = 2.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "THREADS (${threads.size})",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono
            )
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onHide, contentPadding = DbgBtnPad) {
                Text("Hide", color = ide.dim, fontSize = Type.label)
            }
        }
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalArrangement = Arrangement.spacedBy(2.dp)
        ) {
            threads.forEach { t ->
                Text(
                    "${t.tid} ${t.name}".trim(),
                    color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
                )
            }
        }
    }
}

@Composable
private fun SessionView(vm: StudioViewModel) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxSize()) {
        // memory + stack hex views
        val mem = vm.dbgMem
        val stack = vm.dbgStack
        if (mem != null) HexDump("MEMORY @ 0x%X".format(mem.first), mem.second, ide)
        if (stack != null) HexDump("STACK @ 0x%X".format(stack.first), stack.second, ide)
        // event log — the pid/arch line moved up here out of the list's tail,
        // where it sat below the oldest event and was never read.
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 3.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("EVENT LOG", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
            Spacer(Modifier.weight(1f))
            Text(
                "pid ${vm.dbgState?.pid ?: "-"} · ${vm.dbgState?.arch ?: "-"}",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
            )
        }
        if (vm.dbgEvents.isEmpty()) {
            EmptyPanel(
                "No debugger events yet",
                "Breakpoint hits, signals and exits are logged here. Registers, memory and the " +
                    "stack refresh every time the process stops."
            )
        } else {
            LazyColumn(
                Modifier
                    .fillMaxSize()
                    .background(ide.bg),
                contentPadding = bottomInset()
            ) {
                items(vm.dbgEvents.size) { i ->
                    val (ts, msg) = vm.dbgEvents[vm.dbgEvents.size - 1 - i]
                    Text(
                        "[$ts] $msg",
                        color = if (msg.startsWith("BP")) ide.red else
                            if (msg.startsWith("process exited")) ide.dim2 else ide.text,
                        fontSize = Type.label, fontFamily = Mono,
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 1.dp)
                    )
                }
            }
        }
    }
}

@Composable
private fun HexDump(title: String, hexData: String, ide: IdeColors) {
    // One vertical scroll for all 256 bytes the ViewModel actually fetched (the
    // old cap drew four rows, i.e. 64 of them), and one horizontal scroll shared
    // by every row so the columns stay aligned while it is swiped sideways.
    val vScroll = rememberScrollState()
    val hScroll = rememberScrollState()
    Column(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
    ) {
        Text(
            title, color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono,
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 1.dp)
        )
        val bytes = remember(hexData) {
            hexData.chunked(2).mapNotNull { it.toLongOrNull(16) }
        }
        val rows = (bytes.size + 15) / 16
        Column(
            Modifier
                .heightIn(max = 140.dp)
                .verticalScroll(vScroll)
                .horizontalScroll(hScroll)
                .padding(horizontal = 10.dp)
        ) {
            repeat(rows) { r ->
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
                    // The offset is formatted on its own: the ASCII column can
                    // legitimately contain a '%' (0x25), and folding it into the
                    // format string would make String.format throw on it.
                    "%04X".format(base) + "  $line $ascii",
                    color = ide.text, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
                )
            }
        }
        Spacer(Modifier.height(2.dp))
    }
}

@Composable
private fun TraceView(vm: StudioViewModel) {
    val ide = LocalIde.current
    var args by remember { mutableStateOf("/system/bin/toybox echo hello-nocturne") }
    var maxEvents by remember { mutableStateOf("200") }
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 6.dp)) {
            Text(
                "Syscall tracer (legacy): logs every syscall of the child. Requires root/debuggable.",
                color = ide.amber, fontSize = Type.label
            )
            Spacer(Modifier.height(6.dp))
            OutlinedTextField(
                value = args, onValueChange = { args = it },
                label = { Text("argv (newline-separated)") }, singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .semantics { contentDescription = "Program and arguments to trace" },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.height(6.dp))
            // Stays a Row: a 120dp field plus two compact buttons measures
            // ~295dp against a 360dp phone, so it fits with room to spare.
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = maxEvents,
                    onValueChange = { maxEvents = it.filter { c -> c.isDigit() }.take(4) },
                    label = { Text("Max events") }, singleLine = true,
                    modifier = Modifier
                        .width(120.dp)
                        .semantics { contentDescription = "Maximum number of syscalls to record" },
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.width(8.dp))
                Button(
                    onClick = {
                        val argv = args.split('\n').map { it.trim() }.filter { it.isNotEmpty() }
                        vm.debugRun(argv, maxEvents.toIntOrNull() ?: 200)
                    },
                    enabled = !vm.debugRunning,
                    contentPadding = DbgBtnPad
                ) { Text("Run trace", fontSize = Type.label) }
                Spacer(Modifier.width(6.dp))
                TextButton(
                    onClick = { vm.debugStop() }, enabled = vm.debugRunning,
                    contentPadding = DbgBtnPad
                ) { Text("Stop", color = ide.red, fontSize = Type.label) }
            }
        }
        val res = vm.debugResult
        if (res != null && !res.ok && res.error != null) {
            Text(
                "ERROR: ${res.error}",
                color = ide.red, fontSize = Type.label, fontFamily = Mono,
                modifier = Modifier.padding(horizontal = 12.dp)
            )
        }
        val events = res?.events ?: emptyList()
        if (events.isEmpty()) {
            // The old body rendered nothing at all before the first run, and a
            // bare "(no events)" after a run that recorded none.
            when {
                res == null -> EmptyPanel(
                    "No trace yet",
                    "Set the program and arguments above, then tap Run trace."
                )
                res.ok -> EmptyPanel(
                    "No syscalls recorded",
                    "The child exited before any syscall was traced. Check the path and arguments."
                )
                else -> EmptyPanel(
                    "Trace failed",
                    "ptrace needs root or a debuggable process, and SELinux can refuse it even then."
                )
            }
        } else {
            LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset()) {
                items(events.size) { i ->
                    val e = events[i]
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 10.dp, vertical = 2.dp)
                    ) {
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

@Composable
private fun SpawnDialog(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    var prog by remember { mutableStateOf("/system/bin/toybox") }
    var args by remember { mutableStateOf("sleep 30") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Spawn process", color = ide.accent, fontSize = Type.section) },
        text = {
            Column {
                OutlinedTextField(
                    value = prog, onValueChange = { prog = it },
                    label = { Text("Program path") }, singleLine = true,
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = args, onValueChange = { args = it },
                    label = { Text("Arguments") }, singleLine = true,
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Suggested: /system/bin/toybox sleep 30 — then BP @ func on a selected function.",
                    color = ide.dim2, fontSize = Type.caption
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
        title = { Text("Attach to PID", color = ide.accent, fontSize = Type.section) },
        text = {
            Column {
                OutlinedTextField(
                    value = pid, onValueChange = { pid = it.filter { c -> c.isDigit() } },
                    label = { Text("PID") }, singleLine = true,
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(4.dp))
                Text(
                    "Attach requires same-uid or root. Find PIDs via adb shell ps.",
                    color = ide.dim2, fontSize = Type.caption
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

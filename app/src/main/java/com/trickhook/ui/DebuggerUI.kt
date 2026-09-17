package com.trickhook.ui

import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.ContentTransform
import androidx.compose.animation.SizeTransform
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.scaleIn
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
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
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import com.trickhook.model.DbgBp
import com.trickhook.model.DbgState
import com.trickhook.shizuku.DbgBackend
import com.trickhook.shizuku.ShizukuGate
import com.trickhook.shizuku.ShizukuStage
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
private val DbgBtnPad = PaddingValues(horizontal = Space.m, vertical = Space.s)

/** Every interactive target on this screen clears Material's 48dp minimum. */
private val TouchTarget = Modifier.sizeIn(minWidth = 48.dp, minHeight = 48.dp)

/**
 * Display order for the register strip; whatever the architecture does not
 * report is skipped. Hoisted out of the composable because it is 34 constant
 * strings that were being rebuilt on every frame of a live session.
 */
private val RegOrder = listOf(
    "pc", "sp", "lr", "fp", "a0", "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
    "rip", "rsp", "rbp", "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
    "r12", "r13", "r14", "r15", "eflags", "pstate", "orig_rax", "cs"
)

/** How much of a 256-byte dump is on screen at once; the rest is one swipe away. */
private val DumpHeight = 140.dp

/** Both dumps on screen together, where the event log needs room of its own. */
private val DumpHeightPaired = 96.dp

/**
 * Breathing period of the RUNNING indicator. Deliberately outside the Motion
 * scale: those rungs are for transitions on the reading path and top out at
 * 260ms, which as a repeating pulse reads as a strobe rather than a heartbeat.
 * It still goes through [motionMs], so reduce-motion stops it dead.
 */
private const val PulseMs = 900

/**
 * The session, as this screen asks about it.
 *
 * `vm.dbgState` is now the accumulated session state, not the answer to the
 * last command: [StudioViewModel.dbgCmd] folds each op's answer into it, and
 * [StudioViewModel] clears it when a session ends. This class carries no
 * merging of its own any more — it is a projection plus the four questions the
 * screen actually asks, which is the part that was never the ViewModel's job.
 */
private data class DbgView(
    val state: String = "none",
    val pid: Long = 0L,
    val arch: String = "",
    val regs: Map<String, Long> = emptyMap(),
    val bps: List<DbgBp> = emptyList()
) {
    val stopped: Boolean get() = state == "stopped"
    val running: Boolean get() = state == "running"
    val live: Boolean get() = state != "none"

    /**
     * There is a process to talk to. Everything except `poll` is answered with
     * "no active session" once the pid is gone, and dbgCmd turns that into a
     * WARN — which is now a toast, so a command sent on a 400ms loop to a dead
     * session would be a toast on a 400ms loop.
     */
    val active: Boolean get() = stopped || running

    companion object {
        fun of(s: DbgState?): DbgView =
            if (s == null) DbgView()
            else DbgView(s.state, s.pid, s.arch, s.regs, s.bps)
    }
}

@OptIn(ExperimentalLayoutApi::class)
@Composable
fun DebuggerPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var showSpawn by remember { mutableStateOf(false) }
    var showAttach by remember { mutableStateOf(false) }
    // True from the moment Spawn or Attach is confirmed until the session
    // answers. dbgBusy cannot stand in for it: dbgCmd raises that flag from a
    // coroutine, so it is still false on the frame the dialog closes.
    var launching by remember { mutableStateOf(false) }
    // The address the MEMORY dump is pinned to. Null means it follows the
    // program counter, which is what makes the dump appear without being asked.
    var memWatch by remember { mutableStateOf<Long?>(null) }
    val view = DbgView.of(vm.dbgState)
    val ctx = LocalContext.current
    val backend = vm.dbgBackend

    // A privileged backend has a process behind it that has to exist before it
    // can be told anything, so Spawn and Attach wait for it rather than sending
    // a command into a null binder and reporting "command failed".
    val backendLive = !backend.privileged || ShizukuGate.ready

    // Registers the Shizuku listeners the first time this tab is opened and
    // re-reads the world on every entry after that: a permission granted inside
    // Shizuku's own app while Nocturne was on another tab is picked up here
    // rather than needing a restart. Nothing is started by it.
    LaunchedEffect(Unit) { ShizukuGate.attach(ctx) }

    // Shizuku only says whether it is shell or root once its binder has
    // answered, which can be after the backend chip was pressed. Without this,
    // a root user would sit on a backend labelled "shell" with Attach greyed
    // out for a capability they actually have. Re-labelling does not disturb a
    // live session: it is the same process either way.
    LaunchedEffect(ShizukuGate.serverUid, backend) {
        val uid = ShizukuGate.serverUid
        if (backend.privileged && uid >= 0) {
            val real = DbgBackend.forUid(uid)
            if (real != backend) vm.selectDbgBackend(real)
        }
    }

    // A spawn that fails leaves dbgMode on SESSION with no process behind it
    // and never answers, so the skeleton needs an end of its own — otherwise it
    // would sit there forever with Spawn and Attach disabled behind it.
    LaunchedEffect(launching) {
        if (launching) {
            delay(3000)
            launching = false
        }
    }

    // poll debugger state while a session is live
    LaunchedEffect(vm.dbgMode) {
        vm.dbgThreads = emptyList()
        var readPc: Long? = null
        while (vm.dbgMode == DbgMode.SESSION) {
            vm.dbgCmd("""{"op":"poll"}""")
            // Read the session state back from the ViewModel on every turn,
            // never from a value captured in composition: this loop outlives
            // the composition that started it, so a captured `view` would be
            // frozen at whatever the session looked like when Spawn was tapped.
            val live = DbgView.of(vm.dbgState)
            // bp_list is the only op that reports the breakpoint set — bp_add
            // answers with just the address it installed — and the ViewModel's
            // merge is what lets its answer, which carries nothing else, be
            // asked for without blanking the rest of the screen.
            if (live.active) vm.dbgCmd("""{"op":"bp_list"}""")
            if (live.live) launching = false
            if (live.stopped) {
                // One regs command feeds both the strip and the memory read:
                // its answer is the only place the PC is ever reported.
                vm.dbgCmd("""{"op":"regs"}""") { r ->
                    val pc = r.regs["pc"] ?: r.regs["rip"]
                    // Only on a NEW stop. Re-reading while the process sits
                    // still would fight a hand-typed address and refetch the
                    // same 256 bytes twice a second for nothing.
                    if (pc != null && pc != 0L && pc != readPc) {
                        readPc = pc
                        vm.dbgReadMem(memWatch ?: pc)
                    }
                }
                vm.dbgReadStack()
            } else {
                readPc = null
            }
            delay(400)
        }
        launching = false
    }

    Column(Modifier.fillMaxSize()) {
        // ---- toolbar chrome: the title, the live state, and the session
        // lifecycle. One surface at level 2 rather than two bands that happen
        // to share a colour, so no hairline runs through the header.
        Column(
            Modifier
                .fillMaxWidth()
                .surface2(RectangleShape)
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Space.l, vertical = Space.m),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    "DEBUGGER",
                    color = ide.text, fontSize = Type.mono,
                    fontWeight = FontWeight.Bold, fontFamily = Mono
                )
                Spacer(Modifier.weight(1f))
                StateIndicator(view, vm.dbgMode)
            }

            BackendRow(vm)

            // FlowRow, not Row: at a large font scale even two buttons and a
            // Kill will not fit one line on a 360dp phone.
            FlowRow(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Space.l, vertical = Space.s),
                horizontalArrangement = Arrangement.spacedBy(Space.s),
                verticalArrangement = Arrangement.spacedBy(Space.s)
            ) {
                // Not !dbgBusy: the 400ms poll holds that flag up for most of a
                // live session, which left every control here blinking between
                // enabled and disabled. Only a launch in flight blocks a launch.
                Button(
                    onClick = { showSpawn = true }, enabled = !launching && backendLive,
                    contentPadding = DbgBtnPad
                ) { Text("Spawn", fontSize = Type.label) }
                // Disabled, not allowed to fail. PTRACE_ATTACH to a process the
                // shell backend did not start is refused by the kernel and by
                // SELinux every single time, so the control says so by being
                // unavailable instead of by producing an error afterwards.
                Button(
                    onClick = { showAttach = true },
                    enabled = !launching && backendLive && backend.offersAttach,
                    contentPadding = DbgBtnPad
                ) { Text("Attach", fontSize = Type.label) }
                if (vm.dbgMode == DbgMode.SESSION) {
                    TextButton(onClick = { vm.dbgKill() }, contentPadding = DbgBtnPad) {
                        Text("Kill", color = ide.red, fontSize = Type.label)
                    }
                }
            }

            // What this backend cannot do, beside the control it greys out.
            val limit = backend.limit
            if (limit != null) {
                Text(
                    limit,
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
                    modifier = Modifier.padding(horizontal = Space.l, vertical = Space.xs)
                )
            }
        }

        // The whole Shizuku state machine, in the one place it matters.
        if (backend.privileged) ShizukuStrip(vm)

        // ---- the control stack. One panel surface for all of it: four
        // adjacent bands each drawing their own background would stack two
        // hairlines between every pair now that a surface carries a border.
        if (vm.dbgMode == DbgMode.SESSION) {
            Column(
                Modifier
                    .fillMaxWidth()
                    .surface1(RectangleShape)
            ) {
                ExecRow(vm, view)
                AddressRow(vm, view.bps, view.stopped) { addr ->
                    memWatch = addr
                    if (addr != null) vm.dbgReadMem(addr)
                }
                RegsRow(view)
                ThreadsRow(vm)
            }
        }

        // ---- body: legacy trace or session view. Three entirely different
        // screens, so the switch fades and settles instead of cutting;
        // SizeTransform(clip = false) keeps the outgoing one from being sliced
        // while the box resizes around it.
        val bodyMs = motionMs()
        AnimatedContent(
            targetState = vm.dbgMode,
            modifier = Modifier.weight(1f),
            transitionSpec = {
                ContentTransform(
                    targetContentEnter = fadeIn(tween(bodyMs)) +
                        scaleIn(tween(bodyMs), initialScale = 0.98f),
                    initialContentExit = fadeOut(tween(bodyMs)),
                    sizeTransform = SizeTransform(clip = false)
                )
            },
            label = "debugger mode"
        ) { mode ->
            when (mode) {
                DbgMode.TRACE -> TraceView(vm)
                DbgMode.SESSION -> SessionView(vm, view, launching)
                DbgMode.NONE -> Hint(
                    "Two debugger modes:\n" +
                        "  • Spawn/Attach — real ptrace session: breakpoints, registers, memory, stack, threads.\n" +
                        "  • (Old) syscall tracer — set program below and Run trace.",
                    if (backend.privileged) {
                        "Through Shizuku the sample is staged into /data/local/tmp as uid " +
                            (if (backend == DbgBackend.SHIZUKU_ROOT) "0" else "2000") +
                            ", made executable, and traced as a child of that process."
                    } else {
                        "In-process ptrace needs root or a debuggable target, and SELinux can " +
                            "refuse it even then. An imported sample cannot be run here at all — " +
                            "switch to the Shizuku backend above."
                    }
                )
            }
        }
    }

    if (showSpawn) SpawnDialog(vm, onLaunch = { launching = true }) { showSpawn = false }
    if (showAttach) AttachDialog(vm, onLaunch = { launching = true }) { showAttach = false }
}

/**
 * The live session state, with a dot that breathes while the process runs.
 * Under reduce-motion the dot is simply drawn: a slowed pulse is still a pulse,
 * and the setting asks for no movement, not for less of it — so the infinite
 * transition is never even created.
 */
@Composable
private fun StateIndicator(view: DbgView, mode: DbgMode) {
    val ide = LocalIde.current
    val label = when {
        view.live -> view.state.uppercase()
        mode == DbgMode.TRACE -> "TRACE MODE"
        else -> "NO SESSION"
    }
    val tint = when (view.state) {
        "stopped" -> ide.amber
        "running" -> ide.entry
        "exited" -> ide.red
        else -> ide.dim2
    }
    val pulseMs = motionMs(PulseMs)
    val alpha = if (view.running && pulseMs > 0) {
        val pulse = rememberInfiniteTransition(label = "running")
        val a by pulse.animateFloat(
            initialValue = 1f,
            targetValue = 0.3f,
            animationSpec = infiniteRepeatable(
                animation = tween(pulseMs, easing = LinearEasing),
                repeatMode = RepeatMode.Reverse
            ),
            label = "running alpha"
        )
        a
    } else {
        1f
    }
    Row(verticalAlignment = Alignment.CenterVertically) {
        Box(
            Modifier
                .size(Space.m)
                .alpha(alpha)
                .background(tint, CircleShape)
        )
        Spacer(Modifier.width(Space.s))
        Text(label, color = tint, fontSize = Type.mono, fontFamily = Mono, maxLines = 1)
    }
}

/**
 * Execution controls. These are the five that used to run off the right edge;
 * wrapping them is what makes Regs and Threads reachable at all.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ExecRow(vm: StudioViewModel, view: DbgView) {
    val stopped = view.stopped
    FlowRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.l, vertical = Space.s),
        horizontalArrangement = Arrangement.spacedBy(Space.s),
        verticalArrangement = Arrangement.spacedBy(Space.s)
    ) {
        // Continue and Step are the two buttons on this screen that get pressed
        // over and over, so they are the two that earn real tactile feedback.
        val contSource = remember { MutableInteractionSource() }
        val contPressed by contSource.collectIsPressedAsState()
        Button(
            onClick = { vm.dbgCont() },
            enabled = stopped,
            interactionSource = contSource,
            modifier = Modifier.pressScale(contPressed),
            contentPadding = DbgBtnPad
        ) {
            Icon(
                Icons.Filled.PlayArrow, contentDescription = null,
                modifier = Modifier.size(14.dp)
            )
            Spacer(Modifier.width(Space.s))
            Text("Continue", fontSize = Type.label)
        }

        val stepSource = remember { MutableInteractionSource() }
        val stepPressed by stepSource.collectIsPressedAsState()
        Button(
            onClick = { vm.dbgStep() },
            enabled = stopped,
            interactionSource = stepSource,
            modifier = Modifier.pressScale(stepPressed),
            contentPadding = DbgBtnPad
        ) { Text("Step", fontSize = Type.label) }

        Button(
            onClick = { vm.dbgBpAtSelectedFunction() },
            enabled = vm.selectedFunc != null, contentPadding = DbgBtnPad
        ) { Text("BP @ func", fontSize = Type.label) }
        Button(onClick = { vm.dbgRegs() }, contentPadding = DbgBtnPad) {
            Text("Regs", fontSize = Type.label)
        }
        Button(onClick = { vm.dbgRefreshThreads() }, contentPadding = DbgBtnPad) {
            Text("Threads", fontSize = Type.label)
        }
    }
}

/**
 * One address, two things to do with it.
 *
 * The MEMORY dump had no producer at all: `dbgReadMem` had not a single caller
 * anywhere in the app, so `vm.dbgMem` was permanently null and the hexdump that
 * draws it was dead code on screen. Read is the missing half.
 *
 * It shares the breakpoint field rather than adding a second one below it: the
 * two ask for exactly the same thing, and a debugger stacked six control rows
 * deep on a 360dp phone cannot spend a 56dp text field twice on one hex
 * address. Reading an address and then breaking on it is also the order the
 * work actually happens in.
 *
 * Read pins the address: a pinned address is re-read at every new stop, so the
 * dump behaves like a watch window instead of snapping back to the program
 * counter each time the process moves. Emptying the field unpins it, and the
 * dump follows the PC again.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun AddressRow(
    vm: StudioViewModel,
    bps: List<DbgBp>,
    stopped: Boolean,
    onWatch: (Long?) -> Unit
) {
    val ide = LocalIde.current
    var text by remember { mutableStateOf("") }
    val addr = parseAddr(text)
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.l, vertical = Space.s)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            OutlinedTextField(
                value = text,
                onValueChange = {
                    text = it
                    if (it.isBlank()) onWatch(null)
                },
                label = { Text("Address (hex)", fontSize = Type.caption) },
                singleLine = true,
                // weight, not a fixed 170dp: the field gives up whatever the
                // buttons need instead of pushing them off the edge.
                modifier = Modifier
                    .weight(1f)
                    .semantics {
                        contentDescription =
                            "Address in hexadecimal, for a breakpoint or a memory read"
                    },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.width(Space.s))
            TextButton(
                onClick = { addr?.let { vm.dbgAddBp(it) } },
                // Was `addr.isNotBlank()`, which offered the action on text that
                // no parse could turn into an address and then did nothing.
                enabled = addr != null,
                contentPadding = DbgBtnPad
            ) { Text("Set BP", fontSize = Type.label) }
            Spacer(Modifier.width(Space.s))
            TextButton(
                onClick = { addr?.let { a -> onWatch(a) } },
                // ptrace can only peek at a stopped tracee, so a read while the
                // process runs would fail every time it was offered.
                enabled = stopped && addr != null,
                contentPadding = DbgBtnPad
            ) { Text("Read", fontSize = Type.label) }
        }
        // Chips arrive and leave as breakpoints are added, hit and deleted, so
        // the block grows and shrinks rather than shunting the strip below it.
        Box(
            Modifier
                .fillMaxWidth()
                .animateContentSize(tween(motionMs()))
        ) {
            if (bps.isEmpty()) {
                Text(
                    "No breakpoints. Type a hex address above and tap Set BP, or select a " +
                        "function and use BP @ func.",
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
                    modifier = Modifier.padding(vertical = Space.s)
                )
            } else {
                // Chips wrap instead of running off the edge — with two or more
                // breakpoints the old Row clipped them, and tapping one is still
                // the only way to delete it.
                val chipShape = RoundedCornerShape(Space.m)
                FlowRow(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(Space.s),
                    verticalArrangement = Arrangement.spacedBy(Space.s)
                ) {
                    bps.forEach { b ->
                        val label = "0x%X".format(b.addr)
                        Row(
                            TouchTarget
                                // surface2 clips to the shape itself, so the
                                // ripple of the click below stays inside it.
                                .surface2(chipShape)
                                .clickable(
                                    onClickLabel = "Delete breakpoint at $label",
                                    role = Role.Button
                                ) { vm.dbgDelBp(b.addr) }
                                .padding(horizontal = Space.m),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Icon(
                                Icons.Filled.Close, contentDescription = null,
                                tint = ide.red, modifier = Modifier.size(12.dp)
                            )
                            Spacer(Modifier.width(Space.s))
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
}

@Composable
private fun RegsRow(view: DbgView) {
    val ide = LocalIde.current
    val regs = view.regs
    val shown = RegOrder.filter { regs.containsKey(it) }
    // The ScrollState is hoisted here rather than hidden inside a Modifier
    // extension so the fade edges below can ask it what is still off-screen.
    val scroll = rememberScrollState()
    val fadeStart by remember { derivedStateOf { scroll.value > 0 } }
    val fadeEnd by remember { derivedStateOf { scroll.value < scroll.maxValue } }
    Box(
        Modifier
            .fillMaxWidth()
            // The strip is one line when the process stops and two lines of
            // explanation when it has not; both states are real, so the height
            // moves between them instead of snapping.
            .animateContentSize(tween(motionMs()))
    ) {
        if (shown.isEmpty()) {
            Text(
                "Registers appear when the process stops — hit a breakpoint, or Step.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
                modifier = Modifier.padding(horizontal = Space.l, vertical = Space.m)
            )
        } else {
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(scroll)
                    .padding(horizontal = Space.l, vertical = Space.xs)
            ) {
                shown.forEach { r ->
                    Column(Modifier.padding(horizontal = Space.s)) {
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
 * drew, and the answer landed in a DbgState the 400ms poll then replaced. It
 * now answers into `vm.dbgThreads`, which nothing on the poll path touches, and
 * this draws it from there.
 */
@Composable
private fun ThreadsRow(vm: StudioViewModel) {
    val threads = vm.dbgThreads
    if (threads.isEmpty()) return
    val ide = LocalIde.current
    val itemMs = motionMs()
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.l, vertical = Space.xs)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                "THREADS (${threads.size})",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono
            )
            Spacer(Modifier.weight(1f))
            TextButton(
                onClick = { vm.dbgThreads = emptyList() },
                contentPadding = DbgBtnPad
            ) { Text("Hide", color = ide.dim, fontSize = Type.label) }
        }
        // A lazy row rather than a wrapping FlowRow: a process with thirty
        // threads would otherwise push the event log off the bottom of the
        // screen, and only a lazy list can animate a thread in or out.
        LazyRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(Space.l),
            contentPadding = PaddingValues(vertical = Space.xs)
        ) {
            items(threads, key = { it.tid }) { t ->
                Text(
                    "${t.tid} ${t.name}".trim(),
                    color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1,
                    modifier = Modifier.animateItem(
                        fadeInSpec = tween(itemMs),
                        placementSpec = tween(itemMs),
                        fadeOutSpec = tween(itemMs)
                    )
                )
            }
        }
    }
}

@Composable
private fun SessionView(vm: StudioViewModel, view: DbgView, launching: Boolean) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxSize()) {
        // memory + stack hex views. Either can appear or vanish as the process
        // stops and moves, so the pair grows into place instead of popping and
        // shoving the event log down a screenful at a time.
        val mem = vm.dbgMem
        val stack = vm.dbgStack
        Column(
            Modifier
                .fillMaxWidth()
                .animateContentSize(tween(motionMs()))
        ) {
            // Both dumps at once, on a screen that already carries three
            // rows of controls, would leave the event log under it nothing at
            // all. Each still holds every byte that was fetched; a shorter
            // window just means one more swipe to reach the end of it.
            val cap = if (mem != null && stack != null) DumpHeightPaired else DumpHeight
            if (mem != null) HexDump("MEMORY @ 0x%X".format(mem.first), mem.second, ide, cap)
            if (stack != null) HexDump("STACK @ 0x%X".format(stack.first), stack.second, ide, cap)
        }
        // event log — the pid/arch line moved up here out of the list's tail,
        // where it sat below the oldest event and was never read.
        Row(
            Modifier
                .fillMaxWidth()
                .surface2(RectangleShape)
                .padding(horizontal = Space.l, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text("EVENT LOG", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
            Spacer(Modifier.weight(1f))
            val pidText = if (view.pid != 0L) view.pid.toString() else "-"
            val archText = view.arch.ifEmpty { "-" }
            Text(
                "pid $pidText · $archText",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
            )
        }
        when {
            // A spawn or an attach takes as long as the process takes to stop.
            // The shape of what is coming beats both a blank panel and a
            // spinner that says only "something".
            launching -> Column(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Space.l, vertical = Space.m)
            ) { SkeletonLines(lines = 6) }

            vm.dbgEvents.isEmpty() -> EmptyPanel(
                "No debugger events yet",
                "Breakpoint hits, signals and exits are logged here. Registers, memory and the " +
                    "stack refresh every time the process stops."
            )

            else -> {
                val events = vm.dbgEvents
                // Stable per-row identity, so that a new event slides the older
                // ones down instead of every row being redrawn one place lower.
                // Duplicates are real here — the same breakpoint hit twice in
                // one second is two identical lines — and a repeated key is a
                // crash, not a glitch, so each repeat is numbered.
                val keys = remember(events) {
                    val seen = HashMap<String, Int>()
                    events.map { (ts, msg) ->
                        val base = "$ts|$msg"
                        val n = (seen[base] ?: 0) + 1
                        seen[base] = n
                        "$base|$n"
                    }
                }
                val itemMs = motionMs()
                val listState = rememberLazyListState()
                // A keyed lazy list anchors its scroll to the key of the first
                // visible row, so an event prepended at the top lands ABOVE the
                // viewport and is never seen. Follow the head only while the
                // reader is already at it; anyone who has scrolled back through
                // the log stays where they put themselves.
                LaunchedEffect(events) {
                    if (listState.firstVisibleItemIndex <= 1) {
                        if (itemMs == 0) listState.scrollToItem(0)
                        else listState.animateScrollToItem(0)
                    }
                }
                LazyColumn(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(ide.bg),
                    state = listState,
                    contentPadding = bottomInset()
                ) {
                    items(events.size, key = { i -> keys[keys.size - 1 - i] }) { i ->
                        val (ts, msg) = events[events.size - 1 - i]
                        Text(
                            "[$ts] $msg",
                            color = if (msg.startsWith("BP")) ide.red else
                                if (msg.startsWith("process exited")) ide.dim2 else ide.text,
                            fontSize = Type.label, fontFamily = Mono,
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = Space.l, vertical = Space.xs)
                                .animateItem(
                                    fadeInSpec = tween(itemMs),
                                    placementSpec = tween(itemMs),
                                    fadeOutSpec = tween(itemMs)
                                )
                        )
                    }
                }
            }
        }
    }
}

@Composable
private fun HexDump(title: String, hexData: String, ide: IdeColors, cap: Dp) {
    // One vertical scroll for all 256 bytes the ViewModel actually fetched (the
    // old cap drew four rows, i.e. 64 of them), and one horizontal scroll shared
    // by every row so the columns stay aligned while it is swiped sideways.
    val vScroll = rememberScrollState()
    val hScroll = rememberScrollState()
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.l, vertical = Space.xs)
            .surface1()
            .padding(Space.s)
    ) {
        Text(
            title, color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono,
            modifier = Modifier.padding(horizontal = Space.s)
        )
        val bytes = remember(hexData) {
            hexData.chunked(2).mapNotNull { it.toLongOrNull(16) }
        }
        val rows = (bytes.size + 15) / 16
        Column(
            Modifier
                .heightIn(max = cap)
                .verticalScroll(vScroll)
                .horizontalScroll(hScroll)
                .padding(horizontal = Space.s)
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
    }
}

@Composable
private fun TraceView(vm: StudioViewModel) {
    val ide = LocalIde.current
    var args by remember { mutableStateOf("/system/bin/toybox echo hello-nocturne") }
    var maxEvents by remember { mutableStateOf("200") }
    Column(Modifier.fillMaxSize()) {
        Column(Modifier.padding(horizontal = Space.l, vertical = Space.m)) {
            Text(
                "Syscall tracer (legacy): logs every syscall of the child. Requires root/debuggable.",
                color = ide.amber, fontSize = Type.label, lineHeight = Type.labelLine
            )
            Spacer(Modifier.height(Space.m))
            OutlinedTextField(
                value = args, onValueChange = { args = it },
                label = { Text("argv (newline-separated)") }, singleLine = true,
                modifier = Modifier
                    .fillMaxWidth()
                    .semantics { contentDescription = "Program and arguments to trace" },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.height(Space.m))
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
                Spacer(Modifier.width(Space.m))
                Button(
                    onClick = {
                        val argv = args.split('\n').map { it.trim() }.filter { it.isNotEmpty() }
                        vm.debugRun(argv, maxEvents.toIntOrNull() ?: 200)
                    },
                    enabled = !vm.debugRunning,
                    contentPadding = DbgBtnPad
                ) { Text("Run trace", fontSize = Type.label) }
                Spacer(Modifier.width(Space.s))
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
                modifier = Modifier.padding(horizontal = Space.l)
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
                            .padding(horizontal = Space.l, vertical = Space.xs)
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

/**
 * Which process the session runs in, and one line saying what that buys.
 *
 * Two chips, not three: the privileged one names the privilege the Shizuku
 * server actually has rather than offering both and letting the user find out.
 * [ShizukuGate.serverUid] is 0 for a root or Sui backend and 2000 for adb, so
 * the label is read off the server, never guessed.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun BackendRow(vm: StudioViewModel) {
    val ide = LocalIde.current
    val live = vm.dbgBackend
    val privileged = DbgBackend.forUid(ShizukuGate.serverUid)
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.l, vertical = Space.xs)
    ) {
        FlowRow(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(Space.s),
            verticalArrangement = Arrangement.spacedBy(Space.s)
        ) {
            BackendChip(DbgBackend.LOCAL, live == DbgBackend.LOCAL) {
                vm.selectDbgBackend(DbgBackend.LOCAL)
            }
            BackendChip(privileged, live.privileged) {
                vm.selectDbgBackend(privileged)
            }
        }
        // The capability line follows the SELECTED backend, so it is always
        // describing the thing that is about to run.
        Text(
            live.summary,
            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
            modifier = Modifier.padding(vertical = Space.xs)
        )
    }
}

@Composable
private fun BackendChip(backend: DbgBackend, selected: Boolean, onPick: () -> Unit) {
    val ide = LocalIde.current
    val shape = RoundedCornerShape(Space.m)
    val tint = if (selected) ide.accent else ide.dim2
    Row(
        TouchTarget
            .surface2(shape)
            .clickable(
                onClickLabel = "Run the debugger in the " + backend.label + " backend",
                role = Role.RadioButton,
                onClick = onPick
            )
            .padding(horizontal = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(Space.m)
                .background(tint, CircleShape)
        )
        Spacer(Modifier.width(Space.s))
        Text(backend.label, color = tint, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1)
    }
}

/**
 * Every state Shizuku can be in, and the one thing to do about each of them.
 *
 * Shizuku is not a boolean. It can be absent, present but not started, started
 * but never asked, asked and refused, granted, starting, running, or it can die
 * in the middle of a session — and each of those needs a different sentence and
 * a different button. None of them dead-ends: "not installed" links to where
 * Shizuku comes from instead of telling the user to go and find it.
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun ShizukuStrip(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val stage = ShizukuGate.stage

    val title = when (stage) {
        ShizukuStage.NOT_INSTALLED -> "SHIZUKU NOT INSTALLED"
        ShizukuStage.NOT_RUNNING -> "SHIZUKU NOT RUNNING"
        ShizukuStage.UNSUPPORTED -> "SHIZUKU TOO OLD"
        ShizukuStage.ASK -> "PERMISSION NEEDED"
        ShizukuStage.DENIED -> "PERMISSION REFUSED"
        ShizukuStage.GRANTED -> "READY TO CONNECT"
        ShizukuStage.BINDING -> "STARTING"
        ShizukuStage.BOUND -> "CONNECTED"
        ShizukuStage.BIND_FAILED -> "COULD NOT START"
        ShizukuStage.BINDER_DEAD -> "CONNECTION LOST"
    }
    val tint = when (stage) {
        ShizukuStage.BOUND -> ide.entry
        ShizukuStage.GRANTED -> ide.cyan
        ShizukuStage.BIND_FAILED, ShizukuStage.BINDER_DEAD -> ide.red
        else -> ide.amber
    }
    val actionLabel = when (stage) {
        ShizukuStage.NOT_INSTALLED -> "Get Shizuku"
        ShizukuStage.NOT_RUNNING, ShizukuStage.UNSUPPORTED, ShizukuStage.DENIED -> "Open Shizuku"
        ShizukuStage.ASK -> "Grant permission"
        ShizukuStage.GRANTED -> "Connect"
        ShizukuStage.BIND_FAILED -> "Try again"
        ShizukuStage.BINDER_DEAD -> "Reconnect"
        ShizukuStage.BOUND -> "Disconnect"
        ShizukuStage.BINDING -> ""
    }
    val onAction = {
        when (stage) {
            ShizukuStage.NOT_INSTALLED, ShizukuStage.NOT_RUNNING,
            ShizukuStage.UNSUPPORTED, ShizukuStage.DENIED -> {
                val intent = ShizukuGate.openIntent()
                if (intent == null) {
                    vm.log("WARN", "Nothing on this device can open " + ShizukuGate.DOWNLOAD_URL)
                } else {
                    try {
                        ctx.startActivity(intent)
                    } catch (t: Throwable) {
                        vm.log("ERROR", "Could not open Shizuku: " + (t.message ?: "no activity"))
                    }
                }
            }

            ShizukuStage.ASK -> ShizukuGate.requestPermission()

            ShizukuStage.BOUND -> {
                // The privileged process owns the tracee, so stopping it kills
                // the session. Ending the session first keeps the screen and
                // the process telling the same story.
                if (vm.dbgMode == DbgMode.SESSION) vm.dbgKill()
                ShizukuGate.disconnect()
            }

            else -> ShizukuGate.connect()
        }
    }

    Column(
        Modifier
            .fillMaxWidth()
            // The strip is one line when it is connected and a paragraph plus
            // two buttons when it is not, and it moves between those a lot
            // while someone is setting Shizuku up.
            .animateContentSize(tween(motionMs()))
            .surface1(RectangleShape)
            .padding(horizontal = Space.l, vertical = Space.m)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(
                Modifier
                    .size(Space.m)
                    .background(tint, CircleShape)
            )
            Spacer(Modifier.width(Space.s))
            Text(title, color = tint, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1)
            Spacer(Modifier.weight(1f))
            // Sui is a Magisk module, not the Shizuku app, and it is always
            // root. Worth naming, because none of the "open Shizuku" advice
            // applies to it.
            if (ShizukuGate.sui) StatChip("SUI", ide.violet)
        }

        val line = ShizukuGate.serviceLine
        if (stage == ShizukuStage.BOUND && line.isNotEmpty()) {
            Text(
                line,
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 2,
                modifier = Modifier.padding(vertical = Space.xs)
            )
        } else {
            Text(
                ShizukuGate.detail,
                color = ide.dim, fontSize = Type.caption, lineHeight = Type.captionLine,
                modifier = Modifier.padding(vertical = Space.xs)
            )
        }

        // Where the sample is right now, so nobody has to wonder whether
        // something was left in /data/local/tmp.
        val staged = ShizukuGate.stagedPath
        if (staged.isNotEmpty()) {
            Text(
                "staged " + staged,
                color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 2
            )
        }
        // One skeleton, not two: staging and starting are both "something is
        // happening over there and it takes seconds".
        if (vm.dbgStaging || stage == ShizukuStage.BINDING) SkeletonLines(lines = 2)

        FlowRow(
            modifier = Modifier
                .fillMaxWidth()
                .padding(top = Space.s),
            horizontalArrangement = Arrangement.spacedBy(Space.s),
            verticalArrangement = Arrangement.spacedBy(Space.s)
        ) {
            if (actionLabel.isNotEmpty()) {
                Button(onClick = onAction, contentPadding = DbgBtnPad) {
                    Text(actionLabel, fontSize = Type.label)
                }
            }
            // Granting happens in another app, and nothing tells us when the
            // user comes back if the tab was never left. This is that.
            TextButton(onClick = { ShizukuGate.attach(ctx) }, contentPadding = DbgBtnPad) {
                Text("Re-check", color = ide.dim, fontSize = Type.label)
            }
        }
    }
}

@Composable
private fun SpawnDialog(vm: StudioViewModel, onLaunch: () -> Unit, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    var prog by remember { mutableStateOf("/system/bin/toybox") }
    var args by remember { mutableStateOf("sleep 30") }
    val open = vm.currentPath
    // The headline action, and the one the whole Shizuku backend exists for.
    // Offered only where it can actually work: the in-process backend cannot
    // execve anything out of app storage at any path, so showing it there would
    // be a button that is always wrong.
    val runnable = if (vm.dbgBackend.canStage) open else null
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Spawn process", color = ide.accent, fontSize = Type.section) },
        text = {
            // Scrolls: with the staged-run block on top, two fields and two
            // captions, this body is taller than a dialog on a short phone.
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (runnable != null) {
                    Button(
                        onClick = {
                            vm.dbgSpawnStaged(args)
                            onLaunch()
                            onDismiss()
                        },
                        enabled = !vm.dbgStaging,
                        modifier = Modifier.fillMaxWidth(),
                        contentPadding = DbgBtnPad
                    ) {
                        Text(
                            "Run " + runnable.substringAfterLast('/'),
                            fontSize = Type.label, maxLines = 1
                        )
                    }
                    Spacer(Modifier.height(Space.s))
                    Text(
                        "Copies the open file into /data/local/tmp through the privileged " +
                            "process, makes it executable there, and traces it as that process's " +
                            "own child. It is deleted again when the session ends.",
                        color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                    )
                    Spacer(Modifier.height(Space.l))
                }
                OutlinedTextField(
                    value = prog, onValueChange = { prog = it },
                    label = { Text("Program path") }, singleLine = true,
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(Space.m))
                OutlinedTextField(
                    value = args, onValueChange = { args = it },
                    label = { Text("Arguments") }, singleLine = true,
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(Space.s))
                Text(
                    "Suggested: /system/bin/toybox sleep 30 — then BP @ func on a selected function.",
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                vm.dbgSpawn(prog, args)
                onLaunch()
                onDismiss()
            }) { Text("Spawn", color = ide.accent) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = ide.dim) } }
    )
}

@Composable
private fun AttachDialog(vm: StudioViewModel, onLaunch: () -> Unit, onDismiss: () -> Unit) {
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
                Spacer(Modifier.height(Space.s))
                Text(
                    if (vm.dbgBackend == DbgBackend.SHIZUKU_ROOT) {
                        "Running as uid 0: any pid on the device can be attached. Find one with " +
                            "adb shell ps -A, or in the Threads list of a session you started."
                    } else {
                        "Attach requires same-uid or root. Find PIDs via adb shell ps."
                    },
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                pid.toLongOrNull()?.let { vm.dbgAttach(it); onLaunch() }
                onDismiss()
            }) { Text("Attach", color = ide.accent) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = ide.dim) } }
    )
}

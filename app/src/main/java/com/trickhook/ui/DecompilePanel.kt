package com.trickhook.ui

import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Subject
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.model.FunctionDetail
import com.trickhook.vm.StudioViewModel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

private val KEYWORDS = setOf(
    "void", "if", "goto", "return", "unsigned", "int", "long", "while", "else"
)

/** Material's minimum tap target, and WCAG 2.2 SC 2.5.8's with room to spare. */
private val Touch = 48.dp

/** Side by side stops helping once a column is narrower than a line of C. */
private val SplitAt = 700.dp

private fun highlightPseudo(src: String, ide: IdeColors): AnnotatedString = buildAnnotatedString {
    src.lines().forEachIndexed { idx, line ->
        if (idx > 0) append("\n")
        val trimmed = line.trimStart()
        when {
            trimmed.startsWith("L_") -> {
                append(line)
                addStyle(SpanStyle(color = ide.amber, fontWeight = FontWeight.Bold), length - line.length, length)
            }
            trimmed.startsWith("//") || trimmed.startsWith("/*") -> {
                append(line)
                addStyle(SpanStyle(color = ide.dim), length - line.length, length)
            }
            else -> {
                // tokenize: keyword / hex number / comment tail
                var i = 0
                val commentAt = line.indexOf("//")
                val codeEnd = if (commentAt >= 0) commentAt else line.length
                while (i < codeEnd) {
                    val c = line[i]
                    when {
                        c.isLetter() -> {
                            val start = i
                            while (i < codeEnd && (line[i].isLetterOrDigit() || line[i] == '_')) i++
                            val word = line.substring(start, i)
                            if (word in KEYWORDS) {
                                append(word)
                                addStyle(SpanStyle(color = ide.violet, fontWeight = FontWeight.Bold), length - word.length, length)
                            } else append(word)
                        }
                        c.isDigit() -> {
                            val start = i
                            while (i < codeEnd && (line[i].isLetterOrDigit() || line[i] == 'x' || line[i] == 'X')) i++
                            val num = line.substring(start, i)
                            append(num)
                            addStyle(SpanStyle(color = ide.amber), length - num.length, length)
                        }
                        else -> {
                            append(c)
                            i++
                        }
                    }
                }
                if (commentAt >= 0) {
                    append(line.substring(commentAt))
                    addStyle(SpanStyle(color = ide.dim), length - (line.length - commentAt), length)
                }
            }
        }
    }
}

/**
 * One row of the cross-reference sheet. `target` null means the row cannot
 * navigate: an import stub, or an address outside every known function.
 * Deliberately the same shape as the Assembly panel's rows, so the two sheets
 * read as one feature rather than two.
 */
private class PseudoXref(
    val site: Long,
    val target: Long?,
    val label: String,
    val type: String,
    val note: String
)

/**
 * Who references this function, or what it references. The engine's
 * per-function xrefs come first and the whole-binary call-edge index is the
 * fallback when it found none — the same rule the Assembly panel's strip
 * applies, so the two counts agree for the same function.
 */
private fun pseudoXrefRows(
    vm: StudioViewModel,
    d: FunctionDetail,
    incoming: Boolean
): List<PseudoXref> = if (incoming) {
    val xs = d.xrefsIn
    if (xs.isNotEmpty()) xs.map { x ->
        val owner = vm.functionContaining(x.from)
        PseudoXref(
            site = x.from,
            target = owner?.takeIf { it.from != "import" }?.addr,
            label = owner?.let { vm.effectiveFuncName(it.addr) } ?: "unmapped",
            type = x.type.ifEmpty { "ref" },
            note = if (owner == null) "outside any known function" else ""
        )
    } else vm.callersOf(d.addr).map { e ->
        val owner = vm.functionAt(e.from) ?: vm.functionContaining(e.from)
        PseudoXref(
            site = e.from,
            target = owner?.takeIf { it.from != "import" }?.addr,
            label = owner?.let { vm.effectiveFuncName(it.addr) } ?: e.fromName.ifEmpty { "unmapped" },
            type = e.kind.ifEmpty { "call" },
            note = if (owner == null) "outside any known function" else ""
        )
    }
} else {
    val xs = d.xrefsOut
    if (xs.isNotEmpty()) xs.map { x ->
        val callee = vm.functionAt(x.to) ?: vm.functionContaining(x.to)
        val isImport = callee?.from == "import"
        PseudoXref(
            site = x.from,
            target = if (callee != null && !isImport) callee.addr else null,
            label = callee?.let { vm.effectiveFuncName(it.addr) } ?: hexFmt(x.to),
            type = x.type.ifEmpty { "call" },
            note = if (isImport) "import" else if (callee == null) "unresolved target" else ""
        )
    } else vm.calleesOf(d.addr).map { e ->
        val callee = vm.functionAt(e.to) ?: vm.functionContaining(e.to)
        val isImport = callee?.from == "import"
        PseudoXref(
            site = e.from,
            target = if (callee != null && !isImport) callee.addr else null,
            label = callee?.let { vm.effectiveFuncName(it.addr) } ?: e.toName.ifEmpty { hexFmt(e.to) },
            type = e.kind.ifEmpty { "call" },
            note = if (isImport) "import" else if (callee == null) "unresolved target" else ""
        )
    }
}

@Composable
fun DecompilePanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val d = vm.detail
    // Nullable rather than a separate `hasPseudo` flag, so every use below is
    // guarded by a plain null check the compiler can smart-cast through.
    val pseudo = d?.pseudo?.takeIf { it.isNotEmpty() }

    // Which backend produced the open text, and which one a comparison would
    // run. `pseudoMode` is what actually ran; `decompiler` is only what was
    // asked for, and the two differ whenever Ghidra was selected and could not
    // start.
    val mode = d?.pseudoMode ?: ""
    val ghidra = mode == "Ghidra"
    val primaryLabel = when {
        ghidra -> "Ghidra p-code"
        mode == "IR" -> "ASM→IR→C"
        else -> "ASM→C fallback"
    }
    val primaryTint = when {
        ghidra -> ide.accent
        mode == "IR" -> ide.violet
        else -> ide.dim
    }
    val altIsGhidra = vm.decompiler != "ghidra"
    // A comparison needs two DIFFERENT backends, and the pair collapses in two
    // ways. Without SLEIGH, Ghidra cannot run at all — loadAlternatePseudo()
    // clears pseudoAlt and logs a WARN for that direction, and in the other
    // direction the left pane has ALREADY silently fallen back to the IR
    // lifter, so the "other" backend would repeat it. The same happens when
    // Ghidra is installed but could not handle this one function. In every
    // collapsed case the side you cannot have is Ghidra, so name it Ghidra and
    // never fire a decompile that would return a second copy of the left pane.
    val altUsable = vm.sleighReady && (altIsGhidra || ghidra)
    val altIsIr = altUsable && !altIsGhidra
    val altLabel = if (altIsIr) "ASM→IR→C" else "Ghidra p-code"
    val altTint = if (altIsIr) ide.violet else ide.accent

    // Which side the segmented control is showing at phone widths.
    var showAlt by remember { mutableStateOf(false) }
    // null when the cross-reference sheet is closed; otherwise which direction
    // it is showing. Same state shape as the Assembly panel's strip.
    var xrefIncoming by remember { mutableStateOf<Boolean?>(null) }

    // Each pane keeps its own scroll, except in the segmented layout where only
    // one is composed at a time: sharing the state there is the whole point,
    // because flipping backends then lands you on the same line.
    val vScroll = rememberScrollState()
    val hScroll = rememberScrollState()
    val vScrollAlt = rememberScrollState()
    val hScrollAlt = rememberScrollState()

    // pseudoAlt belongs to whichever function was open when it was fetched and
    // the ViewModel clears it on every selectFunction, so the comparison is
    // recomputed on demand. `pseudoAlt == null` is a key so a new function
    // refetches, while a FAILED fetch — which also leaves it null — does not
    // spin: nothing changed, so the effect does not restart. Nothing is fired
    // at all when the other backend cannot run.
    LaunchedEffect(vm.compareBackends, d?.addr, vm.decompiler, vm.sleighReady, vm.pseudoAlt == null) {
        if (vm.compareBackends && d != null && altUsable &&
            vm.pseudoAlt == null && !vm.pseudoAltBusy
        ) vm.loadAlternatePseudo()
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(start = 12.dp, end = 2.dp, top = 2.dp, bottom = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    d?.let { it.displayName.ifEmpty { it.name } } ?: "—",
                    color = ide.text, fontSize = Type.body,
                    fontWeight = FontWeight.Medium, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                if (d != null) Text(
                    "${hexFmt(d.addr)} · ${d.size} bytes · ${d.from}",
                    color = ide.dim2, fontSize = Type.caption,
                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            // The toggle hangs on the function, not on the output: when the
            // selected backend produced nothing, comparing it against the other
            // one is the whole reason you are here.
            if (d != null) PseudoCompareToggle(vm)
            if (pseudo != null) {
                val clip = LocalClipboardManager.current
                Box(
                    Modifier
                        .size(Touch)
                        .clip(RoundedCornerShape(10.dp))
                        .clickable(role = Role.Button) {
                            clip.setText(AnnotatedString(pseudo))
                            vm.log("OK", "Pseudo-C copied to the clipboard")
                        },
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Filled.ContentCopy, contentDescription = "Copy pseudo-C",
                        tint = ide.dim, modifier = Modifier.size(18.dp)
                    )
                }
            }
        }
        DecompileProgress(vm)
        // Where this text came from, and where the code around it goes. The
        // xref chips lead because navigation beats provenance; the row scrolls
        // sideways because six chips do not fit across 360dp.
        if (d != null) {
            // Counted the same way the Assembly panel counts them: the engine's
            // own xrefs when it returned any, the whole-binary call table when
            // it did not. The two strips must never disagree about one function.
            val nIn = if (d.xrefsIn.isNotEmpty()) d.xrefsIn.size else vm.callersOf(d.addr).size
            val nOut = if (d.xrefsOut.isNotEmpty()) d.xrefsOut.size else vm.calleesOf(d.addr).size
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = 12.dp, vertical = 2.dp),
                horizontalArrangement = Arrangement.spacedBy(6.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                PseudoXrefChip("refs in", nIn, ide.cyan) { xrefIncoming = true }
                PseudoXrefChip("calls out", nOut, ide.accent) { xrefIncoming = false }
                StatChip(primaryLabel, primaryTint)
                val stats = d.irStats
                if (stats != null && mode == "IR") {
                    StatChip("${stats.stmts} IR", ide.cyan)
                    // Violet is what mnemonicColor paints call/bl/blr in the
                    // listing, so the count and the instructions agree.
                    StatChip("${stats.calls} calls", ide.violet)
                    if (stats.whiles > 0) StatChip("${stats.whiles} loops", ide.amber)
                    if (stats.ifs > 0) StatChip("${stats.ifs} if", ide.dim)
                }
                // When the high-fidelity backend was asked for but could not run,
                // say why here rather than silently serving different output.
                if (!ghidra && vm.decompiler == "ghidra" && vm.decompilerNote.isNotEmpty())
                    StatChip(vm.decompilerNote, ide.amber)
            }
            val sheetFor = xrefIncoming
            if (sheetFor != null) PseudoXrefSheet(
                vm, d, incoming = sheetFor, onDismiss = { xrefIncoming = null }
            )
        }
        when {
            vm.meta == null -> Box(
                Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center
            ) {
                EmptyPanel(
                    "No binary open",
                    "Open a file and pick a function; the decompiler runs on one function at a time."
                )
            }
            d == null -> Box(
                Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center
            ) {
                EmptyPanel(
                    "Select a function to decompile",
                    "Pipeline: assembly lifted to an expression IR, propagated, then structured — while/if/calls with args."
                )
            }
            !vm.compareBackends ->
                PseudoBody(pseudo, primaryLabel, Modifier.weight(1f).fillMaxWidth(), vScroll, hScroll)
            else -> BoxWithConstraints(Modifier.weight(1f).fillMaxWidth()) {
                // 360dp of monospace at 12sp is about fifty columns. Halved, a
                // pane holds twenty-five — less than one line of reconstructed
                // C — so on a phone the two backends share the full width and
                // take turns, and only a tablet or landscape gets real columns.
                if (maxWidth >= SplitAt) {
                    Row(Modifier.fillMaxSize()) {
                        Column(Modifier.weight(1f).fillMaxHeight()) {
                            PseudoPaneLabel(primaryLabel, primaryTint)
                            PseudoBody(
                                pseudo, primaryLabel,
                                Modifier.weight(1f).fillMaxWidth(), vScroll, hScroll
                            )
                        }
                        Box(Modifier.width(1.dp).fillMaxHeight().background(ide.border))
                        Column(Modifier.weight(1f).fillMaxHeight()) {
                            PseudoPaneLabel(altLabel, altTint)
                            PseudoAltPane(
                                vm, altLabel, altUsable, primaryLabel,
                                Modifier.weight(1f).fillMaxWidth(), vScrollAlt, hScrollAlt
                            )
                        }
                    }
                } else {
                    Column(Modifier.fillMaxSize()) {
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 4.dp)
                                .clip(RoundedCornerShape(8.dp))
                                .background(ide.panel2)
                                .selectableGroup()
                        ) {
                            PseudoSegment(primaryLabel, primaryTint, !showAlt, Modifier.weight(1f)) {
                                showAlt = false
                            }
                            PseudoSegment(altLabel, altTint, showAlt, Modifier.weight(1f)) {
                                showAlt = true
                            }
                        }
                        if (showAlt) PseudoAltPane(
                            vm, altLabel, altUsable, primaryLabel,
                            Modifier.weight(1f).fillMaxWidth(), vScroll, hScroll
                        )
                        else PseudoBody(
                            pseudo, primaryLabel,
                            Modifier.weight(1f).fillMaxWidth(), vScroll, hScroll
                        )
                    }
                }
            }
        }
        // Whole-binary export does not need a selected function, so the bar is
        // available whenever something is loaded.
        if (vm.meta != null) ExportBar(vm)
    }
}

/**
 * The comparison switch. It used to be a radio button inside the overflow
 * menu, where flipping it threw away the text you were reading and started the
 * decompile over; this leaves the selected backend alone and fetches the other
 * one's output beside it.
 */
@Composable
private fun PseudoCompareToggle(vm: StudioViewModel) {
    val ide = LocalIde.current
    val on = vm.compareBackends
    Row(
        Modifier
            .clip(RoundedCornerShape(8.dp))
            .toggleable(
                value = on,
                role = Role.Switch,
                onValueChange = { vm.compareBackends = it }
            )
            .sizeIn(minHeight = Touch)
            .padding(horizontal = 8.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.CompareArrows, contentDescription = null,
            tint = if (on) ide.accent else ide.dim,
            modifier = Modifier.size(17.dp)
        )
        Spacer(Modifier.width(5.dp))
        Text(
            "Compare",
            color = if (on) ide.accent else ide.dim,
            fontSize = Type.label,
            fontWeight = if (on) FontWeight.SemiBold else FontWeight.Normal
        )
    }
}

/**
 * A count you can open. Same wording and same chip as the Assembly panel's
 * strip; the difference here is a real tap target under it, because this row
 * is chips on their own rather than chips inside a 60dp header block.
 */
@Composable
private fun PseudoXrefChip(label: String, count: Int, tint: Color, onClick: () -> Unit) {
    val ide = LocalIde.current
    val base = Modifier
        .sizeIn(minHeight = Touch)
        .clip(RoundedCornerShape(6.dp))
    Box(
        if (count > 0) base.clickable(role = Role.Button, onClick = onClick) else base,
        contentAlignment = Alignment.Center
    ) {
        StatChip(label, count.toString(), if (count > 0) tint else ide.dim2)
    }
}

/** One half of a two-segment switcher. Selection is a role, not just a colour. */
@Composable
private fun PseudoSegment(
    label: String,
    tint: Color,
    selected: Boolean,
    modifier: Modifier,
    onClick: () -> Unit
) {
    val ide = LocalIde.current
    Box(
        modifier
            .background(if (selected) tint.copy(alpha = 0.14f) else Color.Transparent)
            .selectable(selected = selected, role = Role.Tab, onClick = onClick)
            .sizeIn(minHeight = Touch)
            .padding(horizontal = 8.dp),
        contentAlignment = Alignment.Center
    ) {
        Text(
            label,
            color = if (selected) tint else ide.dim2,
            fontSize = Type.label, fontFamily = Mono,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
    }
}

/** The column header in the side-by-side layout, where there is no switcher. */
@Composable
private fun PseudoPaneLabel(label: String, tint: Color) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel2)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            label, color = tint, fontSize = Type.label,
            fontFamily = Mono, fontWeight = FontWeight.Bold,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
    }
}

/**
 * One pane of pseudo-C. [src] is nullable because a backend returning nothing
 * is a normal outcome and the pane has to say so — that is precisely the case
 * you opened the comparison to investigate.
 */
@Composable
private fun PseudoBody(
    src: String?,
    label: String,
    modifier: Modifier,
    v: ScrollState,
    h: ScrollState
) {
    val ide = LocalIde.current
    // A backend that answers with an empty string has produced nothing just as
    // surely as one that answers with null.
    val body = src?.takeIf { it.isNotEmpty() }
    if (body == null) {
        Box(modifier, contentAlignment = Alignment.Center) {
            EmptyPanel(
                "$label produced no output for this function",
                "Nothing came back from the backend. The Assembly tab still has the listing."
            )
        }
    } else {
        val annotated = remember(body, ide) { highlightPseudo(body, ide) }
        // weight() is a ColumnScope modifier, so it belongs on the container
        // here rather than on the Text inside SelectionContainer's lambda.
        SelectionContainer(modifier) {
            Text(
                annotated,
                fontFamily = Mono, fontSize = Type.mono, lineHeight = 17.sp,
                modifier = Modifier
                    .fillMaxSize()
                    .verticalScroll(v)
                    .horizontalScroll(h)
                    .padding(12.dp)
            )
        }
    }
}

/**
 * The comparison pane. Every state it can be in is named: cannot run, running,
 * came back with nothing, or here it is. An empty pane would be the one thing
 * that reads as a bug.
 */
@Composable
private fun PseudoAltPane(
    vm: StudioViewModel,
    altLabel: String,
    usable: Boolean,
    primaryLabel: String,
    modifier: Modifier,
    v: ScrollState,
    h: ScrollState
) {
    val ide = LocalIde.current
    val alt = vm.pseudoAlt
    Box(modifier, contentAlignment = Alignment.Center) {
        when {
            !usable -> if (!vm.sleighReady) EmptyPanel(
                "Ghidra p-code cannot run on this device",
                "The SLEIGH specifications are not installed, so the built-in IR lifter is the only backend available and both sides would show the same text."
            ) else EmptyPanel(
                "Only $primaryLabel ran for this function",
                if (vm.decompilerNote.isNotEmpty()) "${vm.decompilerNote}. The other backend is the one already on the left."
                else "The other backend is the one already on the left, so there is nothing to compare against."
            )
            vm.pseudoAltBusy -> Column(
                Modifier.fillMaxWidth().padding(horizontal = 32.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                Text(
                    "Decompiling with $altLabel…",
                    color = ide.dim, fontSize = Type.body, fontFamily = Mono
                )
                Spacer(Modifier.height(10.dp))
                LinearProgressIndicator(
                    color = ide.accent,
                    trackColor = ide.borderStrong,
                    modifier = Modifier
                        .fillMaxWidth()
                        .height(4.dp)
                        .clip(RoundedCornerShape(2.dp))
                )
            }
            alt == null -> Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                EmptyPanel(
                    "$altLabel has not run on this function",
                    "The comparison is fetched per function and dropped whenever you move to another one."
                )
                Row(
                    Modifier
                        .sizeIn(minHeight = Touch)
                        .clip(RoundedCornerShape(8.dp))
                        .clickable(role = Role.Button) { vm.loadAlternatePseudo() }
                        .padding(horizontal = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.CompareArrows, contentDescription = null,
                        tint = ide.accent, modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(6.dp))
                    Text("Run $altLabel", color = ide.accent, fontSize = Type.label)
                }
            }
            else -> PseudoBody(alt, altLabel, Modifier.fillMaxSize(), v, h)
        }
    }
}

/**
 * Who calls this function and what it calls. The engine has returned both on
 * every decompile since the beginning and nothing has ever drawn them; the only
 * way to ask was to leave for the call graph and pay for a second native pass
 * over the whole binary. Rows go through navigateTo, so Back comes home.
 *
 * Deliberately the same sheet as the Assembly panel's — same title, same row,
 * same rule about which rows can be tapped — because it answers the same
 * question about the same function.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PseudoXrefSheet(
    vm: StudioViewModel,
    d: FunctionDetail,
    incoming: Boolean,
    onDismiss: () -> Unit
) {
    val ide = LocalIde.current
    val rows = remember(d.addr, incoming, vm.renames.size) { pseudoXrefRows(vm, d, incoming) }
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.padding(bottom = 16.dp)) {
            Column(Modifier.padding(horizontal = 20.dp, vertical = 4.dp)) {
                Text(
                    if (incoming) "References to this function" else "Calls out of this function",
                    color = ide.text, fontSize = Type.title, fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(3.dp))
                Text(
                    "${rows.size} · ${vm.effectiveFuncName(d.addr)} @ ${hexFmt(d.addr)}",
                    color = ide.dim2, fontSize = Type.label, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.height(8.dp))
            if (rows.isEmpty()) {
                EmptyPanel(
                    if (incoming) "Nothing references this function" else "This function calls nothing",
                    "The engine found no edges in either its own analysis or the whole-binary call table."
                )
            } else LazyColumn(Modifier.heightIn(max = 420.dp)) {
                items(rows.size) { i ->
                    val r = rows[i]
                    val target = r.target
                    val base = Modifier
                        .fillMaxWidth()
                        .heightIn(min = Touch)
                    Row(
                        // A row with nothing to jump to — an import stub, an
                        // address outside every known function — is drawn as a
                        // leaf instead of rippling under your finger and then
                        // doing nothing.
                        (if (target != null) base.clickable(role = Role.Button) {
                            onDismiss()
                            vm.navigateTo(addr = target)
                        } else base).padding(horizontal = 20.dp, vertical = 8.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            hexFmt(r.site), color = ide.dim2, fontSize = Type.monoSmall,
                            fontFamily = Mono, maxLines = 1
                        )
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                r.label,
                                color = if (target != null) ide.text else ide.dim,
                                fontSize = Type.label, fontFamily = Mono,
                                maxLines = 1, overflow = TextOverflow.Ellipsis
                            )
                            if (r.note.isNotEmpty()) Text(
                                r.note, color = ide.dim2, fontSize = Type.caption,
                                maxLines = 1, overflow = TextOverflow.Ellipsis
                            )
                        }
                        Spacer(Modifier.width(8.dp))
                        StatChip(r.type, mnemonicColor(r.type, ide))
                    }
                    HorizontalDivider(color = ide.border)
                }
            }
        }
    }
}

private data class ExportKind(
    val id: String,
    val icon: ImageVector,
    val title: String,
    val detail: String
)

/**
 * Export the decompiled output to a file the user picks — the equivalent of
 * IDA's File > Produce file. The engine writes the listing itself; this only
 * chooses the shape and the destination.
 */
@Composable
private fun ExportBar(vm: StudioViewModel) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            // The bar is the last child of a fillMaxSize Column, so under the
            // forced edge-to-edge of targetSdk 35 it sat directly beneath the
            // gesture pill, which ate the taps. The panel fill still runs to
            // the bottom of the screen; only the touchable row is inset.
            .windowInsetsPadding(WindowInsets.navigationBars)
            .clickable(enabled = !vm.exportBusy, role = Role.Button) { showExportSheet = true }
            .sizeIn(minHeight = Touch)
            .padding(horizontal = 12.dp, vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.FileDownload, contentDescription = null,
            tint = if (vm.exportBusy) ide.dim else ide.accent,
            modifier = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(10.dp))
        Text(
            if (vm.exportBusy) "Exporting…" else "Export as source",
            color = if (vm.exportBusy) ide.dim else ide.text,
            fontSize = Type.body, fontWeight = FontWeight.Medium
        )
    }
}

/**
 * Export picker. Hoisted out of the Pseudo-C tab so the command palette and
 * the overflow menu can raise it too — buried at the bottom of one tab, nobody
 * found it.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportSheet(vm: StudioViewModel, onPick: (String) -> Unit, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    // The file-picker launcher deliberately lives in StudioApp, not here: this
    // sheet is composed conditionally, so dismissing it used to unregister the
    // launcher before launch() ran. SAF still created the document the user
    // picked, nothing ever wrote to it, and the export landed as 0 bytes.
    val kinds = listOf(
        ExportKind("c-all", Icons.Filled.Code, "Whole binary",
            "${vm.meta?.functions?.size ?: 0} functions decompiled to pseudo-C"),
        ExportKind("c-one", Icons.Filled.Description, "This function",
            vm.detail?.name?.ifEmpty { "the selected function" } ?: "no function selected"),
        ExportKind("h-all", Icons.Filled.Subject, "Header stub",
            "signatures only, no bodies"),
        ExportKind("asm-all", Icons.Filled.DataObject, "Assembly listing",
            "disassembly with auto-comments")
    )
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.padding(bottom = 22.dp)) {
            Column(Modifier.padding(horizontal = 20.dp, vertical = 4.dp)) {
                Text("Export decompiled output", color = ide.text,
                    fontSize = Type.title, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(3.dp))
                Text(
                    "Reconstructed from machine code — it will not recompile as-is.",
                    color = ide.dim2, fontSize = Type.label
                )
            }
            Spacer(Modifier.height(10.dp))
            kinds.forEach { k ->
                val enabled = k.id != "c-one" || vm.detail != null
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(enabled = enabled, role = Role.Button) { onPick(k.id) }
                        .sizeIn(minHeight = Touch)
                        .padding(horizontal = 20.dp, vertical = 12.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        k.icon, contentDescription = null,
                        tint = if (enabled) ide.accent else ide.dim,
                        modifier = Modifier.size(19.dp)
                    )
                    Spacer(Modifier.width(14.dp))
                    Column(Modifier.weight(1f)) {
                        Text(
                            k.title,
                            color = if (enabled) ide.text else ide.dim,
                            fontSize = Type.body, fontWeight = FontWeight.Medium
                        )
                        Text(k.detail, color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
                    }
                }
                // border, not border at half alpha: the divider measured 1.12:1
                // against the sheet, which is a line nobody can see.
                HorizontalDivider(color = ide.border)
            }
        }
    }
}


// A progress row shown while the engine is decompiling — IDA-style, so a
// long Ghidra pass looks like work in flight rather than a hang. Only what we
// actually know: the phase, the target and the elapsed time; a plain
// indeterminate bar for the rest, because the native call is one atomic step
// from Kotlin's side.
@Composable
private fun DecompileProgress(vm: StudioViewModel) {
    val ide = LocalIde.current
    val phase = vm.decompilePhase
    val target = vm.decompileTargetName
    val startMs = vm.decompileStartMs
    if (phase.isBlank() || startMs == 0L) return

    // Repaint once a second so the elapsed number actually moves. Cancelled
    // when the composable leaves, which is what makes it stop when the
    // decompile lands.
    var elapsed by remember(startMs) { mutableStateOf(0L) }
    LaunchedEffect(startMs) {
        while (isActive) {
            elapsed = System.currentTimeMillis() - startMs
            delay(200)
        }
    }

    Column(
        Modifier
            .fillMaxWidth()
            .background(ide.panel2)
            .padding(horizontal = 12.dp, vertical = 8.dp)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                phase, color = ide.text, fontSize = Type.mono,
                fontFamily = Mono, fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1f)
            )
            val secs = elapsed / 1000
            val ms = (elapsed % 1000) / 100
            Text(
                "%d.%ds".format(secs, ms),
                color = ide.amber, fontSize = Type.mono, fontFamily = Mono
            )
        }
        if (target.isNotEmpty())
            Text(
                target, color = ide.dim2, fontSize = Type.caption,
                fontFamily = Mono, maxLines = 1,
                modifier = Modifier.padding(top = 2.dp)
            )
        Spacer(Modifier.height(6.dp))
        LinearProgressIndicator(
            color = ide.accent,
            // border is 1.29:1 on this surface, so the unfilled half of the bar
            // was invisible and the bar read as a lone sliver on nothing.
            trackColor = ide.borderStrong,
            modifier = Modifier
                .fillMaxWidth()
                .height(4.dp)
                .clip(RoundedCornerShape(2.dp))
        )
    }
}

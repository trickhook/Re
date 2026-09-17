package com.trickhook.ui

import androidx.compose.animation.Crossfade
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.foundation.LocalIndication
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
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
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.CheckCircleOutline
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.DesktopWindows
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Hub
import androidx.compose.material.icons.filled.Stop
import androidx.compose.material.icons.filled.Subject
import androidx.compose.material.icons.filled.Terminal
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.trickhook.update.humanBytes
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.exportScopeNoun
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive

private val KEYWORDS = setOf(
    "void", "if", "goto", "return", "unsigned", "int", "long", "while", "else"
)

/** Material's minimum tap target, and WCAG 2.2 SC 2.5.8's with room to spare. */
private val Touch = 48.dp

/** Side by side stops helping once a column is narrower than a line of C. */
private val SplitAt = 700.dp

/** The one control radius in this panel; surfaces bring their own from Common. */
private val Control = RoundedCornerShape(8.dp)

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
 * Why a backend comparison has nothing to show, or null when it has. Computed
 * once, beside the rule that decides whether to fetch at all, so the pane can
 * never name a different reason from the one that stopped the fetch.
 */
private data class AltBlocked(val title: String, val sub: String)

@Composable
fun DecompilePanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val d = vm.detail
    // Nullable rather than a separate `hasPseudo` flag, so every use below is
    // guarded by a plain null check the compiler can smart-cast through.
    val pseudo = d?.pseudo?.takeIf { it.isNotEmpty() }
    // The primary decompile is in flight. `detail` still holds the PREVIOUS
    // function until the native call lands, so this is the only way to tell
    // "here is your code" from "here is the code of the function you left".
    val busy = vm.detailBusy

    // Which backend produced the open text, and which one a comparison would
    // run. `pseudoMode` is what actually ran; `decompiler` is only what was
    // asked for, and the two differ whenever Ghidra was selected and could not
    // start.
    val mode = d?.pseudoMode ?: ""
    val ghidra = mode == "Ghidra"
    // A DEX method reaches neither decompiler: Engine::functionDetail answers
    // the whole DEX branch with a fixed method stub and never looks at the
    // backend selection, so there is exactly one possible output for it.
    val dalvik = mode == "dex"
    val primaryLabel = when {
        ghidra -> "Ghidra p-code"
        mode == "IR" -> "ASM→IR→C"
        dalvik -> "Dalvik stub"
        else -> "ASM→C fallback"
    }
    val primaryTint = when {
        ghidra -> ide.accent
        mode == "IR" -> ide.violet
        else -> ide.dim
    }
    val altIsGhidra = vm.decompiler != "ghidra"
    // A comparison needs two DIFFERENT backends. Now that SLEIGH actually
    // installs, two real backends is the ordinary case, so the ways the pair
    // collapses are named one at a time instead of being lumped under "Ghidra
    // is not here":
    //
    //  - DEX: one backend exists at all, whichever one is selected.
    //  - no SLEIGH: whichever direction you face, the side you cannot have is
    //    Ghidra — either it would be the comparison, or it was asked for, fell
    //    back, and the left pane is already the IR lifter.
    //  - Ghidra selected but fell back on THIS function: the other backend is
    //    the IR lifter, which is exactly what the left pane is showing.
    //
    // A collapsed pair must never fire a decompile, because the answer would be
    // a second copy of the left pane with the other backend's name over it.
    //
    // Only the last of those turns on what happened to THIS function, and what
    // happened is `pseudoMode`, which belongs to the function still on screen —
    // so it is held back while a decompile is in flight. Switching the backend
    // from the palette re-decompiles the open function, and during those
    // seconds the outgoing mode would otherwise have the pane state,
    // confidently, that the pair collapsed for a result that has not landed.
    // (The DEX branch turns on the FORMAT, which cannot go stale: `detail` is
    // cleared when a different binary is opened.)
    val blocked: AltBlocked? = when {
        d == null -> null
        dalvik -> AltBlocked(
            "DEX methods have only one backend",
            "Dalvik bytecode never reaches the native decompilers — the engine answers with the same method stub whichever backend is selected, so both sides would be identical."
        )
        !vm.sleighReady -> AltBlocked(
            "Ghidra p-code cannot run on this device",
            "The SLEIGH specifications are not installed, so the built-in IR lifter is the only backend available and both sides would show the same text."
        )
        !altIsGhidra && !ghidra && !busy -> AltBlocked(
            "Only $primaryLabel ran for this function",
            if (vm.decompilerNote.isNotEmpty())
                "${vm.decompilerNote}. The other backend is the one already on the left."
            else "Ghidra was selected and fell back here, so the other backend is the one already on the left."
        )
        else -> null
    }
    val altUsable = d != null && blocked == null
    val altIsIr = altUsable && !altIsGhidra
    val altLabel = when {
        altIsIr -> "ASM→IR→C"
        dalvik -> "No second backend"
        else -> "Ghidra p-code"
    }
    val altTint = when {
        altIsIr -> ide.violet
        dalvik -> ide.dim
        else -> ide.accent
    }

    // Which side the segmented control is showing at phone widths.
    var showAlt by remember { mutableStateOf(false) }
    // null when the cross-reference sheet is closed; otherwise which direction
    // it is showing. Same state shape as the Assembly panel's strip.
    var xrefIncoming by remember { mutableStateOf<Boolean?>(null) }
    // Whether the comparison has already been attempted for this function with
    // this selection. `pseudoAlt` is null both before a fetch and after a failed
    // one, and now that Ghidra can really start, "it ran and returned nothing"
    // is a state a user reaches rather than a theoretical branch.
    var altTried by remember(d?.addr, vm.decompiler) { mutableStateOf(false) }

    // Each pane keeps its own scroll, except in the segmented layout where only
    // one is composed at a time: sharing the state there is the whole point,
    // because flipping backends then lands you on the same line.
    val vScroll = rememberScrollState()
    val hScroll = rememberScrollState()
    val vScrollAlt = rememberScrollState()
    val hScrollAlt = rememberScrollState()

    val runAlt = {
        altTried = true
        vm.loadAlternatePseudo()
    }

    // pseudoAlt belongs to whichever function was open when it was fetched and
    // the ViewModel clears it on every selectFunction, so the comparison is
    // recomputed on demand. `pseudoAlt == null` is a key so a new function
    // refetches, while a FAILED fetch — which also leaves it null — does not
    // spin: nothing changed, so the effect does not restart.
    //
    // `detailBusy` is both a key and a guard because selectFunction clears
    // pseudoAlt BEFORE it replaces `detail`: without it this fires a comparison
    // for the function you just left, and loadAlternatePseudo flips the engine's
    // single global backend for the duration of its call — underneath the
    // primary decompile that is running at that moment. That was harmless while
    // Ghidra could never start and the fetch was always refused; it is a
    // seconds-long native pass on the wrong backend now that it can.
    LaunchedEffect(
        vm.compareBackends, d?.addr, vm.decompiler, vm.sleighReady,
        altUsable, busy, vm.pseudoAlt == null
    ) {
        if (vm.compareBackends && altUsable && !busy &&
            vm.pseudoAlt == null && !vm.pseudoAltBusy
        ) runAlt()
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(start = Space.l, end = Space.xs, top = Space.xs, bottom = Space.xs),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    d?.let { it.displayName.ifEmpty { it.name } } ?: "—",
                    color = ide.text, fontSize = Type.body, lineHeight = Type.bodyLine,
                    fontWeight = FontWeight.Medium, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                if (d != null) Text(
                    "${hexFmt(d.addr)} · ${d.size} bytes · ${d.from}",
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            // The toggle hangs on the function, not on the output: when the
            // selected backend produced nothing, comparing it against the other
            // one is the whole reason you are here.
            if (d != null) PseudoCompareToggle(vm)
            if (pseudo != null) {
                val clip = LocalClipboardManager.current
                val press = remember { MutableInteractionSource() }
                val pressed by press.collectIsPressedAsState()
                Box(
                    Modifier
                        .size(Touch)
                        .pressScale(pressed)
                        .clip(Control)
                        .clickable(
                            interactionSource = press,
                            indication = LocalIndication.current,
                            role = Role.Button
                        ) {
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
        // The indeterminate bar is the status strip's own progress affordance
        // and the skeleton is the body's; both at once is two answers to one
        // question, so the bar stands down whenever the body below is a
        // skeleton for the same work. The phase and the clock never go away —
        // they are what prove the engine is alive.
        DecompileProgress(vm, bar = !busy)
        // Where this text came from, and where the code around it goes. The
        // xref chips lead because navigation beats provenance; the row scrolls
        // sideways because six chips do not fit across 360dp.
        if (d != null) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .animateContentSize(tween(motionMs()))
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = Space.l, vertical = Space.xs),
                horizontalArrangement = Arrangement.spacedBy(Space.m),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // One counting rule for the whole app, and it lives in the
                // ViewModel. This strip and the Assembly strip each used to
                // carry their own and read different numbers for one function.
                val floors = vm.xrefsAreFloors
                PseudoXrefChip("refs in", vm.xrefInCount(d), ide.cyan, floors) { xrefIncoming = true }
                PseudoXrefChip("calls out", vm.xrefOutCount(d), ide.accent, floors) { xrefIncoming = false }
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
            // Row builder, row and sheet all live in Common.kt now: this was a
            // verbatim copy of the Assembly panel's, and the two had already
            // drifted in touch target, row width and sheet inset.
            if (sheetFor != null) XrefSheet(
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
            // Not while a decompile is in flight: opening a binary selects its
            // first function for you, and telling you to select one while one is
            // being decompiled is the panel contradicting its own status line.
            d == null && !busy -> Box(
                Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center
            ) {
                EmptyPanel(
                    "Select a function to decompile",
                    "Pipeline: assembly lifted to an expression IR, propagated, then structured — while/if/calls with args."
                )
            }
            else -> BoxWithConstraints(Modifier.weight(1f).fillMaxWidth()) {
                val compare = vm.compareBackends && d != null
                // 360dp of monospace at 12sp is about fifty columns. Halved, a
                // pane holds twenty-five — less than one line of reconstructed
                // C — so on a phone the two backends share the full width and
                // take turns, and only a tablet or landscape gets real columns.
                if (maxWidth >= SplitAt) {
                    // The split grows in from zero width instead of the body
                    // snapping in two. animateContentSize animates a size
                    // CHANGE, so the column that carries the comparison is
                    // always composed and simply holds nothing while the
                    // comparison is off — same trick for the label that appears
                    // over the left pane.
                    val altWidth = (maxWidth - 1.dp) / 2
                    Row(Modifier.fillMaxSize()) {
                        Column(Modifier.weight(1f).fillMaxHeight()) {
                            Box(
                                Modifier
                                    .fillMaxWidth()
                                    .animateContentSize(tween(motionMs()))
                            ) {
                                if (compare) PseudoPaneLabel(primaryLabel, primaryTint)
                            }
                            PseudoBody(
                                pseudo, primaryLabel, busy,
                                Modifier.weight(1f).fillMaxWidth(), vScroll, hScroll
                            )
                        }
                        Row(
                            Modifier
                                .fillMaxHeight()
                                .animateContentSize(tween(motionMs()))
                        ) {
                            if (compare) {
                                Box(Modifier.width(1.dp).fillMaxHeight().background(ide.border))
                                Column(Modifier.width(altWidth).fillMaxHeight()) {
                                    PseudoPaneLabel(altLabel, altTint)
                                    PseudoAltPane(
                                        vm, altLabel, primaryLabel, pseudo, blocked, altTried,
                                        runAlt, Modifier.weight(1f).fillMaxWidth(),
                                        vScrollAlt, hScrollAlt
                                    )
                                }
                            }
                        }
                    }
                } else if (compare) {
                    Column(Modifier.fillMaxSize()) {
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .padding(horizontal = Space.l, vertical = Space.s)
                                .surface2(Control)
                                .selectableGroup()
                        ) {
                            PseudoSegment(primaryLabel, primaryTint, !showAlt, Modifier.weight(1f)) {
                                showAlt = false
                            }
                            PseudoSegment(altLabel, altTint, showAlt, Modifier.weight(1f)) {
                                showAlt = true
                            }
                        }
                        // One pane at a time in the same place, sharing one
                        // scroll position: the two texts are meant to be read as
                        // an A/B flip, and a hard cut makes you re-find the line
                        // you were on. A fade this short is legible rather than
                        // slow — and motionMs() turns it back into a cut for
                        // anyone who has switched animation off system-wide.
                        Crossfade(
                            targetState = showAlt,
                            animationSpec = tween(motionMs(Motion.fast)),
                            label = "backend",
                            modifier = Modifier.weight(1f).fillMaxWidth()
                        ) { alt ->
                            if (alt) PseudoAltPane(
                                vm, altLabel, primaryLabel, pseudo, blocked, altTried,
                                runAlt, Modifier.fillMaxSize(), vScroll, hScroll
                            ) else PseudoBody(
                                pseudo, primaryLabel, busy, Modifier.fillMaxSize(), vScroll, hScroll
                            )
                        }
                    }
                } else PseudoBody(
                    pseudo, primaryLabel, busy, Modifier.fillMaxSize(), vScroll, hScroll
                )
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
    val press = remember { MutableInteractionSource() }
    val pressed by press.collectIsPressedAsState()
    Row(
        Modifier
            .pressScale(pressed)
            .clip(Control)
            .toggleable(
                value = on,
                interactionSource = press,
                indication = LocalIndication.current,
                role = Role.Switch,
                onValueChange = { vm.compareBackends = it }
            )
            .sizeIn(minHeight = Touch)
            .padding(horizontal = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.CompareArrows, contentDescription = null,
            tint = if (on) ide.accent else ide.dim,
            modifier = Modifier.size(16.dp)
        )
        Spacer(Modifier.width(Space.s))
        Text(
            "Compare",
            color = if (on) ide.accent else ide.dim,
            fontSize = Type.label, lineHeight = Type.labelLine,
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
private fun PseudoXrefChip(
    label: String,
    count: Int,
    tint: Color,
    floored: Boolean,
    onClick: () -> Unit
) {
    val ide = LocalIde.current
    val base = Modifier
        .sizeIn(minHeight = Touch)
        .clip(RoundedCornerShape(6.dp))
    Box(
        if (count > 0) base.clickable(role = Role.Button, onClick = onClick) else base,
        contentAlignment = Alignment.Center
    ) {
        // floorCount, not toString: above the engine's reference cap this
        // number is a floor, and the sheet it opens says by how much.
        StatChip(label, floorCount(count, floored), if (count > 0) tint else ide.dim2)
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
            .padding(horizontal = Space.m),
        contentAlignment = Alignment.Center
    ) {
        Text(
            label,
            color = if (selected) tint else ide.dim2,
            fontSize = Type.label, lineHeight = Type.labelLine, fontFamily = Mono,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
    }
}

/** The column header in the side-by-side layout, where there is no switcher. */
@Composable
private fun PseudoPaneLabel(label: String, tint: Color) {
    Row(
        Modifier
            .fillMaxWidth()
            .surface2(RectangleShape)
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            label, color = tint, fontSize = Type.label, lineHeight = Type.labelLine,
            fontFamily = Mono, fontWeight = FontWeight.Bold,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
    }
}

/**
 * One pane of pseudo-C. [src] is nullable because a backend returning nothing
 * is a normal outcome and the pane has to say so — that is precisely the case
 * you opened the comparison to investigate. [loading] outranks both: the text
 * still on screen belongs to the function you just left.
 */
@Composable
private fun PseudoBody(
    src: String?,
    label: String,
    loading: Boolean,
    modifier: Modifier,
    v: ScrollState,
    h: ScrollState
) {
    val ide = LocalIde.current
    // A backend that answers with an empty string has produced nothing just as
    // surely as one that answers with null.
    val body = src?.takeIf { it.isNotEmpty() }
    when {
        // Shaped like the C that is coming — ragged line lengths, indented
        // bodies, a short closing brace — so seconds of Ghidra read as "your
        // code is on its way" instead of "something is happening somewhere".
        loading -> Box(modifier, contentAlignment = Alignment.TopStart) {
            SkeletonLines(lines = 14, indent = true)
        }
        body == null -> Box(modifier, contentAlignment = Alignment.Center) {
            EmptyPanel(
                "$label produced no output for this function",
                "Nothing came back from the backend. The Assembly tab still has the listing."
            )
        }
        else -> {
            val annotated = remember(body, ide) { highlightPseudo(body, ide) }
            // weight() is a ColumnScope modifier, so it belongs on the container
            // here rather than on the Text inside SelectionContainer's lambda.
            SelectionContainer(modifier) {
                Text(
                    annotated,
                    fontFamily = Mono, fontSize = Type.mono, lineHeight = Type.monoLine,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(v)
                        .horizontalScroll(h)
                        .padding(Space.l)
                )
            }
        }
    }
}

/**
 * The comparison pane. Every state it can be in is named: cannot run, queued,
 * running, came back with nothing, came back with the SAME text, or here it is.
 * An empty pane would be the one thing that reads as a bug.
 */
@Composable
private fun PseudoAltPane(
    vm: StudioViewModel,
    altLabel: String,
    primaryLabel: String,
    primary: String?,
    blocked: AltBlocked?,
    tried: Boolean,
    onRun: () -> Unit,
    modifier: Modifier,
    v: ScrollState,
    h: ScrollState
) {
    val ide = LocalIde.current
    val alt = vm.pseudoAlt
    Box(modifier, contentAlignment = Alignment.Center) {
        when {
            blocked != null -> EmptyPanel(blocked.title, blocked.sub)
            // Queued is a real state now: the comparison waits for the primary
            // decompile rather than flipping the engine's backend underneath it.
            vm.pseudoAltBusy || vm.detailBusy -> Column(Modifier.fillMaxWidth()) {
                Text(
                    if (vm.pseudoAltBusy) "Decompiling with $altLabel…"
                    else "Queued behind $primaryLabel…",
                    color = ide.dim, fontSize = Type.body, lineHeight = Type.bodyLine,
                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.padding(horizontal = Space.l, vertical = Space.m)
                )
                SkeletonLines(lines = 10, indent = true)
            }
            alt == null -> Column(
                Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Two different facts, and with Ghidra able to start they are
                // both reachable: it has not been asked yet, or it was asked and
                // came back empty. The console line carries the reason.
                if (tried) EmptyPanel(
                    "$altLabel returned nothing for this function",
                    "It ran and produced no text; the console says why. Running it again is safe."
                ) else EmptyPanel(
                    "$altLabel has not run on this function",
                    "The comparison is fetched per function and dropped whenever you move to another one."
                )
                val press = remember { MutableInteractionSource() }
                val pressed by press.collectIsPressedAsState()
                Row(
                    Modifier
                        .sizeIn(minHeight = Touch)
                        .pressScale(pressed)
                        .clip(Control)
                        .clickable(
                            interactionSource = press,
                            indication = LocalIndication.current,
                            role = Role.Button,
                            onClick = onRun
                        )
                        .padding(horizontal = Space.l),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.CompareArrows, contentDescription = null,
                        tint = ide.accent, modifier = Modifier.size(16.dp)
                    )
                    Spacer(Modifier.width(Space.s))
                    Text(
                        "Run $altLabel", color = ide.accent,
                        fontSize = Type.label, lineHeight = Type.labelLine
                    )
                }
            }
            // The degenerate pair the engine can produce all on its own: Ghidra
            // falls back to the IR lifter INSIDE the same native call when no
            // SLEIGH specification covers a function, so a comparison can come
            // back ok and byte-identical to the pane beside it. Saying so beats
            // two identical panes — on a phone they take turns in one place, so
            // identical output reads as a switch that does nothing.
            alt == primary -> EmptyPanel(
                "Both backends returned the same text",
                "$altLabel came back byte-for-byte identical to $primaryLabel. Ghidra falls back to the built-in IR lifter when no specification covers a function, which is the usual reason for this."
            )
            else -> PseudoBody(alt, altLabel, false, Modifier.fillMaxSize(), v, h)
        }
    }
}

private data class ExportKind(
    val id: String,
    val icon: ImageVector,
    val title: String,
    val detail: String,
    /** Rows are drawn in list order and a new group prints its own heading. */
    val group: String
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
            .surface1(RectangleShape)
            // The bar is the last child of a fillMaxSize Column, so under the
            // forced edge-to-edge of targetSdk 35 it sat directly beneath the
            // gesture pill, which ate the taps. The panel fill still runs to
            // the bottom of the screen; only the touchable row is inset.
            .windowInsetsPadding(WindowInsets.navigationBars)
            .animateContentSize(tween(motionMs()))
            // While a run is up this reopens the progress panel rather than
            // going dead. A minutes-long export that can only be watched from
            // the screen it was started on is a run you cannot cancel from
            // anywhere else, which is worse than no cancel at all.
            .clickable(role = Role.Button) {
                if (vm.exportBusy) showExportProgress = true else showExportSheet = true
            }
            .sizeIn(minHeight = Touch)
            .padding(horizontal = Space.l, vertical = Space.l),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.FileDownload, contentDescription = null,
            tint = ide.accent,
            modifier = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(Space.m))
        val p = vm.exportProgress
        Text(
            when {
                !vm.exportBusy -> "Export as source"
                p != null && p.total > 0 -> "Exporting ${p.done} of ${p.total} — tap to watch or stop"
                else -> "Exporting… tap to watch or stop"
            },
            color = ide.text,
            fontSize = Type.body, lineHeight = Type.bodyLine, fontWeight = FontWeight.Medium,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
    }
}

private const val SRC_GROUP = "Decompiled output"
private const val IDA_GROUP = "Take it to IDA Pro"
private const val FRIDA_GROUP = "Hook it with Frida"

/**
 * The heading over one group of export kinds. Two groups sit in this sheet and
 * they are not the same kind of thing: one is a listing to read, the other is a
 * script that changes somebody's database, and the caveat that belongs to each
 * belongs beside it rather than in one line at the top covering both.
 */
@Composable
private fun ExportGroupLabel(group: String) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(start = Space.xl, top = Space.m, end = Space.xl, bottom = Space.s)
    ) {
        Text(
            group.uppercase(), color = ide.dim,
            fontSize = Type.caption, lineHeight = Type.captionLine,
            fontWeight = FontWeight.Medium, letterSpacing = Type.upperTracking
        )
        Text(
            when (group) {
                SRC_GROUP -> "reconstructed from machine code — it will not recompile as-is"
                IDA_GROUP -> "runs in your own IDA and applies what you named here"
                else -> "a Frida script to trace, dump and (optionally) patch on a live device"
            },
            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
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

    // What the user has actually authored, which is all the IDA scripts carry:
    // with none of it there is nothing to send, so those two rows go grey.
    val authored = vm.renames.size + vm.comments.size + vm.bookmarks.size
    val authoredLine =
        if (authored == 0) "nothing named or commented yet"
        else "${vm.renames.size} names · ${vm.comments.size} comments · ${vm.bookmarks.size} bookmarks"
    // The engine decompiles every non-import function it DISCOVERED, not the
    // page of them this app happens to be holding, so the row says what the
    // run will really cost. It read `functions.size` before, which on a large
    // library promised 12,000 and delivered 98,022.
    val m = vm.meta
    val exportFns = maxOf(m?.functionsTotal ?: 0, m?.functions?.size ?: 0)
    // Exported symbols are what the "hook the exports" Frida script targets.
    val exportCount = m?.exports?.size ?: 0
    val kinds = listOf(
        ExportKind("c-all", Icons.Filled.Code, "Whole binary",
            "$exportFns functions decompiled to pseudo-C" +
                (if (exportFns > 2000) " · minutes, and it blocks the engine" else ""),
            SRC_GROUP),
        ExportKind("c-one", Icons.Filled.Description, "This function",
            vm.detail?.name?.ifEmpty { "the selected function" } ?: "no function selected", SRC_GROUP),
        ExportKind("h-all", Icons.Filled.Subject, "Header stub",
            "signatures only, no bodies", SRC_GROUP),
        ExportKind("asm-all", Icons.Filled.DataObject, "Assembly listing",
            "disassembly with auto-comments", SRC_GROUP),
        ExportKind("ida-py", Icons.Filled.Terminal, "IDAPython script",
            authoredLine, IDA_GROUP),
        ExportKind("ida-idc", Icons.Filled.DesktopWindows, "IDC script",
            if (authored == 0) authoredLine else "the same, for any IDA back to 7.0", IDA_GROUP),
        ExportKind("frida-one", Icons.Filled.BugReport, "Hook this function",
            vm.detail?.name?.ifBlank { "the selected function" } ?: "no function selected",
            FRIDA_GROUP),
        ExportKind("frida-exports", Icons.Filled.Hub, "Hook the exports",
            if (exportCount == 0) "no exported symbols"
            else "$exportCount exported symbol" + (if (exportCount == 1) "" else "s") +
                (if (exportCount > com.trickhook.model.FRIDA_EXPORTS_CAP)
                    " · capped at ${com.trickhook.model.FRIDA_EXPORTS_CAP}" else ""),
            FRIDA_GROUP)
    )
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        // No NavBarSpacer in here: material3 1.3.1 gives ModalBottomSheet
        // BottomSheetDefaults.windowInsets, which already carries the bottom
        // system-bar inset, so a spacer inside the content pads it twice. The
        // gap below is optical breathing room, not an inset — same decision as
        // the shared XrefSheet in Common.kt.
        Column(Modifier.padding(bottom = Space.xl)) {
            Column(Modifier.padding(horizontal = Space.xl, vertical = Space.s)) {
                Text(
                    "Export", color = ide.text,
                    fontSize = Type.title, lineHeight = Type.titleLine,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(Space.xs))
                Text(
                    "A listing to read, or your own work as a script for IDA Pro.",
                    color = ide.dim2, fontSize = Type.label, lineHeight = Type.labelLine
                )
                // Said once, here, rather than discovered when the app appears
                // to hang: a whole-binary run holds the engine mutex for its
                // whole length, and nothing else native answers until it ends.
                // Progress and stop are the two exceptions, and they are what
                // the panel this opens is made of.
                Spacer(Modifier.height(Space.xs))
                TruncationNote(
                    if (vm.exportBusy)
                        "An export is already running. Tap the export bar or use the command " +
                            "palette to watch it or stop it."
                    else
                        "A whole-binary listing runs for minutes and holds the engine for all of " +
                            "it. You can watch it and stop it; a stopped run leaves a finished file."
                )
            }
            Spacer(Modifier.height(Space.m))
            kinds.forEachIndexed { i, k ->
                if (i == 0 || kinds[i - 1].group != k.group) ExportGroupLabel(k.group)
                // Nothing starts while a run is up. `exportSource` refuses a
                // second one anyway, but the refusal happens AFTER the system
                // file picker has already created an empty document — so the
                // gate belongs here, where the picker has not been opened yet.
                val enabled = !vm.exportBusy && when (k.id) {
                    "c-one", "frida-one" -> vm.detail != null
                    "ida-py", "ida-idc" -> authored > 0
                    "frida-exports" -> exportCount > 0
                    else -> true
                }
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(enabled = enabled, role = Role.Button) { onPick(k.id) }
                        .sizeIn(minHeight = Touch)
                        .padding(horizontal = Space.xl, vertical = Space.l),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        k.icon, contentDescription = null,
                        tint = if (enabled) ide.accent else ide.dim,
                        modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(Space.l))
                    Column(Modifier.weight(1f)) {
                        Text(
                            k.title,
                            color = if (enabled) ide.text else ide.dim,
                            fontSize = Type.body, lineHeight = Type.bodyLine,
                            fontWeight = FontWeight.Medium
                        )
                        Text(
                            k.detail, color = ide.dim2, fontSize = Type.caption,
                            lineHeight = Type.captionLine, fontFamily = Mono
                        )
                    }
                }
                // border, not border at half alpha: the divider measured 1.12:1
                // against the sheet, which is a line nobody can see.
                HorizontalDivider(color = ide.border)
            }
        }
    }
}


// A progress row shown while the engine is decompiling — IDA-style, so a long
// Ghidra pass looks like work in flight rather than a hang. Only what we
// actually know: the phase, the target and the elapsed time. [bar] is the
// indeterminate strip, which the caller turns off when the body below is
// already carrying a skeleton for the same work.
@Composable
private fun DecompileProgress(vm: StudioViewModel, bar: Boolean) {
    val ide = LocalIde.current
    val phase = vm.decompilePhase
    val target = vm.decompileTargetName
    val startMs = vm.decompileStartMs
    if (phase.isBlank() || startMs == 0L) return

    // Repaint five times a second so the elapsed number actually moves.
    // Cancelled when the composable leaves, which is what makes it stop when
    // the decompile lands.
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
            .surface2(RectangleShape)
            .animateContentSize(tween(motionMs()))
            .padding(horizontal = Space.l, vertical = Space.m)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                phase, color = ide.text, fontSize = Type.mono, lineHeight = Type.monoLine,
                fontFamily = Mono, fontWeight = FontWeight.Medium,
                modifier = Modifier.weight(1f)
            )
            val secs = elapsed / 1000
            val ms = (elapsed % 1000) / 100
            Text(
                "%d.%ds".format(secs, ms),
                color = ide.amber, fontSize = Type.mono, lineHeight = Type.monoLine,
                fontFamily = Mono
            )
        }
        if (target.isNotEmpty())
            Text(
                target, color = ide.dim2, fontSize = Type.caption,
                lineHeight = Type.captionLine, fontFamily = Mono, maxLines = 1,
                modifier = Modifier.padding(top = Space.xs)
            )
        if (bar) {
            Spacer(Modifier.height(Space.s))
            LinearProgressIndicator(
                color = ide.accent,
                // border is 1.29:1 on this surface, so the unfilled half of the
                // bar was invisible and the bar read as a lone sliver on nothing.
                trackColor = ide.borderStrong,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp))
            )
        }
    }
}

/**
 * What a "produce file" run is doing, while it does it.
 *
 * This panel exists because the export is unlike every other call in the app:
 * it holds the engine mutex for its whole run, which is minutes on a large
 * binary, and while it does, nothing else native can answer. Without a number
 * moving on screen that is indistinguishable from a hang — so the two calls
 * that ARE lock-free, progress and stop, are what this is built out of.
 *
 * Three things it is careful about:
 *
 *  - Failures are not an error state. A function the decompiler refuses gets
 *    its banner and a marker in the file where a reader will see it, and the
 *    run carries on. 64 of 5,363 is a run that succeeded, and the wording says
 *    so rather than painting it red.
 *  - A stopped run is not lost work. Cancellation is checked between functions
 *    and leaves a valid file whose trailer says where it stops.
 *  - Dismissing this does not stop anything. The export bar and the header
 *    phase line keep reporting, and a tap on the bar brings it back.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ExportProgressSheet(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val p = vm.exportProgress
    val result = vm.exportResult
    val running = vm.exportBusy
    val kind = vm.exportKindRunning
    val startMs = vm.exportStartMs

    // The clock is the one thing that keeps moving when `total` is still 0 —
    // the engine counts its targets before it reports any of them, and a panel
    // with nothing changing on it reads as frozen.
    var elapsed by remember(startMs) { mutableStateOf(0L) }
    LaunchedEffect(startMs, running) {
        while (isActive && running && startMs > 0L) {
            elapsed = System.currentTimeMillis() - startMs
            delay(200)
        }
    }

    val done = p?.done ?: 0
    val total = p?.total ?: 0
    val failed = p?.failed ?: 0
    // Two sources, deliberately. `exportStopping` is this app's own intent and
    // lands the instant Stop is pressed; `cancelling` is the engine saying it
    // has the flag. Either one means the run is on its way down, and waiting
    // only for the second would leave the button looking unpressed.
    val stopping = vm.exportStopping || (p?.cancelling == true)
    val fraction = if (total > 0) (done.toFloat() / total.toFloat()).coerceIn(0f, 1f) else 0f

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.padding(start = Space.xl, top = Space.s, end = Space.xl, bottom = Space.xl)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    when {
                        running && stopping -> "Stopping"
                        running -> "Producing " + exportScopeNoun(kind)
                        result != null && result.cancelled -> "Export stopped"
                        result != null && result.ok -> "Export finished"
                        result != null -> "Export failed"
                        else -> "Export finished"
                    },
                    color = ide.text, fontSize = Type.title, lineHeight = Type.titleLine,
                    fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f)
                )
                if (running && startMs > 0L) {
                    Text(
                        "%d:%02d".format(elapsed / 60000, (elapsed / 1000) % 60),
                        color = ide.amber, fontSize = Type.mono, lineHeight = Type.monoLine,
                        fontFamily = Mono
                    )
                }
            }
            Spacer(Modifier.height(Space.m))

            // The bar goes indeterminate only for the first moment, while the
            // engine is still counting what it is about to write. After that it
            // is a real fraction of a real total.
            if (running) {
                if (total > 0) {
                    LinearProgressIndicator(
                        progress = { fraction },
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .clip(RoundedCornerShape(2.dp)),
                        color = ide.accent,
                        trackColor = ide.borderStrong
                    )
                } else {
                    LinearProgressIndicator(
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(4.dp)
                            .clip(RoundedCornerShape(2.dp)),
                        color = ide.accent,
                        trackColor = ide.borderStrong
                    )
                }
                Spacer(Modifier.height(Space.m))
                Text(
                    if (total > 0) "$done of $total functions" else "Counting what to write…",
                    color = ide.text, fontSize = Type.body, lineHeight = Type.bodyLine,
                    fontFamily = Mono
                )
                Spacer(Modifier.height(Space.xs))
                Text(
                    when {
                        stopping ->
                            "Finishing the function it is on. What is already written stays written."
                        failed > 0 ->
                            "$failed could not be decompiled — each one is marked in the file and the run carries on."
                        else ->
                            "Every other engine call waits until this finishes."
                    },
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                )
            } else {
                val icon = if (result != null && !result.ok) Icons.Filled.Stop
                else Icons.Filled.CheckCircleOutline
                val tint = when {
                    result == null -> ide.dim
                    !result.ok -> ide.red
                    result.cancelled -> ide.amber
                    else -> ide.entry
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    RowIcon(icon, tint, 16.dp)
                    Text(
                        when {
                            result == null -> "Nothing is running."
                            !result.ok -> result.error ?: "The export failed."
                            result.cancelled ->
                                "${result.functions} of ${result.total} functions written before you stopped it."
                            else -> "${result.functions} functions written."
                        },
                        color = ide.text, fontSize = Type.body, lineHeight = Type.bodyLine,
                        modifier = Modifier.weight(1f)
                    )
                }
                if (result != null && result.ok) {
                    Spacer(Modifier.height(Space.m))
                    // Two separate reassurances, and both are needed. A marked
                    // failure is a normal outcome, and a stopped run produced a
                    // file that is complete as far as it goes — neither is the
                    // user losing their work.
                    Text(
                        buildString {
                            if (result.failed > 0) {
                                append(result.failed)
                                append(
                                    if (result.failed == 1) " function could not be decompiled; it is"
                                    else " functions could not be decompiled; each one is"
                                )
                                append(" marked in the file where you will see it. ")
                            }
                            if (result.cancelled) {
                                append("The file is valid and its trailer says where it stops. ")
                            }
                            if (result.bytes > 0) append(humanBytes(result.bytes))
                            append(" saved to the file you picked.")
                        }.trim(),
                        color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                    )
                }
            }

            Spacer(Modifier.height(Space.l))
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (running) {
                    TextButton(
                        onClick = { vm.stopExport() },
                        enabled = !stopping
                    ) {
                        Text(
                            if (stopping) "Stopping…" else "Stop",
                            color = if (stopping) ide.dim2 else ide.accent,
                            fontSize = Type.label
                        )
                    }
                    Spacer(Modifier.width(Space.m))
                    TextButton(onClick = onDismiss) {
                        Text("Keep it running", color = ide.dim, fontSize = Type.label)
                    }
                } else {
                    TextButton(onClick = onDismiss) {
                        Text("Done", color = ide.accent, fontSize = Type.label)
                    }
                }
            }
        }
    }
}

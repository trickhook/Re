package com.trickhook.ui

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateDpAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.ScrollState
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ChevronLeft
import androidx.compose.material.icons.filled.ChevronRight
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.ExpandMore
import androidx.compose.material.icons.filled.Subject
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import com.trickhook.model.AsmLine
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab

/** The one content gutter these panels share, so the left edge never shifts. */
private val PanelGutter = Space.l

/**
 * Touch target for one listing line. A disassembly row used to be ~17dp of
 * text whose long-press was the only way to rename, comment or bookmark, so
 * the app's core interaction was a coin flip. This is Material's minimum and
 * WCAG 2.5.5's; lowering it to ~28dp buys back about eight lines per screen
 * if density ever has to win.
 */
// 28dp, not the 48dp a discrete control would get. A disassembly listing is
// the one place in this app where density IS the feature — at 48dp a 640dp
// screen holds 13 instructions where it held 37, and reading control flow
// means seeing the block, not one line of it. 28dp still gives the row a real
// target, which 17dp and an empty onClick never did.
private val AsmRowMinHeight = 28.dp

/**
 * A hex row carries no gesture of its own, so it is sized for reading rather
 * than for the thumb: tighter than [AsmRowMinHeight] on purpose.
 */
private val HexRowMinHeight = 22.dp

/**
 * Corner radius of the small tappable pills in these panels. Kept here so the
 * ripple clip of the Box that makes a [StatChip] tappable matches the chip's own
 * background exactly; a radius is a shape, not spacing, so it does not come off
 * the [Space] scale.
 */
private val ChipCorner = 6.dp

/**
 * Advance width of one monospace glyph as a fraction of the font size. Droid
 * Sans Mono and Roboto Mono are both 0.60em; the extra 0.02 is slack, and
 * every column below is `widthIn(min = …)` rather than `width(…)` so an
 * underestimate grows the column instead of clipping the text.
 */
private const val MONO_ADVANCE = 0.62f

/**
 * Width of [chars] monospace glyphs at [size]. Goes through Density, so the
 * columns track the user's font-size setting instead of staying at a dp value
 * that was only ever right at 1.0x — which is what silently cut the tail off
 * every hex row and every long operand.
 */
@Composable
private fun monoWidth(size: TextUnit, chars: Int): Dp =
    with(LocalDensity.current) { (size * MONO_ADVANCE).toDp() } * chars

// ========================================================== Assembly panel ==
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AssemblyPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta
    val d = vm.detail

    // annotation dialog target, and which side of the xref sheet is open
    var annotateAddr by remember { mutableStateOf<Long?>(null) }
    var xrefIncoming by remember { mutableStateOf<Boolean?>(null) }
    // The line the user last touched: the accent bar, and where TRACE starts.
    var selectedLine by remember(d?.addr) { mutableStateOf(-1) }

    // Scroll position survives a tab switch because it lives in the ViewModel.
    val listState = rememberLazyListState(vm.asmIndex, vm.asmOffset)
    // ONE scroll state for every row, so the columns stay in step sideways.
    val hScroll = rememberScrollState()

    // Saved when the panel leaves composition — a tab switch, which is exactly
    // when the position used to be lost. Writing on every scroll frame would
    // invalidate this composable at 60fps, because the initial value is read
    // right here in the body.
    DisposableEffect(listState) {
        onDispose {
            vm.asmIndex = listState.firstVisibleItemIndex
            vm.asmOffset = listState.firstVisibleItemScrollOffset
        }
    }

    // A different function means a different listing: restoring the old index
    // into it would land somewhere arbitrary. Returning to the tab with the
    // same function keeps the place, which is the point of hoisting it.
    //
    // The owner of that saved position is `vm.asmIndexFor`, stamped by
    // selectFunction — NOT a local `remember`. A local one was seeded with the
    // function already on screen, so on a fresh composition it always agreed
    // with itself and the guard never fired: picking a function from the
    // Functions tab and coming back here opened a 40-instruction listing at
    // row 197 with the trace chip reading "201/40". A stamp that outlives this
    // panel is the only thing that can see a move made while it was gone.
    val fnAddr = d?.addr
    val asmCount = d?.asm?.size ?: 0
    LaunchedEffect(fnAddr, vm.asmIndexFor, vm.traceStepFor, asmCount) {
        if (vm.asmIndexFor != fnAddr) {
            // The listing on screen is not the one the saved position was
            // measured in — either a move is in flight, or the one that was
            // asked for never arrived. Either way row 197 means nothing here.
            // Only selectFunction writes the stamp; this reads it, so a jump
            // still being decompiled keeps its identity while it loads.
            vm.asmIndex = 0
            vm.asmOffset = 0
            vm.traceStep = -1
            listState.scrollToItem(0)
        } else if (vm.traceStepFor != fnAddr || vm.traceStep >= asmCount) {
            // Either the step was counted in another function's listing, or it
            // is past the end of this one. The second case is the visible one;
            // the first is the quiet one, because step 5 of a 4,000-instruction
            // body is a legal index into a 40-instruction body and simply
            // points at the wrong line. Neither number means anything here.
            vm.traceStep = -1
        }
    }

    // Someone asked to be taken to an address — the palette, a string row, a
    // bookmark. Wait for the function to finish loading, then land on the line.
    LaunchedEffect(vm.gotoAddr, fnAddr, vm.detailBusy, vm.tab) {
        if (vm.gotoAddr == null) return@LaunchedEffect
        // A goto is addressed to the tab the user is being sent to, and the
        // Hex and Graph panels consume the same field. Only the panel that is
        // actually the destination may answer, or an outgoing panel still on
        // screen for the length of a transition swallows the request — and,
        // now, warns about an address that was never meant for it.
        if (vm.tab != Tab.ASSEMBLY) return@LaunchedEffect
        // The ONE reason to leave a request standing: the function that holds
        // it is still being decompiled, and this effect re-runs when that
        // clears. Every other path below consumes, because a request that
        // survives this panel fires again on whichever panel composes next.
        if (vm.detailBusy) return@LaunchedEffect
        val target = vm.consumeGoto() ?: return@LaunchedEffect
        val asm = d?.asm
        if (asm.isNullOrEmpty()) {
            vm.log("WARN", "Nothing is disassembled here, so ${hexFmt(target)} has no line to land on")
            return@LaunchedEffect
        }
        // Analyzer.cpp:109-116 backfills a function's size with the gap to the
        // next function, while the disassembler stops at the real end of the
        // body — so an address in that gap satisfies functionContaining and
        // still lands past the last instruction here. Name the range rather
        // than scrolling nowhere and leaving the request armed.
        if (target < asm[0].addr || target > asm[asm.size - 1].addr) {
            vm.log(
                "WARN",
                "${hexFmt(target)} is outside this listing " +
                    "(${hexFmt(asm[0].addr)}-${hexFmt(asm[asm.size - 1].addr)})"
            )
            return@LaunchedEffect
        }
        val idx = asm.indexOfLast { it.addr <= target }
        if (idx >= 0) {
            selectedLine = idx
            listState.scrollToItem(idx)
        }
    }

    // Follow the instruction pointer while stepping, but only when it has left
    // the screen — scrolling on every tap would throw the context away.
    LaunchedEffect(vm.traceStep) {
        val s = vm.traceStep
        if (s < 0) return@LaunchedEffect
        val visible = listState.layoutInfo.visibleItemsInfo
        val first = visible.firstOrNull()?.index ?: 0
        val last = visible.lastOrNull()?.index ?: 0
        if (s <= first || s >= last) listState.animateScrollToItem((s - 3).coerceAtLeast(0))
    }

    if (meta == null) {
        EmptyPanel("No binary open", "Open a file to disassemble it.")
        return
    }

    Column(Modifier.fillMaxSize()) {
        // ---- one header band, not three ------------------------------------
        // A panel2 toolbar, a panel TRACE row and an un-backgrounded header
        // card used to stack to ~145dp of chrome in three different greys
        // before the first instruction. They are one band now, and the stepper
        // moved to the bottom of the screen where the thumb is.
        // The band's height changes as the xref chips and the hint come and go,
        // so it grows and shrinks instead of shoving the first instruction down
        // a whole row at once.
        Column(
            Modifier
                .fillMaxWidth()
                .surface2(RectangleShape)
                .animateContentSize(tween(motionMs()))
                .padding(horizontal = PanelGutter, vertical = Space.s)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(30.dp)
                        .background(ide.accent.copy(alpha = 0.14f), RoundedCornerShape(Space.m)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Filled.Subject, contentDescription = null,
                        tint = ide.accent, modifier = Modifier.size(15.dp)
                    )
                }
                Spacer(Modifier.width(Space.m))
                Column(Modifier.weight(1f)) {
                    val title = if (d == null) "Select function…"
                    else vm.renames["0x%08X".format(d.addr)] ?: d.displayName.ifEmpty { d.name }
                    FunctionPicker(vm, title)
                    Text(
                        if (d == null)
                            "${meta.arch.ifEmpty { "-" }} · ${meta.backend.ifEmpty { "-" }} · ${meta.functions.size} functions"
                        else
                            "${hexFmt(d.addr)} · ${d.size} bytes · ${d.from} · ${d.backend}",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                }
                if (d != null) {
                    val clip = LocalClipboardManager.current
                    IconButton(onClick = {
                        val text = d.asm.joinToString("\n") { l ->
                            buildString {
                                append(hexFmt(l.addr)); append("  "); append(l.mnem)
                                if (l.ops.isNotEmpty()) { append(' '); append(l.ops) }
                                if (l.comment.isNotEmpty()) { append("    ; "); append(l.comment) }
                            }
                        }
                        clip.setText(AnnotatedString(text))
                        vm.log("OK", "Listing copied to the clipboard (${d.asm.size} lines)")
                    }) {
                        Icon(
                            Icons.Filled.ContentCopy, contentDescription = "Copy listing",
                            tint = ide.dim, modifier = Modifier.size(17.dp)
                        )
                    }
                }
            }
            if (d != null) {
                // ---- cross-references, the X key -----------------------------
                // One rule for both numbers, and it lives in the ViewModel:
                // the same function used to read "refs in 0" here and "3 in" on
                // the Functions tab because four call sites each had their own.
                val nIn = vm.xrefInCount(d)
                val nOut = vm.xrefOutCount(d)
                Spacer(Modifier.height(Space.s))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(ChipCorner))
                            .clickable(enabled = nIn > 0, role = Role.Button) { xrefIncoming = true }
                    ) { StatChip("refs in", nIn.toString(), ide.cyan) }
                    Spacer(Modifier.width(Space.s))
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(ChipCorner))
                            .clickable(enabled = nOut > 0, role = Role.Button) { xrefIncoming = false }
                    ) { StatChip("calls out", nOut.toString(), ide.accent) }
                    Spacer(Modifier.width(Space.s))
                    // Clamped, because traceStep is an index into a listing that
                    // can be replaced under it: unclamped it printed "201/40".
                    val stepping = vm.traceStep >= 0 && asmCount > 0
                    val stepShown = if (stepping) vm.traceStep.coerceIn(0, asmCount - 1) else 0
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(ChipCorner))
                            .clickable(enabled = asmCount > 0, role = Role.Button) {
                                // Stamped with the listing on screen, not with
                                // wherever selectFunction is currently headed:
                                // a move can be in flight while this is tapped.
                                vm.traceStepFor = fnAddr
                                vm.traceStep = if (stepping) -1 else selectedLine.coerceAtLeast(0)
                            }
                    ) {
                        StatChip(
                            "trace",
                            if (stepping) "${stepShown + 1}/$asmCount" else "start",
                            ide.amber
                        )
                    }
                }
                if (selectedLine < 0) {
                    // Discoverability used to live in the Hint that renders only
                    // when NO function is selected — i.e. never while the
                    // feature was usable. It sits over the listing now, and
                    // retires itself the first time a line is touched.
                    Spacer(Modifier.height(Space.s))
                    Text(
                        "Tap a line to rename, comment or bookmark it",
                        color = ide.dim2, fontSize = Type.caption,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        // The decompiler can spend seconds on a large function, and `detail`
        // still holds the PREVIOUS one while it works. A skeleton shaped like a
        // listing says "this is not your function yet" where a 16dp spinner in
        // the corner said nothing at all. A re-run on the same address (the
        // rename self-refresh) keeps the listing on screen instead of flashing.
        if (vm.detailBusy && (fnAddr == null || vm.asmIndexFor != fnAddr)) {
            // No wrapper: SkeletonLines brings its own ide.panel ground and its
            // own gutter, and boxing it here would float it as a card.
            SkeletonLines(lines = 12, indent = true)
        } else if (d == null) {
            Hint(
                "Select a function to disassemble.",
                "Capstone engine: ${meta.backend.ifEmpty { "-" }} · arch: ${meta.arch.ifEmpty { "-" }}"
            )
        } else if (d.asm.isEmpty()) {
            EmptyPanel(
                "Nothing to disassemble here",
                d.error ?: "The engine returned no instructions for this address."
            )
        } else {
            // Every row scrolls sideways together, and the longest line in the
            // function sets the travel, so the columns cannot drift apart.
            val longest = remember(d.addr, d.asm.size) {
                d.asm.maxOfOrNull { l ->
                    l.mnem.length.coerceAtLeast(8) + 1 + l.ops.length +
                        if (l.comment.isEmpty()) 0 else l.comment.length + 3
                } ?: 0
            }
            val contentW = monoWidth(Type.mono, longest)
            val traceOpen = vm.traceStep >= 0
            LazyColumn(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .background(ide.bg),
                state = listState,
                // The stepper bar carries the navigation-bar inset when it is
                // open, so only one of the two ever pays for it.
                contentPadding =
                    if (traceOpen) PaddingValues(bottom = Space.m) else bottomInset(extra = Space.m)
            ) {
                items(d.asm.size) { i ->
                    val line = d.asm[i]
                    AsmRow(
                        line = line,
                        highlighted = i == vm.traceStep,
                        hScroll = hScroll,
                        selected = i == selectedLine,
                        comment = vm.comments["0x%08X".format(line.addr)],
                        contentMinWidth = contentW,
                        onClick = { selectedLine = i; annotateAddr = line.addr },
                        onLongClick = { selectedLine = i; annotateAddr = line.addr }
                    )
                }
            }
            // The stepper is 52dp plus the navigation inset and it arrives in
            // the middle of a read, so it grows the listing's floor up instead
            // of snapping it. Zero-height when closed, so it costs nothing.
            Column(
                Modifier
                    .fillMaxWidth()
                    .animateContentSize(tween(motionMs()))
            ) {
                if (traceOpen) {
                    val step = vm.traceStep.coerceIn(0, d.asm.size - 1)
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .surface2(RectangleShape)
                            .navigationBarsPadding()
                            .heightIn(min = 52.dp)
                            .padding(horizontal = Space.s),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        IconButton(
                            onClick = { vm.traceStep = (step - 1).coerceAtLeast(0) },
                            enabled = step > 0
                        ) {
                            Icon(
                                Icons.Filled.ChevronLeft, contentDescription = "Previous instruction",
                                tint = if (step > 0) ide.text else ide.dim2, modifier = Modifier.size(26.dp)
                            )
                        }
                        Column(
                            Modifier.weight(1f),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                "IP ${hexFmt(d.asm[step].addr)}",
                                color = ide.amber, fontSize = Type.mono, fontFamily = Mono,
                                maxLines = 1, textAlign = TextAlign.Center
                            )
                            Text(
                                "${step + 1} / ${d.asm.size}",
                                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                                maxLines = 1, textAlign = TextAlign.Center
                            )
                        }
                        IconButton(
                            onClick = { vm.traceStep = (step + 1).coerceAtMost(d.asm.size - 1) },
                            enabled = step < d.asm.size - 1
                        ) {
                            Icon(
                                Icons.Filled.ChevronRight, contentDescription = "Next instruction",
                                tint = if (step < d.asm.size - 1) ide.text else ide.dim2,
                                modifier = Modifier.size(26.dp)
                            )
                        }
                        TextButton(onClick = { vm.traceStep = -1 }) {
                            Text("Reset", color = ide.dim, fontSize = Type.label)
                        }
                    }
                }
            }
        }
    }

    annotateAddr?.let { addr ->
        AnnotateDialog(
            vm = vm,
            addr = addr,
            funcName = d?.let { vm.renames["0x%08X".format(it.addr)] ?: it.displayName.ifEmpty { it.name } } ?: "",
            onDismiss = { annotateAddr = null }
        )
    }

    // The sheet, its row builder and its resolution rules live in Common.kt:
    // this file and DecompilePanel.kt carried verbatim copies that had already
    // drifted apart, so "who calls this" answered differently depending on
    // which tab you asked from.
    val sheetFor = xrefIncoming
    if (sheetFor != null && d != null) {
        XrefSheet(vm, d, incoming = sheetFor, onDismiss = { xrefIncoming = null })
    }
}

@Composable
fun AnnotateDialog(vm: StudioViewModel, addr: Long, funcName: String, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val existing = vm.comments["0x%08X".format(addr)] ?: ""
    var comment by remember { mutableStateOf(existing) }
    var rename by remember { mutableStateOf("") }
    var bookmark by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Annotate @ ${hexFmt(addr)}", color = ide.accent, fontSize = Type.section, fontFamily = Mono) },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                if (funcName.isNotEmpty()) {
                    Text("Function: $funcName", color = ide.dim, fontSize = Type.label, fontFamily = Mono)
                    Spacer(Modifier.height(Space.m))
                    OutlinedTextField(
                        value = rename, onValueChange = { rename = it },
                        label = { Text("Rename function…") }, singleLine = true,
                        textStyle = TextStyle(fontSize = Type.label, fontFamily = Mono, color = ide.text)
                    )
                }
                Spacer(Modifier.height(Space.m))
                OutlinedTextField(
                    value = comment, onValueChange = { comment = it },
                    label = { Text("Comment (empty = delete)") },
                    textStyle = TextStyle(fontSize = Type.label, fontFamily = Mono, color = ide.text)
                )
                if (existing.isNotEmpty()) {
                    TextButton(onClick = { vm.removeComment(ctx, addr); onDismiss() }) {
                        Text("Remove comment", color = ide.dim, fontSize = Type.label)
                    }
                }
                Spacer(Modifier.height(Space.m))
                OutlinedTextField(
                    value = bookmark, onValueChange = { bookmark = it },
                    label = { Text("Bookmark label (optional)") }, singleLine = true,
                    textStyle = TextStyle(fontSize = Type.label, fontFamily = Mono, color = ide.text)
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (rename.isNotBlank()) vm.renameFunction(ctx, addr, rename)
                vm.addComment(ctx, addr, comment)
                if (bookmark.isNotBlank()) vm.addBookmark(ctx, addr, bookmark)
                onDismiss()
            }) { Text("Save", color = ide.accent) }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel", color = ide.dim) } }
    )
}

/**
 * The function name in the header, with a chevron: the picker is the title
 * now rather than a 40dp Material Button sitting in a band of its own.
 */
@Composable
private fun FunctionPicker(vm: StudioViewModel, label: String) {
    val ide = LocalIde.current
    val fns = vm.meta?.functions ?: emptyList()
    var expanded by remember { mutableStateOf(false) }
    Box {
        Row(
            Modifier
                .clip(RoundedCornerShape(ChipCorner))
                .clickable(role = Role.Button) { expanded = true }
                .padding(vertical = Space.xs),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                label, color = ide.text, fontSize = Type.body, fontFamily = Mono,
                fontWeight = FontWeight.Medium, maxLines = 1, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f, fill = false)
            )
            Icon(
                Icons.Filled.ExpandMore, contentDescription = "Choose a function",
                tint = ide.dim, modifier = Modifier.size(16.dp)
            )
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            if (fns.isEmpty()) {
                DropdownMenuItem(text = { Text("No functions", color = ide.dim) }, onClick = {})
            }
            fns.take(500).forEach { f ->
                val display = vm.renames["0x%08X".format(f.addr)] ?: f.name
                DropdownMenuItem(
                    text = {
                        Row {
                            Text(
                                display, color = ide.text, fontSize = Type.label, fontFamily = Mono,
                                modifier = Modifier.width(monoWidth(Type.label, 22)), maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                            Spacer(Modifier.width(Space.m))
                            Text(hexFmt(f.addr), color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                        }
                    },
                    onClick = {
                        expanded = false
                        // A jump the user chose, so it belongs on the back stack.
                        vm.navigateTo(addr = f.addr)
                    }
                )
            }
        }
    }
}

/**
 * One line of disassembly.
 *
 * The address stays pinned on the left — it is the datum you scan for — and
 * mnemonic/operands/comment ride a horizontal scroll shared by every row, so
 * a long ARM shifted-register form or an x86 memory operand can be read to
 * the end instead of being cut mid-token. It used to clip with
 * TextOverflow.Clip and no scroll at all, which meant `ldr x8, [x0, #0x1a8]`
 * and `ldr x8, [x0, #0x1a` rendered identically: not a cosmetic bug in a
 * disassembler but a wrong answer. The trailing comment was also unweighted,
 * so Row measured it first and a long Capstone note squeezed the operands to
 * about ten characters; inside the scroll both are at intrinsic width and
 * neither can starve the other.
 */
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AsmRow(
    line: AsmLine,
    highlighted: Boolean,
    hScroll: ScrollState,
    selected: Boolean = false,
    comment: String? = null,
    contentMinWidth: Dp = 0.dp,
    onClick: (() -> Unit)? = null,
    onLongClick: (() -> Unit)? = null
) {
    val ide = LocalIde.current
    val marker = ide.accent
    val addrW = monoWidth(Type.mono, 9)
    val mnemW = monoWidth(Type.mono, 8)
    // The accent bar grows out of the gutter instead of blinking into it. This
    // is the ONLY animation on a listing row: the rows themselves are never
    // animated per item, because nothing here ever changes position and a
    // placement animation on the densest screen in the app costs frames for
    // nothing. Read in drawBehind, so it invalidates drawing and not layout.
    val barWidth by animateDpAsState(
        targetValue = if (highlighted || selected) 3.dp else 0.dp,
        animationSpec = tween(motionMs(Motion.fast)),
        label = "asmAccentBar"
    )
    Column(
        Modifier
            .fillMaxWidth()
            .background(
                when {
                    highlighted -> marker.copy(alpha = 0.09f)
                    selected -> ide.panel2
                    else -> Color.Transparent
                }
            )
            .drawBehind {
                val w = barWidth.toPx()
                if (w <= 0f) return@drawBehind
                drawRect(
                    if (highlighted) marker else marker.copy(alpha = 0.5f),
                    size = Size(w, size.height)
                )
            }
            .then(
                if (onClick != null)
                    Modifier.combinedClickable(
                        role = Role.Button,
                        onClickLabel = "Annotate this line",
                        onClick = onClick,
                        onLongClick = onLongClick
                    )
                else Modifier
            )
            .heightIn(min = AsmRowMinHeight)
            .padding(start = PanelGutter, end = PanelGutter, top = Space.s, bottom = Space.s),
        verticalArrangement = Arrangement.Center
    ) {
        Row(Modifier.fillMaxWidth()) {
            Text(
                hexFmt(line.addr), color = ide.dim2, fontSize = Type.mono, fontFamily = Mono,
                maxLines = 1, modifier = Modifier.widthIn(min = addrW)
            )
            Row(
                Modifier
                    .weight(1f)
                    .horizontalScroll(hScroll)
            ) {
                Row(Modifier.widthIn(min = contentMinWidth)) {
                    Text(
                        line.mnem, color = mnemonicColor(line.mnem, ide), fontSize = Type.mono,
                        fontFamily = Mono, fontWeight = FontWeight.Medium, maxLines = 1,
                        overflow = TextOverflow.Ellipsis, modifier = Modifier.widthIn(min = mnemW)
                    )
                    Text(
                        line.ops, color = ide.text, fontSize = Type.mono, fontFamily = Mono,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                    if (line.comment.isNotEmpty()) {
                        Spacer(Modifier.width(Space.m))
                        Text(
                            "; ${line.comment}", color = ide.dim2, fontSize = Type.monoSmall,
                            fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
        if (comment != null) {
            Text(
                "; $comment", color = ide.accent, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 2, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = addrW)
            )
        }
    }
}
// ================================================================ Hex panel ==
/**
 * The raw bytes, one line per address.
 *
 * It used to print a single-line column header — OFFSET, 00…0F, ASCII — above
 * rows that were two stacked Texts, the ASCII line preceded by ten hardcoded
 * spaces. The header described a layout that did not exist. Worse, 16 bytes at
 * a fixed dp width is 58 monospace characters, about 365dp of glyphs inside
 * the ~340dp a 360dp phone has to give, with maxLines = 1 and no scroll: the
 * trailing bytes were dropped at the default font scale with nothing on screen
 * saying so. Bytes-per-row is measured now, and one shared ScrollState carries
 * the header and every row sideways together when even that is not enough.
 */
@Composable
fun HexPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val data = vm.hexData
    // Whether an address can be translated to a file offset at all. ELF and PE
    // carry a section table; DEX does not, and there its addresses already ARE
    // file offsets. Read once, used by the Go field and by the highlight.
    val hasSections = vm.meta?.sections?.isNotEmpty() == true
    val listState = rememberLazyListState(vm.hexIndex)
    val hScroll = rememberScrollState()
    var jump by remember { mutableStateOf("") }
    // An offset the toolbar asked for; the body owns bytes-per-row, so it does
    // the arithmetic and this only carries the request across.
    var pendingOffset by remember { mutableStateOf<Long?>(null) }

    DisposableEffect(listState) {
        onDispose { vm.hexIndex = listState.firstVisibleItemIndex }
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .surface2(RectangleShape)
                .padding(horizontal = PanelGutter, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = jump,
                onValueChange = { jump = it },
                label = { Text("Offset (hex)") },
                singleLine = true,
                modifier = Modifier.width(monoWidth(Type.label, 20)),
                textStyle = TextStyle(fontSize = Type.label, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.width(Space.m))
            Button(onClick = {
                val v = jump.removePrefix("0x").removePrefix("0X").toLongOrNull(16) ?: return@Button
                // Typing a virtual address into an offset field is the common
                // slip, and the section table can tell the difference — when
                // there is one. With no table (DEX) the value is taken as the
                // offset it already is rather than discarded.
                val size = data?.size ?: 0
                pendingOffset = when {
                    v < size -> v
                    hasSections -> vm.fileOffsetOf(v) ?: v
                    else -> v
                }
            }) { Text("Go") }
            Spacer(Modifier.weight(1f))
            Text(
                "${data?.size ?: 0} / ${vm.meta?.sizeBytes ?: 0} bytes",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        if (data == null) {
            EmptyPanel("No binary open", "Open a file to inspect its raw bytes.")
        } else {
            BoxWithConstraints(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
            ) {
                // One glyph at the current font scale, not a dp guess. A full
                // row is offset(8) + gap(2) + hex(3n-1) + gap(2) + ascii(n) =
                // 11 + 4n characters, so 32 bytes only ever fit a wide tablet.
                //
                // Requiring all of 12 + 4n for 16 bytes wanted 471dp of glyphs,
                // which no phone has: the canonical hex row was unreachable on
                // the form factor this app is actually used on, and every phone
                // fell to 8 bytes a line. The bar for 16 is now the offset plus
                // the hex column — 12 + 2n, about 273dp — and the ASCII tail
                // rides the horizontal scroll this panel already shares between
                // the header and every row.
                val chW = monoWidth(Type.monoSmall, 1)
                val avail = maxWidth - PanelGutter * 2
                val perRow = when {
                    avail >= chW * (12 + 4 * 32) -> 32
                    avail >= chW * (12 + 2 * 16) -> 16
                    else -> 8
                }
                val rows = (data.size + perRow - 1) / perRow
                // Where the selected function's bytes are ON DISK.
                //
                // With a section table the address is virtual and has to be
                // translated. Without one there is nothing to translate: DEX
                // emits no sections at all (Engine.cpp:602-617) and its
                // FunctionDetail.addr IS a file offset (the method's codeOff,
                // Engine.cpp:760-775). Translating unconditionally therefore
                // returned null for every DEX function — that is, for every
                // APK, the app's headline workflow — and the highlight simply
                // never appeared. Translate when there is a table, trust the
                // address when there is not.
                val det = vm.detail
                val selStart = det?.let { if (hasSections) vm.fileOffsetOf(it.addr) else it.addr } ?: -1L
                val selEnd = if (selStart >= 0L) selStart + (det?.size ?: 0L) else -1L

                // Two ways to move this list, and both speak in FILE OFFSETS:
                // the toolbar's Go field, and vm.hexGotoOffset from another
                // panel. Only this panel knows how many bytes a row holds on
                // this screen, so only this panel may do the division — which
                // is why the old channel, a row index computed elsewhere as
                // offset/16, landed on the wrong byte at every perRow but 16.
                LaunchedEffect(pendingOffset, vm.hexGotoOffset, perRow) {
                    val off = pendingOffset ?: vm.consumeHexGoto() ?: return@LaunchedEffect
                    pendingOffset = null
                    listState.scrollToItem(hexRowOf(off, perRow, rows))
                }
                // A goto from another panel arrives as a virtual address, so it
                // gets the same treatment as the highlight above.
                LaunchedEffect(vm.gotoAddr, perRow, rows, vm.tab) {
                    // Same rule as the listing: answer only when this is the
                    // tab the request was aimed at.
                    if (vm.tab != Tab.HEX) return@LaunchedEffect
                    val target = vm.consumeGoto() ?: return@LaunchedEffect
                    val off = if (hasSections) (vm.fileOffsetOf(target) ?: target) else target
                    listState.scrollToItem(hexRowOf(off, perRow, rows))
                }

                Column(Modifier.fillMaxSize()) {
                    // The header is built from the same perRow as the rows, so
                    // it can never describe a layout the rows do not have.
                    val byteLabels = remember(perRow) {
                        (0 until perRow).joinToString(" ") { String.format("%02X", it) }
                    }
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .surface1(RectangleShape)
                            .padding(horizontal = PanelGutter, vertical = Space.xs)
                    ) {
                        Row(Modifier.horizontalScroll(hScroll)) {
                            Text(
                                "OFFSET", color = ide.dim, fontSize = Type.monoSmall, fontFamily = Mono,
                                maxLines = 1, modifier = Modifier.widthIn(min = chW * 8)
                            )
                            Spacer(Modifier.width(chW * 2))
                            Text(
                                byteLabels, color = ide.dim, fontSize = Type.monoSmall, fontFamily = Mono,
                                maxLines = 1, modifier = Modifier.widthIn(min = chW * (perRow * 3 - 1))
                            )
                            Spacer(Modifier.width(chW * 2))
                            Text(
                                "ASCII", color = ide.dim, fontSize = Type.monoSmall, fontFamily = Mono,
                                maxLines = 1, modifier = Modifier.widthIn(min = chW * perRow)
                            )
                        }
                    }
                    LazyColumn(
                        Modifier
                            .weight(1f)
                            .fillMaxWidth()
                            .background(ide.bg),
                        state = listState,
                        contentPadding = bottomInset(extra = Space.m)
                    ) {
                        items(rows) { r ->
                            HexRow(data, r * perRow, perRow, selStart, selEnd, hScroll, chW)
                        }
                    }
                }
            }
        }
    }
}

/** Which row holds [off], clamped to the list. */
private fun hexRowOf(off: Long, perRow: Int, rows: Int): Int =
    (off / perRow).coerceIn(0L, (rows - 1).coerceAtLeast(0).toLong()).toInt()

@Composable
private fun HexRow(
    data: ByteArray,
    base: Int,
    perRow: Int,
    selStart: Long,
    selEnd: Long,
    hScroll: ScrollState,
    chW: Dp
) {
    val ide = LocalIde.current
    val count = minOf(perRow, data.size - base)
    val hex = StringBuilder()
    val ascii = StringBuilder()
    for (i in 0 until perRow) {
        if (i > 0) hex.append(' ')
        if (i < count) {
            val b = data[base + i]
            hex.append(String.format("%02X", b))
            ascii.append(if (b in 0x20..0x7E) b.toInt().toChar() else '.')
        } else {
            // Padded, not shortened: every row measures the same, so the
            // columns of the last row still line up with the header.
            hex.append("  ")
            ascii.append(' ')
        }
    }
    val inSel = selStart >= 0L && base.toLong() + count > selStart && base.toLong() < selEnd
    Row(
        Modifier
            .fillMaxWidth()
            .background(if (inSel) ide.accent.copy(alpha = 0.07f) else Color.Transparent)
            .heightIn(min = HexRowMinHeight)
            .padding(horizontal = PanelGutter),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Row(
            Modifier.horizontalScroll(hScroll),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                String.format("%08X", base), color = ide.dim2, fontSize = Type.monoSmall,
                fontFamily = Mono, maxLines = 1, modifier = Modifier.widthIn(min = chW * 8)
            )
            Spacer(Modifier.width(chW * 2))
            Text(
                hex.toString(), color = ide.text, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, modifier = Modifier.widthIn(min = chW * (perRow * 3 - 1))
            )
            Spacer(Modifier.width(chW * 2))
            Text(
                ascii.toString(), color = ide.dim, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, modifier = Modifier.widthIn(min = chW * perRow)
            )
        }
    }
}

package com.trickhook.ui

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
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
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
import com.trickhook.model.FunctionDetail
import com.trickhook.vm.StudioViewModel

/** The one content gutter these panels share, so the left edge never shifts. */
private val PanelGutter = 12.dp

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
    val fnAddr = d?.addr
    var restoredFor by remember { mutableStateOf(fnAddr) }
    LaunchedEffect(fnAddr) {
        if (fnAddr != restoredFor) {
            restoredFor = fnAddr
            vm.traceStep = -1
            listState.scrollToItem(0)
        }
    }

    // Someone asked to be taken to an address — the palette, a string row, a
    // bookmark. Wait for the function to finish loading, then land on the line.
    LaunchedEffect(vm.gotoAddr, fnAddr, vm.detailBusy) {
        val target = vm.gotoAddr ?: return@LaunchedEffect
        if (vm.detailBusy) return@LaunchedEffect
        val asm = d?.asm
        if (asm.isNullOrEmpty()) return@LaunchedEffect
        if (target < asm[0].addr || target > asm[asm.size - 1].addr) return@LaunchedEffect
        val idx = asm.indexOfLast { it.addr <= target }
        vm.consumeGoto()
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
        Column(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = PanelGutter, vertical = 6.dp)
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Box(
                    Modifier
                        .size(30.dp)
                        .background(ide.accent.copy(alpha = 0.14f), RoundedCornerShape(9.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        Icons.Filled.Subject, contentDescription = null,
                        tint = ide.accent, modifier = Modifier.size(15.dp)
                    )
                }
                Spacer(Modifier.width(10.dp))
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
                if (vm.detailBusy) {
                    Spacer(Modifier.width(8.dp))
                    CircularProgressIndicator(color = ide.accent, modifier = Modifier.size(16.dp))
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
                // xrefsIn/xrefsOut come back on every function the engine
                // decompiles; meta.callEdges covers the callers when the
                // engine found none. Both were parsed and thrown away.
                val nIn = if (d.xrefsIn.isNotEmpty()) d.xrefsIn.size else vm.callersOf(d.addr).size
                val nOut = if (d.xrefsOut.isNotEmpty()) d.xrefsOut.size else vm.calleesOf(d.addr).size
                Spacer(Modifier.height(5.dp))
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .clickable(enabled = nIn > 0, role = Role.Button) { xrefIncoming = true }
                    ) { StatChip("refs in", nIn.toString(), ide.cyan) }
                    Spacer(Modifier.width(6.dp))
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .clickable(enabled = nOut > 0, role = Role.Button) { xrefIncoming = false }
                    ) { StatChip("calls out", nOut.toString(), ide.accent) }
                    Spacer(Modifier.width(6.dp))
                    val stepping = vm.traceStep >= 0
                    Box(
                        Modifier
                            .clip(RoundedCornerShape(6.dp))
                            .clickable(enabled = d.asm.isNotEmpty(), role = Role.Button) {
                                vm.traceStep = if (stepping) -1 else selectedLine.coerceAtLeast(0)
                            }
                    ) {
                        StatChip(
                            "trace",
                            if (stepping) "${vm.traceStep + 1}/${d.asm.size}" else "start",
                            ide.amber
                        )
                    }
                }
                if (selectedLine < 0) {
                    // Discoverability used to live in the Hint that renders only
                    // when NO function is selected — i.e. never while the
                    // feature was usable. It sits over the listing now, and
                    // retires itself the first time a line is touched.
                    Spacer(Modifier.height(4.dp))
                    Text(
                        "Tap a line to rename, comment or bookmark it",
                        color = ide.dim2, fontSize = Type.caption,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                }
            }
        }

        if (d == null) {
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
                contentPadding = if (traceOpen) PaddingValues(bottom = 8.dp) else bottomInset(extra = 8.dp)
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
            if (traceOpen) {
                val step = vm.traceStep.coerceIn(0, d.asm.size - 1)
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(ide.panel2)
                        .navigationBarsPadding()
                        .heightIn(min = 52.dp)
                        .padding(horizontal = 4.dp),
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

    annotateAddr?.let { addr ->
        AnnotateDialog(
            vm = vm,
            addr = addr,
            funcName = d?.let { vm.renames["0x%08X".format(it.addr)] ?: it.displayName.ifEmpty { it.name } } ?: "",
            onDismiss = { annotateAddr = null }
        )
    }

    val sheetFor = xrefIncoming
    if (sheetFor != null && d != null) {
        AsmXrefSheet(vm, d, incoming = sheetFor, onDismiss = { xrefIncoming = null })
    }
}

/** One row of the cross-reference sheet. `target` null means it cannot resolve. */
private data class AsmXrefRow(
    val site: Long,
    val target: Long?,
    val label: String,
    val type: String,
    val note: String
)

/**
 * The answer to "who calls this" and "what does this call", from data the
 * engine already returned. Rows that resolve to a real function navigate to
 * it — through navigateTo, so Back undoes the jump. Import stubs resolve to
 * nothing decompilable, so they are listed and not clickable rather than
 * offering a tap that ends in "No function at that address".
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun AsmXrefSheet(
    vm: StudioViewModel,
    d: FunctionDetail,
    incoming: Boolean,
    onDismiss: () -> Unit
) {
    val ide = LocalIde.current
    val rows = remember(d.addr, incoming, vm.renames.size) {
        if (incoming) {
            val xs = d.xrefsIn
            if (xs.isNotEmpty()) xs.map { x ->
                val owner = vm.functionContaining(x.from)
                AsmXrefRow(
                    site = x.from,
                    target = owner?.takeIf { it.from != "import" }?.addr,
                    label = owner?.let { vm.effectiveFuncName(it.addr) } ?: "unmapped",
                    type = x.type.ifEmpty { "ref" },
                    note = if (owner == null) "outside any known function" else ""
                )
            } else vm.callersOf(d.addr).map { e ->
                val owner = vm.functionAt(e.from) ?: vm.functionContaining(e.from)
                AsmXrefRow(
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
                AsmXrefRow(
                    site = x.from,
                    target = if (callee != null && !isImport) callee.addr else null,
                    label = callee?.let { vm.effectiveFuncName(it.addr) } ?: hexFmt(x.to),
                    type = x.type.ifEmpty { "call" },
                    note = if (isImport) "import" else if (callee == null) "unresolved target" else ""
                )
            } else vm.calleesOf(d.addr).map { e ->
                val callee = vm.functionAt(e.to) ?: vm.functionContaining(e.to)
                val isImport = callee?.from == "import"
                AsmXrefRow(
                    site = e.from,
                    target = if (callee != null && !isImport) callee.addr else null,
                    label = callee?.let { vm.effectiveFuncName(it.addr) } ?: e.toName.ifEmpty { hexFmt(e.to) },
                    type = e.kind.ifEmpty { "call" },
                    note = if (isImport) "import" else if (callee == null) "unresolved target" else ""
                )
            }
        }
    }
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
            } else {
                LazyColumn(Modifier.heightIn(max = 420.dp)) {
                    items(rows.size) { i ->
                        val r = rows[i]
                        val target = r.target
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .then(
                                    if (target != null)
                                        Modifier.clickable(role = Role.Button) {
                                            onDismiss()
                                            vm.navigateTo(addr = target)
                                        }
                                    else Modifier
                                )
                                .heightIn(min = 48.dp)
                                .padding(horizontal = 20.dp, vertical = 8.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                hexFmt(r.site), color = ide.dim2, fontSize = Type.monoSmall,
                                fontFamily = Mono, maxLines = 1,
                                modifier = Modifier.widthIn(min = monoWidth(Type.monoSmall, 9))
                            )
                            Spacer(Modifier.width(10.dp))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    r.label,
                                    color = if (target != null) ide.text else ide.dim,
                                    fontSize = Type.label, fontFamily = Mono,
                                    maxLines = 1, overflow = TextOverflow.Ellipsis
                                )
                                if (r.note.isNotEmpty()) {
                                    Text(
                                        r.note, color = ide.dim2, fontSize = Type.caption,
                                        maxLines = 1, overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            Spacer(Modifier.width(8.dp))
                            StatChip(r.type, mnemonicColor(r.type, ide))
                        }
                        HorizontalDivider(color = ide.border)
                    }
                }
            }
            NavBarSpacer()
        }
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
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = rename, onValueChange = { rename = it },
                        label = { Text("Rename function…") }, singleLine = true,
                        textStyle = TextStyle(fontSize = Type.label, fontFamily = Mono, color = ide.text)
                    )
                }
                Spacer(Modifier.height(6.dp))
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
                Spacer(Modifier.height(6.dp))
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
                .clip(RoundedCornerShape(6.dp))
                .clickable(role = Role.Button) { expanded = true }
                .padding(vertical = 2.dp),
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
                            Spacer(Modifier.width(8.dp))
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
                if (highlighted) drawRect(marker, size = Size(2.dp.toPx(), size.height))
                else if (selected) drawRect(marker.copy(alpha = 0.5f), size = Size(2.dp.toPx(), size.height))
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
            .padding(start = PanelGutter, end = PanelGutter, top = 4.dp, bottom = 4.dp),
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
                        Spacer(Modifier.width(8.dp))
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
                .background(ide.panel2)
                .padding(horizontal = PanelGutter, vertical = 6.dp),
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
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                val v = jump.removePrefix("0x").removePrefix("0X").toLongOrNull(16) ?: return@Button
                // Typing a virtual address into an offset field is the common
                // slip, and the section table can tell the difference.
                val size = data?.size ?: 0
                pendingOffset = if (v < size) v else (vm.fileOffsetOf(v) ?: v)
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
                // One glyph at the current font scale, not a dp guess: the row
                // is offset(8) + gap(2) + hex(3n-1) + gap(2) + ascii(n)
                // characters, so it fits when 12 + 4n of them fit.
                val chW = monoWidth(Type.monoSmall, 1)
                val avail = maxWidth - PanelGutter * 2
                val perRow = when {
                    avail >= chW * (12 + 4 * 32) -> 32
                    avail >= chW * (12 + 4 * 16) -> 16
                    else -> 8
                }
                val rows = (data.size + perRow - 1) / perRow
                // The tint used to come from vm.detail.addr — a virtual address
                // compared against file offsets, so it highlighted the wrong
                // bytes on every binary with a non-zero load base.
                val selStart = vm.detail?.let { vm.fileOffsetOf(it.addr) } ?: -1L
                val selEnd = if (selStart >= 0L) selStart + (vm.detail?.size ?: 0L) else -1L

                LaunchedEffect(pendingOffset, perRow) {
                    val off = pendingOffset ?: return@LaunchedEffect
                    pendingOffset = null
                    listState.scrollToItem(hexRowOf(off, perRow, rows))
                }
                // A goto from another panel arrives as a virtual address.
                LaunchedEffect(vm.gotoAddr, perRow, rows) {
                    val target = vm.gotoAddr ?: return@LaunchedEffect
                    vm.consumeGoto()
                    listState.scrollToItem(hexRowOf(vm.fileOffsetOf(target) ?: target, perRow, rows))
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
                            .background(ide.panel)
                            .padding(horizontal = PanelGutter, vertical = 3.dp)
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
                        contentPadding = bottomInset(extra = 8.dp)
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
            .heightIn(min = 22.dp)
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

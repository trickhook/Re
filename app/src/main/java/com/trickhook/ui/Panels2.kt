package com.trickhook.ui

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
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
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyItemScope
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material.icons.filled.Functions
import androidx.compose.material.icons.filled.Grid4x4
import androidx.compose.material.icons.filled.Storage
import androidx.compose.material3.AlertDialog
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
import androidx.compose.ui.graphics.RectangleShape
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
import com.trickhook.model.FuncInfo
import com.trickhook.model.Section
import com.trickhook.model.Segment
import com.trickhook.model.SymbolInfo
import com.trickhook.vm.StudioViewModel
import com.trickhook.vm.Tab
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

// ================================================================== shared ==

private val ChipShape = RoundedCornerShape(6.dp)

/**
 * One segment of a mode toggle.
 *
 * This file used to hold three different answers to the same question — the
 * map's plain text labels, the console's tinted chips, and nothing at all for
 * the symbol tables, which is why two of the three binary tables the engine
 * parses were unreachable. One shape now: a 48dp target, a tinted pill when
 * selected and [Modifier.surface1] when not, with the colour crossfading
 * instead of snapping.
 */
@Composable
private fun ModeChip(
    label: String,
    count: Int,
    selected: Boolean,
    tint: Color,
    onSelect: () -> Unit
) {
    val ide = LocalIde.current
    val fg by animateColorAsState(
        targetValue = if (selected) tint else ide.dim2,
        animationSpec = tween(motionMs(Motion.fast)),
        label = "modeChip"
    )
    Box(
        Modifier
            .heightIn(min = 48.dp)
            .selectable(selected = selected, role = Role.Tab, onClick = onSelect)
            .padding(horizontal = Space.xs),
        contentAlignment = Alignment.Center
    ) {
        Text(
            "$label $count",
            color = fg,
            fontSize = Type.caption, fontFamily = Mono,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            maxLines = 1,
            modifier = Modifier
                .then(
                    // borderStrong is the token for an edge you can touch; the
                    // unselected chip is a plain level-1 surface.
                    if (selected) Modifier
                        .background(tint.copy(alpha = 0.12f), ChipShape)
                        .border(1.dp, ide.borderStrong, ChipShape)
                    else Modifier.surface1(ChipShape)
                )
                .padding(horizontal = Space.m, vertical = Space.s)
        )
    }
}

/**
 * The entry/exit spec for the lists whose contents genuinely come and go as a
 * filter changes. Durations run through [motionMs], so with animation switched
 * off system-wide the rows cut instead of easing — the listing and the hex view
 * stay unanimated either way, because there the row under your finger never
 * moves and the animation would only cost a frame.
 */
@Composable
private fun LazyItemScope.rowMotion(): Modifier {
    val fade = motionMs(Motion.fast)
    val move = motionMs()
    // With reduce-motion on this is a bare Modifier, not a zero-length tween:
    // no animation node per row, nothing to tick and nothing to cancel.
    return if (fade == 0) Modifier
    else Modifier.animateItem(
        fadeInSpec = tween(fade),
        placementSpec = tween(move),
        fadeOutSpec = tween(fade)
    )
}

/**
 * Put the hex view on a file offset and go there.
 *
 * The offset has to come from [StudioViewModel.fileOffsetOf]: a virtual address
 * used raw lands on the wrong bytes for every binary with a non-zero load
 * address, the same bug that made the hex selection tint highlight the wrong
 * range. And it is handed over as an OFFSET, never as a row index — this used
 * to write `hexIndex = fileOffset / 16`, while the hex view now measures 8, 16
 * or 32 bytes per row from the screen width. That division landed on half the
 * intended byte on a phone and on double it on a tablet. Only the panel that
 * chose the row width can turn an offset into a row.
 */
private fun panelJumpToHex(vm: StudioViewModel, fileOffset: Long) {
    vm.requestHexGoto(fileOffset)
    vm.navigateTo(tab = Tab.HEX)
}

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
    // Keyed on identity and size, never on the list itself: AnalysisMeta and
    // every list it holds are data classes, so `remember(all, query)` deep-
    // compared up to 3,000 elements on each keystroke — more work than the
    // search it was there to avoid. The hits are INDICES into `all` so that the
    // LazyColumn key is unique by construction and stable across filters; an
    // address would be neither if the engine ever emitted two strings at one.
    val hits: List<Int> = remember(System.identityHashCode(all), all.size, query) {
        when {
            all.isEmpty() -> emptyList()
            query.isBlank() -> all.indices.toList()
            else -> all.indices.filter { all[it].value.contains(query, ignoreCase = true) }
        }
    }
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .surface2(RectangleShape)
                .padding(horizontal = Space.m, vertical = Space.s),
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
            Spacer(Modifier.width(Space.m))
            Text(
                if (query.isBlank()) "${all.size}" else "${hits.size}/${all.size}",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
            )
        }
        when {
            // Still reading the file. Ghost rows in the shape of the list say
            // "working"; the empty panel said "this binary has no strings",
            // which was a claim the app had not yet earned.
            vm.busy && all.isEmpty() -> SkeletonLines(14)

            all.isEmpty() -> EmptyPanel(
                "No strings",
                "Open a binary — the extracted strings from its data sections land here."
            )

            hits.isEmpty() -> Column(
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

            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
                items(hits.size, key = { hits[it] }) { i ->
                    StringsHitRow(vm, all[hits[i]], rowMotion())
                }
            }
        }
    }
}

@Composable
private fun StringsHitRow(vm: StudioViewModel, s: FoundStr, modifier: Modifier = Modifier) {
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
        modifier
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
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                s.value,
                color = if (canJump) ide.text else ide.dim,
                fontSize = Type.mono, lineHeight = Type.monoLine, fontFamily = Mono,
                maxLines = 2, overflow = TextOverflow.Ellipsis
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(hexFmt(s.addr), color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono)
                Spacer(Modifier.width(Space.m))
                Text(
                    where, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
        }
        Spacer(Modifier.width(Space.m))
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

// ============================================================ Functions ==

// `symbolsMode` is a plain String on the ViewModel because six writers across
// StudioApp and CommandPalette set it by literal. These are those three values.
private const val MODE_FUNCTIONS = "functions"
private const val MODE_IMPORTS = "imports"
private const val MODE_EXPORTS = "exports"

/**
 * The three symbol tables of a binary — functions, imports, exports — behind
 * one toggle.
 *
 * `vm.symbolsMode` had six writers and no reader. The palette set it to
 * "imports" before sending you here, the drawer offered a row reading "open
 * Functions, then Imports", and this panel listed `meta.functions` and nothing
 * else. Worse than a dead end: `Analyzer.cpp` deliberately keeps PLT stubs out
 * of `funcs`, so an import is NEVER in that list, and "Show all 412 in
 * Functions" arrived at "No function matches" — the tool denying a symbol it
 * had listed a moment earlier. `meta.exports`, `meta.needed` and `meta.soName`
 * had no home anywhere in the app at all.
 */
@Composable
fun FunctionsPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta
    val funcs = meta?.functions ?: emptyList()
    val imports = meta?.imports ?: emptyList()
    val exports = meta?.exports ?: emptyList()
    val mode = vm.symbolsMode
    val query = vm.funcQuery
    val funcsMode = mode != MODE_IMPORTS && mode != MODE_EXPORTS

    // JNI bindings first, exactly as the palette orders them: on an APK's
    // native library they are what you opened the file for.
    val exportsSorted = remember(System.identityHashCode(exports), exports.size) {
        exports.sortedByDescending { it.name.startsWith("Java_") }
    }
    val symbols = when (mode) {
        MODE_IMPORTS -> imports
        MODE_EXPORTS -> exportsSorted
        else -> emptyList()
    }
    val total = if (funcsMode) funcs.size else symbols.size

    // Deliberately NOT memoized: the match reads `renames`, and a rename that
    // leaves the map the same size would leave a remembered list stale while
    // the name on the row had already changed. The predicate is the palette's,
    // character for character, so that "Show all 412" and the list it opens
    // cannot disagree about 412.
    val funcHits: List<Int> = when {
        !funcsMode || funcs.isEmpty() -> emptyList()
        query.isBlank() -> funcs.indices.toList()
        else -> funcs.indices.filter {
            funcs[it].name.contains(query, ignoreCase = true) ||
                vm.effectiveFuncName(funcs[it].addr).contains(query, ignoreCase = true)
        }
    }
    // Memoized on identity plus size: AnalysisMeta's lists are data classes and
    // a value key would deep-compare every symbol on every keystroke. Indices,
    // not addresses — a symbol table aliases freely, two exports share one
    // address all the time, and every ELF import sits at address 0, so an
    // address key would be a duplicate-key crash waiting for the right binary.
    val symHits: List<Int> = remember(
        mode, System.identityHashCode(symbols), symbols.size, query
    ) {
        when {
            symbols.isEmpty() -> emptyList()
            query.isBlank() -> symbols.indices.toList()
            else -> symbols.indices.filter {
                symbols[it].name.contains(query, ignoreCase = true)
            }
        }
    }
    val shown = if (funcsMode) funcHits.size else symHits.size

    val noun = when (mode) {
        MODE_IMPORTS -> "import"
        MODE_EXPORTS -> "export"
        else -> "function"
    }
    // `needed` and `soName` are parsed out of every ELF and were rendered
    // nowhere; each belongs to the mode that explains what it is.
    val note = when {
        meta == null -> ""
        mode == MODE_IMPORTS && meta.needed.isNotEmpty() ->
            "resolved at load time from " + meta.needed.joinToString(" · ")
        mode == MODE_EXPORTS && meta.soName.isNotEmpty() -> "SONAME " + meta.soName
        else -> ""
    }

    Column(Modifier.fillMaxSize()) {
        // Search, toggle and context line are one block. The context line
        // exists for two modes of three, so the top of the list moves when you
        // switch: animateContentSize makes that a slide instead of a jump.
        Column(
            Modifier
                .fillMaxWidth()
                .surface2(RectangleShape)
                .animateContentSize(tween(motionMs()))
        ) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Space.m, vertical = Space.s),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = query,
                    onValueChange = { vm.funcQuery = it },
                    label = { Text("Search ${noun}s") },
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
                        .semantics { contentDescription = "Search ${noun}s" },
                    textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.width(Space.m))
                Text(
                    if (query.isBlank()) "$total" else "$shown/$total",
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
                )
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState())
                    .padding(horizontal = Space.s)
                    .selectableGroup(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                ModeChip("Functions", funcs.size, funcsMode, ide.accent) {
                    vm.symbolsMode = MODE_FUNCTIONS
                }
                Spacer(Modifier.width(Space.s))
                ModeChip("Imports", imports.size, mode == MODE_IMPORTS, ide.accent) {
                    vm.symbolsMode = MODE_IMPORTS
                }
                Spacer(Modifier.width(Space.s))
                ModeChip("Exports", exports.size, mode == MODE_EXPORTS, ide.accent) {
                    vm.symbolsMode = MODE_EXPORTS
                }
            }
            if (note.isNotEmpty()) {
                Text(
                    note,
                    color = ide.dim2, fontSize = Type.monoSmall, lineHeight = Type.monoSmallLine,
                    fontFamily = Mono, maxLines = 2, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(start = Space.l, end = Space.l, bottom = Space.m)
                )
            }
        }
        when {
            vm.busy && total == 0 -> SkeletonLines(14)

            total == 0 -> EmptyPanel(
                "No ${noun}s",
                when {
                    meta == null -> "Open a binary and its symbol tables land here."
                    mode == MODE_IMPORTS ->
                        "Nothing is imported, or this format carries no import table — only ELF and PE do."
                    mode == MODE_EXPORTS ->
                        "Nothing is exported, or this format carries no export table — only ELF and PE do."
                    else ->
                        "Open a binary the engine can disassemble and its functions land here."
                }
            )

            shown == 0 -> SymbolsNoMatch(vm, query, mode, funcsMode, noun, total, funcs, imports, exports)

            funcsMode -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
                items(funcHits.size, key = { funcHits[it] }) { i ->
                    FunctionRow(vm, funcs[funcHits[i]], rowMotion())
                }
            }

            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
                items(symHits.size, key = { symHits[it] }) { i ->
                    SymbolRow(vm, symbols[symHits[i]], mode == MODE_EXPORTS, rowMotion())
                }
            }
        }
    }
}

/**
 * The case that made the toggle necessary: your query matches a table you are
 * not looking at. Saying "no function matches" and stopping there is how the
 * app used to deny a symbol the palette had just listed; now it names the table
 * that has the hits and takes one tap to get there.
 */
@Composable
private fun SymbolsNoMatch(
    vm: StudioViewModel,
    query: String,
    mode: String,
    funcsMode: Boolean,
    noun: String,
    total: Int,
    funcs: List<FuncInfo>,
    imports: List<SymbolInfo>,
    exports: List<SymbolInfo>
) {
    val ide = LocalIde.current
    // Only reached when the current table has nothing, so three counting passes
    // here cost nothing on the typing path.
    val elsewhere = buildList {
        if (!funcsMode) {
            val n = funcs.count { it.name.contains(query, ignoreCase = true) }
            if (n > 0) add(Triple(MODE_FUNCTIONS, "Functions", n))
        }
        if (mode != MODE_IMPORTS) {
            val n = imports.count { it.name.contains(query, ignoreCase = true) }
            if (n > 0) add(Triple(MODE_IMPORTS, "Imports", n))
        }
        if (mode != MODE_EXPORTS) {
            val n = exports.count { it.name.contains(query, ignoreCase = true) }
            if (n > 0) add(Triple(MODE_EXPORTS, "Exports", n))
        }
    }
    Column(Modifier.fillMaxWidth(), horizontalAlignment = Alignment.CenterHorizontally) {
        EmptyPanel(
            "No $noun matches \"$query\"",
            if (funcsMode) "$total functions in this binary, by name or by the name you gave it."
            else "$total ${noun}s in this binary, none whose name contains that text."
        )
        // One offer per line rather than a row of them: three labels at this
        // size overflow a 360dp screen, and an empty state has vertical space
        // to spare.
        for ((target, label, n) in elsewhere) {
            TextButton(onClick = { vm.symbolsMode = target }) {
                Text("Show $n in $label", color = ide.cyan, fontSize = Type.label)
            }
        }
        TextButton(onClick = { vm.funcQuery = "" }) {
            Text("Clear search", color = ide.accent, fontSize = Type.label)
        }
    }
}

@Composable
private fun FunctionRow(vm: StudioViewModel, f: FuncInfo, modifier: Modifier = Modifier) {
    val ide = LocalIde.current
    val renamed = vm.renames["0x%08X".format(f.addr)]
    // `nCallees`/`nCallers` are built from the engine's INTERNAL-ONLY edge sets,
    // while the Assembly tab counts every edge: a function calling printf,
    // malloc, free and one local helper read "1 out" here and "calls out 4"
    // there, for the same function on two tabs. The call-graph index is the
    // source the other screen falls back to, and when the row IS the function
    // currently open its FunctionDetail is better still — xrefInCount and
    // xrefOutCount are the one rule both screens now share.
    val d = vm.detail?.takeIf { it.ok && it.addr == f.addr }
    val outN = if (d != null) vm.xrefOutCount(d) else vm.calleesOf(f.addr).size
    val inN = if (d != null) vm.xrefInCount(d) else vm.callersOf(f.addr).size
    Row(
        modifier
            .fillMaxWidth()
            .clickable(onClickLabel = "Open this function", role = Role.Button) {
                // navigateTo, not selectFunction. This list was the app's only
                // holdout: selectFunction pushes no history, so Back did not
                // undo the pick, and it does not change tab either, so tapping
                // a row only recoloured it while the decompile ran on a screen
                // you could not see.
                vm.navigateTo(tab = Tab.ASSEMBLY, addr = f.addr)
            }
            .heightIn(min = 48.dp)
            .padding(horizontal = Space.l, vertical = Space.s),
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
                "${f.from} · ${f.size} bytes · $outN out / $inN in",
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        Spacer(Modifier.width(Space.m))
        Text(hexFmt(f.addr), color = ide.cyan, fontSize = Type.monoSmall, fontFamily = Mono)
    }
}

/**
 * An import or an export. [SymbolInfo] carries a name and an address and
 * nothing else — no size, no origin, no edge counts — so this is not the
 * function row with its fields blanked out.
 *
 * Every ELF import has address 0. `ElfLoader` records a dynamic symbol as an
 * import precisely when it is undefined and its value is 0, because the loader
 * resolves it at run time and the file genuinely does not say where it will
 * land. Such a row shows NO address — a grey 00000000 would be a number the
 * binary never contained — and is not clickable, because there is nothing to
 * open. That is the normal look of the Imports list for a `.so`, not an edge
 * case, so the name stays at full strength and only the affordances go.
 *
 * For the rest the tap rule is the palette's, unchanged: the function whose
 * body covers the address, or nothing.
 */
@Composable
private fun SymbolRow(
    vm: StudioViewModel,
    s: SymbolInfo,
    isExport: Boolean,
    modifier: Modifier = Modifier
) {
    val ide = LocalIde.current
    val fn = if (s.addr != 0L) vm.functionContaining(s.addr) else null
    val jni = isExport && s.name.startsWith("Java_")
    val where = when {
        s.addr == 0L -> "resolved at load time · no address in this file"
        fn != null -> "in ${vm.effectiveFuncName(fn.addr)}"
        else -> "no disassembled body at this address"
    }
    Row(
        modifier
            .fillMaxWidth()
            .then(
                if (fn != null) Modifier.clickable(
                    onClickLabel = "Open in Assembly",
                    role = Role.Button
                ) {
                    vm.navigateTo(tab = Tab.ASSEMBLY, addr = fn.addr)
                    vm.requestGoto(s.addr)
                } else Modifier
            )
            .heightIn(min = 48.dp)
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(
            if (isExport) Icons.Filled.ArrowUpward else Icons.Filled.ArrowDownward,
            if (jni) ide.entry else ide.dim, 13.dp,
            contentDescription = if (isExport) "export" else "import"
        )
        Column(Modifier.weight(1f)) {
            Text(
                s.name,
                color = ide.text,
                fontSize = Type.mono, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                if (jni) "JNI entry point · $where" else where,
                color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        if (s.addr != 0L) {
            Spacer(Modifier.width(Space.m))
            // Cyan is this app's "there is somewhere to go". An address that
            // exists but has no disassembled body is real information and stays
            // legible, in dim2, without promising a destination.
            Text(
                hexFmt(s.addr),
                color = if (fn != null) ide.cyan else ide.dim2,
                fontSize = Type.monoSmall, fontFamily = Mono
            )
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
    // `Engine.cpp` fills `sections` for ELF and PE only, so a DEX — which means
    // every APK, the app's main flow — has none, and mode 0, the default,
    // opened an empty grid while the six-row layout the DEX loader DOES emit
    // sat one tap away under Segments.
    //
    // The fallback moves the DEFAULT only. `chose` records that you picked a
    // mode yourself, and after that the panel shows what you asked for, empty
    // state and its explanation included.
    var chose by remember(System.identityHashCode(meta)) { mutableStateOf(false) }
    val segs = if (!chose && sections.isEmpty() && segments.isNotEmpty()) true else vm.mapMode == 1
    val rows = if (segs) segments.size else sections.size
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .surface2(RectangleShape)
                .padding(horizontal = Space.s)
                .selectableGroup(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            ModeChip("Sections", sections.size, !segs, ide.accent) { chose = true; vm.mapMode = 0 }
            Spacer(Modifier.width(Space.s))
            ModeChip("Segments", segments.size, segs, ide.accent) { chose = true; vm.mapMode = 1 }
            Spacer(Modifier.weight(1f))
            Text(
                if (segs) "load map" else "section table",
                color = ide.dim2, fontSize = Type.caption,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        when {
            vm.busy && rows == 0 -> SkeletonLines(6)

            meta == null -> EmptyPanel(
                "No binary open",
                "The section and segment tables come from the file header — open a file to read them."
            )

            rows == 0 -> EmptyPanel(
                if (segs) "No segments" else "No sections",
                if (segs) "This format has no program headers, so there is no load map to show."
                else "This file declares no section headers — try the segment view."
            )

            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
                items(rows) { i ->
                    if (segs) MapSegmentRow(vm, segments[i]) else MapSectionRow(vm, sections[i])
                }
            }
        }
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
            .padding(horizontal = Space.l, vertical = Space.s),
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
        Spacer(Modifier.width(Space.m))
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
            .padding(horizontal = Space.l, vertical = Space.s),
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
        Spacer(Modifier.width(Space.m))
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
    // Indices into the log, so a row keeps its identity when the level filter
    // changes under it and animateItem has something to animate. Two lines
    // logged in the same millisecond share a timestamp, so the line itself
    // would not be a unique key. (log() drops the oldest 200 past 800, which
    // shifts every index once; the list is pinned to its tail by then, so that
    // costs one meaningless frame and never a duplicate key.)
    val hits: List<Int> =
        if (level == "ALL") lines.indices.toList()
        else lines.indices.filter { lines[it].level == level }
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
                        Spacer(Modifier.width(Space.m))
                    }
                    if (warns > 0) {
                        StatChip("WARN", "$warns", ide.amber)
                        Spacer(Modifier.width(Space.m))
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
                .surface1(RectangleShape)
                .horizontalScroll(rememberScrollState())
                .padding(horizontal = Space.s)
                .selectableGroup(),
            verticalAlignment = Alignment.CenterVertically
        ) {
            ModeChip("ALL", lines.size, level == "ALL", ide.text) { level = "ALL" }
            for (lv in listOf("INFO", "OK", "WARN", "ERROR")) {
                Spacer(Modifier.width(Space.s))
                ModeChip(lv, lines.count { it.level == lv }, level == lv, levelColor(lv, ide)) {
                    level = lv
                }
            }
        }
        when {
            lines.isEmpty() -> EmptyPanel(
                "Console empty",
                "Opening a file, decompiling and exporting all report here."
            )

            hits.isEmpty() -> EmptyPanel(
                when (level) {
                    "ERROR" -> "No errors"
                    "WARN" -> "No warnings"
                    else -> "No $level lines"
                },
                "${lines.size} lines are hidden by the $level filter."
            )

            else -> {
                val state = rememberLazyListState()
                LaunchedEffect(hits.size, level) {
                    if (hits.isNotEmpty()) state.scrollToItem(hits.size - 1)
                }
                LazyColumn(
                    Modifier.fillMaxSize(), state = state,
                    contentPadding = bottomInset(Space.l)
                ) {
                    items(hits.size, key = { hits[it] }) { i ->
                        ConsoleLineRow(lines[hits[i]], stamp, rowMotion())
                    }
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
                    color = ide.dim, fontSize = Type.body, lineHeight = Type.bodyLine
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
private fun ConsoleLineRow(
    l: ConsoleLine,
    stamp: SimpleDateFormat,
    modifier: Modifier = Modifier
) {
    val ide = LocalIde.current
    val tint = levelColor(l.level, ide)
    val wash = when (l.level) {
        "ERROR" -> ide.red.copy(alpha = 0.10f)
        "WARN" -> ide.amber.copy(alpha = 0.08f)
        else -> Color.Transparent
    }
    Row(
        modifier
            .fillMaxWidth()
            .background(wash)
            .padding(horizontal = Space.l, vertical = Space.xs)
    ) {
        Text(
            stamp.format(Date(l.ts)),
            color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
        )
        Spacer(Modifier.width(Space.m))
        Text(
            l.level, color = tint, fontSize = Type.monoSmall, fontFamily = Mono,
            fontWeight = FontWeight.Bold, maxLines = 1,
            modifier = Modifier.widthIn(min = 42.dp)
        )
        Spacer(Modifier.width(Space.m))
        Text(
            l.msg,
            color = if (l.level == "ERROR" || l.level == "WARN") tint else ide.text,
            fontSize = Type.mono, lineHeight = Type.monoLine, fontFamily = Mono,
            modifier = Modifier.weight(1f)
        )
    }
}

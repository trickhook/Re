package com.trickhook.ui

import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.LazyItemScope
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CallMade
import androidx.compose.material.icons.filled.CallReceived
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.trickhook.model.CallEdge
import com.trickhook.vm.StudioViewModel

// ========================================================= Call graph panel ==
/**
 * Xrefs, both directions. Two things used to be wrong here and both were
 * invisible: the panel waited for a native pass that had already been done at
 * load time (`meta.callEdges`, whose only use in the whole app was logging its
 * own size), and every row resolved its target by matching the edge's name
 * string against the function table — so renaming a function, which is the
 * point of the annotation system, silently unlinked all of its rows.
 *
 * Everything below resolves by ADDRESS (`CallEdge.from` / `CallEdge.to`) and
 * labels by [StudioViewModel.effectiveFuncName], so renames show up here the
 * same moment they show up in the Functions list.
 */
@Composable
fun CallGraphPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val sel = vm.selectedFunc
    var focusMode by remember { mutableStateOf(sel != null) }

    val meta = vm.meta
    // The native pass produces a richer graph, but it is not a prerequisite:
    // the edges parsed at open time are already a complete call graph.
    val cg = vm.callGraph?.takeIf { it.ok && it.edges.isNotEmpty() }
    // `focus` is the address the recompute was asked for, 0 meaning the whole
    // binary. Engine.cpp now really filters on it — a focused answer used to
    // come back as the entire graph, five bytes of JSON smaller — so a focused
    // graph holds ONLY the edges touching that one function. It can stand in
    // for no other view: the whole-binary list would silently show a slice, and
    // another function's focus view would read "calls nothing" and be wrong.
    val native = cg?.takeIf { it.focus == 0L || (sel != null && it.focus == sel) }
    val whole = cg?.takeIf { it.focus == 0L }
    val edges: List<CallEdge> = whole?.edges ?: meta?.callEdges.orEmpty()
    // What the engine FOUND, which is not what it sent: both JSON paths cap the
    // array and report the count beside it. Without this the header printed the
    // cap — 12000 — in the voice of a measurement.
    val edgesTotal = (if (whole != null) whole.edgesTotal else meta?.callEdgesTotal ?: 0)
        .coerceAtLeast(edges.size)

    val open: (Long) -> Unit = { addr ->
        // navigateTo, not selectFunction: the jump belongs in Back's history.
        vm.navigateTo(addr = addr)
        focusMode = true
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = Space.l, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "CALL GRAPH",
                    color = ide.text, fontSize = Type.label,
                    fontWeight = FontWeight.Bold, fontFamily = Mono, maxLines = 1
                )
                Text(
                    when {
                        // The spinner that used to sit in this row is now a
                        // skeleton with the shape of the list below, so the
                        // header only has to say which state it is in.
                        vm.callGraphBusy -> "recomputing…"
                        edges.isEmpty() -> "no edges"
                        else -> {
                            val n = if (edgesTotal > edges.size) "${edges.size} of $edgesTotal"
                            else "${edges.size}"
                            "$n edges · " + (if (whole != null) "recomputed" else "from analysis")
                        }
                    },
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            val refresh = remember { MutableInteractionSource() }
            val refreshPressed by refresh.collectIsPressedAsState()
            IconButton(
                onClick = { vm.loadCallGraph(if (focusMode) sel ?: 0L else 0L) },
                enabled = !vm.callGraphBusy && vm.meta != null,
                interactionSource = refresh,
                modifier = Modifier.pressScale(refreshPressed)
            ) {
                Icon(
                    Icons.Filled.Refresh,
                    contentDescription = if (focusMode) "Recompute this function's call graph"
                    else "Recompute the whole-binary call graph",
                    tint = ide.dim, modifier = Modifier.size(18.dp)
                )
            }
        }

        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel)
                .selectableGroup()
        ) {
            ModeTab("This function", focusMode, sel != null, Modifier.weight(1f)) { focusMode = true }
            ModeTab("Whole binary", !focusMode, true, Modifier.weight(1f)) { focusMode = false }
        }

        when {
            meta == null -> EmptyPanel(
                "No binary open",
                "Open a file and the call graph is built with the rest of the analysis."
            )
            // The native pass replaces the whole edge list, so leaving the old
            // one on screen under a spinner would be claiming it is current.
            // The skeleton has the shape of what is coming instead: a flush-left
            // section label, indented rows under it, a short tail. It brings its
            // own full-bleed padding, so it is not wrapped in any.
            vm.callGraphBusy -> SkeletonLines(lines = 12, indent = true)
            edges.isEmpty() -> EmptyPanel(
                "No call edges in this binary",
                "The BL/CALL cross-reference scan found nothing to link. " +
                    "Recompute runs the native pass again."
            )
            focusMode && sel == null -> EmptyPanel(
                "No function selected",
                "Pick a function to see what it calls and what calls it, " +
                    "or switch to the whole-binary view."
            )
            focusMode -> FocusView(vm, ide, sel ?: 0L, native?.edges, open)
            else -> WholeBinaryView(vm, ide, edges, sel, open)
        }
    }
}

@Composable
private fun ModeTab(
    label: String,
    selected: Boolean,
    enabled: Boolean,
    modifier: Modifier,
    onClick: () -> Unit
) {
    val ide = LocalIde.current
    Column(
        modifier
            .selectable(selected = selected, enabled = enabled, role = Role.Tab, onClick = onClick)
            .heightIn(min = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(
            label,
            color = when {
                !enabled -> ide.dim2
                selected -> ide.text
                else -> ide.dim
            },
            fontSize = Type.label,
            fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
            maxLines = 1
        )
        Spacer(Modifier.height(Space.s))
        // Selection is not carried by weight and colour alone.
        Box(
            Modifier
                .width(52.dp)
                .height(2.dp)
                .background(if (selected) ide.accent else Color.Transparent)
        )
    }
}

/** IDA-style xrefs for one function: what it calls, and what calls it. */
@Composable
private fun FocusView(
    vm: StudioViewModel,
    ide: IdeColors,
    addr: Long,
    nativeEdges: List<CallEdge>?,
    open: (Long) -> Unit
) {
    // Both sides come from an address-keyed index built once per analysis, so
    // this is two map lookups rather than a scan per row.
    //
    // The keys are IDENTITIES and a size, never the objects themselves:
    // AnalysisMeta is a data class, so keying on `vm.meta` made every single
    // recomposition of this view walk its sections, its segments, its four
    // thousand functions, its three thousand strings and every DEX class and
    // method — twice — plus a full element-by-element List<CallEdge> compare.
    // CommandPalette already keys its own lookups this way.
    val nativeId = System.identityHashCode(nativeEdges)
    val nativeN = nativeEdges?.size ?: 0
    val metaId = System.identityHashCode(vm.meta)
    // No .distinctBy: this panel was the only screen in the app that collapsed
    // repeated edges, which is why one function could read "calls out 5" on the
    // Assembly and Pseudo-C strips and "calls (1)" here. One edge, one row, the
    // same rule as every other list — and `buildCallGraph` already merges the
    // several call sites between one pair of functions into a single edge, so
    // there is no second dedup left for the UI to invent.
    val callees = remember(nativeId, nativeN, addr, metaId) {
        nativeEdges?.filter { it.from == addr } ?: vm.calleesOf(addr)
    }
    val callers = remember(nativeId, nativeN, addr, metaId) {
        nativeEdges?.filter { it.to == addr } ?: vm.callersOf(addr)
    }

    // The counts come from the one shared definition when we hold the detail
    // this panel is describing, so the section headings, the Assembly strip and
    // the Pseudo-C strip cannot disagree about one function any more.
    val detail = vm.detail?.takeIf { it.addr == addr }
    val outCount = detail?.let { vm.xrefOutCount(it) } ?: callees.size
    val inCount = detail?.let { vm.xrefInCount(it) } ?: callers.size
    // Both numbers, and every edge under them, come off a reference map that
    // drops what it cannot hold. Above its cap they are floors.
    val floors = vm.xrefsAreFloors

    LazyColumn(
        Modifier
            .fillMaxSize()
            .background(ide.bg),
        contentPadding = bottomInset(Space.l)
    ) {
        item(key = "head") {
            Column(Modifier.padding(horizontal = Space.l, vertical = Space.m)) {
                Text(
                    vm.effectiveFuncName(addr),
                    color = ide.accent, fontSize = Type.body, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                Text(
                    hexFmt(addr),
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                )
                // Once, at the top, rather than beside each `+`.
                val floorNote = xrefFloorNote(vm)
                if (floorNote != null) {
                    Spacer(Modifier.height(Space.xs))
                    TruncationNote(floorNote)
                }
            }
        }
        item(key = "sec_out") {
            SectionLabel(rowMotion(), ide, Icons.Filled.CallMade, "calls", outCount, floors)
        }
        // Only when both agree there is nothing: "calls nothing" under a heading
        // that says 7 is the kind of contradiction this pass exists to remove.
        if (callees.isEmpty() && outCount == 0) item(key = "none_out") {
            NoneRow(rowMotion(), ide, "This function calls nothing.")
        }
        // The heading counts reference SITES and the rows are call-graph EDGES;
        // Engine.cpp:969-975 says in as many words that those are two different
        // questions. Two call instructions to the same target are two sites and
        // one edge, so rather than hide one number the panel names both.
        if (callees.size != outCount) item(key = "gap_out") {
            NoneRow(
                rowMotion(), ide,
                "${floorCount(outCount, floors)} call sites · ${callees.size} distinct targets"
            )
        }
        items(callees.size, key = { i -> "o_" + callees[i].to + "_" + i }) { i ->
            val e = callees[i]
            CallRow(vm, ide, rowMotion(), e.to, e.kind, e.toName, open)
        }
        item(key = "sec_in") {
            SectionLabel(rowMotion(), ide, Icons.Filled.CallReceived, "called by", inCount, floors)
        }
        if (callers.isEmpty() && inCount == 0) item(key = "none_in") {
            NoneRow(rowMotion(), ide, "Nothing in this binary calls it.")
        }
        if (callers.size != inCount) item(key = "gap_in") {
            NoneRow(
                rowMotion(), ide,
                "${floorCount(inCount, floors)} reference sites · ${callers.size} distinct callers"
            )
        }
        items(callers.size, key = { i -> "i_" + callers[i].from + "_" + i }) { i ->
            val e = callers[i]
            // A caller is always a real function in this image, never an import.
            CallRow(vm, ide, rowMotion(), e.from, "call", e.fromName, open)
        }
    }
}

/** Every edge in the binary, grouped by the function that makes the call. */
@Composable
private fun WholeBinaryView(
    vm: StudioViewModel,
    ide: IdeColors,
    edges: List<CallEdge>,
    selected: Long?,
    open: (Long) -> Unit
) {
    // Identity and size, not the list: `remember(edges)` compared four thousand
    // CallEdge objects field by field on every recomposition of this panel.
    val groups = remember(System.identityHashCode(edges), edges.size) {
        edges.groupBy { it.from }.entries.sortedBy { it.key }
    }
    LazyColumn(
        Modifier
            .fillMaxSize()
            .background(ide.bg),
        contentPadding = bottomInset(Space.l)
    ) {
        groups.forEach { (caller, list) ->
            item(key = "h_$caller") {
                // Resolved, not assumed: an edge endpoint is not guaranteed to
                // be a function start, and effectiveFuncName invents a sub_ name
                // for anything it cannot find — which is how a header ends up
                // naming a function that does not exist.
                val owner = vm.functionAt(caller) ?: vm.functionContaining(caller)
                Row(
                    rowMotion()
                        .fillMaxWidth()
                        .background(ide.panel2)
                        .padding(horizontal = Space.l, vertical = Space.s),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        if (owner != null) vm.effectiveFuncName(owner.addr) else hexFmt(caller),
                        // accent means "this is where you are", nothing else —
                        // and `selected` being null must never match an owner
                        // this binary could not resolve.
                        color = if (selected != null && owner?.addr == selected) ide.accent
                        else ide.text,
                        fontSize = Type.label, fontFamily = Mono,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    // One edge per (caller, target) pair, however many call
                    // instructions are behind it — the engine merges them and
                    // reports the count in `sites`. "7 calls" over 4 rows was
                    // this panel's own comment about sites and edges, broken.
                    val nSites = list.sumOf { it.sites }
                    Text(
                        if (nSites != list.size) "${list.size} targets · $nSites calls"
                        else "${list.size} calls",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                        maxLines = 1
                    )
                }
            }
            items(list.size, key = { i -> "e_" + caller + "_" + i }) { i ->
                val e = list[i]
                CallRow(vm, ide, rowMotion(), e.to, e.kind, e.toName, open)
            }
        }
    }
}

@Composable
private fun SectionLabel(
    modifier: Modifier,
    ide: IdeColors,
    icon: ImageVector,
    label: String,
    n: Int,
    floored: Boolean = false
) {
    Row(
        modifier
            .fillMaxWidth()
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(icon, ide.dim, 14.dp, null)
        // "calls (7)" above seven rows is a count; "calls (7+)" above seven
        // rows says the engine's reference map stopped counting, which is a
        // different claim and the only honest one above its cap.
        Text(
            "$label (${floorCount(n, floored)})",
            color = ide.dim, fontSize = Type.label, fontFamily = Mono
        )
    }
}

@Composable
private fun NoneRow(modifier: Modifier, ide: IdeColors, text: String) {
    Text(
        text,
        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
        // Space.xxl is the RowIcon gutter a CallRow indents by, plus one more
        // step so the sentence lines up with the row labels and not the arrows.
        modifier = modifier.padding(
            start = Space.xxl + Space.l, end = Space.l, top = Space.xs, bottom = Space.m
        )
    )
}

/**
 * Entry, exit and placement for the xref lists. Rows really do come and go
 * here: switching mode, picking another function or recomputing rebuilds both
 * sides. A fast fade over a base-length move, the same spec the other list
 * panels use, with every duration through [motionMs].
 */
@Composable
private fun LazyItemScope.rowMotion(): Modifier {
    val fade = motionMs(Motion.fast)
    val move = motionMs()
    // A bare Modifier under reduce-motion, not a zero-length tween: no
    // animation node per row, nothing to tick and nothing to cancel.
    return if (fade == 0) Modifier
    else Modifier.animateItem(
        fadeInSpec = tween(fade),
        placementSpec = tween(move),
        fadeOutSpec = tween(fade)
    )
}

/**
 * One edge. Resolution is `functionAt` and then `functionContaining` — two
 * cheap lookups, not the per-row linear scan over `meta.functions` this panel
 * used to do inside a LazyColumn, and not the exact-match-only rule it used
 * after that: an endpoint of a CallEdge is not guaranteed to be a function
 * start, so "called by" rows kept failing to resolve and the same caller showed
 * up as a named, tappable row in the xref sheet and as dead grey text here.
 *
 * Whatever resolves is what gets navigated to and what gets named, so
 * `navigateTo` receives a function start by construction rather than by luck,
 * and `effectiveFuncName` is never handed an address it would have to invent a
 * `sub_` name for. A row that resolves to nothing is still drawn quiet and left
 * un-clickable instead of rippling and then doing nothing.
 */
@Composable
private fun CallRow(
    vm: StudioViewModel,
    ide: IdeColors,
    modifier: Modifier,
    addr: Long,
    kind: String,
    rawName: String,
    open: (Long) -> Unit
) {
    val isImport = kind == "import"
    val target = if (isImport) null else (vm.functionAt(addr) ?: vm.functionContaining(addr))
    val label = when {
        isImport -> rawName.ifEmpty { hexFmt(addr) }
        target != null -> vm.effectiveFuncName(target.addr)
        else -> rawName.ifEmpty { hexFmt(addr) }
    }
    val goTo = target?.addr
    val base = modifier
        .fillMaxWidth()
        .then(
            if (goTo != null) Modifier.clickable(role = Role.Button, onClickLabel = "Open $label") {
                open(goTo)
            } else Modifier
        )
        .heightIn(min = 48.dp)
        .padding(start = Space.xxl, end = Space.l, top = Space.s, bottom = Space.s)
    Row(base, verticalAlignment = Alignment.CenterVertically) {
        Text(
            if (goTo != null) "|-> " else "|   ",
            color = ide.dim, fontSize = Type.label, fontFamily = Mono
        )
        Text(
            label,
            color = when {
                isImport -> ide.amber
                goTo != null -> ide.cyan
                else -> ide.dim2
            },
            fontSize = Type.label, fontFamily = Mono,
            maxLines = 1, overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        Spacer(Modifier.width(Space.m))
        Text(
            if (isImport) "import" else hexFmt(addr),
            color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
            modifier = if (isImport) Modifier
                .background(ide.amber.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                .padding(horizontal = Space.s, vertical = Space.xs)
            else Modifier
        )
    }
}

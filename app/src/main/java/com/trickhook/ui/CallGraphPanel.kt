package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CallMade
import androidx.compose.material.icons.filled.CallReceived
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
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
    val native = vm.callGraph?.takeIf { it.ok && it.edges.isNotEmpty() }
    val edges: List<CallEdge> = native?.edges ?: meta?.callEdges.orEmpty()

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
                .padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "CALL GRAPH",
                    color = ide.text, fontSize = Type.label,
                    fontWeight = FontWeight.Bold, fontFamily = Mono, maxLines = 1
                )
                Text(
                    if (edges.isEmpty()) "no edges"
                    else "${edges.size} edges" + (if (native != null) " · recomputed" else " · from analysis"),
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            if (vm.callGraphBusy) {
                CircularProgressIndicator(
                    color = ide.accent,
                    strokeWidth = 2.dp,
                    modifier = Modifier.size(16.dp)
                )
                Spacer(Modifier.width(8.dp))
            }
            IconButton(
                onClick = { vm.loadCallGraph(if (focusMode) sel ?: 0L else 0L) },
                enabled = !vm.callGraphBusy && vm.meta != null
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
        Spacer(Modifier.height(5.dp))
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
    val callees = remember(nativeEdges, addr, vm.meta) {
        (nativeEdges?.filter { it.from == addr } ?: vm.calleesOf(addr)).distinctBy { it.to }
    }
    val callers = remember(nativeEdges, addr, vm.meta) {
        (nativeEdges?.filter { it.to == addr } ?: vm.callersOf(addr)).distinctBy { it.from }
    }

    LazyColumn(
        Modifier
            .fillMaxSize()
            .background(ide.bg),
        contentPadding = bottomInset(12.dp)
    ) {
        item {
            Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
                Text(
                    vm.effectiveFuncName(addr),
                    color = ide.accent, fontSize = Type.body, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                Text(
                    hexFmt(addr),
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                )
            }
        }
        item { SectionLabel(ide, Icons.Filled.CallMade, "calls", callees.size) }
        if (callees.isEmpty()) item { NoneRow(ide, "This function calls nothing.") }
        items(callees.size, key = { i -> "o_" + callees[i].to + "_" + i }) { i ->
            val e = callees[i]
            CallRow(vm, ide, e.to, e.kind, e.toName, open)
        }
        item { SectionLabel(ide, Icons.Filled.CallReceived, "called by", callers.size) }
        if (callers.isEmpty()) item { NoneRow(ide, "Nothing in this binary calls it.") }
        items(callers.size, key = { i -> "i_" + callers[i].from + "_" + i }) { i ->
            val e = callers[i]
            // A caller is always a real function in this image, never an import.
            CallRow(vm, ide, e.from, "call", e.fromName, open)
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
    val groups = remember(edges) { edges.groupBy { it.from }.entries.sortedBy { it.key } }
    LazyColumn(
        Modifier
            .fillMaxSize()
            .background(ide.bg),
        contentPadding = bottomInset(12.dp)
    ) {
        groups.forEach { (caller, list) ->
            item(key = "h_$caller") {
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(ide.panel2)
                        .padding(horizontal = 12.dp, vertical = 5.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        vm.effectiveFuncName(caller),
                        // accent means "this is where you are", nothing else.
                        color = if (caller == selected) ide.accent else ide.text,
                        fontSize = Type.label, fontFamily = Mono,
                        maxLines = 1, overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.weight(1f)
                    )
                    Text(
                        "${list.size} calls",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                    )
                }
            }
            items(list.size, key = { i -> "e_" + caller + "_" + i }) { i ->
                val e = list[i]
                CallRow(vm, ide, e.to, e.kind, e.toName, open)
            }
        }
    }
}

@Composable
private fun SectionLabel(ide: IdeColors, icon: androidx.compose.ui.graphics.vector.ImageVector, label: String, n: Int) {
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(icon, ide.dim, 14.dp, null)
        Text("$label ($n)", color = ide.dim, fontSize = Type.label, fontFamily = Mono)
    }
}

@Composable
private fun NoneRow(ide: IdeColors, text: String) {
    Text(
        text,
        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
        modifier = Modifier.padding(start = 36.dp, end = 12.dp, top = 2.dp, bottom = 6.dp)
    )
}

/**
 * One edge. Resolution is `functionAt(addr)` — an O(1) map lookup, not the
 * per-row linear scan over `meta.functions` this panel used to do inside a
 * LazyColumn — and a row that cannot resolve to anything is drawn quiet and
 * left un-clickable instead of rippling and then doing nothing.
 */
@Composable
private fun CallRow(
    vm: StudioViewModel,
    ide: IdeColors,
    addr: Long,
    kind: String,
    rawName: String,
    open: (Long) -> Unit
) {
    val isImport = kind == "import"
    val target = if (isImport) null else vm.functionAt(addr)
    val label = when {
        isImport -> rawName.ifEmpty { "0x" + hexFmt(addr) }
        target != null -> vm.effectiveFuncName(addr)
        else -> rawName.ifEmpty { "0x" + hexFmt(addr) }
    }
    val tappable = target != null
    val base = Modifier
        .fillMaxWidth()
        .then(
            if (tappable) Modifier.clickable(role = Role.Button, onClickLabel = "Open $label") {
                open(addr)
            } else Modifier
        )
        .heightIn(min = 48.dp)
        .padding(start = 24.dp, end = 12.dp, top = 4.dp, bottom = 4.dp)
    Row(base, verticalAlignment = Alignment.CenterVertically) {
        Text(
            if (tappable) "|-> " else "|   ",
            color = ide.dim, fontSize = Type.label, fontFamily = Mono
        )
        Text(
            label,
            color = when {
                isImport -> ide.amber
                tappable -> ide.cyan
                else -> ide.dim2
            },
            fontSize = Type.label, fontFamily = Mono,
            maxLines = 1, overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f)
        )
        Spacer(Modifier.width(8.dp))
        Text(
            if (isImport) "import" else hexFmt(addr),
            color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
            modifier = if (isImport) Modifier
                .background(ide.amber.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                .padding(horizontal = 6.dp, vertical = 2.dp)
            else Modifier
        )
    }
}

package com.trickhook.ui

import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.AccountTree
import androidx.compose.material.icons.filled.Fullscreen
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Subject
import androidx.compose.material.icons.filled.ZoomIn
import androidx.compose.material.icons.filled.ZoomOut
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathEffect
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.layout.onSizeChanged
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.trickhook.model.CfgBlock
import com.trickhook.vm.StudioViewModel

private data class NodePos(
    val block: CfgBlock, val x: Float, val y: Float, val depth: Int, val kind: String
)

/**
 * Graph geometry is expressed in density-independent units: one world unit is
 * one dp, and the draw transform multiplies by `density * graphScale`. Node
 * text can therefore be sized off the shared [Type] scale and still honour the
 * user's font-size setting — the old code drew at a raw `textSize = 22f`, which
 * is seven dp of text on a three-times-density phone no matter what the system
 * font scale says.
 */
private const val GAP_X = 54f
private const val GAP_Y = 22f

/** The four kinds, in legend order. The legend is generated from this list. */
private val BLOCK_KINDS = listOf("entry", "exit", "branch", "normal")

private fun blockKind(b: CfgBlock, entryAddr: Long): String = when {
    b.start == entryAddr -> "entry"
    b.succ.isEmpty() -> "exit"
    b.succ.size > 1 -> "branch"
    else -> "normal"
}

/**
 * The word for a kind. Colour is never the only carrier of this information:
 * the word is drawn inside the node, the legend is built from the same pair,
 * and each kind also gets a distinct marker shape in [drawNode].
 */
private fun kindLabel(kind: String): String = when (kind) {
    "entry" -> "entry"
    "exit" -> "exit"
    "branch" -> "branch"
    else -> "linear"
}

/**
 * Entry used to be `ide.accent` — hot pink in dark, crimson in light — while
 * the legend underneath it said "green=entry". `ide.entry` is the real jade
 * token (9.07:1 on the dark background, 5.20:1 on the light one).
 */
private fun kindColor(kind: String, ide: IdeColors): Color = when (kind) {
    "entry" -> ide.entry
    "exit" -> ide.red
    "branch" -> ide.amber
    else -> ide.cyan
}

private fun succText(b: CfgBlock): String =
    if (b.succ.isEmpty()) "-> exit" else "-> " + b.succ.joinToString(", ")

private fun blockDesc(n: NodePos): String =
    "${kindLabel(n.kind)} block L_${hexFmt(n.block.start)}, " +
        "${n.block.nInstr} instructions, ${n.block.succ.size} successors"

private fun graphLayout(
    blocks: List<CfgBlock>, entryAddr: Long, nodeW: Float, nodeH: Float
): Pair<List<NodePos>, Map<Int, NodePos>> {
    if (blocks.isEmpty()) return emptyList<NodePos>() to emptyMap()
    val byId = blocks.associateBy { it.id }
    val depth = HashMap<Int, Int>()
    val start = blocks.minOf { it.id }
    val queue = ArrayDeque<Int>()
    queue.add(start)
    depth[start] = 0
    while (queue.isNotEmpty()) {
        val id = queue.removeFirst()
        val d = depth[id] ?: 0
        byId[id]?.succ?.forEach { s ->
            if (byId.containsKey(s) && !depth.containsKey(s)) {
                depth[s] = d + 1
                queue.add(s)
            }
        }
    }
    var nextDepth = (depth.values.maxOrNull() ?: -1) + 1
    byId.keys.sorted().forEach { id ->
        if (!depth.containsKey(id)) depth[id] = nextDepth++
    }
    val perDepth = HashMap<Int, Int>()
    val nodes = blocks.map { b ->
        val d = depth[b.id] ?: 0
        val row = perDepth.getOrDefault(d, 0)
        perDepth[d] = row + 1
        NodePos(b, d * (nodeW + GAP_X), row * (nodeH + GAP_Y), d, blockKind(b, entryAddr))
    }
    return nodes to nodes.associateBy { it.block.id }
}

@Composable
fun GraphPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val d = vm.detail
    val density = LocalDensity.current
    val dens = density.density
    // Nodes grow with the font scale, because the text inside them does.
    val fs = density.fontScale.coerceIn(1f, 2f)
    val nodeW = 24f + 128f * fs
    val nodeH = 16f + 44f * fs

    var listView by remember { mutableStateOf(false) }
    var showGoto by remember { mutableStateOf(false) }
    var selected by remember(d?.addr) { mutableStateOf<Int?>(null) }
    var vpW by remember { mutableFloatStateOf(0f) }
    var vpH by remember { mutableFloatStateOf(0f) }

    val hasGraph = d != null && d.blocks.isNotEmpty()
    val nodes = remember(d?.addr, d?.blocks?.size, nodeW) {
        if (d == null) emptyList<NodePos>() to emptyMap<Int, NodePos>()
        else graphLayout(d.blocks, d.addr, nodeW, nodeH)
    }
    val nodes0 = nodes.first
    val byId = nodes.second
    val worldW = remember(nodes0) { (nodes0.maxOfOrNull { it.x + nodeW } ?: 1f) + 16f }
    val worldH = remember(nodes0) { (nodes0.maxOfOrNull { it.y + nodeH } ?: 1f) + 16f }

    fun applyFit() {
        if (vpW <= 0f || vpH <= 0f || nodes0.isEmpty()) return
        val s = minOf(vpW / (worldW * dens), vpH / (worldH * dens)).coerceIn(0.2f, 1.6f)
        vm.graphScale = s
        vm.graphPanX = 12f
        vm.graphPanY = 12f
    }

    fun zoomBy(z: Float) {
        val old = vm.graphScale
        val next = (old * z).coerceIn(0.2f, 4f)
        if (next == old) return
        // Zoom about the middle of the viewport, not about world (0,0), so the
        // graph does not slide off screen as it grows.
        val k = next / old
        vm.graphPanX = vpW / 2f - (vpW / 2f - vm.graphPanX) * k
        vm.graphPanY = vpH / 2f - (vpH / 2f - vm.graphPanY) * k
        vm.graphScale = next
    }

    fun centerOn(n: NodePos) {
        val ws = vm.graphScale * dens
        val w = if (vpW > 0f) vpW else 900f
        val h = if (vpH > 0f) vpH else 600f
        vm.graphPanX = w / 2f - (n.x + nodeW / 2f) * ws
        vm.graphPanY = h / 2f - (n.y + nodeH / 2f) * ws
    }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "CFG " + (d?.displayName?.ifEmpty { d.name } ?: "no function"),
                color = ide.text, fontSize = Type.label, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.weight(1f)
            )
            IconButton(onClick = { showGoto = !showGoto }, enabled = hasGraph) {
                Icon(
                    Icons.Filled.Search, contentDescription = "Jump to address",
                    tint = if (showGoto) ide.accent else ide.dim, modifier = Modifier.size(18.dp)
                )
            }
            IconButton(onClick = { zoomBy(0.8f) }, enabled = hasGraph) {
                Icon(Icons.Filled.ZoomOut, contentDescription = "Zoom out", tint = ide.dim, modifier = Modifier.size(18.dp))
            }
            IconButton(onClick = { zoomBy(1.25f) }, enabled = hasGraph) {
                Icon(Icons.Filled.ZoomIn, contentDescription = "Zoom in", tint = ide.dim, modifier = Modifier.size(18.dp))
            }
            IconButton(onClick = { applyFit() }, enabled = hasGraph) {
                Icon(Icons.Filled.Fullscreen, contentDescription = "Fit graph to screen", tint = ide.dim, modifier = Modifier.size(18.dp))
            }
            IconButton(onClick = { listView = !listView }, enabled = hasGraph) {
                Icon(
                    if (listView) Icons.Filled.AccountTree else Icons.Filled.Subject,
                    contentDescription = if (listView) "Show the diagram" else "Show the blocks as a list",
                    tint = if (listView) ide.accent else ide.dim, modifier = Modifier.size(18.dp)
                )
            }
        }

        if (showGoto && hasGraph) {
            var search by remember(d?.addr) { mutableStateOf("") }
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(ide.panel)
                    .padding(horizontal = 10.dp, vertical = 4.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = search,
                    onValueChange = { search = it },
                    placeholder = { Text("address, e.g. 401a20", fontSize = Type.caption, color = ide.dim2) },
                    singleLine = true,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .semantics { contentDescription = "Virtual address to jump to, hexadecimal" },
                    textStyle = TextStyle(fontSize = Type.label, fontFamily = Mono, color = ide.text)
                )
                TextButton(
                    onClick = {
                        val v = search.trim().removePrefix("0x").removePrefix("0X").toLongOrNull(16)
                        if (v == null) vm.log("WARN", "Not a hex address: ${search.trim()}")
                        else vm.requestGoto(v)
                    },
                    modifier = Modifier.heightIn(min = 48.dp)
                ) { Text("Go", fontSize = Type.label) }
            }
        }

        if (d == null || d.blocks.isEmpty()) {
            EmptyPanel(
                if (d == null) "No function selected"
                else "This function has no control-flow graph",
                "Pick a function in the Functions tab or the drawer. " +
                    "The graph is drag-to-rearrange, pinch-to-zoom, and has a list view for screen readers."
            )
        } else {
            val offsets = remember(d.addr) { mutableStateMapOf<Int, Offset>() }
            // The one address we have already gone looking for. Without it a
            // request whose function fails to decompile stays parked and yanks
            // the viewport the next time the user picks any other function --
            // which is exactly what the deleted process-global did.
            var gotoTried by remember { mutableStateOf<Long?>(null) }

            // ---- external requests, now owned by the ViewModel ----------------
            LaunchedEffect(vm.gotoAddr, d.addr, nodes0, vpW) {
                val g = vm.gotoAddr ?: return@LaunchedEffect
                val n = nodes0.firstOrNull { g >= it.block.start && g < it.block.end }
                if (n != null) {
                    vm.consumeGoto()
                    gotoTried = null
                    selected = n.block.id
                    centerOn(n)
                    return@LaunchedEffect
                }
                // Not in this function: load the one that does contain it and
                // let this effect run again once its blocks arrive. A request
                // nothing can satisfy is dropped here and reported, never left
                // parked to fire minutes later.
                val f = vm.functionContaining(g)
                when {
                    // The only function that can satisfy this is still being
                    // decompiled. Wait for its blocks rather than calling the
                    // address missing.
                    f != null && f.addr != d.addr &&
                        vm.selectedFunc == f.addr && vm.detailBusy -> Unit
                    f == null || f.addr == d.addr || gotoTried == g -> {
                        vm.consumeGoto()
                        gotoTried = null
                        vm.log("WARN", "No block contains 0x${hexFmt(g)}")
                    }
                    else -> {
                        gotoTried = g
                        vm.navigateTo(addr = f.addr)
                    }
                }
            }
            LaunchedEffect(vm.graphZoomReq) {
                val z = vm.graphZoomReq
                if (z != 1f) {
                    vm.graphZoomReq = 1f
                    zoomBy(z)
                }
            }
            LaunchedEffect(vm.graphFitReq, vpW, vpH) {
                if (vm.graphFitReq && vpW > 0f) {
                    vm.graphFitReq = false
                    applyFit()
                }
            }
            // First sight of a graph, or a viewport the graph has drifted
            // entirely out of: frame it. Otherwise the hoisted pan and zoom are
            // left exactly as the user left them.
            LaunchedEffect(d.addr, nodes0, vpW, vpH) {
                if (vpW <= 0f || vpH <= 0f) return@LaunchedEffect
                val ws = vm.graphScale * dens
                val onScreen = vm.graphPanX + worldW * ws > 0f && vm.graphPanX < vpW &&
                    vm.graphPanY + worldH * ws > 0f && vm.graphPanY < vpH
                val untouched = vm.graphScale == 1f && vm.graphPanX == 0f && vm.graphPanY == 0f
                if (untouched || !onScreen) applyFit()
            }

            if (listView) {
                // weight(1f), never fillMaxSize: an unweighted child of a Column
                // eats the whole remaining height and squeezes the legend below
                // it to nothing.
                BlockList(Modifier.weight(1f), nodes0, selected, ide) { n ->
                    selected = n.block.id
                    centerOn(n)
                }
            } else {
                val titlePaint = remember(fs) {
                    android.graphics.Paint().apply {
                        isAntiAlias = true
                        typeface = Typeface.MONOSPACE
                        textSize = Type.mono.value * fs
                    }
                }
                val bodyPaint = remember(fs) {
                    android.graphics.Paint().apply {
                        isAntiAlias = true
                        typeface = Typeface.MONOSPACE
                        textSize = Type.monoSmall.value * fs
                    }
                }
                val counts = remember(nodes0) { nodes0.groupingBy { it.kind }.eachCount() }
                val selDesc = selected?.let { id -> byId[id]?.let { ", selected: " + blockDesc(it) } } ?: ""
                val graphDesc = "Control-flow graph, ${nodes0.size} blocks, " +
                    "${nodes0.sumOf { it.block.succ.size }} edges. " +
                    BLOCK_KINDS.filter { (counts[it] ?: 0) > 0 }
                        .joinToString(", ") { "${counts[it]} ${kindLabel(it)}" } +
                    selDesc + ". Open the list view for block-by-block navigation."

                Box(
                    Modifier
                        .weight(1f)
                        .fillMaxWidth()
                        .clipToBounds()
                        .onSizeChanged { vpW = it.width.toFloat(); vpH = it.height.toFloat() }
                        .pointerInput(Unit) {
                            detectTransformGestures { _, pan, zoom, _ ->
                                vm.graphScale = (vm.graphScale * zoom).coerceIn(0.2f, 4f)
                                vm.graphPanX += pan.x
                                vm.graphPanY += pan.y
                            }
                        }
                ) {
                    Canvas(
                        Modifier
                            .fillMaxSize()
                            .semantics { contentDescription = graphDesc }
                            .pointerInput(d.addr, nodeW) {
                                detectTapGestures(
                                    onTap = { tap ->
                                        val ws = vm.graphScale * dens
                                        val gx = (tap.x - vm.graphPanX) / ws
                                        val gy = (tap.y - vm.graphPanY) / ws
                                        val hit = nodes0.firstOrNull { n ->
                                            val o = offsets[n.block.id] ?: Offset.Zero
                                            gx >= n.x + o.x && gx <= n.x + o.x + nodeW &&
                                                gy >= n.y + o.y && gy <= n.y + o.y + nodeH
                                        }
                                        selected = hit?.block?.id
                                    }
                                )
                            }
                            .pointerInput(d.addr, nodeW) {
                                detectDragGestures { change, drag ->
                                    change.consume()
                                    val ws = vm.graphScale * dens
                                    val gx = (change.previousPosition.x - vm.graphPanX) / ws
                                    val gy = (change.previousPosition.y - vm.graphPanY) / ws
                                    val hit = nodes0.firstOrNull { n ->
                                        val o = offsets[n.block.id] ?: Offset.Zero
                                        gx >= n.x + o.x && gx <= n.x + o.x + nodeW &&
                                            gy >= n.y + o.y && gy <= n.y + o.y + nodeH
                                    }
                                    if (hit != null) {
                                        val cur = offsets[hit.block.id] ?: Offset.Zero
                                        offsets[hit.block.id] = cur + drag / ws
                                    } else {
                                        vm.graphPanX += drag.x
                                        vm.graphPanY += drag.y
                                    }
                                }
                            }
                    ) {
                        withTransform({
                            translate(vm.graphPanX, vm.graphPanY)
                            val ws = vm.graphScale * dens
                            scale(ws, ws, pivot = Offset.Zero)
                        }) {
                            nodes0.forEach { n ->
                                val o1 = offsets[n.block.id] ?: Offset.Zero
                                n.block.succ.forEach { sId ->
                                    val t = byId[sId] ?: return@forEach
                                    val o2 = offsets[sId] ?: Offset.Zero
                                    val from = Offset(n.x + o1.x + nodeW, n.y + o1.y + nodeH / 2)
                                    val to = Offset(t.x + o2.x, t.y + o2.y + nodeH / 2)
                                    // A back edge is violet AND dashed: two
                                    // channels, so it survives colour blindness.
                                    val back = (t.y + o2.y) <= (n.y + o1.y)
                                    drawEdge(from, to, if (back) ide.violet else ide.dim, back)
                                }
                            }
                            nodes0.forEach { n ->
                                val o = offsets[n.block.id] ?: Offset.Zero
                                drawNode(
                                    n, n.x + o.x, n.y + o.y, nodeW, nodeH, fs,
                                    selected == n.block.id, ide, titlePaint, bodyPaint
                                )
                            }
                        }
                    }

                    Canvas(
                        Modifier
                            .align(Alignment.BottomEnd)
                            .padding(8.dp)
                            .size(width = 150.dp, height = 88.dp)
                            // It floats over the graph and you can drag it, so
                            // it needs an edge that actually reads as one.
                            .clip(RoundedCornerShape(4.dp))
                            .background(ide.panel.copy(alpha = 0.92f))
                            .border(1.dp, ide.borderStrong, RoundedCornerShape(4.dp))
                            .pointerInput(nodeW) {
                                detectDragGestures { change, amt ->
                                    change.consume()
                                    val mm = minOf(150f / worldW, 88f / worldH)
                                    if (mm > 0f) {
                                        vm.graphPanX -= amt.x / mm * vm.graphScale
                                        vm.graphPanY -= amt.y / mm * vm.graphScale
                                    }
                                }
                            }
                    ) {
                        // dp per world unit, then dp -> px for this untransformed canvas
                        val mm = minOf(150f / worldW, 88f / worldH) * dens
                        nodes0.forEach { n ->
                            val o = offsets[n.block.id] ?: Offset.Zero
                            drawRect(
                                color = kindColor(n.kind, ide).copy(alpha = 0.8f),
                                topLeft = Offset((n.x + o.x) * mm + 2f, (n.y + o.y) * mm + 2f),
                                size = Size(
                                    (nodeW * mm - 3f).coerceAtLeast(1f),
                                    (nodeH * mm - 3f).coerceAtLeast(1f)
                                )
                            )
                        }
                        val ws = vm.graphScale * dens
                        if (ws > 0f && vpW > 0f) {
                            drawRect(
                                color = ide.text,
                                topLeft = Offset(-vm.graphPanX / ws * mm, -vm.graphPanY / ws * mm),
                                size = Size(vpW / ws * mm, vpH / ws * mm),
                                style = Stroke(width = 1.5.dp.toPx())
                            )
                        }
                    }
                }
            }

            GraphLegend(ide, d.blocks.size, d.asm.size)
        }
    }
}

/**
 * The legend is generated from the same [BLOCK_KINDS] / [kindColor] pair the
 * nodes are drawn with, so it cannot go back to naming a colour that is not on
 * screen — which is what "green=entry" did for as long as entry was pink.
 */
@Composable
private fun GraphLegend(ide: IdeColors, blocks: Int, instrs: Int) {
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            // Pinned to the bottom of the window under forced edge-to-edge, so
            // it has to clear the gesture pill itself.
            .navigationBarsPadding()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 10.dp, vertical = 5.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            "$blocks blocks · $instrs instr",
            color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
        )
        BLOCK_KINDS.forEach { k ->
            Spacer(Modifier.width(10.dp))
            Box(
                Modifier
                    .size(9.dp)
                    .background(kindColor(k, ide), RoundedCornerShape(2.dp))
            )
            Spacer(Modifier.width(4.dp))
            Text(kindLabel(k), color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1)
        }
        Spacer(Modifier.width(10.dp))
        Text(
            "dashed · back edge",
            color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
        )
    }
}

/**
 * The same graph as text. A Canvas is one opaque rectangle to TalkBack however
 * it is labelled, so the blocks are also reachable as real focusable rows.
 */
@Composable
private fun BlockList(
    modifier: Modifier,
    nodes: List<NodePos>,
    selected: Int?,
    ide: IdeColors,
    onPick: (NodePos) -> Unit
) {
    LazyColumn(
        modifier
            .fillMaxWidth()
            .background(ide.bg),
        contentPadding = bottomInset(12.dp)
    ) {
        items(nodes.size) { i ->
            val n = nodes[i]
            val c = kindColor(n.kind, ide)
            Row(
                Modifier
                    .fillMaxWidth()
                    .selectable(
                        selected = selected == n.block.id,
                        role = Role.Button,
                        onClick = { onPick(n) }
                    )
                    .background(if (selected == n.block.id) ide.panel2 else Color.Transparent)
                    .heightIn(min = 48.dp)
                    .padding(horizontal = 12.dp, vertical = 6.dp)
                    .semantics { contentDescription = blockDesc(n) },
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    kindLabel(n.kind),
                    color = c, fontSize = Type.caption, fontFamily = Mono, maxLines = 1,
                    modifier = Modifier
                        .background(c.copy(alpha = 0.12f), RoundedCornerShape(4.dp))
                        .padding(horizontal = 6.dp, vertical = 3.dp)
                )
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        "L_" + hexFmt(n.block.start),
                        color = ide.text, fontSize = Type.mono, fontFamily = Mono, maxLines = 1
                    )
                    Text(
                        "${n.block.nInstr} instr · ${succText(n.block)}",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
                    )
                }
                // The successor arrows above are block ids, so the row has to
                // say which id it is or they point at nothing.
                Text(
                    "#" + n.block.id,
                    color = ide.dim, fontSize = Type.caption, fontFamily = Mono, maxLines = 1
                )
            }
        }
        item {
            Text(
                "Tap a block to select it and centre the diagram on it.",
                color = ide.dim2, fontSize = Type.caption,
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)
            )
        }
    }
}

private fun DrawScope.drawEdge(from: Offset, to: Offset, color: Color, dashed: Boolean) {
    val effect = if (dashed) PathEffect.dashPathEffect(floatArrayOf(7f, 5f), 0f) else null
    val midX = (from.x + to.x) / 2
    drawLine(color, from, Offset(midX, from.y), strokeWidth = 1.5f, pathEffect = effect)
    drawLine(color, Offset(midX, from.y), Offset(midX, to.y), strokeWidth = 1.5f, pathEffect = effect)
    drawLine(color, Offset(midX, to.y), to, strokeWidth = 1.5f, pathEffect = effect)
    val p = Path().apply {
        moveTo(to.x, to.y)
        lineTo(to.x - 7f, to.y - 4f)
        lineTo(to.x - 7f, to.y + 4f)
        close()
    }
    drawPath(p, color)
}

/**
 * Kind reaches the eye three ways: the stroke colour, a marker shape (an arrow
 * feeding an entry, a fork leaving a branch, a doubled outline on an exit) and
 * the kind word printed in the node. Colour alone failed for anyone who cannot
 * separate pink from crimson from amber.
 */
private fun DrawScope.drawNode(
    n: NodePos, x: Float, y: Float, w: Float, h: Float, fs: Float,
    selected: Boolean, ide: IdeColors,
    title: android.graphics.Paint, body: android.graphics.Paint
) {
    val c = kindColor(n.kind, ide)
    val radius = CornerRadius(6f, 6f)
    drawRoundRect(
        color = if (selected) ide.accent.copy(alpha = 0.18f) else ide.panel2,
        topLeft = Offset(x, y), size = Size(w, h), cornerRadius = radius
    )
    drawRoundRect(
        color = c, topLeft = Offset(x, y), size = Size(w, h), cornerRadius = radius,
        style = Stroke(width = if (selected) 2.5f else 1.5f)
    )
    // Every node gets a filled leading edge; entry gets a fat one plus a solid
    // top band, exit a doubled outline, branch a fork on the side the two
    // successors leave from. All of it stays inside the node's own box except
    // the fork, which has the whole column gap to itself.
    val barW = if (n.kind == "entry") 8f else 3f
    drawRect(color = c, topLeft = Offset(x, y + 6f), size = Size(barW, h - 12f))
    when (n.kind) {
        "entry" -> drawRect(
            color = c, topLeft = Offset(x + barW, y + 1.5f),
            size = Size(w - barW - 3f, 3f)
        )
        "exit" -> drawRoundRect(
            color = c, topLeft = Offset(x + 4f, y + 4f),
            size = Size(w - 8f, h - 8f), cornerRadius = CornerRadius(4f, 4f),
            style = Stroke(width = 1f)
        )
        "branch" -> drawPath(
            Path().apply {
                moveTo(x + w + 1f, y + h / 2 - 6f)
                lineTo(x + w + 11f, y + h / 2)
                lineTo(x + w + 1f, y + h / 2 + 6f)
                close()
            }, c
        )
    }
    drawIntoCanvas { canvas ->
        val nc = canvas.nativeCanvas
        val pad = 12f
        val b1 = pad + Type.mono.value * fs
        val b2 = b1 + 15f * fs
        val b3 = b2 + 13f * fs
        title.color = ide.text.toArgb()
        nc.drawText("L_" + hexFmt(n.block.start), x + pad, y + b1, title)
        body.color = c.toArgb()
        val tag = kindLabel(n.kind)
        nc.drawText(tag, x + w - pad - body.measureText(tag), y + b1, body)
        body.color = ide.dim.toArgb()
        nc.drawText("${n.block.nInstr} instr", x + pad, y + b2, body)
        body.color = ide.dim2.toArgb()
        nc.drawText(succText(n.block), x + pad, y + b3, body)
    }
}

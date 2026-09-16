package com.trickhook.ui

import android.graphics.Typeface
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.gestures.detectTapGestures
import androidx.compose.foundation.gestures.detectTransformGestures
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clipToBounds
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.DrawScope
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.drawIntoCanvas
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.graphics.nativeCanvas
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.model.CfgBlock
import com.trickhook.vm.StudioViewModel

private data class NodePos(
    val block: CfgBlock, val x: Float, val y: Float, val depth: Int, val kind: String
)

private const val NW = 190f
private const val NH = 70f
private const val GX = 80f
private const val GY = 46f

private fun blockKind(b: CfgBlock, entryAddr: Long): String = when {
    b.start == entryAddr -> "entry"
    b.succ.isEmpty() -> "exit"
    b.succ.size > 1 -> "branch"
    else -> "normal"
}

private fun graphLayout(blocks: List<CfgBlock>, entryAddr: Long):
        Pair<List<NodePos>, Map<Int, NodePos>> {
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
        NodePos(b, d * (NW + GX), row * (NH + GY), d, blockKind(b, entryAddr))
    }
    return nodes to nodes.associateBy { it.block.id }
}

private fun kindColor(kind: String, ide: IdeColors): Color = when (kind) {
    "entry" -> ide.accent            // green: entry block
    "exit" -> ide.red                // red: return/exit
    "branch" -> ide.amber            // amber: conditional
    else -> ide.cyan                 // cyan: straight-line
}

@Composable
fun GraphPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val d = vm.detail
    Column(Modifier.fillMaxSize()) {
        // toolbar: search + zoom + function label
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 8.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "CFG · " + (d?.displayName?.ifEmpty { d.name } ?: "—"),
                color = ide.text, fontSize = 12.sp, fontFamily = Mono
            )
            Spacer(Modifier.width(8.dp))
            var search by remember(d?.addr) { mutableStateOf("") }
            OutlinedTextField(
                value = search,
                onValueChange = { search = it },
                placeholder = { Text("jump to addr…", fontSize = 10.sp, color = ide.dim) },
                singleLine = true,
                modifier = Modifier.weight(1f).height(48.dp),
                textStyle = TextStyle(fontSize = 11.sp, fontFamily = Mono, color = ide.text)
            )
            TextButton(onClick = {
                val v = search.removePrefix("0x").toLongOrNull(16)
                if (v != null) gotoRequest = v
            }) { Text("Go", fontSize = 11.sp) }
            TextButton(onClick = { zoomReq = 1.25f }) { Text("＋", color = ide.text) }
            TextButton(onClick = { zoomReq = 0.8f }) { Text("－", color = ide.text) }
            TextButton(onClick = { fitReq = true }) { Text("Fit", color = ide.accent, fontSize = 11.sp) }
        }
        if (d == null || d.blocks.isEmpty()) {
            Hint(
                "Select a function to see its Control Flow Graph — dooro shaqo si aad u arkid graph-ka.",
                "Drag nodes · pinch zoom · colored: green=entry, red=exit, amber=branch."
            )
        } else {
            val (nodes0, byId) = remember(d.addr, d.blocks.size) { graphLayout(d.blocks, d.addr) }
            var scale by remember { mutableFloatStateOf(0.85f) }
            var off by remember { mutableStateOf(Offset.Zero) }
            val offsets = remember(d.addr) { mutableStateMapOf<Int, Offset>() }
            var selected by remember(d.addr) { mutableStateOf<Int?>(null) }

            // external requests from toolbar / command palette
            val goto = gotoRequest
            if (goto != null) {
                gotoRequest = null
                val n = nodes0.firstOrNull { goto >= it.block.start && goto < it.block.end }
                if (n != null) {
                    selected = n.block.id
                    off = Offset(-n.x * 0.85f + 300f, -n.y * 0.85f + 200f)
                    scale = 0.85f
                }
            }
            val zr = zoomReq
            if (zr != 1f) {
                zoomReq = 1f
                scale = (scale * zr).coerceIn(0.2f, 4f)
            }
            if (fitReq) {
                fitReq = false
                val maxX = nodes0.maxOf { it.x + NW }
                val maxY = nodes0.maxOf { it.y + NH }
                if (maxX > 0 && maxY > 0) scale = 0.85f
                off = Offset(60f, 40f)
            }

            val paint = remember {
                android.graphics.Paint().apply {
                    isAntiAlias = true; textSize = 22f; typeface = Typeface.MONOSPACE
                }
            }
            val labelPaint = remember {
                android.graphics.Paint().apply {
                    isAntiAlias = true; textSize = 16f; typeface = Typeface.MONOSPACE
                }
            }

            Box(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .clipToBounds()
                    .pointerInput(Unit) {
                        detectTransformGestures { _, pan, zoom, _ ->
                            scale = (scale * zoom).coerceIn(0.2f, 4f)
                            off += pan
                        }
                    }
            ) {
                Canvas(
                    Modifier
                        .fillMaxSize()
                        .pointerInput(d.addr) {
                            detectTapGestures(
                                onTap = { tap ->
                                    // canvas -> graph coords
                                    val gx = (tap.x - off.x) / scale
                                    val gy = (tap.y - off.y) / scale
                                    val hit = nodes0.firstOrNull { n ->
                                        val o = offsets[n.block.id] ?: Offset.Zero
                                        gx >= n.x + o.x && gx <= n.x + o.x + NW &&
                                            gy >= n.y + o.y && gy <= n.y + o.y + NH
                                    }
                                    selected = hit?.block?.id
                                }
                            )
                        }
                        .pointerInput(d.addr) {
                            detectDragGestures { change, drag ->
                                change.consume()
                                val gx = (change.previousPosition.x - off.x) / scale
                                val gy = (change.previousPosition.y - off.y) / scale
                                val hit = nodes0.firstOrNull { n ->
                                    val o = offsets[n.block.id] ?: Offset.Zero
                                    gx >= n.x + o.x && gx <= n.x + o.x + NW &&
                                        gy >= n.y + o.y && gy <= n.y + o.y + NH
                                }
                                if (hit != null) {
                                    val cur = offsets[hit.block.id] ?: Offset.Zero
                                    offsets[hit.block.id] = cur + drag
                                } else {
                                    off += drag
                                }
                            }
                        }
                ) {
                    withTransform({
                        translate(off.x, off.y)
                        scale(scale, scale, pivot = Offset.Zero)
                    }) {
                        // edges
                        nodes0.forEach { n ->
                            val o1 = offsets[n.block.id] ?: Offset.Zero
                            n.block.succ.forEach { sId ->
                                val t = byId[sId] ?: return@forEach
                                val o2 = offsets[sId] ?: Offset.Zero
                                val from = Offset(n.x + o1.x + NW, n.y + o1.y + NH / 2)
                                val to = Offset(t.x + o2.x, t.y + o2.y + NH / 2)
                                val back = (t.y + o2.y) <= (n.y + o1.y)
                                drawEdge(from, to, if (back) ide.violet else ide.dim)
                            }
                        }
                        // nodes
                        nodes0.forEach { n ->
                            val o = offsets[n.block.id] ?: Offset.Zero
                            val x = n.x + o.x
                            val y = n.y + o.y
                            val fill = if (selected == n.block.id)
                                ide.accent.copy(alpha = 0.20f) else ide.panel2
                            drawRoundRect(
                                color = fill, topLeft = Offset(x, y),
                                size = Size(NW, NH), cornerRadius = CornerRadius(10f, 10f)
                            )
                            drawRoundRect(
                                color = kindColor(n.kind, ide), topLeft = Offset(x, y),
                                size = Size(NW, NH), cornerRadius = CornerRadius(10f, 10f),
                                style = Stroke(width = if (selected == n.block.id) 4f else 2.5f)
                            )
                            drawNodeText(paint, labelPaint, n, x, y, ide)
                        }
                    }
                }

                // minimap (bottom-right)
                Canvas(Modifier
                    .align(Alignment.BottomEnd)
                    .padding(8.dp)
                    .size(width = 170.dp, height = 100.dp)
                    .background(ide.panel.copy(alpha = 0.85f))
                    .pointerInput(Unit) {
                        detectDragGestures { change, amt ->
                            change.consume()
                            off -= amt / scale * 1.2f
                        }
                    }
                ) {
                    val canvasW = size.width
                    val canvasH = size.height
                    val maxX = nodes0.maxOf { it.x + NW } + 40f
                    val maxY = nodes0.maxOf { it.y + NH } + 40f
                    val sx = canvasW / maxX
                    val sy = canvasH / maxY
                    val s = minOf(sx, sy)
                    nodes0.forEach { n ->
                        val o = offsets[n.block.id] ?: Offset.Zero
                        drawRect(
                            color = kindColor(n.kind, ide).copy(alpha = 0.75f),
                            topLeft = Offset((n.x + o.x) * s + 2f, (n.y + o.y) * s + 2f),
                            size = Size(NW * s - 3f, NH * s - 3f)
                        )
                    }
                    // viewport box: visible world size ~ canvas size/scale
                    val vpW = this@Canvas.size.width / scale * s
                    val vpH = this@Canvas.size.height / scale * s
                    drawRect(
                        color = ide.text.copy(alpha = 0.9f),
                        topLeft = Offset(-off.x / scale * s, -off.y / scale * s),
                        size = Size(vpW, vpH),
                        style = Stroke(width = 2f)
                    )
                }
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(ide.panel)
                    .padding(horizontal = 10.dp, vertical = 2.dp)
            ) {
                Text(
                    "${d.blocks.size} blocks · ${d.asm.size} instr · green=entry red=exit amber=branch · drag nodes to rearrange",
                    color = ide.dim, fontSize = 10.sp, fontFamily = Mono
                )
            }
        }
    }
}

// cross-panel graph requests
var gotoRequest by mutableStateOf<Long?>(null)
var zoomReq by mutableStateOf(1f)
var fitReq by mutableStateOf(false)

private fun DrawScope.drawEdge(from: Offset, to: Offset, color: Color) {
    val midX = (from.x + to.x) / 2
    drawLine(color, from, Offset(midX, from.y), strokeWidth = 3f)
    drawLine(color, Offset(midX, from.y), Offset(midX, to.y), strokeWidth = 3f)
    drawLine(color, Offset(midX, to.y), to, strokeWidth = 3f)
    val p = Path().apply {
        moveTo(to.x, to.y)
        lineTo(to.x - 14f, to.y - 7f)
        lineTo(to.x - 14f, to.y + 7f)
        close()
    }
    drawPath(p, color)
}

private fun DrawScope.drawNodeText(
    paint: android.graphics.Paint,
    labelPaint: android.graphics.Paint,
    n: NodePos, x: Float, y: Float,
    ide: IdeColors
) {
    drawIntoCanvas { c ->
        val nc = c.nativeCanvas
        paint.color = toArgb(kindColor(n.kind, ide))
        nc.drawText("L_" + hexFmt(n.block.start), x + 10, y + 24, paint)
        paint.color = toArgb(ide.text)
        nc.drawText("${n.block.nInstr} instr", x + 10, y + 46, paint)
        labelPaint.color = toArgb(ide.dim)
        nc.drawText(
            "-> ${n.block.succ.joinToString(",") { it.toString() }.ifEmpty { "exit" }}",
            x + 10, y + 64, labelPaint
        )
    }
}

private fun toArgb(c: Color): Int = android.graphics.Color.argb(
    (c.alpha * 255).toInt(), (c.red * 255).toInt(), (c.green * 255).toInt(), (c.blue * 255).toInt()
)

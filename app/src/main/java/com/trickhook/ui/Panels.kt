package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.ExperimentalFoundationApi
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Subject
import androidx.compose.material3.Icon
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Size
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.model.AsmLine
import com.trickhook.vm.StudioViewModel
import kotlinx.coroutines.launch

// ========================================================== Assembly panel ==
@OptIn(ExperimentalFoundationApi::class)
@Composable
fun AssemblyPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta
    val d = vm.detail
    val ctx = LocalContext.current

    // annotation dialog state
    var annotateAddr by remember { mutableStateOf<Long?>(null) }

    Column(Modifier.fillMaxSize()) {
        // function picker row
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            FunctionPicker(vm)
            Spacer(Modifier.weight(1f))
            Text(
                d?.backend ?: meta?.backend ?: "",
                color = ide.dim, fontSize = 10.sp, fontFamily = Mono
            )
            if (vm.detailBusy) {
                Spacer(Modifier.width(8.dp))
                CircularProgressIndicator(color = ide.accent, modifier = Modifier.size(16.dp))
            }
        }

        if (d == null) {
            Hint(
                "Select a function to disassemble.",
                "Capstone engine: ${meta?.backend ?: "-"} · arch: ${meta?.arch ?: "-"} · long-press a line to rename/comment/bookmark"
            )
        } else {
            // trace controls (simple step-through player)
            var step by remember(d.addr) { mutableStateOf(-1) }
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(ide.panel)
                    .padding(horizontal = 10.dp, vertical = 2.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text("TRACE", color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                Spacer(Modifier.width(8.dp))
                TextButton(onClick = { if (step > -1) step-- }, enabled = step >= 0) { Text("◀ Prev") }
                TextButton(onClick = { if (step < d.asm.size - 1) step++ }, enabled = step < d.asm.size - 1) { Text("Next ▶") }
                TextButton(onClick = { step = -1 }) { Text("Reset") }
                Spacer(Modifier.weight(1f))
                Text(
                    if (step >= 0) "IP: ${hexFmt(d.asm[step].addr)} (${step + 1}/${d.asm.size})" else "-",
                    color = ide.amber, fontSize = 11.sp, fontFamily = Mono
                )
            }
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 11.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
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
                    Text(
                        d.displayName.ifEmpty { d.name },
                        color = ide.text, fontSize = 13.sp, fontFamily = Mono,
                        fontWeight = FontWeight.Medium, maxLines = 1
                    )
                    Text(
                        "${hexFmt(d.addr)} · ${d.size} bytes · ${d.from}",
                        color = ide.dim, fontSize = 10.sp, fontFamily = Mono, maxLines = 1
                    )
                }
                val clip = LocalClipboardManager.current
                Icon(
                    Icons.Filled.ContentCopy, contentDescription = "Copy listing",
                    tint = ide.dim,
                    modifier = Modifier
                        .size(30.dp)
                        .clickable {
                            val text = d.asm.joinToString("\n") { l ->
                                buildString {
                                    append(hexFmt(l.addr)); append("  "); append(l.mnem)
                                    if (l.ops.isNotEmpty()) { append(' '); append(l.ops) }
                                    if (l.comment.isNotEmpty()) { append("    ; "); append(l.comment) }
                                }
                            }
                            clip.setText(AnnotatedString(text))
                            vm.log("OK", "Listing copied to the clipboard (${d.asm.size} lines)")
                        }
                        .padding(6.dp)
                )
            }
            LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
                items(d.asm.size) { i ->
                    val line = d.asm[i]
                    val userComment = vm.comments["0x%08X".format(line.addr)]
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .combinedClickable(
                                onClick = {},
                                onLongClick = { annotateAddr = line.addr }
                            )
                    ) {
                        AsmRow(line, highlighted = i == step)
                        if (userComment != null) {
                            Text(
                                "        ; ${userComment}",
                                color = ide.accent, fontSize = 10.5.sp, fontFamily = Mono,
                                modifier = Modifier.padding(horizontal = 10.dp)
                            )
                        }
                    }
                }
                item { Spacer(Modifier.height(40.dp)) }
            }
        }
    }

    annotateAddr?.let { addr ->
        AnnotateDialog(
            vm = vm,
            addr = addr,
            funcName = d?.displayName?.ifEmpty { d.name } ?: "",
            onDismiss = { annotateAddr = null }
        )
    }
}

@Composable
fun AnnotateDialog(vm: StudioViewModel, addr: Long, funcName: String, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    var comment by remember { mutableStateOf(vm.comments["0x%08X".format(addr)] ?: "") }
    var rename by remember { mutableStateOf("") }
    var bookmark by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        containerColor = ide.panel,
        title = { Text("Annotate @ ${hexFmt(addr)}", color = ide.accent, fontSize = 15.sp, fontFamily = Mono) },
        text = {
            Column {
                if (funcName.isNotEmpty()) {
                    Text("Function: $funcName", color = ide.dim, fontSize = 11.sp, fontFamily = Mono)
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = rename, onValueChange = { rename = it },
                        label = { Text("Rename function…") }, singleLine = true,
                        textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
                    )
                }
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = comment, onValueChange = { comment = it },
                    label = { Text("Comment (empty = delete)") },
                    textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
                )
                Spacer(Modifier.height(6.dp))
                OutlinedTextField(
                    value = bookmark, onValueChange = { bookmark = it },
                    label = { Text("Bookmark label (optional)") }, singleLine = true,
                    textStyle = TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
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

@Composable
private fun FunctionPicker(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta ?: return
    var expanded by remember { mutableStateOf(false) }
    val selectedName = meta.functions.firstOrNull { it.addr == vm.selectedFunc }
        ?.let { vm.renames["0x%08X".format(it.addr)] ?: it.name } ?: "Select function…"
    Box {
        Button(onClick = { expanded = true }) {
            Text(selectedName, fontSize = 12.sp, fontFamily = Mono, maxLines = 1, modifier = Modifier.width(190.dp))
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            if (meta.functions.isEmpty()) {
                DropdownMenuItem(text = { Text("No functions", color = ide.dim) }, onClick = {})
            }
            meta.functions.take(500).forEach { f ->
                val display = vm.renames["0x%08X".format(f.addr)] ?: f.name
                DropdownMenuItem(
                    text = {
                        Row {
                            Text(
                                display, color = ide.text, fontSize = 12.sp, fontFamily = Mono,
                                modifier = Modifier.width(170.dp), maxLines = 1
                            )
                            Spacer(Modifier.width(8.dp))
                            Text(hexFmt(f.addr), color = ide.dim, fontSize = 11.sp, fontFamily = Mono)
                        }
                    },
                    onClick = {
                        expanded = false
                        vm.selectFunction(f.addr)
                    }
                )
            }
        }
    }
}

@Composable
fun AsmRow(line: AsmLine, highlighted: Boolean) {
    val ide = LocalIde.current
    // Raw bytes used to sit between the address and the mnemonic, which left
    // almost no width for operands on a phone. They live in the Hex tab; here
    // the four columns that matter get the space.
    val marker = ide.accent
    Row(
        Modifier
            .fillMaxWidth()
            .background(if (highlighted) marker.copy(alpha = 0.09f) else Color.Transparent)
            .drawBehind {
                if (highlighted) drawRect(marker, size = Size(2.dp.toPx(), size.height))
            }
            .padding(start = 16.dp, end = 12.dp, top = 1.dp, bottom = 1.dp)
    ) {
        Text(
            hexFmt(line.addr), color = ide.dim.copy(alpha = 0.55f), fontSize = 11.sp,
            fontFamily = Mono, modifier = Modifier.width(74.dp)
        )
        Text(
            line.mnem, color = mnemonicColor(line.mnem, ide), fontSize = 11.sp,
            fontFamily = Mono, fontWeight = FontWeight.Medium,
            modifier = Modifier.width(60.dp), maxLines = 1
        )
        Text(
            line.ops, color = ide.text, fontSize = 11.sp, fontFamily = Mono,
            modifier = Modifier.weight(1f), maxLines = 1
        )
        if (line.comment.isNotEmpty()) {
            Spacer(Modifier.width(8.dp))
            Text(
                "; ${line.comment}", color = ide.dim.copy(alpha = 0.55f), fontSize = 10.sp,
                fontFamily = Mono, maxLines = 1
            )
        }
    }
}

// ================================================================ Hex panel ==
@Composable
fun HexPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val data = vm.hexData
    Column(Modifier.fillMaxSize()) {
        var jump by remember { mutableStateOf("") }
        val listState = androidx.compose.foundation.lazy.rememberLazyListState()
        val scope = rememberCoroutineScope()
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            OutlinedTextField(
                value = jump,
                onValueChange = { jump = it },
                label = { Text("Offset (hex)") },
                singleLine = true,
                modifier = Modifier.width(150.dp),
                textStyle = androidx.compose.ui.text.TextStyle(fontSize = 12.sp, fontFamily = Mono, color = ide.text)
            )
            Spacer(Modifier.width(8.dp))
            Button(onClick = {
                val v = jump.removePrefix("0x").toLongOrNull(16) ?: return@Button
                val rows = ((data?.size ?: 0) + 15) / 16
                scope.launch {
                    listState.scrollToItem(((v / 16).toInt()).coerceIn(0, (rows - 1).coerceAtLeast(0)))
                }
            }) { Text("Go") }
            Spacer(Modifier.weight(1f))
            Text(
                "${data?.size ?: 0} / ${vm.meta?.sizeBytes ?: 0} bytes",
                color = ide.dim, fontSize = 10.sp, fontFamily = Mono
            )
        }
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel)
                .padding(horizontal = 10.dp, vertical = 2.dp)
        ) {
            Text("OFFSET", color = ide.dim, fontSize = 10.sp, fontFamily = Mono, modifier = Modifier.width(76.dp))
            Text("00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F   ASCII", color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
        }
        if (data == null) {
            Hint("Open a file to inspect its raw bytes.")
        } else {
            val selStart = vm.detail?.addr ?: -1L
            val selEnd = if (vm.detail != null) vm.detail!!.addr + vm.detail!!.size else -1L
            val rows = (data.size + 15) / 16
            LazyColumn(Modifier.fillMaxSize(), state = listState) {
                items(rows) { r ->
                    HexRow(data, r * 16, selStart, selEnd)
                }
                item { Spacer(Modifier.height(40.dp)) }
            }
        }
    }
}

@Composable
private fun HexRow(data: ByteArray, base: Int, selStart: Long, selEnd: Long) {
    val ide = LocalIde.current
    val count = minOf(16, data.size - base)
    val sb = StringBuilder()
    val ascii = StringBuilder()
    for (i in 0 until 16) {
        if (i < count) {
            val b = data[base + i]
            sb.append(String.format("%02X ", b))
            ascii.append(if (b in 0x20..0x7E) b.toInt().toChar() else '.')
        } else sb.append("   ")
    }
    val inSel = base.toLong() + 16 > selStart && base.toLong() < selEnd
    Column(
        Modifier
            .fillMaxWidth()
            .background(if (inSel) ide.accent.copy(alpha = 0.07f) else Color.Transparent)
            .padding(horizontal = 10.dp, vertical = 1.dp)
    ) {
        Text(
            "${String.format("%08X", base)}  $sb",
            color = ide.text, fontSize = 10.5.sp, fontFamily = Mono, maxLines = 1
        )
        Text(
            "          $ascii",
            color = ide.dim, fontSize = 10.5.sp, fontFamily = Mono, maxLines = 1
        )
    }
}

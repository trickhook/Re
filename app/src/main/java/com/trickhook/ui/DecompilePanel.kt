package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Subject
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.graphics.Color
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.vm.StudioViewModel

private val KEYWORDS = setOf(
    "void", "if", "goto", "return", "unsigned", "int", "long", "while", "else"
)

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

@Composable
fun DecompilePanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val d = vm.detail
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 11.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                d?.displayName?.ifEmpty { d.name } ?: "—",
                color = ide.text, fontSize = 13.sp,
                fontWeight = FontWeight.Medium, fontFamily = Mono, maxLines = 1,
                modifier = Modifier.weight(1f)
            )
            val clip = LocalClipboardManager.current
            val pseudoNow = d?.pseudo
            if (!pseudoNow.isNullOrEmpty()) {
                Icon(
                    Icons.Filled.ContentCopy, contentDescription = "Copy pseudo-C",
                    tint = ide.dim,
                    modifier = Modifier
                        .size(30.dp)
                        .clickable {
                            clip.setText(AnnotatedString(pseudoNow))
                            vm.log("OK", "Pseudo-C copied to the clipboard")
                        }
                        .padding(6.dp)
                )
            }
        }
        // Pipeline stats as tinted chips: what the IR actually recovered, at a
        // glance, instead of a run-on line of text.
        val mode = d?.pseudoMode ?: ""
        val stats = d?.irStats
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, bottom = 10.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            StatChip(if (mode == "IR") "ASM→IR→C" else "ASM→C fallback",
                if (mode == "IR") ide.violet else ide.dim)
            if (stats != null && mode == "IR") {
                StatChip("${stats.stmts} IR", ide.cyan)
                StatChip("${stats.calls} calls", ide.accent)
                if (stats.whiles > 0) StatChip("${stats.whiles} loops", ide.amber)
                if (stats.ifs > 0) StatChip("${stats.ifs} if", ide.dim)
            }
        }
        val pseudo = d?.pseudo
        if (pseudo.isNullOrEmpty()) {
            Box(Modifier.weight(1f)) {
                Hint(
                    "Select a function to decompile.",
                    "Pipeline: assembly lifted to an expression IR, propagated, then structured (while/if/calls with args)."
                )
            }
        } else {
            val annotated = remember(pseudo, vm.darkTheme) { highlightPseudo(pseudo, ide) }
            // weight() is a ColumnScope modifier, so it belongs on the container
            // here rather than on the Text inside SelectionContainer's lambda.
            SelectionContainer(Modifier.weight(1f).fillMaxWidth()) {
                Text(
                    annotated,
                    fontFamily = Mono, fontSize = 12.sp, lineHeight = 17.sp,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .horizontalScroll(rememberScrollState())
                        .padding(12.dp)
                )
            }
        }
        // Whole-binary export does not need a selected function, so the bar is
        // available whenever something is loaded.
        if (vm.meta != null) ExportBar(vm)
    }
}

@Composable
private fun StatChip(label: String, tint: Color) {
    Text(
        label, color = tint, fontSize = 9.5.sp, fontFamily = Mono,
        modifier = Modifier
            .background(tint.copy(alpha = 0.10f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    )
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
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun ExportBar(vm: StudioViewModel) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            .clickable(enabled = !vm.exportBusy) { showExportSheet = true }
            .padding(horizontal = 16.dp, vertical = 13.dp),
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
            fontSize = 13.sp, fontWeight = FontWeight.Medium
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
                    fontSize = 16.sp, fontWeight = FontWeight.SemiBold)
                Spacer(Modifier.height(3.dp))
                Text(
                    "Reconstructed from machine code — it will not recompile as-is.",
                    color = ide.dim, fontSize = 11.5.sp
                )
            }
            Spacer(Modifier.height(10.dp))
            kinds.forEach { k ->
                val enabled = k.id != "c-one" || vm.detail != null
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(enabled = enabled) { onPick(k.id) }
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
                            fontSize = 13.5.sp, fontWeight = FontWeight.Medium
                        )
                        Text(k.detail, color = ide.dim, fontSize = 10.5.sp, fontFamily = Mono)
                    }
                }
                HorizontalDivider(color = ide.border.copy(alpha = 0.5f))
            }
        }
    }
}

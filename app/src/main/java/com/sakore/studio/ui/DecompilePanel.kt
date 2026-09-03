package com.sakore.studio.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.sakore.studio.vm.StudioViewModel

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
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp)
        ) {
            Text(
                "Pseudo-C · " + (d?.displayName?.ifEmpty { d.name } ?: "—"),
                color = ide.text, fontSize = 12.sp, fontWeight = FontWeight.Bold, fontFamily = Mono
            )
            Spacer(Modifier.weight(1f))
            val mode = d?.pseudoMode ?: ""
            val stats = d?.irStats
            Text(
                buildString {
                    append(if (mode == "IR") "ASM→IR→C" else "ASM→C (fallback)")
                    if (stats != null && mode == "IR")
                        append(" · ${stats.calls} calls · ${stats.whiles} while · ${stats.ifs} if")
                },
                color = if (mode == "IR") ide.accent else ide.dim, fontSize = 10.sp
            )
        }
        val pseudo = d?.pseudo
        if (pseudo.isNullOrEmpty()) {
            Hint(
                "Select a function to decompile — dooro shaqo si aad u hesho pseudo-C.",
                "Pipeline: assembly lifted to an expression IR, propagated, then structured (while/if/calls with args)."
            )
        } else {
            val annotated = remember(pseudo, vm.darkTheme) { highlightPseudo(pseudo, ide) }
            SelectionContainer {
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
    }
}

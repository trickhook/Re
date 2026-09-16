package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

val Mono: FontFamily = FontFamily.Monospace

fun hexFmt(v: Long, width: Int = 8): String = String.format("%0${width}X", v)

@Composable
fun Hint(text: String, sub: String? = null) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(24.dp)
    ) {
        Text(text, color = ide.dim, fontSize = 13.sp)
        if (sub != null) {
            Spacer(Modifier.height(4.dp))
            Text(sub, color = ide.dim.copy(alpha = 0.7f), fontSize = 12.sp)
        }
    }
}

@Composable
fun PanelHeader(title: String, subtitle: String? = null, trailing: @Composable (() -> Unit)? = null) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel2)
            .padding(horizontal = 10.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(title, color = ide.text, fontSize = 13.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
            if (subtitle != null) {
                Text(subtitle, color = ide.dim, fontSize = 10.sp)
            }
        }
        Spacer(Modifier.weight(1f))
        trailing?.invoke()
    }
}

@Composable
fun KeyValue(k: String, v: String, kColor: Color? = null, vColor: Color? = null) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp)
    ) {
        Text(
            k, color = kColor ?: ide.dim, fontSize = 12.sp, fontFamily = Mono,
            modifier = Modifier.width(150.dp), maxLines = 1
        )
        Text(v, color = vColor ?: ide.text, fontSize = 12.sp, fontFamily = Mono, maxLines = 2)
    }
}

fun mnemonicColor(m: String, ide: IdeColors): Color {
    val m0 = m.lowercase()
    return when {
        m0 == "ret" || m0 == "retn" || m0 == "retq" || m0 == "retaa" || m0 == "retab" -> ide.red
        m0 == "call" || m0 == "bl" || m0 == "blr" -> ide.violet
        m0 == "jmp" || m0 == "b" || m0 == "br" || m0.startsWith("j") || m0.startsWith("b.") ||
            m0 == "cbz" || m0 == "cbnz" || m0 == "tbz" || m0 == "tbnz" -> ide.amber
        m0 == "nop" || m0 == "endbr64" || m0 == "int3" || m0 == ".byte" || m0 == ".word" -> ide.dim
        m0 == "pacibsp" || m0 == "stp" || m0 == "ldp" || m0 == "push" || m0 == "pop" -> ide.cyan
        else -> ide.accent
    }
}

fun levelColor(level: String, ide: IdeColors): Color = when (level) {
    "OK" -> ide.accent
    "WARN" -> ide.amber
    "ERROR" -> ide.red
    else -> ide.dim
}

fun defaultTextStyle() = TextStyle(fontSize = 12.sp)

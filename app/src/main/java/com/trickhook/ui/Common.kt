package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

val Mono: FontFamily = FontFamily.Monospace

fun hexFmt(v: Long, width: Int = 8): String = String.format("%0${width}X", v)

/**
 * The type scale. Every panel used to hand-type its own `13.sp` / `12.sp` /
 * `9.5.sp`, which is how sixteen different sizes ended up on screen at once.
 * Pick the rung that matches the role; do not invent a new number.
 */
object Type {
    val display = 32.sp
    val title = 17.sp
    val section = 15.sp
    val body = 13.sp
    val label = 12.sp
    val caption = 10.sp
    val mono = 12.sp
    val monoSmall = 10.sp
}

@Composable
fun Hint(text: String, sub: String? = null) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(24.dp)
    ) {
        Text(text, color = ide.dim, fontSize = Type.body)
        if (sub != null) {
            Spacer(Modifier.height(4.dp))
            Text(sub, color = ide.dim2, fontSize = Type.label)
        }
    }
}

/**
 * The empty state a panel shows when it has nothing to draw. Panels used to
 * render literally nothing, which is indistinguishable from a panel that is
 * broken. No icon and no emoji — the words are the whole message.
 */
@Composable
fun EmptyPanel(title: String, sub: String? = null) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = 32.dp, vertical = 48.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center
    ) {
        Text(title, color = ide.dim, fontSize = Type.body, textAlign = TextAlign.Center)
        if (sub != null) {
            Spacer(Modifier.height(6.dp))
            Text(
                sub, color = ide.dim2, fontSize = Type.caption,
                textAlign = TextAlign.Center, lineHeight = 15.sp
            )
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
            Text(title, color = ide.text, fontSize = Type.body, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
            if (subtitle != null) {
                Text(subtitle, color = ide.dim, fontSize = Type.caption)
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
            k, color = kColor ?: ide.dim, fontSize = Type.mono, fontFamily = Mono,
            modifier = Modifier.width(150.dp), maxLines = 1
        )
        Text(v, color = vColor ?: ide.text, fontSize = Type.mono, fontFamily = Mono, maxLines = 2)
    }
}

/**
 * A small labelled statistic. Lifted verbatim out of DecompilePanel, where it
 * was private, so the other panels can stop reinventing it.
 */
@Composable
fun StatChip(label: String, tint: Color) {
    Text(
        label, color = tint, fontSize = 9.5.sp, fontFamily = Mono,
        modifier = Modifier
            .background(tint.copy(alpha = 0.10f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp)
    )
}

/**
 * The same chip with the caption and the number separated, for the call sites
 * that have them as two strings. Deliberately identical in shape, padding and
 * size to the two-argument form so the two can sit in one Row.
 */
@Composable
fun StatChip(label: String, value: String, tint: Color) {
    val ide = LocalIde.current
    Row(
        Modifier
            .background(tint.copy(alpha = 0.10f), RoundedCornerShape(6.dp))
            .padding(horizontal = 8.dp, vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = ide.dim2, fontSize = 9.5.sp, fontFamily = Mono, maxLines = 1)
        Spacer(Modifier.width(5.dp))
        Text(value, color = tint, fontSize = 9.5.sp, fontFamily = Mono, maxLines = 1)
    }
}

/**
 * The gap that keeps the last row of a column clear of the system navigation
 * bar. Replaces the scattered `Spacer(Modifier.height(40.dp))` guesses, which
 * were both too large on gesture navigation and too small on three-button.
 */
@Composable
fun NavBarSpacer() {
    Spacer(Modifier.navigationBarsPadding())
}

/**
 * The same inset as [NavBarSpacer], as `contentPadding` for a LazyColumn —
 * where a trailing Spacer item would scroll the list's own scrollbar instead.
 */
@Composable
fun bottomInset(extra: Dp = 0.dp): PaddingValues = PaddingValues(
    bottom = WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding() + extra
)

fun mnemonicColor(m: String, ide: IdeColors): Color {
    val m0 = m.lowercase()
    return when {
        m0 == "ret" || m0 == "retn" || m0 == "retq" || m0 == "retaa" || m0 == "retab" -> ide.red
        m0 == "call" || m0 == "bl" || m0 == "blr" -> ide.violet
        m0 == "jmp" || m0 == "b" || m0 == "br" || m0.startsWith("j") || m0.startsWith("b.") ||
            m0 == "cbz" || m0 == "cbnz" || m0 == "tbz" || m0 == "tbnz" -> ide.amber
        m0 == "nop" || m0 == "endbr64" || m0 == "int3" || m0 == ".byte" || m0 == ".word" -> ide.dim
        m0 == "pacibsp" || m0 == "stp" || m0 == "ldp" || m0 == "push" || m0 == "pop" -> ide.cyan
        // Everything else is ordinary data movement and arithmetic, which is
        // most of a listing. Painting it accent made the whole disassembly
        // pink and left nothing for the branches to stand out against.
        else -> ide.text
    }
}

fun levelColor(level: String, ide: IdeColors): Color = when (level) {
    "OK" -> ide.entry
    "WARN" -> ide.amber
    "ERROR" -> ide.red
    else -> ide.dim
}

/**
 * Leading icon for a list row. Occupies the same 24dp gutter the rows were
 * built around, so every list stays aligned regardless of glyph width — which
 * is what emoji could never guarantee across devices and fonts.
 */
@Composable
fun RowIcon(
    icon: ImageVector,
    tint: Color,
    size: Dp = 15.dp,
    contentDescription: String? = null
) {
    Box(Modifier.width(24.dp), contentAlignment = Alignment.CenterStart) {
        Icon(icon, contentDescription = contentDescription, tint = tint, modifier = Modifier.size(size))
    }
}

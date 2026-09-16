package com.trickhook.ui

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

/**
 * Nocturne palette.
 *
 * The colours are sampled straight out of the launcher artwork rather than
 * picked by eye: #FB1B69 is the pink of the badge, #F4E7E4 the hair highlight,
 * #D80048 / #670634 the eyes. The greys carry a faint violet cast so panels sit
 * on the same hue axis as the accent instead of reading as neutral slate.
 *
 * Contrast against the dark background: text 16.8:1, accent 5.2:1 — both clear
 * of WCAG AA for body text. On the light theme the accent is darkened to
 * #C2003F (6.0:1), since the artwork pink only reaches 3.9:1 on white.
 */
data class IdeColors(
    val bg: Color,
    val panel: Color,
    val panel2: Color,
    val border: Color,
    val text: Color,
    val dim: Color,
    val accent: Color,
    val amber: Color,
    val cyan: Color,
    val red: Color,
    val violet: Color
)

fun darkIde() = IdeColors(
    bg      = Color(0xFF08060B),
    panel   = Color(0xFF120E16),
    panel2  = Color(0xFF1B1520),
    border  = Color(0xFF2E2436),
    text    = Color(0xFFF4E7E4),
    dim     = Color(0xFF9A8C97),
    accent  = Color(0xFFFB1B69),
    amber   = Color(0xFFF2A65A),
    cyan    = Color(0xFF8AA6FF),
    red     = Color(0xFFFF4D6D),
    violet  = Color(0xFFC792EA)
)

fun lightIde() = IdeColors(
    bg      = Color(0xFFFAF6F8),
    panel   = Color(0xFFFFFFFF),
    panel2  = Color(0xFFF2ECF1),
    border  = Color(0xFFDDD2DC),
    text    = Color(0xFF1A1119),
    dim     = Color(0xFF6E6270),
    accent  = Color(0xFFC2003F),
    amber   = Color(0xFFB35C00),
    cyan    = Color(0xFF3B4FB0),
    red     = Color(0xFFB3002D),
    violet  = Color(0xFF7B3FA0)
)

val LocalIde = staticCompositionLocalOf { darkIde() }

@Composable
fun NocturneTheme(dark: Boolean, content: @Composable () -> Unit) {
    val scheme = if (dark) {
        darkColorScheme(
            primary          = Color(0xFFFB1B69),
            secondary        = Color(0xFFC792EA),
            tertiary         = Color(0xFF8AA6FF),
            background       = Color(0xFF08060B),
            surface          = Color(0xFF120E16),
            surfaceVariant   = Color(0xFF1B1520),
            onPrimary        = Color(0xFF14020A),
            onBackground     = Color(0xFFF4E7E4),
            onSurface        = Color(0xFFF4E7E4),
            onSurfaceVariant = Color(0xFFC9BCC5),
            outline          = Color(0xFF3B2F45)
        )
    } else {
        lightColorScheme(
            primary          = Color(0xFFC2003F),
            secondary        = Color(0xFF7B3FA0),
            tertiary         = Color(0xFF3B4FB0),
            background       = Color(0xFFFAF6F8),
            surface          = Color(0xFFFFFFFF),
            surfaceVariant   = Color(0xFFF2ECF1),
            onPrimary        = Color.White,
            onBackground     = Color(0xFF1A1119),
            onSurface        = Color(0xFF1A1119),
            onSurfaceVariant = Color(0xFF4A4050),
            outline          = Color(0xFFBCAEBA)
        )
    }
    CompositionLocalProvider(LocalIde provides (if (dark) darkIde() else lightIde())) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

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
 *
 * The second tier of tokens was added because the first tier was being faked at
 * the call site. Every measurement below is a real sRGB relative-luminance
 * ratio, (L1+0.05)/(L2+0.05):
 *
 *  - `dim2` is the quiet text tier. It used to be `dim.copy(alpha = 0.7f)`,
 *    which composites to #716670 on the dark panel — 3.49:1, below AA, and
 *    worse still on `panel2`. It is now a real colour on the same hue and
 *    saturation as `dim`, six lightness steps down: dark h313 s6% 58%->52%,
 *    light h291 41%->44%. Dark 5.20:1 on bg / 4.92:1 on panel / 4.61:1 on
 *    panel2; light 4.94 / 5.30 / 4.55. Quieter than `dim` (dark 6.31 / 5.97,
 *    light 5.38 / 5.76) while still clearing AA on every surface, which is the
 *    whole point of the tier.
 *
 *  - `borderStrong` is the boundary for edges you can actually touch — chips,
 *    tappable cards — where WCAG 1.4.11 wants 3:1, not the 1.2:1 that `border`
 *    manages as a decorative hairline. It is deliberately the same hue and
 *    saturation as `border` with only the lightness moved (dark h273 s20%
 *    18%->45%, light h305 s14% 85%->54%), so the two read as one family.
 *    Dark 3.32:1 on panel / 3.11:1 on panel2; light 3.78 / 3.25.
 *
 *  - `entry` is success / a CFG entry block / a console OK line. A jade, hue
 *    158 — blue-leaning green, so it sits with the violet-cast greys rather
 *    than fighting them, and nowhere near the pink accent. Dark #26C58B is
 *    9.07:1 on bg and 8.58:1 on panel; light #0D7750 is 5.20:1 on bg and
 *    5.57:1 on panel.
 *
 *  - `onAccent` is text and icons drawn on an accent fill. It is the same pair
 *    the Material scheme already uses for onPrimary: #14020A on the dark pink
 *    is 5.24:1, white on the light #C2003F is 6.24:1.
 *
 * `entry` is intentionally absent from the Material colour scheme — there is no
 * Material slot that means "success", so it lives on IdeColors only.
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
    val violet: Color,
    val dim2: Color,
    val borderStrong: Color,
    val entry: Color,
    val onAccent: Color
)

fun darkIde() = IdeColors(
    bg           = Color(0xFF08060B),
    panel        = Color(0xFF120E16),
    panel2       = Color(0xFF1B1520),
    border       = Color(0xFF2E2436),
    text         = Color(0xFFF4E7E4),
    dim          = Color(0xFF9A8C97),
    accent       = Color(0xFFFB1B69),
    amber        = Color(0xFFF2A65A),
    cyan         = Color(0xFF8AA6FF),
    red          = Color(0xFFFF4D6D),
    violet       = Color(0xFFC792EA),
    dim2         = Color(0xFF8C7D89),
    borderStrong = Color(0xFF755C8A),
    entry        = Color(0xFF26C58B),
    onAccent     = Color(0xFF14020A)
)

fun lightIde() = IdeColors(
    bg           = Color(0xFFFAF6F8),
    panel        = Color(0xFFFFFFFF),
    panel2       = Color(0xFFF2ECF1),
    border       = Color(0xFFDDD2DC),
    text         = Color(0xFF1A1119),
    dim          = Color(0xFF6E6270),
    accent       = Color(0xFFC2003F),
    amber        = Color(0xFFB35C00),
    cyan         = Color(0xFF3B4FB0),
    red          = Color(0xFFB3002D),
    violet       = Color(0xFF7B3FA0),
    dim2         = Color(0xFF77667A),
    borderStrong = Color(0xFF9A7997),
    entry        = Color(0xFF0D7750),
    onAccent     = Color(0xFFFFFFFF)
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

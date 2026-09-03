package com.sakore.studio.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.graphics.Color

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
    bg = Color(0xFF121417),
    panel = Color(0xFF1B1F25),
    panel2 = Color(0xFF232830),
    border = Color(0xFF2E3540),
    text = Color(0xFFD6DBE1),
    dim = Color(0xFF8A94A0),
    accent = Color(0xFF4EC94E),
    amber = Color(0xFFFFB74D),
    cyan = Color(0xFF64B5F6),
    red = Color(0xFFFF6E6E),
    violet = Color(0xFFB39DDB)
)

fun lightIde() = IdeColors(
    bg = Color(0xFFFAFAFA),
    panel = Color(0xFFFFFFFF),
    panel2 = Color(0xFFF0F2F5),
    border = Color(0xFFD8DDE3),
    text = Color(0xFF1B1F23),
    dim = Color(0xFF6A737D),
    accent = Color(0xFF2E7D32),
    amber = Color(0xFFE65100),
    cyan = Color(0xFF1565C0),
    red = Color(0xFFC62828),
    violet = Color(0xFF6A1B9A)
)

val LocalIde = staticCompositionLocalOf { darkIde() }

@Composable
fun SakoTheme(dark: Boolean, content: @Composable () -> Unit) {
    val scheme = if (dark) {
        darkColorScheme(
            primary = Color(0xFF4EC94E),
            secondary = Color(0xFFFFB74D),
            tertiary = Color(0xFF64B5F6),
            background = Color(0xFF121417),
            surface = Color(0xFF1B1F25),
            surfaceVariant = Color(0xFF232830),
            onPrimary = Color(0xFF0B0D0F),
            onBackground = Color(0xFFD6DBE1),
            onSurface = Color(0xFFD6DBE1),
            onSurfaceVariant = Color(0xFFAAB3BD),
            outline = Color(0xFF3A414B)
        )
    } else {
        lightColorScheme(
            primary = Color(0xFF2E7D32),
            secondary = Color(0xFFE65100),
            tertiary = Color(0xFF1565C0),
            background = Color(0xFFFAFAFA),
            surface = Color(0xFFFFFFFF),
            surfaceVariant = Color(0xFFF0F2F5),
            onPrimary = Color.White,
            onBackground = Color(0xFF1B1F23),
            onSurface = Color(0xFF1B1F23),
            onSurfaceVariant = Color(0xFF444B52),
            outline = Color(0xFFB9C0C7)
        )
    }
    CompositionLocalProvider(LocalIde provides (if (dark) darkIde() else lightIde())) {
        MaterialTheme(colorScheme = scheme, content = content)
    }
}

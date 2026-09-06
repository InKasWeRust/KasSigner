package org.kassigner.kassigner.app

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Shapes
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import org.kassigner.kassigner.infrastructure.persistence.AppearanceTheme

/** KasSee Web palette mirrored by the native Android client. */
object KasSeePalette {
    val Background = Color(0xFF080C12)
    val Surface = Color(0xFF111820)
    val SurfaceRaised = Color(0xFF18202B)
    val Border = Color(0xFF1E2A38)
    val BorderFocus = Color(0xFF2A3A4E)
    val Teal = Color(0xFF49EACB)
    val TealDim = Color(0xFF2EA88E)
    val Text = Color(0xFFD4D8DE)
    val TextDim = Color(0xFF6B7A8D)
    val TextMuted = Color(0xFF3D4D5E)
    val Danger = Color(0xFFE5534B)
    val Success = Color(0xFF3FB950)
    val Warning = Color(0xFFD29922)
}

private val KasSeeDarkColors = darkColorScheme(
    primary = KasSeePalette.Teal,
    onPrimary = KasSeePalette.Background,
    primaryContainer = KasSeePalette.TealDim,
    onPrimaryContainer = KasSeePalette.Background,
    secondary = KasSeePalette.TealDim,
    onSecondary = KasSeePalette.Background,
    background = KasSeePalette.Background,
    onBackground = KasSeePalette.Text,
    surface = KasSeePalette.Surface,
    onSurface = KasSeePalette.Text,
    surfaceVariant = KasSeePalette.SurfaceRaised,
    onSurfaceVariant = KasSeePalette.TextDim,
    outline = KasSeePalette.Border,
    outlineVariant = KasSeePalette.BorderFocus,
    error = KasSeePalette.Danger,
    onError = Color.White,
)

/* Keep the Android-only light-mode option, while retaining the same KasSee geometry and teal identity. */
private val KasSeeLightColors = lightColorScheme(
    primary = Color(0xFF147D6C),
    onPrimary = Color.White,
    primaryContainer = Color(0xFFB9F4E8),
    onPrimaryContainer = Color(0xFF05201B),
    secondary = Color(0xFF256E63),
    onSecondary = Color.White,
    background = Color(0xFFF4F7F8),
    onBackground = Color(0xFF172027),
    surface = Color.White,
    onSurface = Color(0xFF172027),
    surfaceVariant = Color(0xFFE9EFF2),
    onSurfaceVariant = Color(0xFF53616C),
    outline = Color(0xFFD1DCE2),
    outlineVariant = Color(0xFFB7C5CD),
    error = Color(0xFFB3261E),
    onError = Color.White,
)

private val KasSeeShapes = Shapes(
    extraSmall = RoundedCornerShape(8.dp),
    small = RoundedCornerShape(10.dp),
    medium = RoundedCornerShape(14.dp),
    large = RoundedCornerShape(14.dp),
    extraLarge = RoundedCornerShape(18.dp),
)

private val KasSeeTypography = Typography(
    headlineMedium = Typography().headlineMedium.copy(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
    ),
    headlineSmall = Typography().headlineSmall.copy(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
    ),
    titleLarge = Typography().titleLarge.copy(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
    ),
    titleMedium = Typography().titleMedium.copy(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
    ),
    bodyLarge = Typography().bodyLarge.copy(fontFamily = FontFamily.SansSerif),
    bodyMedium = Typography().bodyMedium.copy(fontFamily = FontFamily.SansSerif),
    bodySmall = Typography().bodySmall.copy(fontFamily = FontFamily.SansSerif),
    labelLarge = Typography().labelLarge.copy(
        fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.SemiBold,
    ),
    labelMedium = Typography().labelMedium.copy(fontFamily = FontFamily.Monospace),
    labelSmall = Typography().labelSmall.copy(fontFamily = FontFamily.Monospace),
)

@Composable
fun KasSignerTheme(appearance: AppearanceTheme, content: @Composable () -> Unit) {
    val dark = when (appearance) {
        AppearanceTheme.SYSTEM -> isSystemInDarkTheme()
        AppearanceTheme.LIGHT -> false
        AppearanceTheme.DARK -> true
    }
    MaterialTheme(
        colorScheme = if (dark) KasSeeDarkColors else KasSeeLightColors,
        typography = KasSeeTypography,
        shapes = KasSeeShapes,
        content = content,
    )
}

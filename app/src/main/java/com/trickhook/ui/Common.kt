package com.trickhook.ui

import android.database.ContentObserver
import android.os.Handler
import android.os.Looper
import android.provider.Settings
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.SpringSpec
import androidx.compose.animation.core.TweenSpec
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBars
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.State
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.staticCompositionLocalOf
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Shape
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.Dp
import androidx.compose.ui.unit.TextUnit
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.model.CallEdge
import com.trickhook.model.FunctionDetail
import com.trickhook.vm.StudioViewModel

val Mono: FontFamily = FontFamily.Monospace

fun hexFmt(v: Long, width: Int = 8): String = String.format("%0${width}X", v)

// =================================================================== space ==

/**
 * The spacing scale. Before this there were 3, 5, 6, 9, 11, 13 and 22dp gaps on
 * screen at the same time, each one picked on its own; the result is a layout
 * that is wrong everywhere by two pixels and right nowhere, which reads as
 * sloppy without ever being locatable. Pick a rung, never a number.
 */
object Space {
    val xs = 2.dp
    val s = 4.dp
    val m = 8.dp
    val l = 12.dp
    val xl = 16.dp
    val xxl = 24.dp
}

// ================================================================== motion ==

/**
 * Mirror of [LocalMotion] for the non-composable side of [Motion].
 *
 * [Motion.tween] and [Motion.spring] are plain functions — they build a spec
 * that is often handed to an animation started outside composition — so they
 * cannot read a CompositionLocal. [NocturneTheme] writes this flag in the same
 * pass that provides [LocalMotion], so the two never disagree for longer than
 * one frame. Written and read on the main thread only.
 *
 * [motionMs] remains the authoritative reader: it observes the CompositionLocal
 * directly and therefore recomposes when the setting changes.
 */
private var motionEnabled: Boolean = true

/**
 * Durations, in milliseconds. This is a dense reverse-engineering IDE, not a
 * consumer app: if an animation makes you wait to read an address it is wrong.
 * Nothing on the reading path goes over [slow], and touch feedback stays at
 * [fast].
 */
object Motion {
    /** Touch feedback: press, chip, ripple-adjacent scale. */
    const val fast = 110

    /** Panel swap, expansion, height change — the default. */
    const val base = 180

    /** Sheets and dialogs only. Nothing else is allowed to take this long. */
    const val slow = 260

    /**
     * A tween that already honours the system animation setting: with
     * reduce-motion on the duration collapses to 0, which Compose treats as an
     * instant cut rather than an animation.
     *
     * Qualified deliberately — inside this object an unqualified `tween` would
     * resolve to this very function and recurse.
     */
    fun <T> tween(d: Int = base): TweenSpec<T> = androidx.compose.animation.core.tween(
        durationMillis = if (motionEnabled) d else 0,
        easing = FastOutSlowInEasing
    )

    /**
     * The one spring in the app: critically damped, medium-low stiffness. Bounce
     * belongs in a consumer app; here it reads as a control that has not settled
     * yet. Under reduce-motion the stiffness jumps to [Spring.StiffnessHigh], so
     * the transform lands in a frame or two instead of easing.
     */
    fun <T> spring(): SpringSpec<T> = androidx.compose.animation.core.spring(
        dampingRatio = Spring.DampingRatioNoBouncy,
        stiffness = if (motionEnabled) Spring.StiffnessMediumLow else Spring.StiffnessHigh
    )
}

/**
 * True when the user has NOT turned animation off in the system.
 *
 * Provided by [NocturneTheme], which wraps the whole app, so every composable
 * can read it without anything being threaded through. Defaults to true for
 * previews and for any tree that is not under the theme.
 */
val LocalMotion: ProvidableCompositionLocal<Boolean> = staticCompositionLocalOf { true }

/**
 * Reads `Settings.Global.ANIMATOR_DURATION_SCALE` — 0 means the user turned
 * animation off, in Developer Options or through an accessibility setting — and
 * keeps watching it, so the preference takes effect while the app is running
 * rather than at the next process start.
 *
 * Only [NocturneTheme] needs to call this; everyone else reads [LocalMotion] or,
 * better, [motionMs].
 */
@Composable
fun rememberMotionEnabled(): Boolean {
    val resolver = LocalContext.current.contentResolver
    var enabled by remember(resolver) { mutableStateOf(animatorScale(resolver) > 0f) }
    DisposableEffect(resolver) {
        val observer = object : ContentObserver(Handler(Looper.getMainLooper())) {
            override fun onChange(selfChange: Boolean) {
                enabled = animatorScale(resolver) > 0f
            }
        }
        // Reading a Global setting needs no permission; registering can still
        // fail on a stripped-down image, and a theme is not worth a crash.
        val ok = try {
            resolver.registerContentObserver(
                Settings.Global.getUriFor(Settings.Global.ANIMATOR_DURATION_SCALE),
                false,
                observer
            )
            true
        } catch (t: Throwable) {
            false
        }
        onDispose {
            if (ok) {
                try {
                    resolver.unregisterContentObserver(observer)
                } catch (t: Throwable) {
                    // Nothing to undo if it was never really registered.
                }
            }
        }
    }
    SideEffect { motionEnabled = enabled }
    return enabled
}

private fun animatorScale(resolver: android.content.ContentResolver): Float = try {
    Settings.Global.getFloat(resolver, Settings.Global.ANIMATOR_DURATION_SCALE, 1f)
} catch (t: Throwable) {
    1f
}

/**
 * The duration to hand any animation spec. Returns 0 when the user has turned
 * animation off, so `tween(motionMs())` degrades to an instant cut and no call
 * site needs a branch of its own.
 *
 * Use this, never [Motion.base] raw.
 */
@Composable
fun motionMs(d: Int = Motion.base): Int = if (LocalMotion.current) d else 0

// ================================================================== depth ==

/**
 * Level 1: a panel or a card. The scale has exactly three levels — `ide.bg` is
 * level 0 and is a background, not a modifier; [surface1] is level 1; [surface2]
 * is level 2. Do not invent a fourth, and do not hand-roll a background/border
 * pair at a call site: the point of the scale is that two panels next to each
 * other cannot drift apart.
 *
 * No shadow. The only lifted object in the app is the primary CTA, and its
 * shadow is neutral — a tinted shadow under a saturated fill reads as bloom.
 */
@Composable
fun Modifier.surface1(shape: Shape = RoundedCornerShape(12.dp)): Modifier {
    val ide = LocalIde.current
    return this
        .clip(shape)
        .background(ide.panel)
        .border(1.dp, ide.border, shape)
}

/** Level 2: headers, sheets, menus — the things that sit on top of a panel. */
@Composable
fun Modifier.surface2(shape: Shape = RoundedCornerShape(12.dp)): Modifier {
    val ide = LocalIde.current
    return this
        .clip(shape)
        .background(ide.panel2)
        .border(1.dp, ide.border, shape)
}

/**
 * Press feedback for the primary CTA and for chips: 1f -> 0.97f.
 *
 * Under reduce-motion the target never leaves 1f — the accessibility setting
 * asks for no scale at all, not for a faster one. The scale is read in the
 * layer phase, so a press costs no recomposition.
 */
@Composable
fun Modifier.pressScale(pressed: Boolean): Modifier {
    val target = if (pressed && LocalMotion.current) 0.97f else 1f
    val scale by animateFloatAsState(
        targetValue = target,
        animationSpec = Motion.tween(Motion.fast),
        label = "pressScale"
    )
    return this.graphicsLayer {
        scaleX = scale
        scaleY = scale
    }
}

// =============================================================== skeleton ==

// Deliberately not uniform: pseudo-C is a ragged right edge, and a column of
// identical grey bars reads as a progress bar someone forgot to fill in. The
// pattern is fixed rather than random so a recomposition never reshuffles it.
private val SkeletonWidths = floatArrayOf(0.72f, 0.94f, 0.55f, 0.83f, 0.38f, 0.66f, 0.90f, 0.47f, 0.78f, 0.61f)
private val SkeletonIndents = intArrayOf(0, 1, 1, 2, 2, 1, 1, 2, 1, 1)
private val SkeletonIndentStep = 14.dp
private val SkeletonBarHeight = 10.dp
private val SkeletonBarShape = RoundedCornerShape(2.dp)

/**
 * The placeholder shown while the decompiler works — which on a large function
 * is seconds, not milliseconds. An indeterminate spinner says only "something is
 * happening"; a skeleton with the SHAPE of the answer says what is coming, and
 * the text lands without the page jumping when it arrives.
 *
 * [indent] true gives the stepped shape of a function body (signature flush
 * left, body indented, closing brace short and flush left again); false gives
 * the flat ghost rows the function list uses while the binary loads.
 *
 * Bars are `ide.panel2` on `ide.panel` and the shimmer crest is `ide.border` —
 * the next token up the same depth ramp. No new colour is introduced.
 *
 * With reduce-motion on, the InfiniteTransition is never composed: the bars are
 * static and nothing is producing frames. An infinite animation with a zero
 * duration is a spin, not a stop.
 */
@Composable
fun SkeletonLines(lines: Int, indent: Boolean = false) {
    val ide = LocalIde.current
    val n = lines.coerceAtLeast(0)
    if (n == 0) return

    val phase: State<Float>? = if (LocalMotion.current) {
        rememberInfiniteTransition(label = "skeleton").animateFloat(
            initialValue = 0f,
            targetValue = 1f,
            animationSpec = infiniteRepeatable(
                animation = androidx.compose.animation.core.tween(1200, easing = LinearEasing),
                repeatMode = RepeatMode.Restart
            ),
            label = "skeletonSweep"
        )
    } else {
        null
    }

    val trough = ide.panel2
    val crest = ide.border
    Column(
        Modifier
            .fillMaxWidth()
            .background(ide.panel)
            .padding(horizontal = Space.l, vertical = Space.l),
        verticalArrangement = Arrangement.spacedBy(Space.m)
    ) {
        for (i in 0 until n) {
            val last = i == n - 1
            val level = when {
                !indent -> 0
                i == 0 || last -> 0
                else -> SkeletonIndents[i % SkeletonIndents.size]
            }
            val fraction = when {
                indent && last && n > 1 -> 0.12f
                i == 0 -> 0.70f
                else -> SkeletonWidths[i % SkeletonWidths.size]
            }
            val bar = Modifier
                .padding(start = SkeletonIndentStep * level)
                .fillMaxWidth(fraction)
                .height(SkeletonBarHeight)
            if (phase == null) {
                Box(bar.background(trough, SkeletonBarShape))
            } else {
                Box(
                    bar
                        .clip(SkeletonBarShape)
                        .drawBehind {
                            // Read in the draw phase, so the sweep costs no
                            // recomposition at 60fps.
                            val band = size.width.coerceAtLeast(1f)
                            val x = -band + phase.value * band * 2f
                            drawRect(
                                Brush.linearGradient(
                                    colors = listOf(trough, crest, trough),
                                    start = Offset(x, 0f),
                                    end = Offset(x + band, 0f)
                                )
                            )
                        }
                )
            }
        }
    }
}

// =================================================================== type ==

/**
 * The type scale. Every panel used to hand-type its own `13.sp` / `12.sp` /
 * `9.5.sp`, which is how sixteen different sizes ended up on screen at once.
 * Pick the rung that matches the role; do not invent a new number.
 *
 * Each rung now carries its line height too — body-class 1.45x, mono and
 * caption 1.35x. Leading is what separates "small text" from typography, and a
 * paragraph at default leading in a 13sp UI is unreadable at arm's length.
 * The SIZES are unchanged, so nothing that already called [Type] moves.
 *
 * [upperTracking] goes on UPPERCASE labels and nowhere else. Monospace never
 * takes tracking: the disassembly's columns line up because every glyph has the
 * same advance, and letter-spacing destroys exactly that.
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

    val displayLine = display * 1.45f
    val titleLine = title * 1.45f
    val sectionLine = section * 1.45f
    val bodyLine = body * 1.45f
    val labelLine = label * 1.45f
    val captionLine = caption * 1.35f
    val monoLine = mono * 1.35f
    val monoSmallLine = monoSmall * 1.35f

    /** Tracking for UPPERCASE labels only. Never on [mono] or [monoSmall]. */
    val upperTracking = 0.8.sp
}

// Advance width of one monospace glyph as a fraction of its point size, used to
// reserve hex columns that stay aligned when the user scales their font.
private const val MONO_GLYPH_ADVANCE = 0.62f

@Composable
private fun monoGlyphs(size: TextUnit, chars: Int): Dp =
    with(LocalDensity.current) { (size * MONO_GLYPH_ADVANCE).toDp() } * chars

// ================================================================ address ==

/**
 * A hex address as a human types it: `0x1234`, `0X1234`, `1234`, `dead beef`,
 * `dead_beef`, with or without surrounding whitespace. Returns null for
 * anything that is not hex, including the empty string and a bare `0x`.
 *
 * Written inline in four files before this, each copy slightly different, and
 * every one of them returned null for a genuine high address: `toLongOrNull(16)`
 * overflows above `Long.MAX_VALUE`, so `FFFFFFFFFFFFFFFF` — a perfectly ordinary
 * kernel or 64-bit sign-extended address — parsed as "not an address" rather
 * than as the negative Long that the whole codebase already uses to hold it.
 * The unsigned pass below is that case.
 */
fun parseAddr(s: String): Long? {
    var t = s.trim()
    if (t.length > 2 && (t.startsWith("0x") || t.startsWith("0X"))) t = t.substring(2)
    t = t.filterNot { it == '_' || it.isWhitespace() }
    if (t.isEmpty() || t.length > 16) return null
    if (!t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
    return t.toLongOrNull(16) ?: t.toULongOrNull(16)?.toLong()
}

// ================================================================= counts ==

/**
 * A number the engine could only put a floor under, written so it cannot be
 * read as the answer: `561+`, not `561`.
 *
 * The engine's cross-reference map stops at 200,000 references and on a real
 * library it held 200,000 of 1,323,435 — 85% dropped in silence. Every
 * nCallers, every nCallees and every xref count is taken from that map, so
 * above the cap all of them are floors. The trailing `+` is the whole
 * convention: no colour, no icon, no warning. [TruncationNote] is where the
 * sentence that explains it goes, once per screen rather than once per number.
 *
 * [floored] false returns the plain number, so a call site never needs a
 * branch of its own.
 */
fun floorCount(n: Int, floored: Boolean): String = if (floored) "$n+" else "$n"

/**
 * "12000 of 98022", or plain "98022" once the two agree.
 *
 * The rule the whole app follows: a list that is a page of something larger
 * names both numbers, and a list that is everything names one. Same shape as
 * `edgeCount` in the ViewModel, which is where it started.
 */
fun ofTotal(shown: Int, total: Int): String =
    // `shown` when the two agree, and when `total` is behind — an engine built
    // before these fields sends no total at all, and printing a 0 there would
    // be a worse lie than the one this replaces.
    if (total > shown) "$shown of $total" else "$shown"

/**
 * The quiet line under a header that says what a number on this screen does
 * not cover. A status, not an alarm: `dim2`, caption size, no icon, no rule —
 * it reads as a footnote because that is what it is.
 */
@Composable
fun TruncationNote(text: String, modifier: Modifier = Modifier) {
    val ide = LocalIde.current
    Text(
        text, color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
        maxLines = 2, overflow = TextOverflow.Ellipsis,
        modifier = modifier
    )
}

/**
 * The one sentence that explains every `+` on the screen, or null when the
 * engine kept every reference it found and there is nothing to explain.
 */
fun xrefFloorNote(vm: StudioViewModel): String? {
    val m = vm.meta ?: return null
    if (!m.xrefsAreFloors) return null
    return "Reference counts are floors: the engine's map holds ${m.xrefsStored} " +
        "of the ${m.xrefsTotal} references it found."
}

// ================================================================== xrefs ==

/**
 * One row of the cross-reference sheet. [target] null means the row cannot
 * navigate: an import stub, or an address outside every known function.
 */
data class XrefRow(
    val site: Long,
    val target: Long?,
    val label: String,
    val type: String,
    val note: String
)

/**
 * One call-graph edge stands for every call between the same pair of functions,
 * and the row can only show one address. Say so rather than letting the other
 * call sites vanish into a row that looks singular.
 */
private fun moreSites(e: CallEdge, note: String): String = when {
    e.sites <= 1 -> note
    note.isEmpty() -> "+${e.sites - 1} more call sites"
    else -> "$note · +${e.sites - 1} more call sites"
}

/**
 * Who references [d], or what [d] references.
 *
 * The engine's per-function xrefs come first and the whole-binary call-edge
 * index is the fallback when it found none — the same rule `xrefInCount` on the
 * ViewModel applies, so the sheet and the chip that opened it can never
 * disagree. This lived in two verbatim copies, one per panel, and they had
 * already drifted; there is exactly one now.
 */
fun xrefRows(vm: StudioViewModel, d: FunctionDetail, incoming: Boolean): List<XrefRow> = if (incoming) {
    val xs = d.xrefsIn
    if (xs.isNotEmpty()) xs.map { x ->
        val owner = vm.functionContaining(x.from)
        XrefRow(
            site = x.from,
            target = owner?.takeIf { it.from != "import" }?.addr,
            label = owner?.let { vm.effectiveFuncName(it.addr) } ?: "unmapped",
            type = x.type.ifEmpty { "ref" },
            note = if (owner == null) "outside any known function" else ""
        )
    } else vm.callersOf(d.addr).map { e ->
        // e.from is the calling FUNCTION's start — that is what resolves an
        // owner. The site column wants the call instruction, which is e.site.
        val owner = vm.functionAt(e.from) ?: vm.functionContaining(e.from)
        XrefRow(
            site = e.callSite,
            target = owner?.takeIf { it.from != "import" }?.addr,
            label = owner?.let { vm.effectiveFuncName(it.addr) } ?: e.fromName.ifEmpty { "unmapped" },
            type = e.kind.ifEmpty { "call" },
            note = moreSites(e, if (owner == null) "outside any known function" else "")
        )
    }
} else {
    val xs = d.xrefsOut
    if (xs.isNotEmpty()) xs.map { x ->
        val callee = vm.functionAt(x.to) ?: vm.functionContaining(x.to)
        val isImport = callee?.from == "import"
        XrefRow(
            site = x.from,
            target = if (callee != null && !isImport) callee.addr else null,
            label = callee?.let { vm.effectiveFuncName(it.addr) } ?: hexFmt(x.to),
            type = x.type.ifEmpty { "call" },
            note = if (isImport) "import" else if (callee == null) "unresolved target" else ""
        )
    } else vm.calleesOf(d.addr).map { e ->
        val callee = vm.functionAt(e.to) ?: vm.functionContaining(e.to)
        val isImport = callee?.from == "import"
        XrefRow(
            site = e.callSite,
            target = if (callee != null && !isImport) callee.addr else null,
            label = callee?.let { vm.effectiveFuncName(it.addr) } ?: e.toName.ifEmpty { hexFmt(e.to) },
            type = e.kind.ifEmpty { "call" },
            note = moreSites(e, if (isImport) "import" else if (callee == null) "unresolved target" else "")
        )
    }
}

/**
 * The cross-reference sheet, shared by Assembly and Pseudo-C. It answers the
 * same question about the same function from either tab, so it is one sheet.
 *
 * Rows that resolve navigate through `navigateTo`, so Back undoes the jump.
 * Import stubs and addresses outside every function resolve to nothing
 * decompilable, so they are drawn as leaves rather than offering a tap that
 * ends in "no function at that address".
 *
 * The count in the subtitle comes from [StudioViewModel.xrefInCount] /
 * [StudioViewModel.xrefOutCount] — the same call the chip that opened this
 * sheet makes — so the header can never read "3" under a chip that read "0".
 *
 * There is deliberately no [NavBarSpacer] in here: material3 1.3.1 gives
 * ModalBottomSheet `BottomSheetDefaults.windowInsets`, which already carries the
 * bottom system-bar inset, so a nav-bar spacer inside the content is either
 * doubled padding or dead code depending on how the insets are consumed. The
 * trailing gap below is plain optical breathing room.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun XrefSheet(
    vm: StudioViewModel,
    d: FunctionDetail,
    incoming: Boolean,
    onDismiss: () -> Unit
) {
    val ide = LocalIde.current
    // Identity, not the value: FunctionDetail is a data class whose equals walks
    // every list it holds. A fresh decompile of the same address is a new
    // instance with new xrefs, and keying on d.addr alone would miss it.
    val rows = remember(System.identityHashCode(d), incoming, vm.renames.size) {
        xrefRows(vm, d, incoming)
    }
    val count = if (incoming) vm.xrefInCount(d) else vm.xrefOutCount(d)
    val siteWidth = monoGlyphs(Type.monoSmall, 9)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.padding(bottom = Space.xl)) {
            Column(Modifier.padding(horizontal = Space.xl, vertical = Space.s)) {
                Text(
                    if (incoming) "References to this function" else "Calls out of this function",
                    color = ide.text, fontSize = Type.title, lineHeight = Type.titleLine,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(Space.xs))
                // The engine caps these arrays at 64 rows and reports the real
                // count separately, so the chip that opened this sheet can read
                // 561 while the list holds 64. Name both instead of letting the
                // header and the list quietly disagree.
                //
                // And 561 is itself a floor whenever the reference map dropped
                // what it could not hold, so the total carries the same `+` the
                // chip does and the note below says why, once.
                val floors = vm.xrefsAreFloors
                val shown =
                    if (rows.size < count) "${rows.size} of ${floorCount(count, floors)}"
                    else floorCount(count, floors)
                Text(
                    "$shown · ${vm.effectiveFuncName(d.addr)} @ ${hexFmt(d.addr)}",
                    color = ide.dim2, fontSize = Type.label, lineHeight = Type.labelLine,
                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                val floorNote = xrefFloorNote(vm)
                if (floorNote != null) {
                    Spacer(Modifier.height(Space.xs))
                    TruncationNote(floorNote)
                }
            }
            Spacer(Modifier.height(Space.m))
            if (rows.isEmpty()) {
                EmptyPanel(
                    if (incoming) "Nothing references this function" else "This function calls nothing",
                    "The engine found no edges in either its own analysis or the whole-binary call table."
                )
            } else {
                LazyColumn(Modifier.heightIn(max = 420.dp)) {
                    items(rows.size) { i ->
                        val r = rows[i]
                        val target = r.target
                        val base = Modifier
                            .fillMaxWidth()
                            .heightIn(min = 48.dp)
                        Row(
                            // A row with nothing to jump to — an import stub, an
                            // address outside every known function — is drawn as
                            // a leaf instead of rippling under your finger and
                            // then doing nothing.
                            (if (target != null) base.clickable(role = Role.Button) {
                                onDismiss()
                                vm.navigateTo(addr = target)
                            } else base).padding(horizontal = Space.xl, vertical = Space.m),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                hexFmt(r.site), color = ide.dim2, fontSize = Type.monoSmall,
                                lineHeight = Type.monoSmallLine, fontFamily = Mono, maxLines = 1,
                                modifier = Modifier.widthIn(min = siteWidth)
                            )
                            Spacer(Modifier.width(Space.m))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    r.label,
                                    color = if (target != null) ide.text else ide.dim,
                                    fontSize = Type.label, lineHeight = Type.labelLine,
                                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis
                                )
                                if (r.note.isNotEmpty()) {
                                    Text(
                                        r.note, color = ide.dim2, fontSize = Type.caption,
                                        lineHeight = Type.captionLine, maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            Spacer(Modifier.width(Space.m))
                            StatChip(r.type, mnemonicColor(r.type, ide))
                        }
                        HorizontalDivider(color = ide.border)
                    }
                }
            }
        }
    }
}

/**
 * The functions that reference one string or datum, opened from the strings
 * panel. XrefSheet above answers "who references this FUNCTION" and is driven by
 * a [FunctionDetail]; a string belongs to no function, so this is driven by the
 * ViewModel's [StudioViewModel.stringXrefs] instead — the engine's data-aware
 * answer (Engine::xrefsTo) for one address.
 *
 * Every row is a referencing SITE and always navigates: the site is an
 * instruction, so even a site outside every known function opens on that
 * address. The count in the subtitle is the engine's honest total, with the
 * loaded count beside it when its per-address cap dropped rows — the same shape
 * XrefSheet uses so the two sheets read alike.
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun StringXrefSheet(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val target = vm.stringXrefsTarget ?: return
    val x = vm.stringXrefs
    val busy = vm.stringXrefsBusy
    val siteWidth = monoGlyphs(Type.monoSmall, 9)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.padding(bottom = Space.xl)) {
            Column(Modifier.padding(horizontal = Space.xl, vertical = Space.s)) {
                Text(
                    when (x?.targetKind) {
                        "code" -> "References to this code address"
                        "data" -> "References to this data"
                        else -> "References to this string"
                    },
                    color = ide.text, fontSize = Type.title, lineHeight = Type.titleLine,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(Space.xs))
                val value = x?.value
                if (!value.isNullOrEmpty()) {
                    Text(
                        "“" + value + "”",
                        color = ide.text, fontSize = Type.label, lineHeight = Type.labelLine,
                        fontFamily = Mono, maxLines = 2, overflow = TextOverflow.Ellipsis
                    )
                    Spacer(Modifier.height(Space.xs))
                }
                val count = when {
                    x == null -> hexFmt(target)
                    x.total > x.refs.size -> "${x.refs.size} of ${x.total} · ${hexFmt(target)}"
                    else -> "${x.total} · ${hexFmt(target)}"
                }
                Text(
                    count,
                    color = ide.dim2, fontSize = Type.label, lineHeight = Type.labelLine,
                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.height(Space.m))
            when {
                busy && x == null -> SkeletonLines(8)
                x == null -> EmptyPanel(
                    "Could not read references",
                    "The engine returned no answer for this address."
                )
                x.refs.isEmpty() -> EmptyPanel(
                    if (x.targetKind == "code") "Nothing references this address"
                    else "Nothing references this string",
                    "The reference scan found no site that points here — the string may be " +
                        "unused, or reached only through a pointer the scan does not follow."
                )
                else -> LazyColumn(Modifier.heightIn(max = 420.dp)) {
                    items(x.refs.size) { i ->
                        val r = x.refs[i]
                        val known = r.funcAddr != 0L && vm.functionAt(r.funcAddr) != null
                        val label = when {
                            known -> vm.effectiveFuncName(r.funcAddr)
                            r.funcAddr != 0L -> r.funcDisplay.ifBlank { r.funcName }
                                .ifBlank { hexFmt(r.funcAddr) }
                            else -> "unmapped"
                        }
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .heightIn(min = 48.dp)
                                .clickable(role = Role.Button) {
                                    vm.gotoStringXref(r.funcAddr, r.from)
                                }
                                .padding(horizontal = Space.xl, vertical = Space.m),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Text(
                                hexFmt(r.from), color = ide.dim2, fontSize = Type.monoSmall,
                                lineHeight = Type.monoSmallLine, fontFamily = Mono, maxLines = 1,
                                modifier = Modifier.widthIn(min = siteWidth)
                            )
                            Spacer(Modifier.width(Space.m))
                            Column(Modifier.weight(1f)) {
                                Text(
                                    label,
                                    color = if (r.funcAddr != 0L) ide.text else ide.dim,
                                    fontSize = Type.label, lineHeight = Type.labelLine,
                                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis
                                )
                                if (r.funcAddr == 0L) {
                                    Text(
                                        "outside any known function", color = ide.dim2,
                                        fontSize = Type.caption, lineHeight = Type.captionLine,
                                        maxLines = 1, overflow = TextOverflow.Ellipsis
                                    )
                                }
                            }
                            Spacer(Modifier.width(Space.m))
                            StatChip(r.type.ifEmpty { "ref" }, mnemonicColor(r.type, ide))
                        }
                        HorizontalDivider(color = ide.border)
                    }
                }
            }
        }
    }
}

// ================================================================= pieces ==

@Composable
fun Hint(text: String, sub: String? = null) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(Space.xxl)
    ) {
        Text(text, color = ide.dim, fontSize = Type.body, lineHeight = Type.bodyLine)
        if (sub != null) {
            Spacer(Modifier.height(Space.s))
            Text(sub, color = ide.dim2, fontSize = Type.label, lineHeight = Type.labelLine)
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
        Text(
            title, color = ide.dim, fontSize = Type.body, lineHeight = Type.bodyLine,
            textAlign = TextAlign.Center
        )
        if (sub != null) {
            Spacer(Modifier.height(Space.m))
            Text(
                sub, color = ide.dim2, fontSize = Type.caption,
                lineHeight = Type.captionLine, textAlign = TextAlign.Center
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
            .padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column {
            Text(
                title, color = ide.text, fontSize = Type.body, lineHeight = Type.bodyLine,
                fontWeight = FontWeight.Bold
            )
            if (subtitle != null) {
                Text(
                    subtitle, color = ide.dim, fontSize = Type.caption,
                    lineHeight = Type.captionLine
                )
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
            k, color = kColor ?: ide.dim, fontSize = Type.mono, lineHeight = Type.monoLine,
            fontFamily = Mono, modifier = Modifier.width(150.dp), maxLines = 1
        )
        Text(
            v, color = vColor ?: ide.text, fontSize = Type.mono, lineHeight = Type.monoLine,
            fontFamily = Mono, maxLines = 2
        )
    }
}

/**
 * A small labelled statistic. Lifted verbatim out of DecompilePanel, where it
 * was private, so the other panels can stop reinventing it.
 *
 * The size is [Type.monoSmall] — the mono rung at caption size — and not the
 * `9.5.sp` it arrived with. That half-point was the last hand-typed size left
 * in the app, and it is the one [Type] names in its own doc as the reason the
 * scale exists. The chips get half a point wider; nothing else moves.
 */
@Composable
fun StatChip(label: String, tint: Color) {
    Text(
        label, color = tint, fontSize = Type.monoSmall, fontFamily = Mono,
        modifier = Modifier
            .background(tint.copy(alpha = 0.10f), RoundedCornerShape(6.dp))
            .padding(horizontal = Space.m, vertical = Space.s)
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
            .padding(horizontal = Space.m, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(label, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1)
        Spacer(Modifier.width(Space.s))
        Text(value, color = tint, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1)
    }
}

/**
 * The gap that keeps the last row of a column clear of the system navigation
 * bar. Replaces the scattered `Spacer(Modifier.height(40.dp))` guesses, which
 * were both too large on gesture navigation and too small on three-button.
 *
 * Not for use inside a ModalBottomSheet — the sheet already applies the bottom
 * system-bar inset itself. See [XrefSheet].
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

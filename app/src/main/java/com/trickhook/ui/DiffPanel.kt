package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.CompareArrows
import androidx.compose.material.icons.filled.FolderOpen
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.trickhook.model.DiffChangedPair
import com.trickhook.model.DiffEntry
import com.trickhook.model.DiffResult
import com.trickhook.model.FunctionDetail
import com.trickhook.vm.StudioViewModel
import kotlin.math.roundToInt

/**
 * Binary diff UI: the "pick binary B" chooser and the results panel.
 *
 * Both are full-screen Dialogs, in the same idiom as InstalledAppsSheet, and
 * both draw only from IdeColors + Common.kt — no new colours, Material icons
 * only. Everything here is dormant until a diff is invoked from the overflow
 * menu or the command palette, so a normal open renders none of it.
 */

/**
 * The "pick binary B" chooser is showing. Its own top-level flag, beside
 * [showInstalledApps], so the overflow menu and the command palette both raise
 * it without threading a boolean through StudioApp.
 */
var showDiffChooser by mutableStateOf(false)

/** How tall a scrolling region may grow before it scrolls inside the dialog. */
private val DiffListHeight = 520.dp
private val DiffPairHeight = 560.dp

// ============================================================ chooser =========

/**
 * The one-tap chooser for binary B: a file from the picker, or a native library
 * out of an installed app (reusing the installed-app lib picker in diff mode).
 */
@Composable
fun DiffChooserDialog(onFile: () -> Unit, onInstalled: () -> Unit, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    Dialog(onDismissRequest = onDismiss, properties = DialogProperties(usePlatformDefaultWidth = false)) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.l, vertical = 40.dp)
                .border(1.dp, ide.borderStrong, MaterialTheme.shapes.medium),
            color = ide.panel,
            shape = MaterialTheme.shapes.medium,
            tonalElevation = 8.dp
        ) {
            Column(Modifier.padding(Space.l)) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.CompareArrows, contentDescription = null,
                        tint = ide.accent, modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(Space.s))
                    Text(
                        "Diff against…", color = ide.accent, fontSize = Type.section,
                        fontFamily = Mono, fontWeight = FontWeight.Bold
                    )
                }
                Spacer(Modifier.height(Space.xs))
                Text(
                    "Compare the open binary against a second one and see which functions are identical, changed, added or removed.",
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                )
                Spacer(Modifier.height(Space.m))
                DiffChooserRow(
                    Icons.Filled.FolderOpen, "A binary file…",
                    "pick another version of the library from storage", onFile
                )
                Spacer(Modifier.height(Space.s))
                DiffChooserRow(
                    Icons.Filled.Android, "An installed app's library…",
                    "a native .so out of an installed app's own APK splits", onInstalled
                )
            }
        }
    }
}

@Composable
private fun DiffChooserRow(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    title: String,
    sub: String,
    onClick: () -> Unit
) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClickLabel = title, onClick = onClick)
            .border(1.dp, ide.borderStrong, RoundedCornerShape(8.dp))
            .heightIn(min = 52.dp)
            .padding(horizontal = Space.m, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, contentDescription = null, tint = ide.dim, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(Space.m))
        Column(Modifier.weight(1f)) {
            Text(title, color = ide.text, fontSize = Type.body)
            Text(sub, color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine)
        }
    }
}

// ============================================================ results =========

@Composable
fun DiffPanel(vm: StudioViewModel) {
    if (!vm.diffOpen) return
    val ide = LocalIde.current
    Dialog(
        onDismissRequest = { vm.closeDiff() },
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.m, vertical = 24.dp)
                .border(1.dp, ide.borderStrong, MaterialTheme.shapes.medium),
            color = ide.panel,
            shape = MaterialTheme.shapes.medium,
            tonalElevation = 8.dp
        ) {
            Column(Modifier.padding(Space.l)) {
                val pair = vm.diffPair
                if (pair != null) {
                    DiffPairView(vm, pair)
                } else {
                    DiffResultsView(vm)
                }
            }
        }
    }
}

@Composable
private fun DiffResultsView(vm: StudioViewModel) {
    val ide = LocalIde.current
    val r = vm.diffResult

    // header
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(Icons.Filled.CompareArrows, contentDescription = null, tint = ide.accent, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(Space.s))
        Text(
            "Binary diff", color = ide.accent, fontSize = Type.section,
            fontFamily = Mono, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)
        )
        Row(
            Modifier
                .clickable(role = Role.Button, onClickLabel = "Close the diff", onClick = { vm.closeDiff() })
                .heightIn(min = 36.dp)
                .padding(horizontal = Space.xs, vertical = Space.xs),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Filled.Close, contentDescription = "Close the diff", tint = ide.dim, modifier = Modifier.size(18.dp))
        }
    }

    when {
        vm.diffRunning && r == null -> {
            Spacer(Modifier.height(Space.m))
            Text(
                (vm.diffPhase.ifBlank { "Comparing" }) + "…",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
            )
            Spacer(Modifier.height(Space.s))
            SkeletonLines(8)
        }
        vm.diffError != null -> {
            Spacer(Modifier.height(Space.m))
            EmptyPanel("Diff failed", vm.diffError)
        }
        r != null -> DiffResultBody(vm, r)
        else -> {
            Spacer(Modifier.height(Space.m))
            EmptyPanel("No diff yet", "Pick a second binary to compare against.")
        }
    }
}

@Composable
private fun DiffResultBody(vm: StudioViewModel, r: DiffResult) {
    val ide = LocalIde.current
    val c = r.counts

    Spacer(Modifier.height(Space.xs))
    Text(
        "${r.aName}  →  ${r.bName}",
        color = ide.text, fontSize = Type.label, fontFamily = Mono,
        maxLines = 2, overflow = TextOverflow.Ellipsis
    )
    Text(
        "A ${r.aArch}   ·   B ${r.bArch}",
        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
    )
    Spacer(Modifier.height(Space.m))

    // Summary chips: the four buckets, each in a distinct token.
    Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
        StatChip("identical", "${r.identical}", ide.entry)
        Spacer(Modifier.width(Space.s))
        StatChip("changed", "${c.changed}", ide.amber)
        Spacer(Modifier.width(Space.s))
        StatChip("added", "${c.added}", ide.cyan)
        Spacer(Modifier.width(Space.s))
        StatChip("removed", "${c.removed}", ide.red)
    }
    Spacer(Modifier.height(Space.s))
    Text(
        "${c.identicalExact} byte-identical · ${c.identicalFingerprint} relocated-unchanged · " +
            "A ${c.aFuncs} fns, B ${c.bFuncs} fns",
        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
        lineHeight = Type.captionLine
    )
    if (r.notes.isNotEmpty()) {
        Spacer(Modifier.height(Space.s))
        r.notes.forEach { n ->
            Text("· $n", color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine)
        }
    }

    Spacer(Modifier.height(Space.m))

    LazyColumn(Modifier.fillMaxWidth().heightIn(max = DiffListHeight)) {
        if (r.changed.isNotEmpty()) {
            item { DiffSectionHeader("Changed", c.changedShown, c.changed, ide.amber) }
            items(r.changed.size) { i -> ChangedRow(r.changed[i]) { vm.openDiffPair(r.changed[i]) } }
        }
        if (r.removed.isNotEmpty()) {
            item { DiffSectionHeader("Removed (in ${r.aName} only)", c.removedShown, c.removed, ide.red) }
            items(r.removed.size) { i -> EntryRow(r.removed[i], ide.red) }
        }
        if (r.added.isNotEmpty()) {
            item { DiffSectionHeader("Added (in ${r.bName} only)", c.addedShown, c.added, ide.cyan) }
            items(r.added.size) { i -> EntryRow(r.added[i], ide.cyan) }
        }
        if (r.changed.isEmpty() && r.removed.isEmpty() && r.added.isEmpty()) {
            item {
                Text(
                    "No differences: every function is identical.",
                    color = ide.entry, fontSize = Type.body, fontFamily = Mono,
                    modifier = Modifier.padding(vertical = Space.m)
                )
            }
        }
    }
}

@Composable
private fun DiffSectionHeader(title: String, shown: Int, total: Int, tint: Color) {
    val ide = LocalIde.current
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.xs, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Dot(tint)
        Spacer(Modifier.width(Space.s))
        Text(
            title, color = ide.text, fontSize = Type.label, fontFamily = Mono,
            fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f),
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        Text(
            ofTotal(shown, total), color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
        )
    }
}

@Composable
private fun Dot(tint: Color) {
    Spacer(
        Modifier
            .size(8.dp)
            .background(tint, RoundedCornerShape(2.dp))
    )
}

@Composable
private fun ChangedRow(p: DiffChangedPair, onClick: () -> Unit) {
    val ide = LocalIde.current
    val pct = (p.similarity * 100).roundToInt()
    val nameChanged = p.nameA != p.nameB
    Column(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Button, onClickLabel = "Open ${p.nameA} side by side", onClick = onClick)
            .heightIn(min = 48.dp)
            .padding(horizontal = Space.s, vertical = Space.s)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                if (nameChanged) "${p.nameA} → ${p.nameB}" else p.nameA,
                color = ide.text, fontSize = Type.body, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
            )
            Spacer(Modifier.width(Space.s))
            Text("$pct%", color = ide.amber, fontSize = Type.label, fontFamily = Mono)
        }
        Spacer(Modifier.height(Space.xs))
        // Similarity bar: how much of the two bodies matched.
        Row(Modifier.fillMaxWidth().height(3.dp)) {
            if (pct > 0) Spacer(Modifier.weight(pct.coerceIn(1, 100).toFloat()).barSegment(ide.amber))
            if (pct < 100) Spacer(Modifier.weight((100 - pct).coerceIn(1, 100).toFloat()).barSegment(ide.border))
        }
        Spacer(Modifier.height(Space.xs))
        Text(
            "A ${hexFmt(p.addrA)}   ·   B ${hexFmt(p.addrB)}",
            color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
        )
    }
}

private fun Modifier.barSegment(color: Color): Modifier = this
    .height(3.dp)
    .background(color, RoundedCornerShape(2.dp))

@Composable
private fun EntryRow(e: DiffEntry, tint: Color) {
    val ide = LocalIde.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = 40.dp).padding(horizontal = Space.s, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            e.name, color = ide.text, fontSize = Type.body, fontFamily = Mono,
            maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
        )
        Spacer(Modifier.width(Space.s))
        Text(hexFmt(e.addr), color = tint, fontSize = Type.caption, fontFamily = Mono)
    }
}

// ============================================================ side by side ====

@Composable
private fun DiffPairView(vm: StudioViewModel, pair: DiffChangedPair) {
    val ide = LocalIde.current
    val pct = (pair.similarity * 100).roundToInt()

    // header with a back arrow to the results list
    Row(verticalAlignment = Alignment.CenterVertically) {
        Row(
            Modifier
                .clickable(role = Role.Button, onClickLabel = "Back to the diff results", onClick = { vm.clearDiffPair() })
                .heightIn(min = 36.dp)
                .padding(horizontal = Space.xs, vertical = Space.xs),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to the diff results",
                tint = ide.accent, modifier = Modifier.size(18.dp)
            )
        }
        Spacer(Modifier.width(Space.s))
        Column(Modifier.weight(1f)) {
            Text(
                if (pair.nameA != pair.nameB) "${pair.nameA} → ${pair.nameB}" else pair.nameA,
                color = ide.accent, fontSize = Type.section, fontFamily = Mono,
                fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                "$pct% of normalized instructions in common",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
            )
        }
    }
    Spacer(Modifier.height(Space.m))

    if (vm.diffPairBusy) {
        SkeletonLines(10)
        return
    }

    val a = vm.diffDetailA
    val b = vm.diffDetailB
    LazyColumn(Modifier.fillMaxWidth().heightIn(max = DiffPairHeight)) {
        // A is the OPEN binary, so the open project's renames and comments — keyed
        // to A's addresses — belong on this side. B is the second binary the diff
        // was run against; its addresses are a different space, so it falls back
        // to the engine's names honestly and shows no overlay.
        item { SideHeader("A", vm.diffResult?.aName ?: "", pair.addrA, a, ide.entry, vm.renames["0x%08X".format(pair.addrA)]) }
        if (a != null && a.ok) items(a.asm.size) { i ->
            val ln = a.asm[i]
            AsmRow(ln, vm.comments["0x%08X".format(ln.addr)])
        }
        else item { EmptyPanel("No disassembly for A", a?.error) }

        item { Spacer(Modifier.height(Space.l)) }

        item { SideHeader("B", vm.diffResult?.bName ?: "", pair.addrB, b, ide.cyan) }
        if (b != null && b.ok) items(b.asm.size) { i -> AsmRow(b.asm[i]) }
        else item { EmptyPanel("No disassembly for B", b?.error) }
    }
}

@Composable
private fun SideHeader(side: String, binName: String, addr: Long, d: FunctionDetail?, tint: Color, renamed: String? = null) {
    val ide = LocalIde.current
    // `renamed` is the open project's rename overlay for this address, resolved by
    // the caller and passed only for the A side: renames are keyed to the OPEN
    // binary's addresses, so B (the compared-against binary) has none to apply.
    val display = renamed ?: (d?.let { if (it.displayName.isNotEmpty()) it.displayName else it.name } ?: hexFmt(addr))
    Column(Modifier.fillMaxWidth().padding(vertical = Space.s)) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                side, color = tint, fontSize = Type.label, fontFamily = Mono, fontWeight = FontWeight.Bold
            )
            Spacer(Modifier.width(Space.s))
            Text(
                display,
                color = ide.text, fontSize = Type.label, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
            )
        }
        Text(
            binName + (if (d != null) "  ·  ${hexFmt(addr)}  ·  ${d.size} bytes  ·  ${d.arch}  ·  ${d.backend}" else "  ·  ${hexFmt(addr)}"),
            color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        if (d != null && d.asmTruncated) {
            Text(
                "listing truncated — not the whole function",
                color = ide.amber, fontSize = Type.caption, fontFamily = Mono
            )
        }
    }
}

@Composable
private fun AsmRow(line: com.trickhook.model.AsmLine, userComment: String? = null) {
    val ide = LocalIde.current
    val hScroll = rememberScrollState()
    Column(
        Modifier.fillMaxWidth().heightIn(min = 20.dp).padding(horizontal = Space.xs, vertical = Space.xs)
    ) {
        Row(Modifier.fillMaxWidth()) {
            Text(
                hexFmt(line.addr), color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, modifier = Modifier.widthIn(min = 78.dp)
            )
            Row(Modifier.weight(1f).horizontalScroll(hScroll)) {
                Text(
                    line.mnem, color = mnemonicColor(line.mnem, ide), fontSize = Type.monoSmall,
                    fontFamily = Mono, fontWeight = FontWeight.Medium, maxLines = 1,
                    modifier = Modifier.widthIn(min = 56.dp)
                )
                Text(
                    line.ops, color = ide.text, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
                )
                // The engine's auto-comment stays dim and inline.
                if (line.comment.isNotEmpty()) {
                    Spacer(Modifier.width(Space.m))
                    Text(
                        "; ${line.comment}", color = ide.dim2, fontSize = Type.monoSmall,
                        fontFamily = Mono, maxLines = 1
                    )
                }
            }
        }
        // The user's own comment (open project overlay, A side only) rides its own
        // line in the accent tint, so it is never confused with the auto-comment.
        if (userComment != null) {
            Text(
                "; $userComment", color = ide.accent, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 2, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 78.dp)
            )
        }
    }
}

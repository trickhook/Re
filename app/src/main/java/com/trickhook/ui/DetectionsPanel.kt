package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.trickhook.model.Detection
import com.trickhook.vm.StudioViewModel

/**
 * Detections view — the anti-analysis & pinning scanner.
 *
 * It runs the engine's read-only Engine::detect over the open binary (once per
 * open file, re-runnable from the header) and browses the result grouped by
 * category. Every row is a destination: a detection attributed to a function
 * opens Assembly on that function and lands on the referencing instruction, the
 * same goto path the string-xref sheet uses ([StudioViewModel.gotoDetection]);
 * an unattributed hit — a matched string that nothing references — reveals its
 * bytes in the hex view instead.
 *
 * Draws only from IdeColors + Common.kt: no new colours, Material icons only.
 */
@Composable
fun DetectionsPanel(vm: StudioViewModel) {
    // Scan once when the tab is first opened for a binary; a cached result
    // survives leaving and returning, and a new binary clears it (resetPanelState).
    LaunchedEffect(vm.currentPath) {
        if (vm.currentPath != null && vm.detections == null && !vm.detectionsBusy) {
            vm.runDetections()
        }
    }

    val result = vm.detections
    val busy = vm.detectionsBusy
    val error = vm.detectionsError

    Column(Modifier.fillMaxSize()) {
        DetectionsHeader(vm, result, busy)
        when {
            // First scan still running: ghost rows in the shape of the list.
            busy && result == null -> SkeletonLines(12)

            error != null && result == null -> EmptyPanel("Scan failed", error)

            result == null -> EmptyPanel(
                "No scan yet",
                "Open a binary — the anti-analysis and pinning scan runs over its strings, " +
                    "functions and references and lands its findings here."
            )

            result.detections.isEmpty() -> EmptyPanel(
                "Nothing detected",
                "No ssl-pinning, root, anti-debug, anti-Frida, emulator or tamper markers " +
                    "matched. This is the absence of known markers, not proof the binary has none."
            )

            else -> {
                // groupBy keeps first-encounter order, and the engine already
                // sorted by (category, confidence, address), so categories come
                // out in database order and rows strongest-first within each.
                val groups = result.detections.groupBy { it.category }
                LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
                    groups.forEach { (category, list) ->
                        item(key = "hdr:$category") {
                            DetectionCategoryHeader(category, result.counts[category] ?: list.size)
                        }
                        items(
                            list.size,
                            key = { "$category|${list[it].funcAddr}|${list[it].stringAddr}" }
                        ) { i ->
                            DetectionRow(vm, list[i])
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DetectionsHeader(vm: StudioViewModel, result: com.trickhook.model.DetectionResult?, busy: Boolean) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .background(ide.panel2)
            .padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            Icons.Filled.Security, contentDescription = null,
            tint = ide.accent, modifier = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(Space.s))
        Column(Modifier.weight(1f)) {
            Text(
                "Detections", color = ide.text, fontSize = Type.body,
                lineHeight = Type.bodyLine, fontWeight = FontWeight.Bold
            )
            val sub = when {
                busy && result == null -> "Scanning the open binary…"
                result == null -> "Anti-analysis & pinning scan"
                else -> {
                    val cats = result.counts.size
                    val un = if (result.unattributed > 0) " · ${result.unattributed} unattributed" else ""
                    "${result.total} across $cats categor${if (cats == 1) "y" else "ies"}$un" +
                        (if (busy) " · rescanning…" else "")
                }
            }
            Text(sub, color = ide.dim, fontSize = Type.caption, lineHeight = Type.captionLine)
        }
        IconButton(onClick = { if (!busy) vm.runDetections() }) {
            Icon(
                Icons.Filled.Refresh,
                contentDescription = "Rescan the open binary",
                tint = if (busy) ide.dim2 else ide.accent,
                modifier = Modifier.size(18.dp)
            )
        }
    }
}

@Composable
private fun DetectionCategoryHeader(category: String, count: Int) {
    val ide = LocalIde.current
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(
            Modifier
                .size(8.dp)
                .background(categoryColor(category), RoundedCornerShape(2.dp))
        )
        Spacer(Modifier.width(Space.s))
        Text(
            categoryTitle(category), color = ide.text, fontSize = Type.label,
            fontFamily = Mono, fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f),
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        Text("$count", color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
    }
}

@Composable
private fun DetectionRow(vm: StudioViewModel, d: Detection) {
    val ide = LocalIde.current
    val known = d.funcAddr != 0L && vm.functionAt(d.funcAddr) != null
    // Where a tap lands: the function for an attributed detection, else the
    // string's bytes in hex for an unattributed one. A row that can reach
    // neither is not clickable — a ripple that leads nowhere is worse than none.
    val hexReachable = d.funcAddr == 0L && d.stringAddr != 0L && vm.fileOffsetOf(d.stringAddr) != null
    val canJump = d.funcAddr != 0L || hexReachable
    val label = when {
        // A guard the engine attributed to a loaded function resolves through the
        // shared overlay helper (renames first), so a renamed guard shows its
        // user name. When the function is not in the loaded page, the same
        // overlay is still consulted by address before the engine's name.
        known -> vm.effectiveFuncName(d.funcAddr)
        d.funcAddr != 0L -> vm.renames["0x%08X".format(d.funcAddr)]
            ?: d.funcDisplay.ifBlank { d.funcName }.ifBlank { hexFmt(d.funcAddr) }
        else -> (d.value ?: "").ifBlank { "unattributed string" }
    }
    val where = if (d.funcAddr != 0L) hexFmt(d.funcAddr) else hexFmt(d.stringAddr)
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                if (canJump) Modifier.clickable(
                    role = Role.Button,
                    onClickLabel = if (d.funcAddr != 0L) "Open in Assembly" else "Show the bytes in Hex"
                ) {
                    if (d.funcAddr != 0L) vm.gotoDetection(d.funcAddr, d.site)
                    else vm.gotoDetectionString(d.stringAddr)
                } else Modifier
            )
            .heightIn(min = 52.dp)
            .padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                label,
                color = if (canJump) ide.text else ide.dim,
                fontSize = Type.body, lineHeight = Type.bodyLine, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Spacer(Modifier.height(Space.xs))
            Row(verticalAlignment = Alignment.CenterVertically) {
                // The exact matched token — the evidence the user judges by.
                Text(
                    d.evidence, color = categoryColor(d.category), fontSize = Type.monoSmall,
                    fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f, fill = false)
                )
                if (d.tokens.size > 1) {
                    Spacer(Modifier.width(Space.s))
                    Text(
                        "+${d.tokens.size - 1}", color = ide.dim2,
                        fontSize = Type.monoSmall, fontFamily = Mono
                    )
                }
                Spacer(Modifier.width(Space.m))
                Text(
                    "${d.source} · $where" + (if (d.funcAddr == 0L) " · no function" else ""),
                    color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
        }
        Spacer(Modifier.width(Space.m))
        StatChip(d.confidence, confidenceColor(d.confidence))
    }
}

// A distinct palette token per category, all already in IdeColors — no new
// colour is introduced. The dot on a category header and its rows' evidence
// share it, so a category reads as one band down the list.
@Composable
private fun categoryColor(category: String): Color {
    val ide = LocalIde.current
    return when (category) {
        "ssl-pinning" -> ide.cyan
        "root-detection" -> ide.red
        "anti-debug" -> ide.amber
        "anti-frida" -> ide.violet
        "emulator-detection" -> ide.entry
        "tamper-detection" -> ide.accent
        else -> ide.dim
    }
}

// Confidence as a severity ramp: high is the alarm colour, low the quiet tier.
@Composable
private fun confidenceColor(confidence: String): Color {
    val ide = LocalIde.current
    return when (confidence) {
        "high" -> ide.red
        "medium" -> ide.amber
        else -> ide.dim2
    }
}

private fun categoryTitle(category: String): String = when (category) {
    "ssl-pinning" -> "SSL pinning"
    "root-detection" -> "Root detection"
    "anti-debug" -> "Anti-debug"
    "anti-frida" -> "Anti-Frida"
    "emulator-detection" -> "Emulator detection"
    "tamper-detection" -> "Tamper detection"
    else -> category
}

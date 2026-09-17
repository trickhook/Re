package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Android
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.trickhook.model.AppLibScan
import com.trickhook.model.AppNativeLib
import com.trickhook.model.InstalledApp
import com.trickhook.vm.StudioViewModel

/**
 * Raised from the home screen, the overflow menu and the command palette.
 *
 * Its own top-level flag, beside CommandPalette's, so the two entry points and
 * StudioApp's render site all read and set the one boolean without threading it
 * through.
 */
var showInstalledApps by mutableStateOf(false)

/**
 * When true, the sheet picks binary B for a DIFF against the open binary rather
 * than opening the chosen library. Set beside [showInstalledApps] by the "Diff
 * against an installed lib…" action; cleared when the sheet closes.
 */
var installedAppsDiffMode by mutableStateOf(false)

/** How tall either list is allowed to grow before it scrolls inside the sheet. */
private val InstalledListHeight = 380.dp

/**
 * The "open a native library straight from an installed app" picker.
 *
 * Two steps in one sheet. Step one lists the installed apps (user apps first,
 * system apps behind a toggle and de-emphasised) resolved through
 * PackageManager exactly as the debugger's attach picker resolves labels. Step
 * two scans the chosen app's base and split APKs for their native libraries and
 * lists them grouped by library name, showing which split and which ABI each
 * came from and preferring the device's primary ABI. Tapping one extracts that
 * single .so and routes it through the ordinary analyse path.
 *
 * It reads the app's own shipped APKs, which are world-readable — no root, no
 * reinstall — and it never patches or repackages anything.
 */
@Composable
fun InstalledAppsSheet(vm: StudioViewModel) {
    if (!showInstalledApps) return
    val ide = LocalIde.current
    val ctx = LocalContext.current

    var selected by remember { mutableStateOf<InstalledApp?>(null) }
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }

    // Enumerate once when the sheet opens; drop both lists when it closes so a
    // stale set never flashes on the next open.
    LaunchedEffect(Unit) { vm.listInstalledApps(ctx) }
    val diffMode = installedAppsDiffMode
    val close = {
        showInstalledApps = false
        installedAppsDiffMode = false
        vm.clearInstalledApps()
    }

    // The scan for step two is kicked off the moment an app is chosen, keyed on
    // the package so it runs once per selection.
    LaunchedEffect(selected?.pkg) {
        selected?.let { vm.scanInstalledLibs(ctx, it.pkg) }
    }

    Dialog(
        onDismissRequest = close,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
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
                val app = selected
                if (app == null) {
                    AppPickHeader(diffMode)
                    Spacer(Modifier.height(Space.m))
                    AppPickStep(
                        vm = vm,
                        query = query,
                        onQuery = { query = it },
                        showSystem = showSystem,
                        onToggleSystem = { showSystem = !showSystem },
                        onPick = { selected = it }
                    )
                } else {
                    LibPickHeader(app, diffMode) { selected = null }
                    Spacer(Modifier.height(Space.m))
                    LibPickStep(vm, app, diffMode) { lib ->
                        if (diffMode) vm.diffAgainstInstalledLib(ctx, lib, app.label)
                        else vm.openInstalledLib(ctx, lib, app.label)
                        close()
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------- step one ==

@Composable
private fun AppPickHeader(diffMode: Boolean) {
    val ide = LocalIde.current
    Text(
        if (diffMode) "Diff against an installed library" else "Open from an installed app",
        color = ide.accent, fontSize = Type.section, fontFamily = Mono,
        fontWeight = FontWeight.Bold
    )
    Spacer(Modifier.height(Space.xs))
    Text(
        if (diffMode)
            "Pick an installed app's native library to compare against the open binary — no root, no reinstall."
        else
            "Reads an installed app's own APK splits for their native libraries — no root, no reinstall.",
        color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
    )
}

@Composable
private fun AppPickStep(
    vm: StudioViewModel,
    query: String,
    onQuery: (String) -> Unit,
    showSystem: Boolean,
    onToggleSystem: () -> Unit,
    onPick: (InstalledApp) -> Unit
) {
    val ide = LocalIde.current
    val apps = vm.installedApps

    // Identity and size, never the list value: a value key would deep-compare
    // every InstalledApp on each recomposition (the codebase's rule for lists).
    val filtered = remember(System.identityHashCode(apps), apps.size, query, showSystem) {
        apps.asSequence()
            .filter { showSystem || !it.isSystem }
            .filter {
                query.isBlank() ||
                    it.label.contains(query, ignoreCase = true) ||
                    it.pkg.contains(query, ignoreCase = true)
            }
            .toList()
    }
    val systemCount = remember(System.identityHashCode(apps), apps.size) {
        apps.count { it.isSystem }
    }

    OutlinedTextField(
        value = query,
        onValueChange = onQuery,
        label = { Text("Filter apps", fontSize = Type.caption) },
        singleLine = true,
        modifier = Modifier
            .fillMaxWidth()
            .semantics { contentDescription = "Filter installed apps by label or package" },
        textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
    )
    Spacer(Modifier.height(Space.s))
    Row(
        Modifier.fillMaxWidth().heightIn(min = 36.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            "${filtered.size} shown", color = ide.dim2,
            fontSize = Type.caption, fontFamily = Mono,
            modifier = Modifier.weight(1f)
        )
        if (systemCount > 0) {
            TogglePill(
                label = if (showSystem) "Hiding no system apps" else "$systemCount system apps hidden",
                on = showSystem,
                onClick = onToggleSystem
            )
        }
    }
    Spacer(Modifier.height(Space.s))

    when {
        vm.installedAppsLoading && apps.isEmpty() -> SkeletonLines(7)
        filtered.isEmpty() -> EmptyPanel(
            if (apps.isEmpty()) "No apps to show"
            else "Nothing matches \"$query\"",
            if (apps.isEmpty())
                "PackageManager returned no installed apps. QUERY_ALL_PACKAGES is declared, so this is unusual."
            else if (!showSystem && systemCount > 0)
                "Only user-installed apps are listed. Tap the toggle above to include the $systemCount system apps."
            else "No installed app's label or package contains that text."
        )
        else -> LazyColumn(Modifier.fillMaxWidth().heightIn(max = InstalledListHeight)) {
            items(filtered.size) { i -> AppRow(filtered[i], onPick) }
        }
    }
}

@Composable
private fun AppRow(app: InstalledApp, onPick: (InstalledApp) -> Unit) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(
                role = Role.Button,
                onClickLabel = "Read the native libraries in ${app.label}"
            ) { onPick(app) }
            .heightIn(min = 52.dp)
            .padding(horizontal = Space.s, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(
            Icons.Filled.Android,
            if (app.isSystem) ide.dim2 else ide.dim, 15.dp,
            contentDescription = null
        )
        Column(Modifier.weight(1f)) {
            Text(
                app.label,
                color = if (app.isSystem) ide.dim else ide.text,
                fontSize = Type.body, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                if (app.versionName.isNotBlank()) "${app.pkg} · v${app.versionName}" else app.pkg,
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        if (app.isSystem) {
            Spacer(Modifier.width(Space.m))
            StatChip("system", ide.dim2)
        }
    }
}

// ---------------------------------------------------------------- step two ==

@Composable
private fun LibPickHeader(app: InstalledApp, diffMode: Boolean, onBack: () -> Unit) {
    val ide = LocalIde.current
    Row(verticalAlignment = Alignment.CenterVertically) {
        Row(
            Modifier
                .clickable(role = Role.Button, onClickLabel = "Back to the app list", onClick = onBack)
                .heightIn(min = 40.dp)
                .padding(horizontal = Space.xs, vertical = Space.xs),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = "Back to the app list",
                tint = ide.accent, modifier = Modifier.size(18.dp)
            )
        }
        Spacer(Modifier.width(Space.s))
        Column(Modifier.weight(1f)) {
            Text(
                app.label, color = ide.accent, fontSize = Type.section, fontFamily = Mono,
                fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                (if (diffMode) "library to diff · " else "native libraries · ") + app.pkg,
                color = ide.dim2,
                fontSize = Type.caption, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun LibPickStep(
    vm: StudioViewModel,
    app: InstalledApp,
    diffMode: Boolean,
    onOpen: (AppNativeLib) -> Unit
) {
    val ide = LocalIde.current
    // Ignore a scan that is still about the previously chosen app.
    val scan: AppLibScan? = vm.installedLibs?.takeIf { it.pkg == app.pkg }

    // if/else, not a subjectless when: the else branch is where `scan` is used
    // as non-null, and this makes the smart cast unmistakable to the compiler.
    if (scan == null || vm.installedLibsLoading) {
        SkeletonLines(6)
    } else if (scan.libs.isEmpty()) {
        EmptyPanel(
            if (scan.ok) "No native libraries" else "Could not read this app",
            scan.note
        )
    } else {
        val primaryAbi = scan.primaryAbi
        val groups = remember(System.identityHashCode(scan)) {
            scan.libs.groupBy { it.libName }.toSortedMap().map { (name, rows) ->
                name to rows.sortedWith(
                    compareByDescending<AppNativeLib> { it.abi == primaryAbi }
                        .thenBy { it.abi }
                        .thenBy { it.splitName }
                )
            }
        }
        val summary = "${scan.libs.size} entries · ${groups.size} libraries" +
            (if (primaryAbi.isNotBlank()) " · primary ABI $primaryAbi" else "") +
            (if (scan.readableApkCount < scan.apkCount)
                " · ${scan.readableApkCount} of ${scan.apkCount} APKs read"
            else " · ${scan.apkCount} APKs")
        LazyColumn(Modifier.fillMaxWidth().heightIn(max = InstalledListHeight)) {
            item {
                Text(
                    summary,
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                    modifier = Modifier.padding(horizontal = Space.s, vertical = Space.s)
                )
            }
            groups.forEach { (name, rows) ->
                item {
                    Text(
                        name, color = ide.text, fontSize = Type.label, fontFamily = Mono,
                        fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(horizontal = Space.s, vertical = Space.s)
                    )
                }
                items(rows.size) { i -> LibRow(rows[i], primaryAbi, diffMode, onOpen) }
            }
        }
    }
}

@Composable
private fun LibRow(lib: AppNativeLib, primaryAbi: String, diffMode: Boolean, onOpen: (AppNativeLib) -> Unit) {
    val ide = LocalIde.current
    val isPrimary = lib.abi == primaryAbi && primaryAbi.isNotBlank()
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(
                role = Role.Button,
                onClickLabel = if (diffMode) "Diff against ${lib.libName} (${lib.abi})"
                else "Extract and analyse ${lib.libName} (${lib.abi})"
            ) { onOpen(lib) }
            .heightIn(min = 48.dp)
            .padding(horizontal = Space.s, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(Icons.Filled.Memory, ide.dim, 13.dp, contentDescription = "Native library")
        Column(Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    lib.abi, color = if (isPrimary) ide.accent else ide.cyan,
                    fontSize = Type.label, fontFamily = Mono, maxLines = 1
                )
                if (isPrimary) {
                    Spacer(Modifier.width(Space.s))
                    StatChip("primary", ide.accent)
                }
            }
            Text(
                lib.splitName, color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        Spacer(Modifier.width(Space.m))
        Text(soSize(lib.size), color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
    }
}

// ------------------------------------------------------------------ pieces ==

/**
 * A small on/off pill for the system-apps toggle, in the palette's own tokens:
 * accent when on, dim when off, its own border so the edge is real.
 */
@Composable
private fun TogglePill(label: String, on: Boolean, onClick: () -> Unit) {
    val ide = LocalIde.current
    val tint = if (on) ide.accent else ide.dim
    Text(
        label, color = tint, fontSize = Type.monoSmall, fontFamily = Mono,
        modifier = Modifier
            .clickable(role = Role.Button, onClickLabel = "Toggle system apps") { onClick() }
            .background(tint.copy(alpha = 0.10f), RoundedCornerShape(6.dp))
            .border(1.dp, ide.borderStrong, RoundedCornerShape(6.dp))
            .padding(horizontal = Space.m, vertical = Space.s)
    )
}

private fun soSize(n: Long): String = when {
    n >= 1024 * 1024 -> "%.1f MB".format(n / 1048576.0)
    n >= 1024 -> "%.0f KB".format(n / 1024.0)
    else -> "$n B"
}

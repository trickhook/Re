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
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.PriorityHigh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.VpnKey
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.trickhook.model.AppNativeLib
import com.trickhook.model.AttackSurface
import com.trickhook.model.CustomPermission
import com.trickhook.model.DeepLink
import com.trickhook.model.SigningCert
import com.trickhook.model.SurfaceComponent
import com.trickhook.model.SurfacePermission
import com.trickhook.vm.StudioViewModel

/**
 * The APK / AndroidManifest attack-surface triage — "what am I looking at, and
 * what does it expose" for one app, before diving into its libraries.
 *
 * A full-screen Dialog in the same idiom as [InstalledAppsSheet] and
 * [DiffPanel], because every per-target drill-in reached from the installed-apps
 * picker in this app is a Dialog, and the picker is itself one. It shows the
 * app's identity, its EXPORTED components made prominent (they are the attack
 * surface), its permissions with the dangerous ones flagged, the deep-link entry
 * points read out of the binary manifest, its native libraries per ABI, and its
 * signing certificate(s). Everything is loaded off the main thread by the
 * ViewModel; this only reads the result.
 */

/** The sheet is showing. A top-level flag beside [showInstalledApps]. */
var showManifestSheet by mutableStateOf(false)

/**
 * The target: an installed package id, or null to mean "the APK file open in
 * the app right now". Set by whichever entry point raised the sheet.
 */
var manifestTargetPkg by mutableStateOf<String?>(null)

/**
 * A human label carried alongside the package by the entry point, so the header
 * reads the app's name while the scan is still in flight. Kept beside the flags
 * rather than threaded through, exactly like the installed-apps picker's flags.
 */
var manifestTargetLabel by mutableStateOf("")

/** How tall the scrolling body may grow before it scrolls inside the dialog. */
private val ManifestBodyHeight = 560.dp

@Composable
fun ManifestSheet(vm: StudioViewModel) {
    if (!showManifestSheet) return
    val ide = LocalIde.current
    val ctx = LocalContext.current

    // Load once per target when the sheet opens; the ViewModel drops a scan that
    // lands after the target changed, so a null key for the file case is fine.
    LaunchedEffect(manifestTargetPkg) {
        val pkg = manifestTargetPkg
        if (pkg != null) vm.loadAttackSurfaceForPackage(ctx, pkg, manifestTargetLabelOrPkg(pkg))
        else vm.loadAttackSurfaceForOpenApk(ctx)
    }
    val close = {
        showManifestSheet = false
        vm.clearAttackSurface()
    }

    Dialog(onDismissRequest = close, properties = DialogProperties(usePlatformDefaultWidth = false)) {
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
                Header(vm, close)
                Spacer(Modifier.height(Space.m))
                val surface = vm.attackSurface
                when {
                    vm.attackSurfaceLoading || surface == null -> SkeletonLines(10)
                    !surface.ok -> EmptyPanel(
                        "Could not read this app",
                        surface.error.ifBlank { "PackageManager returned nothing and no manifest could be decoded." }
                    )
                    else -> Body(surface)
                }
            }
        }
    }
}

private fun manifestTargetLabelOrPkg(pkg: String) = manifestTargetLabel.ifBlank { pkg }

@Composable
private fun Header(vm: StudioViewModel, onClose: () -> Unit) {
    val ide = LocalIde.current
    val surface = vm.attackSurface
    Row(verticalAlignment = Alignment.CenterVertically) {
        Icon(
            Icons.Filled.Security, contentDescription = null,
            tint = ide.accent, modifier = Modifier.size(18.dp)
        )
        Spacer(Modifier.width(Space.s))
        Column(Modifier.weight(1f)) {
            Text(
                surface?.label?.takeIf { it.isNotBlank() } ?: vm.attackSurfaceLabel.ifBlank { "Attack surface" },
                color = ide.accent, fontSize = Type.section, fontFamily = Mono,
                fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            Text(
                (surface?.pkg?.takeIf { it.isNotBlank() } ?: "attack-surface triage") +
                    (surface?.let { " · " + (if (it.source == "installed") "installed" else "APK file") } ?: ""),
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
        }
        Row(
            Modifier
                .clickable(role = Role.Button, onClickLabel = "Close", onClick = onClose)
                .heightIn(min = 36.dp)
                .padding(Space.xs),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Filled.Close, contentDescription = "Close", tint = ide.dim, modifier = Modifier.size(18.dp))
        }
    }
}

@Composable
private fun Body(s: AttackSurface) {
    LazyColumn(Modifier.fillMaxWidth().heightIn(max = ManifestBodyHeight)) {
        item { IdentityBlock(s) }
        item { RiskChips(s) }

        // Exported components first and badged — they ARE the attack surface.
        item { SectionHeader("Exported components", s.exportedCount, LocalIde.current.red, Icons.Filled.Warning) }
        val exported = s.allComponents.filter { it.exported }
        if (exported.isEmpty()) {
            item { QuietLine("No component is exported. Nothing here is reachable from another app.") }
        } else {
            items(exported.size) { i -> ComponentRow(exported[i], exported = true) }
        }

        // Everything internal, collapsed by default so it never buries the above.
        item { InternalComponents(s) }

        item { SectionHeader("Permissions", s.permissions.size, LocalIde.current.amber, Icons.Filled.PriorityHigh) }
        item { PermissionsBlock(s) }

        item { SectionHeader("Deep links", s.deepLinks.size, LocalIde.current.cyan, Icons.Filled.Link) }
        item { DeepLinksBlock(s) }

        item { SectionHeader("Native libraries", s.libScan?.libs?.size ?: 0, LocalIde.current.violet, Icons.Filled.Memory) }
        item { NativeLibsBlock(s) }

        item { SectionHeader("Signing", s.signing.size, LocalIde.current.entry, Icons.Filled.VpnKey) }
        item { SigningBlock(s) }

        item { Spacer(Modifier.height(Space.l)) }
    }
}

// ------------------------------------------------------------- identity ==

@Composable
private fun IdentityBlock(s: AttackSurface) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxWidth().padding(vertical = Space.s)) {
        KeyValue("version", verOrDash(s.versionName, s.versionCode))
        KeyValue("minSdk / targetSdk", "${s.minSdk.ifBlank { "?" }} / ${s.targetSdk.ifBlank { "?" }}")
        // debuggable=true on a shipped build is a finding, not a fact.
        KeyValue(
            "debuggable", flagText(s.debuggable),
            vColor = if (s.debuggable == true) ide.red else null
        )
        // allowBackup=true lets adb pull the app's private data off the device.
        KeyValue(
            "allowBackup", flagText(s.allowBackup),
            vColor = if (s.allowBackup == true) ide.amber else null
        )
        if (s.customPermissions.isNotEmpty())
            KeyValue("declares permissions", "${s.customPermissions.size}")
    }
}

@Composable
private fun RiskChips(s: AttackSurface) {
    val ide = LocalIde.current
    val dangerous = s.permissions.count { it.dangerousGroup != null }
    Row(Modifier.fillMaxWidth().padding(vertical = Space.s), verticalAlignment = Alignment.CenterVertically) {
        StatChip("exported", "${s.exportedCount}", if (s.exportedCount > 0) ide.red else ide.dim2)
        Spacer(Modifier.width(Space.s))
        StatChip("dangerous", "$dangerous", if (dangerous > 0) ide.red else ide.dim2)
        Spacer(Modifier.width(Space.s))
        StatChip("deep links", "${s.deepLinks.size}", if (s.deepLinks.isNotEmpty()) ide.cyan else ide.dim2)
        Spacer(Modifier.width(Space.s))
        StatChip("signers", "${s.signing.size}", if (s.signing.isNotEmpty()) ide.entry else ide.dim2)
    }
}

// ----------------------------------------------------------- components ==

@Composable
private fun InternalComponents(s: AttackSurface) {
    val ide = LocalIde.current
    val internal = s.allComponents.filter { !it.exported }
    if (internal.isEmpty()) return
    var open by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier
                .fillMaxWidth()
                .clickable(role = Role.Button, onClickLabel = "Show internal components") { open = !open }
                .padding(horizontal = Space.s, vertical = Space.m),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (open) "Hide internal components" else "Internal components",
                color = ide.dim, fontSize = Type.label, fontFamily = Mono,
                fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f)
            )
            StatChip("not exported", "${internal.size}", ide.dim2)
        }
        if (open) internal.forEach { ComponentRow(it, exported = false) }
    }
}

@Composable
private fun ComponentRow(c: SurfaceComponent, exported: Boolean) {
    val ide = LocalIde.current
    val typeColor = when (c.type) {
        "activity" -> ide.cyan
        "service" -> ide.violet
        "receiver" -> ide.amber
        else -> ide.red
    }
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.s, vertical = Space.s)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                c.type.uppercase(), color = typeColor, fontSize = Type.caption, fontFamily = Mono,
                fontWeight = FontWeight.Bold, modifier = Modifier.width(72.dp), maxLines = 1
            )
            Text(
                c.name.substringAfterLast('.'),
                color = ide.text, fontSize = Type.label, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
            )
            if (exported) {
                Spacer(Modifier.width(Space.s))
                // An exported component with no permission guard is the higher
                // risk, so it is named for what it is rather than left implicit.
                if (c.permission == null) StatChip("exported · open", ide.red)
                else StatChip("exported", ide.red)
            }
        }
        Text(
            c.name, color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        c.permission?.let {
            Text("guarded by $it", color = ide.entry, fontSize = Type.caption, fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        c.authorities?.takeIf { it.isNotBlank() }?.let {
            Text("authority: $it", color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
        c.deepLinks.forEach { dl ->
            Text("  ${dl.display()}", color = ide.cyan, fontSize = Type.caption, fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
        }
    }
}

// ---------------------------------------------------------- permissions ==

@Composable
private fun PermissionsBlock(s: AttackSurface) {
    val ide = LocalIde.current
    if (s.permissions.isEmpty() && s.customPermissions.isEmpty()) {
        QuietLine("This app requests no permissions and declares none of its own.")
        return
    }
    Column(Modifier.fillMaxWidth()) {
        val dangerous = s.permissions.count { it.dangerousGroup != null }
        if (s.permissions.isNotEmpty()) {
            QuietLine(
                if (dangerous == 0) "${s.permissions.size} requested · none dangerous"
                else "${s.permissions.size} requested · $dangerous dangerous"
            )
            s.permissions.forEach { PermissionRow(it) }
        }
        if (s.customPermissions.isNotEmpty()) {
            Spacer(Modifier.height(Space.s))
            QuietLine("Declares ${s.customPermissions.size} of its own (custom) permissions")
            s.customPermissions.forEach { CustomPermissionRow(it) }
        }
    }
}

@Composable
private fun PermissionRow(p: SurfacePermission) {
    val ide = LocalIde.current
    val group = p.dangerousGroup
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.s, vertical = Space.xs),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (group != null) {
            RowIcon(Icons.Filled.PriorityHigh, ide.red, 13.dp, contentDescription = "Dangerous permission")
        } else {
            Spacer(Modifier.width(24.dp))
        }
        Text(
            p.name, color = ide.text, fontSize = Type.label, fontFamily = Mono, maxLines = 2,
            modifier = Modifier.weight(1f)
        )
        if (group != null) {
            Spacer(Modifier.width(Space.m))
            StatChip("dangerous · $group", ide.red)
        }
    }
}

@Composable
private fun CustomPermissionRow(c: CustomPermission) {
    val ide = LocalIde.current
    // signature-level protection is the safe case; normal/dangerous less so.
    val tint = when (c.protectionLevel) {
        "signature", "signatureOrSystem" -> ide.entry
        "dangerous" -> ide.red
        else -> ide.amber
    }
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.s, vertical = Space.xs),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(Modifier.width(24.dp))
        Text(
            c.name, color = ide.text, fontSize = Type.label, fontFamily = Mono, maxLines = 2,
            modifier = Modifier.weight(1f)
        )
        Spacer(Modifier.width(Space.m))
        StatChip(c.protectionLevel, tint)
    }
}

// ------------------------------------------------------------ deep links ==

@Composable
private fun DeepLinksBlock(s: AttackSurface) {
    val ide = LocalIde.current
    if (s.deepLinksNote.isNotBlank()) {
        QuietLine(s.deepLinksNote)
        return
    }
    if (s.deepLinks.isEmpty()) {
        QuietLine("No intent-filter declares a data URI, so nothing here is a deep-link entry point.")
        return
    }
    Column(Modifier.fillMaxWidth()) {
        QuietLine("External URL entry points, from the manifest's intent-filters:")
        s.deepLinks.forEach { dl ->
            Row(
                Modifier.fillMaxWidth().padding(horizontal = Space.s, vertical = Space.xs),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RowIcon(Icons.Filled.Link, ide.cyan, 13.dp, contentDescription = "Deep link")
                Column(Modifier.weight(1f)) {
                    Text(dl.display(), color = ide.text, fontSize = Type.label, fontFamily = Mono, maxLines = 1, overflow = TextOverflow.Ellipsis)
                    val extra = buildList {
                        if (dl.pathKind == "prefix") add("path prefix")
                        if (dl.pathKind == "pattern") add("path pattern")
                        if (dl.mimeType.isNotEmpty()) add("mime ${dl.mimeType}")
                    }
                    if (extra.isNotEmpty()) {
                        Text(extra.joinToString(" · "), color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1)
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------- native libs ==

@Composable
private fun NativeLibsBlock(s: AttackSurface) {
    val ide = LocalIde.current
    val scan = s.libScan
    if (scan == null) {
        QuietLine("Native libraries were not scanned for this target.")
        return
    }
    if (scan.libs.isEmpty()) {
        QuietLine(scan.note.ifBlank { "No native libraries." })
        return
    }
    // Grouped by ABI, primary ABI first — the compact counterpart to the full
    // extractor in the installed-apps picker, which is where a .so is opened.
    val byAbi = remember(System.identityHashCode(scan)) {
        scan.libs.groupBy { it.abi }.toList().sortedWith(
            compareByDescending<Pair<String, List<AppNativeLib>>> { it.first == scan.primaryAbi }
                .thenBy { it.first }
        )
    }
    Column(Modifier.fillMaxWidth()) {
        QuietLine(
            "${scan.libs.size} entries across ${byAbi.size} ABI" +
                (if (byAbi.size == 1) "" else "s") +
                (if (scan.primaryAbi.isNotBlank()) " · primary ${scan.primaryAbi}" else "")
        )
        byAbi.forEach { (abi, libs) ->
            val isPrimary = abi == scan.primaryAbi && scan.primaryAbi.isNotBlank()
            Row(
                Modifier.fillMaxWidth().padding(horizontal = Space.s, vertical = Space.xs),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    abi, color = if (isPrimary) ide.accent else ide.cyan,
                    fontSize = Type.label, fontFamily = Mono, modifier = Modifier.width(120.dp), maxLines = 1
                )
                Text(
                    libs.map { it.libName }.distinct().joinToString(", "),
                    color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                    maxLines = 2, overflow = TextOverflow.Ellipsis, modifier = Modifier.weight(1f)
                )
            }
        }
    }
}

// -------------------------------------------------------------- signing ==

@Composable
private fun SigningBlock(s: AttackSurface) {
    val ide = LocalIde.current
    if (s.signing.isEmpty()) {
        QuietLine(s.signingNote.ifBlank { "No signing certificate." })
        return
    }
    Column(Modifier.fillMaxWidth()) {
        s.signing.forEachIndexed { i, cert -> SigningCard(cert, i, s.signing.size) }
    }
}

@Composable
private fun SigningCard(cert: SigningCert, index: Int, total: Int) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .padding(vertical = Space.s)
            .border(1.dp, ide.border, RoundedCornerShape(8.dp))
            .padding(Space.m)
    ) {
        if (total > 1) {
            Text("signer ${index + 1} of $total", color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
            Spacer(Modifier.height(Space.xs))
        }
        Text("SHA-256", color = ide.dim, fontSize = Type.caption, fontFamily = Mono)
        Text(
            cert.sha256.ifBlank { "unavailable" },
            color = ide.entry, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 3
        )
        Spacer(Modifier.height(Space.xs))
        if (cert.subject.isNotBlank()) KeyValue("subject", cert.subject)
        if (cert.issuer.isNotBlank()) KeyValue("issuer", cert.issuer)
        if (cert.notBefore.isNotBlank() || cert.notAfter.isNotBlank())
            KeyValue("valid", "${cert.notBefore.ifBlank { "?" }} → ${cert.notAfter.ifBlank { "?" }}")
        if (cert.sha1.isNotBlank()) KeyValue("SHA-1", cert.sha1)
    }
}

// --------------------------------------------------------------- pieces ==

@Composable
private fun SectionHeader(title: String, count: Int, tint: Color, icon: androidx.compose.ui.graphics.vector.ImageVector) {
    val ide = LocalIde.current
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.xs, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, contentDescription = null, tint = tint, modifier = Modifier.size(15.dp))
        Spacer(Modifier.width(Space.s))
        Text(
            title, color = ide.text, fontSize = Type.label, fontFamily = Mono,
            fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f), maxLines = 1
        )
        Text("$count", color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
    }
}

@Composable
private fun QuietLine(text: String) {
    val ide = LocalIde.current
    Text(
        text, color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
        modifier = Modifier.fillMaxWidth().padding(horizontal = Space.s, vertical = Space.s)
    )
}

private fun verOrDash(name: String, code: String): String = when {
    name.isBlank() && code.isBlank() -> "-"
    name.isBlank() -> "($code)"
    code.isBlank() -> name
    else -> "$name ($code)"
}

private fun flagText(b: Boolean?): String = when (b) {
    true -> "true"
    false -> "false"
    null -> "not set"
}

package com.trickhook.ui

import android.graphics.BitmapFactory
import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Photo
import androidx.compose.material.icons.filled.PriorityHigh
import androidx.compose.material.icons.filled.Security
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.model.dangerousPermissionGroup
import com.trickhook.vm.StudioViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.zip.ZipFile

private val APK_SECTIONS = listOf(
    "Manifest", "Components", "Permissions", "DEX", "Native libs", "Resources"
)

/** One flattened manifest component: activity, service, receiver or provider. */
private data class ApkComponentRow(
    val type: String,
    val name: String,
    val exported: String,
    val actions: List<String>
)

/**
 * The group a dangerous permission belongs to, or null if it is not one.
 *
 * The classification itself — the platform dangerous-permission map, matched by
 * exact name inside the platform's own namespaces — is the model layer's
 * [dangerousPermissionGroup], shared with the attack-surface triage so the two
 * views can never disagree about what "dangerous" means.
 */
private fun dangerousGroup(permission: String): String? = dangerousPermissionGroup(permission)

/**
 * The archive the resource list was read out of, or null when nothing here
 * came out of a package.
 *
 * `vm.currentPath` is not it, and that was the original bug: opening an APK
 * extracts classes.dex and repoints currentPath at the extracted file, so the
 * `ZipFile(currentPath)` the preview used to do could never open — and it
 * blamed the entry the user had just tapped for the failure. The stand-in
 * that replaced it, "is the open file itself a ZIP", was true only while the
 * APK happened to also be the analysed file.
 *
 * `vm.apkFile` is the handle to the real package, and it is observable, so a
 * preview started before an open finishes is recomposed rather than stale.
 * It is null once a file from outside the package is opened, which is exactly
 * when these rows stop being about anything readable.
 */
private fun apkArchivePath(vm: StudioViewModel): String? = vm.apkFile?.absolutePath

// ============================================================== APK panel ==
/**
 * The six APK views. Which one is open lives in the ViewModel, so it survives
 * a trip to another tab, and the switcher is a real `Role.Tab` group rather
 * than six bare clickable words.
 */
@Composable
fun ApkPanel(vm: StudioViewModel) {
    val ide = LocalIde.current

    if (vm.manifest == null && vm.apkEntries.isEmpty()) {
        // An open fills apkEntries before the manifest is decoded, so "no APK
        // here" and "still reading the APK" used to be the same screen. A
        // skeleton the shape of the summary says which of the two this is.
        if (vm.busy) {
            Column(Modifier.fillMaxSize().background(ide.bg).padding(Space.xl)) {
                SkeletonLines(6)
            }
        } else {
            Hint(
                "Open an APK to see the manifest, permissions, components, DEX classes, native libs and resources.",
                "APK fur — manifest, permissions, activities/services, DEX, lib .so, resources."
            )
        }
        return
    }

    val mode = vm.apkMode.coerceIn(0, APK_SECTIONS.size - 1)

    Column(Modifier.fillMaxSize()) {
        // Six labels do not fit a 360dp phone, so the strip scrolls instead of
        // squeezing them; selection is carried by a filled pill as well as by
        // colour, and announced as a tab by the selectable() role.
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .horizontalScroll(rememberScrollState())
                .selectableGroup()
                .padding(horizontal = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            APK_SECTIONS.forEachIndexed { i, label ->
                val selected = i == mode
                Box(
                    Modifier
                        .heightIn(min = 48.dp)
                        .selectable(selected = selected, role = Role.Tab) { vm.apkMode = i }
                        .padding(vertical = Space.m, horizontal = Space.xs),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        label,
                        color = if (selected) ide.accent else ide.dim,
                        fontSize = Type.label,
                        fontFamily = Mono,
                        fontWeight = if (selected) FontWeight.Bold else null,
                        modifier = Modifier
                            .background(
                                if (selected) ide.accent.copy(alpha = 0.14f) else Color.Transparent,
                                RoundedCornerShape(8.dp)
                            )
                            .padding(horizontal = Space.m, vertical = Space.s)
                    )
                }
            }
        }

        // The six sections are not the same height: four of them fall back to
        // a wrap-height empty state, the rest fill the panel. Switching used to
        // snap the content area between those two sizes under a strip that had
        // not moved. It grows and shrinks now — and snaps again, correctly, at
        // the zero duration reduce-motion asks for.
        Box(Modifier.fillMaxWidth().animateContentSize(tween(motionMs()))) {
            when (mode) {
                0 -> ManifestSection(vm)
                1 -> ComponentsSection(vm)
                2 -> PermissionsSection(vm)
                3 -> DexSection(vm)
                4 -> LibsSection(vm)
                else -> ResourcesSection(vm)
            }
        }
    }
}

@Composable
private fun ManifestSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val mi = vm.manifest
    if (mi == null) {
        // Binary XML is decoded inside the open, after the entry list is
        // already on screen. Announcing that the APK has no manifest while it
        // is still being parsed is the panel answering a question it has not
        // been told the answer to yet.
        if (vm.busy) {
            Column(Modifier.fillMaxWidth().background(ide.bg).padding(Space.l)) {
                SkeletonLines(3)
                Spacer(Modifier.height(Space.l))
                SkeletonLines(10, indent = true)
            }
        } else {
            EmptyPanel(
                "This APK has no AndroidManifest.xml",
                "Without a manifest there is no package name, no SDK levels and no component list to show."
            )
        }
        return
    }
    if (!mi.ok) {
        LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
            item {
                EmptyPanel(
                    "The manifest could not be decoded",
                    "Binary XML parsing failed. The decoder's own message is below."
                )
            }
            item {
                Text(
                    mi.rawXml.ifEmpty { "No further detail was reported." },
                    color = ide.red, fontSize = Type.mono, fontFamily = Mono, lineHeight = 17.sp,
                    modifier = Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m)
                )
            }
        }
        return
    }
    LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
        item {
            Column(Modifier.padding(Space.l)) {
                Text(
                    mi.packageName, color = ide.accent, fontSize = Type.section, fontFamily = Mono,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(Space.m))
                // The consolidated attack-surface triage for this APK: the same
                // sheet the installed-apps picker opens per app, here for the
                // open file. Exported components, permissions, deep links, native
                // libs and signing in one prominent view rather than spread over
                // the tabs above.
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable(role = Role.Button, onClickLabel = "Open the attack-surface triage") {
                            manifestTargetPkg = null
                            manifestTargetLabel = mi.appLabel
                                .takeIf { it.isNotBlank() && !it.startsWith("@") } ?: mi.packageName
                            showManifestSheet = true
                        }
                        .border(1.dp, ide.borderStrong, RoundedCornerShape(8.dp))
                        .padding(horizontal = Space.m, vertical = Space.m),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Filled.Security, contentDescription = null,
                        tint = ide.accent, modifier = Modifier.size(18.dp)
                    )
                    Spacer(Modifier.width(Space.m))
                    Column(Modifier.weight(1f)) {
                        Text("Attack surface", color = ide.text, fontSize = Type.body)
                        Text(
                            "exported components, permissions, deep links, native libs, signing",
                            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                        )
                    }
                }
                Spacer(Modifier.height(Space.m))
                KeyValue("version", "${mi.versionName} (${mi.versionCode})")
                KeyValue("minSdk / targetSdk", "${mi.minSdk.ifEmpty { "?" }} / ${mi.targetSdk.ifEmpty { "?" }}")
                KeyValue("app label", mi.appLabel.ifEmpty { "-" })
                KeyValue("app icon", mi.appIcon.ifEmpty { "-" })
                // debuggable=true on a shipped build is a finding, not a fact.
                KeyValue(
                    "debuggable", mi.debuggable?.toString() ?: "not set",
                    vColor = if (mi.debuggable == true) ide.red else null
                )
                KeyValue("permissions", "${mi.permissions.size}")
                KeyValue("activities", "${mi.activities.size}")
                KeyValue("services", "${mi.services.size}")
                KeyValue("receivers", "${mi.receivers.size}")
                KeyValue("providers", "${mi.providers.size}")
                if (mi.usesLibraries.isNotEmpty()) KeyValue("native libs", mi.usesLibraries.joinToString())
            }
            Spacer(Modifier.height(Space.m))
            Text(
                "AndroidManifest.xml (decoded)", color = ide.dim2, fontSize = Type.caption,
                modifier = Modifier.padding(horizontal = Space.l)
            )
        }
        item {
            Text(
                mi.rawXml,
                color = ide.text, fontSize = Type.monoSmall, fontFamily = Mono, lineHeight = 15.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(Space.l)
            )
        }
    }
}

@Composable
private fun ComponentsSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val mi = vm.manifest
    if (mi == null) {
        EmptyPanel(
            "This APK has no AndroidManifest.xml",
            "Activities, services, receivers and providers are all declared there, so none can be listed."
        )
        return
    }
    // Identity and a count, never the model itself: ManifestInfo is a data
    // class, so `remember(mi)` compared five component lists, the permission
    // list and the whole decoded XML on every single recomposition.
    val rows = remember(
        System.identityHashCode(mi),
        mi.activities.size + mi.services.size + mi.receivers.size + mi.providers.size
    ) {
        buildList {
            mi.activities.forEach { add(ApkComponentRow("ACTIVITY", it.name, it.exported?.toString() ?: "-", it.actions)) }
            mi.services.forEach { add(ApkComponentRow("SERVICE", it.name, it.exported?.toString() ?: "-", it.actions)) }
            mi.receivers.forEach { add(ApkComponentRow("RECEIVER", it.name, it.exported?.toString() ?: "-", it.actions)) }
            mi.providers.forEach { add(ApkComponentRow("PROVIDER", it.name, it.exported?.toString() ?: "-", it.actions)) }
        }
    }
    if (rows.isEmpty()) {
        EmptyPanel(
            "No components declared",
            "The manifest parsed, but it declares no activities, services, receivers or providers."
        )
        return
    }
    LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
        items(rows.size) { i ->
            val r = rows[i]
            Column(
                Modifier
                    .fillMaxWidth()
                    .animateItem(
                        fadeInSpec = tween(motionMs()),
                        placementSpec = tween(motionMs()),
                        fadeOutSpec = tween(motionMs())
                    )
                    .semantics(mergeDescendants = true) { }
                    .padding(horizontal = Space.m, vertical = Space.s)
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Text(
                        r.type,
                        color = when (r.type) {
                            "ACTIVITY" -> ide.cyan
                            "SERVICE" -> ide.violet
                            "RECEIVER" -> ide.amber
                            else -> ide.red
                        },
                        fontSize = Type.caption, fontFamily = Mono,
                        fontWeight = FontWeight.Bold,
                        modifier = Modifier.width(80.dp)
                    )
                    Text(
                        r.name.substringAfterLast('.'),
                        color = ide.text, fontSize = Type.label, fontFamily = Mono, maxLines = 1,
                        modifier = Modifier.weight(1f)
                    )
                    if (r.exported == "true") {
                        Spacer(Modifier.width(Space.s))
                        StatChip("exported", ide.red)
                    }
                }
                Text(r.name, color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1)
                if (r.actions.isNotEmpty()) {
                    Text(
                        "  actions: ${r.actions.joinToString(", ")}",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 2
                    )
                }
            }
        }
    }
}

@Composable
private fun PermissionsSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val mi = vm.manifest
    if (mi == null) {
        EmptyPanel(
            "This APK has no AndroidManifest.xml",
            "Permissions are declared there, so there is nothing to audit."
        )
        return
    }
    if (mi.permissions.isEmpty()) {
        EmptyPanel(
            "No permissions requested",
            "The manifest declares no uses-permission entries at all."
        )
        return
    }
    // Identity and size: the list is a plain List<String>, so a value key
    // walked and compared every permission on every recomposition.
    val flagged = remember(System.identityHashCode(mi.permissions), mi.permissions.size) {
        mi.permissions.count { dangerousGroup(it) != null }
    }
    LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
        item {
            Text(
                if (flagged == 0) "${mi.permissions.size} permissions · none of them dangerous"
                else "${mi.permissions.size} permissions · $flagged dangerous",
                color = if (flagged == 0) ide.dim2 else ide.red,
                fontSize = Type.caption, fontFamily = Mono,
                modifier = Modifier.padding(horizontal = Space.m, vertical = Space.m)
            )
        }
        items(mi.permissions.size) { i ->
            val p = mi.permissions[i]
            val group = dangerousGroup(p)
            // The row used to say "dangerous" with a 13dp red exclamation mark
            // and nothing else: silent to a screen reader, and invisible to
            // anyone who cannot separate red from grey. Now the glyph is
            // described, and the word is on screen next to it.
            Row(
                Modifier
                    .fillMaxWidth()
                    .animateItem(
                        fadeInSpec = tween(motionMs()),
                        placementSpec = tween(motionMs()),
                        fadeOutSpec = tween(motionMs())
                    )
                    .semantics(mergeDescendants = true) { }
                    .padding(horizontal = Space.m, vertical = Space.s),
                verticalAlignment = Alignment.CenterVertically
            ) {
                if (group != null) {
                    RowIcon(
                        Icons.Filled.PriorityHigh, ide.red, 13.dp,
                        contentDescription = "Dangerous permission"
                    )
                } else {
                    Spacer(Modifier.width(24.dp))
                }
                Text(
                    p, color = ide.text, fontSize = Type.label, fontFamily = Mono, maxLines = 2,
                    modifier = Modifier.weight(1f)
                )
                if (group != null) {
                    Spacer(Modifier.width(Space.m))
                    StatChip("dangerous · $group", ide.red)
                }
            }
        }
    }
}

@Composable
private fun DexSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta
    if (meta == null || meta.dexClasses.isEmpty()) {
        EmptyPanel(
            "No DEX classes extracted",
            "Open a .dex from the Native libs section, or this package ships no Java or Kotlin code."
        )
        return
    }
    var query by remember { mutableStateOf("") }
    // Identity and size, never the list: AnalysisMeta and its lists are data
    // classes, so `remember(query, meta.dexClasses)` deep-compared every one of
    // tens of thousands of DexClassInfo on every keystroke, before the filter
    // it guards had even run. The original index rides along as the row key, so
    // a class that survives a keystroke moves instead of being replaced.
    val classes = remember(query, System.identityHashCode(meta.dexClasses), meta.dexClasses.size) {
        meta.dexClasses.withIndex().filter { (_, c) -> c.name.contains(query, ignoreCase = true) }
    }
    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = query, onValueChange = { query = it },
            label = { Text("Search classes…") }, singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.m, vertical = Space.s),
            textStyle = TextStyle(fontSize = Type.label, fontFamily = Mono, color = ide.text)
        )
        LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
            if (classes.isEmpty()) {
                // The footer used to keep reporting the full class count while
                // the list below it was empty, so the screen contradicted
                // itself. It now only ever describes the rows on screen.
                item {
                    EmptyPanel(
                        "No class matches \"$query\"",
                        // dexClassesTotal is class_defs_size out of the DEX
                        // header and therefore exact; the list stops at the
                        // engine's cap. Saying only the list's length would
                        // send someone away sure a class is not there.
                        if (meta.dexClassesTotal > meta.dexClasses.size)
                            "Searched the ${meta.dexClasses.size} classes loaded; this DEX declares ${meta.dexClassesTotal}."
                        else "${meta.dexClasses.size} classes in this DEX."
                    )
                    TextButton(
                        onClick = { query = "" },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Clear search", color = ide.accent, fontSize = Type.label)
                    }
                }
            } else {
                items(classes.size, key = { classes[it].index }) { i ->
                    val c = classes[i].value
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .animateItem(
                                fadeInSpec = tween(motionMs()),
                                placementSpec = tween(motionMs()),
                                fadeOutSpec = tween(motionMs())
                            )
                            .semantics(mergeDescendants = true) { }
                            .padding(horizontal = Space.m, vertical = Space.xs)
                    ) {
                        Text(c.name, color = ide.cyan, fontSize = Type.label, fontFamily = Mono, maxLines = 1)
                        if (c.superName.isNotEmpty()) {
                            Text(
                                "  extends ${c.superName}", color = ide.dim2,
                                fontSize = Type.caption, fontFamily = Mono, maxLines = 1
                            )
                        }
                    }
                }
                item {
                    val dexName = vm.apkEntries.firstOrNull { it.name.endsWith(".dex") }?.name ?: "file"
                    Text(
                        if (query.isBlank())
                            "${ofTotal(meta.dexClasses.size, meta.dexClassesTotal)} classes · " +
                                "${ofTotal(meta.dexMethods.size, meta.dexMethodsTotal)} methods · " +
                                "extracted from $dexName"
                        else
                            "${classes.size} of ${meta.dexClasses.size} classes match \"$query\"",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                        modifier = Modifier.padding(Space.m)
                    )
                }
            }
        }
    }
}

@Composable
private fun LibsSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    if (vm.apkEntries.isEmpty()) {
        EmptyPanel(
            "No native libraries or DEX files",
            "This APK contains no .so and no .dex entries to extract."
        )
        return
    }
    LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
        items(vm.apkEntries.size) { i ->
            val e = vm.apkEntries[i]
            val so = e.name.endsWith(".so")
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable(
                        enabled = !vm.busy,
                        role = Role.Button,
                        onClickLabel = "Extract and analyse"
                    ) { vm.openApkEntry(e) }
                    .heightIn(min = 44.dp)
                    .padding(horizontal = Space.m, vertical = Space.s),
                verticalAlignment = Alignment.CenterVertically
            ) {
                RowIcon(
                    if (so) Icons.Filled.Memory else Icons.Filled.Description,
                    ide.dim, 13.dp,
                    contentDescription = if (so) "Native library" else "DEX file"
                )
                Text(
                    e.name, color = ide.cyan, fontSize = Type.label, fontFamily = Mono,
                    maxLines = 1, modifier = Modifier.weight(1f)
                )
                Text(humanSizeK(e.size), color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
            }
        }
        item {
            Text(
                "Tap to extract & analyze (ELF) — si aad u falanqayso", color = ide.dim2,
                fontSize = Type.caption, modifier = Modifier.padding(Space.m)
            )
        }
    }
}

@Composable
private fun ResourcesSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val archive = apkArchivePath(vm)
    var previewPath by remember { mutableStateOf<String?>(null) }
    var previewBmp by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var previewErr by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(previewPath, archive) {
        previewBmp = null
        previewErr = null
        val path = previewPath ?: return@LaunchedEffect
        // Never `vm.currentPath`: see apkArchivePath. Opening the extracted
        // classes.dex as a ZIP failed on every single entry, and the message
        // pinned the blame on the entry rather than on the wrong file.
        val apkPath = archive
        if (apkPath == null) {
            previewErr = "The APK itself is not the open file, so its entries cannot be read back."
            return@LaunchedEffect
        }
        try {
            var notInArchive = false
            // Decoding a few megabytes of PNG on the main thread froze the
            // list mid-scroll; it runs off it now.
            val bmp = withContext(Dispatchers.IO) {
                ZipFile(java.io.File(apkPath)).use { zf ->
                    val en = zf.getEntry(path)
                    if (en == null) {
                        notInArchive = true
                        null
                    } else {
                        BitmapFactory.decodeStream(zf.getInputStream(en))
                    }
                }
            }
            // A failed decode used to be swallowed by an empty catch, so a
            // corrupt PNG looked exactly like a file that is not an image —
            // and a missing entry looked like both.
            previewErr = when {
                notInArchive -> "That entry is no longer in the archive."
                bmp == null -> "Could not decode this entry as an image."
                else -> null
            }
            previewBmp = bmp
        } catch (e: Exception) {
            previewErr = "Could not read this entry: ${e.message ?: "unknown error"}"
        }
    }

    Column(Modifier.fillMaxSize()) {
        // Zero-height with nothing to preview, so opening and closing one grows
        // and shrinks the list rather than shoving it down in a single frame.
        Box(Modifier.fillMaxWidth().animateContentSize(tween(motionMs()))) {
            val path = previewPath
            if (path != null) {
                val bmp = previewBmp
                val err = previewErr
                // The decode is off the main thread now, so there is a real gap
                // between the pane appearing and the image existing. The image
                // fades across that gap instead of popping in at full size.
                val imageAlpha by animateFloatAsState(
                    targetValue = if (bmp != null) 1f else 0f,
                    animationSpec = tween(motionMs()),
                    label = "resourcePreviewFade"
                )
                Box(
                    Modifier.fillMaxWidth().height(180.dp).background(ide.panel),
                    contentAlignment = Alignment.Center
                ) {
                    when {
                        bmp != null -> Image(
                            bitmap = bmp.asImageBitmap(),
                            contentDescription = "Preview of $path",
                            contentScale = ContentScale.Fit,
                            modifier = Modifier
                                .fillMaxSize()
                                .padding(Space.m)
                                .alpha(imageAlpha)
                        )
                        err != null -> Text(
                            err, color = ide.red, fontSize = Type.caption, fontFamily = Mono,
                            textAlign = TextAlign.Center,
                            modifier = Modifier.padding(horizontal = Space.xxl)
                        )
                        else -> Text(
                            "Decoding…", color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                        )
                    }
                    Box(
                        Modifier
                            .align(Alignment.TopEnd)
                            .size(48.dp)
                            .clickable(role = Role.Button) { previewPath = null },
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Filled.Close, contentDescription = "Close preview",
                            tint = ide.dim, modifier = Modifier.size(17.dp)
                        )
                    }
                }
            }
        }
        if (vm.apkResources.isEmpty()) {
            EmptyPanel(
                "No resources",
                "This APK has no res/ or assets/ entries, or none survived the 400-entry cap."
            )
        } else {
            LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
                if (archive == null) {
                    // Said once, at the top, instead of once per tap: a row
                    // that cannot open is inert below, not a trap that answers
                    // with the same error every time.
                    item {
                        Text(
                            "Listed from the package, but not readable from here: analysing an APK " +
                                "extracts its DEX and follows that file, so the package is no longer " +
                                "the one Nocturne has open.",
                            color = ide.dim2, fontSize = Type.caption, lineHeight = 14.sp,
                            modifier = Modifier.padding(horizontal = Space.m, vertical = Space.m)
                        )
                    }
                }
                items(vm.apkResources.size) { i ->
                    val r = vm.apkResources[i]
                    // Only an image that can actually be opened ripples.
                    val canPreview = r.isImage && archive != null
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .animateItem(
                                fadeInSpec = tween(motionMs()),
                                placementSpec = tween(motionMs()),
                                fadeOutSpec = tween(motionMs())
                            )
                            .then(
                                if (canPreview) Modifier.clickable(
                                    role = Role.Button,
                                    onClickLabel = "Preview"
                                ) { previewPath = r.path }
                                else Modifier
                            )
                            .heightIn(min = 44.dp)
                            .padding(horizontal = Space.m, vertical = Space.xs),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        RowIcon(
                            when {
                                r.isImage -> Icons.Filled.Photo
                                r.isXml -> Icons.Filled.Code
                                else -> Icons.Filled.Description
                            },
                            ide.dim, 13.dp,
                            contentDescription = when {
                                r.isImage -> "Image"
                                r.isXml -> "XML"
                                else -> "File"
                            }
                        )
                        Text(
                            r.path, color = ide.text, fontSize = Type.label, fontFamily = Mono,
                            maxLines = 1, modifier = Modifier.weight(1f)
                        )
                        Text(humanSizeK(r.size), color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
                    }
                }
                item {
                    Text(
                        if (archive != null) "Tap an image to preview — sawir si aad u aragto"
                        else "${vm.apkResources.size} entries listed from the package",
                        color = ide.dim2,
                        fontSize = Type.caption, modifier = Modifier.padding(Space.m)
                    )
                }
            }
        }
    }
}

private fun humanSizeK(n: Long): String = when {
    n >= 1024 * 1024 -> "%.1f MB".format(n / 1048576.0)
    n >= 1024 -> "%.1f KB".format(n / 1024.0)
    else -> "$n B"
}

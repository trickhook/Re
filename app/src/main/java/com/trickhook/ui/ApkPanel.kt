package com.trickhook.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
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
import com.trickhook.vm.StudioViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.zip.ZipFile

private val APK_SECTIONS = listOf(
    "Manifest", "Components", "Permissions", "DEX", "Native libs", "Resources"
)

/**
 * The platform's runtime ("dangerous") permissions, mapped to the group the
 * system shows the user. The old test was `p.contains("SMS")`, which flagged
 * any third-party permission whose name merely contained one of six words and
 * missed every dangerous permission that did not — it both over- and
 * under-reported. This matches the declared name exactly, and only inside the
 * platform's own namespaces.
 */
private val DANGEROUS_PERMISSIONS: Map<String, String> = mapOf(
    "ACCESS_FINE_LOCATION" to "location",
    "ACCESS_COARSE_LOCATION" to "location",
    "ACCESS_BACKGROUND_LOCATION" to "location",
    "ACCESS_MEDIA_LOCATION" to "location",
    "CAMERA" to "camera",
    "RECORD_AUDIO" to "microphone",
    "READ_CONTACTS" to "contacts",
    "WRITE_CONTACTS" to "contacts",
    "GET_ACCOUNTS" to "contacts",
    "READ_CALENDAR" to "calendar",
    "WRITE_CALENDAR" to "calendar",
    "SEND_SMS" to "SMS",
    "RECEIVE_SMS" to "SMS",
    "READ_SMS" to "SMS",
    "RECEIVE_MMS" to "SMS",
    "RECEIVE_WAP_PUSH" to "SMS",
    "READ_CALL_LOG" to "call log",
    "WRITE_CALL_LOG" to "call log",
    "PROCESS_OUTGOING_CALLS" to "call log",
    "READ_PHONE_STATE" to "phone",
    "READ_PHONE_NUMBERS" to "phone",
    "CALL_PHONE" to "phone",
    "ANSWER_PHONE_CALLS" to "phone",
    "ACCEPT_HANDOVER" to "phone",
    "USE_SIP" to "phone",
    "ADD_VOICEMAIL" to "phone",
    "READ_EXTERNAL_STORAGE" to "storage",
    "WRITE_EXTERNAL_STORAGE" to "storage",
    "READ_MEDIA_IMAGES" to "media",
    "READ_MEDIA_VIDEO" to "media",
    "READ_MEDIA_AUDIO" to "media",
    "READ_MEDIA_VISUAL_USER_SELECTED" to "media",
    "BODY_SENSORS" to "sensors",
    "BODY_SENSORS_BACKGROUND" to "sensors",
    "ACTIVITY_RECOGNITION" to "sensors",
    "BLUETOOTH_SCAN" to "nearby devices",
    "BLUETOOTH_CONNECT" to "nearby devices",
    "BLUETOOTH_ADVERTISE" to "nearby devices",
    "UWB_RANGING" to "nearby devices",
    "NEARBY_WIFI_DEVICES" to "nearby devices",
    "POST_NOTIFICATIONS" to "notifications"
)

private val PLATFORM_PERMISSION_PREFIXES = listOf(
    "android.permission.",
    "com.android.voicemail.permission."
)

/** One flattened manifest component: activity, service, receiver or provider. */
private data class ApkComponentRow(
    val type: String,
    val name: String,
    val exported: String,
    val actions: List<String>
)

/** The group a dangerous permission belongs to, or null if it is not one. */
private fun dangerousGroup(permission: String): String? {
    val p = permission.trim()
    val prefix = PLATFORM_PERMISSION_PREFIXES.firstOrNull { p.startsWith(it) } ?: return null
    return DANGEROUS_PERMISSIONS[p.removePrefix(prefix)]
}

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
        Hint(
            "Open an APK to see the manifest, permissions, components, DEX classes, native libs and resources.",
            "APK fur — manifest, permissions, activities/services, DEX, lib .so, resources."
        )
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
                .padding(horizontal = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            APK_SECTIONS.forEachIndexed { i, label ->
                val selected = i == mode
                Box(
                    Modifier
                        .heightIn(min = 48.dp)
                        .selectable(selected = selected, role = Role.Tab) { vm.apkMode = i }
                        .padding(vertical = 8.dp, horizontal = 2.dp),
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
                            .padding(horizontal = 10.dp, vertical = 6.dp)
                    )
                }
            }
        }

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

@Composable
private fun ManifestSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val mi = vm.manifest
    if (mi == null) {
        EmptyPanel(
            "This APK has no AndroidManifest.xml",
            "Without a manifest there is no package name, no SDK levels and no component list to show."
        )
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
                    modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp)
                )
            }
        }
        return
    }
    LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
        item {
            Column(Modifier.padding(12.dp)) {
                Text(
                    mi.packageName, color = ide.accent, fontSize = Type.section, fontFamily = Mono,
                    fontWeight = FontWeight.Bold
                )
                Spacer(Modifier.height(4.dp))
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
            Spacer(Modifier.height(8.dp))
            Text(
                "AndroidManifest.xml (decoded)", color = ide.dim2, fontSize = Type.caption,
                modifier = Modifier.padding(horizontal = 12.dp)
            )
        }
        item {
            Text(
                mi.rawXml,
                color = ide.text, fontSize = Type.monoSmall, fontFamily = Mono, lineHeight = 15.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp)
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
    val rows = remember(mi) {
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
                    .semantics(mergeDescendants = true) { }
                    .padding(horizontal = 10.dp, vertical = 4.dp)
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
                        Spacer(Modifier.width(6.dp))
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
    val flagged = remember(mi.permissions) { mi.permissions.count { dangerousGroup(it) != null } }
    LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
        item {
            Text(
                if (flagged == 0) "${mi.permissions.size} permissions · none of them dangerous"
                else "${mi.permissions.size} permissions · $flagged dangerous",
                color = if (flagged == 0) ide.dim2 else ide.red,
                fontSize = Type.caption, fontFamily = Mono,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp)
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
                    .semantics(mergeDescendants = true) { }
                    .padding(horizontal = 10.dp, vertical = 4.dp),
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
                    Spacer(Modifier.width(8.dp))
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
    val classes = remember(query, meta.dexClasses) {
        meta.dexClasses.filter { it.name.contains(query, ignoreCase = true) }
    }
    Column(Modifier.fillMaxSize()) {
        OutlinedTextField(
            value = query, onValueChange = { query = it },
            label = { Text("Search classes…") }, singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 4.dp),
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
                        "${meta.dexClasses.size} classes in this DEX."
                    )
                    TextButton(
                        onClick = { query = "" },
                        modifier = Modifier.fillMaxWidth()
                    ) {
                        Text("Clear search", color = ide.accent, fontSize = Type.label)
                    }
                }
            } else {
                items(classes.size) { i ->
                    val c = classes[i]
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .semantics(mergeDescendants = true) { }
                            .padding(horizontal = 10.dp, vertical = 3.dp)
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
                            "${meta.dexClasses.size} classes · ${meta.dexMethods.size} methods · extracted from $dexName"
                        else
                            "${classes.size} of ${meta.dexClasses.size} classes match \"$query\"",
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                        modifier = Modifier.padding(10.dp)
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
                    .padding(horizontal = 10.dp, vertical = 4.dp),
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
                fontSize = Type.caption, modifier = Modifier.padding(10.dp)
            )
        }
    }
}

@Composable
private fun ResourcesSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    var previewPath by remember { mutableStateOf<String?>(null) }
    var previewBmp by remember { mutableStateOf<android.graphics.Bitmap?>(null) }
    var previewErr by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(previewPath) {
        previewBmp = null
        previewErr = null
        val path = previewPath ?: return@LaunchedEffect
        val apkPath = vm.currentPath
        if (apkPath == null) {
            previewErr = "The APK is no longer open."
            return@LaunchedEffect
        }
        try {
            // Decoding a few megabytes of PNG on the main thread froze the
            // list mid-scroll; it runs off it now.
            val bmp = withContext(Dispatchers.IO) {
                ZipFile(java.io.File(apkPath)).use { zf ->
                    val en = zf.getEntry(path) ?: return@use null
                    BitmapFactory.decodeStream(zf.getInputStream(en))
                }
            }
            // A failed decode used to be swallowed by an empty catch, so a
            // corrupt PNG looked exactly like a file that is not an image.
            if (bmp == null) {
                previewErr = "Could not decode this entry as an image."
            } else {
                previewBmp = bmp
            }
        } catch (e: Exception) {
            previewErr = "Could not read this entry: ${e.message ?: "unknown error"}"
        }
    }

    Column(Modifier.fillMaxSize()) {
        val path = previewPath
        if (path != null) {
            Box(
                Modifier.fillMaxWidth().height(180.dp).background(ide.panel),
                contentAlignment = Alignment.Center
            ) {
                val bmp = previewBmp
                val err = previewErr
                when {
                    bmp != null -> Image(
                        bitmap = bmp.asImageBitmap(),
                        contentDescription = "Preview of $path",
                        contentScale = ContentScale.Fit,
                        modifier = Modifier.fillMaxSize().padding(8.dp)
                    )
                    err != null -> Text(
                        err, color = ide.red, fontSize = Type.caption, fontFamily = Mono,
                        textAlign = TextAlign.Center,
                        modifier = Modifier.padding(horizontal = 24.dp)
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
        if (vm.apkResources.isEmpty()) {
            EmptyPanel(
                "No resources",
                "This APK has no res/ or assets/ entries, or none survived the 400-entry cap."
            )
        } else {
            LazyColumn(Modifier.fillMaxSize().background(ide.bg), contentPadding = bottomInset()) {
                items(vm.apkResources.size) { i ->
                    val r = vm.apkResources[i]
                    // Only an image can be previewed, so only an image ripples.
                    Row(
                        Modifier
                            .fillMaxWidth()
                            .then(
                                if (r.isImage) Modifier.clickable(
                                    role = Role.Button,
                                    onClickLabel = "Preview"
                                ) { previewPath = r.path }
                                else Modifier
                            )
                            .heightIn(min = 44.dp)
                            .padding(horizontal = 10.dp, vertical = 2.dp),
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
                        "Tap an image to preview — sawir si aad u aragto", color = ide.dim2,
                        fontSize = Type.caption, modifier = Modifier.padding(10.dp)
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

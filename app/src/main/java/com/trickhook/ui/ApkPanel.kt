package com.trickhook.ui

import android.graphics.BitmapFactory
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Photo
import androidx.compose.material.icons.filled.PriorityHigh
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.vm.StudioViewModel
import java.util.zip.ZipFile

// ============================================================== APK panel ==
@Composable
fun ApkPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var section by remember { mutableStateOf("manifest") }

    if (vm.manifest == null && vm.apkEntries.isEmpty()) {
        Hint(
            "Open an APK to see the manifest, permissions, components, DEX classes, native libs and resources.",
            "APK fur — manifest, permissions, activities/services, DEX, lib .so, resources."
        )
        return
    }

    Column(Modifier.fillMaxSize()) {
        // section switcher
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 6.dp, vertical = 2.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            listOf(
                "manifest" to "Manifest",
                "components" to "Components",
                "permissions" to "Permissions",
                "dex" to "DEX",
                "libs" to "Native libs",
                "resources" to "Resources"
            ).forEach { (key, label) ->
                Text(
                    label,
                    color = if (section == key) ide.accent else ide.dim,
                    fontSize = 12.sp,
                    fontFamily = Mono,
                    fontWeight = if (section == key) androidx.compose.ui.text.font.FontWeight.Bold else null,
                    modifier = Modifier
                        .clickable { section = key }
                        .padding(horizontal = 8.dp, vertical = 6.dp)
                )
            }
        }

        when (section) {
            "manifest" -> ManifestSection(vm)
            "components" -> ComponentsSection(vm)
            "permissions" -> PermissionsSection(vm)
            "dex" -> DexSection(vm)
            "libs" -> LibsSection(vm)
            "resources" -> ResourcesSection(vm)
        }
    }
}

@Composable
private fun ManifestSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val mi = vm.manifest
    Column(Modifier.fillMaxSize()) {
        if (mi == null || !mi.ok) {
            Text(
                mi?.rawXml ?: "No manifest parsed.",
                color = ide.red, fontSize = 12.sp, fontFamily = Mono,
                modifier = Modifier.padding(12.dp)
            )
            return
        }
        LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
            item {
                Column(Modifier.padding(12.dp)) {
                    Text(mi.packageName, color = ide.accent, fontSize = 15.sp, fontFamily = Mono,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.Bold)
                    Spacer(Modifier.height(4.dp))
                    KeyValue("version", "${mi.versionName} (${mi.versionCode})")
                    KeyValue("minSdk / targetSdk", "${mi.minSdk.ifEmpty { "?" }} / ${mi.targetSdk.ifEmpty { "?" }}")
                    KeyValue("app label", mi.appLabel.ifEmpty { "-" })
                    KeyValue("app icon", mi.appIcon.ifEmpty { "-" })
                    KeyValue("debuggable", mi.debuggable?.toString() ?: "not set")
                    KeyValue("permissions", "${mi.permissions.size}")
                    KeyValue("activities", "${mi.activities.size}")
                    KeyValue("services", "${mi.services.size}")
                    KeyValue("receivers", "${mi.receivers.size}")
                    KeyValue("providers", "${mi.providers.size}")
                    if (mi.usesLibraries.isNotEmpty()) KeyValue("native libs", mi.usesLibraries.joinToString())
                }
                Spacer(Modifier.height(8.dp))
                Text("AndroidManifest.xml (decoded)", color = ide.dim, fontSize = 11.sp,
                    modifier = Modifier.padding(horizontal = 12.dp))
            }
            item {
                Text(
                    mi.rawXml,
                    color = ide.text, fontSize = 10.5.sp, fontFamily = Mono, lineHeight = 15.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(12.dp)
                )
            }
        }
    }
}

@Composable
private fun ComponentsSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val mi = vm.manifest ?: return
    LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
        data class Row(val type: String, val name: String, val exported: String, val actions: List<String>)
        val rows = buildList {
            mi.activities.forEach { add(Row("ACTIVITY", it.name, it.exported?.toString() ?: "-", it.actions)) }
            mi.services.forEach { add(Row("SERVICE", it.name, it.exported?.toString() ?: "-", it.actions)) }
            mi.receivers.forEach { add(Row("RECEIVER", it.name, it.exported?.toString() ?: "-", it.actions)) }
            mi.providers.forEach { add(Row("PROVIDER", it.name, it.exported?.toString() ?: "-", it.actions)) }
        }
        items(rows.size) { i ->
            val r = rows[i]
            Column(
                Modifier
                    .fillMaxWidth()
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
                        fontSize = 10.sp, fontFamily = Mono,
                        fontWeight = androidx.compose.ui.text.font.FontWeight.Bold,
                        modifier = Modifier.width(80.dp)
                    )
                    Text(
                        r.name.substringAfterLast('.'),
                        color = ide.text, fontSize = 12.sp, fontFamily = Mono, maxLines = 1,
                        modifier = Modifier.weight(1f)
                    )
                    if (r.exported == "true") {
                        Text("exported", color = ide.red, fontSize = 10.sp, fontFamily = Mono)
                    }
                }
                Text(r.name, color = ide.dim, fontSize = 10.sp, fontFamily = Mono, maxLines = 1)
                if (r.actions.isNotEmpty()) {
                    Text(
                        "  actions: ${r.actions.joinToString(", ")}",
                        color = ide.dim, fontSize = 10.sp, fontFamily = Mono, maxLines = 2
                    )
                }
            }
        }
        item { Spacer(Modifier.height(40.dp)) }
    }
}

@Composable
private fun PermissionsSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val mi = vm.manifest ?: return
    LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
        items(mi.permissions.size) { i ->
            val p = mi.permissions[i]
            val dangerous = p.contains("LOCATION") || p.contains("CAMERA") ||
                p.contains("RECORD_AUDIO") || p.contains("CONTACTS") ||
                p.contains("SMS") || p.contains("CALL_LOG") || p.contains("READ_PHONE")
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 10.dp, vertical = 3.dp)
            ) {
                if (dangerous) RowIcon(Icons.Filled.PriorityHigh, ide.red, 13.dp)
                else Spacer(Modifier.width(24.dp))
                Text(p, color = ide.text, fontSize = 11.5.sp, fontFamily = Mono, maxLines = 1)
            }
        }
        item { Spacer(Modifier.height(40.dp)) }
    }
}

@Composable
private fun DexSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val meta = vm.meta ?: return
    var query by remember { mutableStateOf("") }
    Column(Modifier.fillMaxSize()) {
        androidx.compose.material3.OutlinedTextField(
            value = query, onValueChange = { query = it },
            label = { Text("Search classes…") }, singleLine = true,
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 10.dp, vertical = 4.dp),
            textStyle = androidx.compose.ui.text.TextStyle(
                fontSize = 12.sp, fontFamily = Mono, color = ide.text)
        )
        LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
            val classes = meta.dexClasses.filter { it.name.contains(query, ignoreCase = true) }
            items(classes.size) { i ->
                val c = classes[i]
                Column(Modifier.fillMaxWidth().padding(horizontal = 10.dp, vertical = 2.dp)) {
                    Text(
                        c.name, color = ide.cyan, fontSize = 12.sp, fontFamily = Mono, maxLines = 1
                    )
                    if (c.superName.isNotEmpty())
                        Text("  extends ${c.superName}", color = ide.dim, fontSize = 10.sp, fontFamily = Mono, maxLines = 1)
                }
            }
            item {
                Text(
                    "${meta.dexClasses.size} classes · ${meta.dexMethods.size} methods · extracted from ${vm.apkEntries.firstOrNull { it.name.endsWith(".dex") }?.name ?: "file"}",
                    color = ide.dim, fontSize = 10.sp, fontFamily = Mono,
                    modifier = Modifier.padding(10.dp)
                )
                Spacer(Modifier.height(40.dp))
            }
        }
    }
}

@Composable
private fun LibsSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
        items(vm.apkEntries.size) { i ->
            val e = vm.apkEntries[i]
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable { vm.openApkEntry(e) }
                    .padding(horizontal = 10.dp, vertical = 4.dp)
            ) {
                RowIcon(
                    if (e.name.endsWith(".so")) Icons.Filled.Memory else Icons.Filled.Description,
                    ide.dim, 13.dp
                )
                Text(e.name, color = ide.cyan, fontSize = 11.5.sp, fontFamily = Mono,
                    maxLines = 1, modifier = Modifier.weight(1f))
                Text("${humanSizeK(e.size)}", color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
            }
        }
        item {
            Text("Tap to extract & analyze (ELF) — si aad u falanqayso", color = ide.dim,
                fontSize = 10.sp, modifier = Modifier.padding(10.dp))
            Spacer(Modifier.height(40.dp))
        }
    }
}

@Composable
private fun ResourcesSection(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = androidx.compose.ui.platform.LocalContext.current
    var previewPath by remember { mutableStateOf<String?>(null) }
    var previewBmp by remember { mutableStateOf<android.graphics.Bitmap?>(null) }

    LaunchedEffect(previewPath) {
        previewBmp = null
        val path = previewPath ?: return@LaunchedEffect
        try {
            val apkPath = vm.currentPath
            if (apkPath != null) {
                ZipFile(java.io.File(apkPath)).use { zf ->
                    val en = zf.getEntry(path)
                    if (en != null) {
                        val bmp = BitmapFactory.decodeStream(zf.getInputStream(en))
                        previewBmp = bmp
                    }
                }
            }
        } catch (_: Exception) { }
    }

    Column(Modifier.fillMaxSize()) {
        if (previewPath != null && previewBmp != null) {
            Box(
                Modifier.fillMaxWidth().height(180.dp).background(ide.panel),
                contentAlignment = Alignment.Center
            ) {
                Image(
                    bitmap = previewBmp!!.asImageBitmap(),
                    contentDescription = previewPath,
                    contentScale = ContentScale.Fit,
                    modifier = Modifier.fillMaxSize().padding(8.dp)
                )
            }
        }
        LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
            items(vm.apkResources.size) { i ->
                val r = vm.apkResources[i]
                Row(
                    Modifier
                        .fillMaxWidth()
                        .clickable { if (r.isImage) previewPath = r.path }
                        .padding(horizontal = 10.dp, vertical = 2.dp)
                ) {
                    RowIcon(
                        when {
                            r.isImage -> Icons.Filled.Photo
                            r.isXml -> Icons.Filled.Code
                            else -> Icons.Filled.Description
                        },
                        ide.dim, 13.dp
                    )
                    Text(r.path, color = ide.text, fontSize = 11.sp, fontFamily = Mono,
                        maxLines = 1, modifier = Modifier.weight(1f))
                    Text(humanSizeK(r.size), color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                }
            }
            item {
                Text("Tap an image to preview — sawir si aad u aragto", color = ide.dim,
                    fontSize = 10.sp, modifier = Modifier.padding(10.dp))
                Spacer(Modifier.height(40.dp))
            }
        }
    }
}

private fun humanSizeK(n: Long): String = when {
    n >= 1024 * 1024 -> "%.1f MB".format(n / 1048576.0)
    n >= 1024 -> "%.1f KB".format(n / 1024.0)
    else -> "$n B"
}

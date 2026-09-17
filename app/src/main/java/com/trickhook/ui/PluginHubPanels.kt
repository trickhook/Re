package com.trickhook.ui

import android.content.Intent
import android.net.Uri
import android.util.Base64
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.CheckCircleOutline
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.FileDownload
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.PlayArrow
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.trickhook.hub.DeviceKey
import com.trickhook.hub.IndexResult
import com.trickhook.hub.InstallResult
import com.trickhook.hub.PluginCanonical
import com.trickhook.hub.PluginHub
import com.trickhook.hub.RegistryEntry
import com.trickhook.model.PluginDef
import com.trickhook.vm.StudioViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

// ============================================================== Plugin Hub ==
//
// Three surfaces layered on the existing NocturneScript plugin system, all in
// the app's own palette and primitives: a registry browser that installs
// signed, checksummed plugins from the repository; an editor that signs and
// publishes a plugin through a prefilled GitHub issue; and a device-identity
// card that explains, honestly, what the signing key does and does not prove.
// There is no server and there is no AI anywhere in here.

/**
 * A compact, self-contained action shown in the Plugins panel header. Text with
 * a leading glyph, sized like the panel's other quiet controls; not a Material
 * button, so it stays on the palette.
 */
@Composable
fun HubBarButton(label: String, icon: ImageVector, onClick: () -> Unit) {
    val ide = LocalIde.current
    Row(
        Modifier
            .heightIn(min = 36.dp)
            .clip(RoundedCornerShape(9.dp))
            .border(1.dp, ide.borderStrong, RoundedCornerShape(9.dp))
            .clickable(role = Role.Button, onClickLabel = label, onClick = onClick)
            .padding(horizontal = Space.l),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, contentDescription = null, tint = ide.accent, modifier = Modifier.size(15.dp))
        Spacer(Modifier.width(Space.s))
        Text(label, color = ide.text, fontSize = Type.label, fontWeight = FontWeight.Medium)
    }
}

// ------------------------------------------------------------ browser sheet --

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PluginHubSheet(vm: StudioViewModel, onNewPlugin: () -> Unit, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()

    // null result = still loading. A completed fetch is one of the three states.
    var result by remember { mutableStateOf<IndexResult?>(null) }
    var selected by remember { mutableStateOf<RegistryEntry?>(null) }
    var installingId by remember { mutableStateOf<String?>(null) }
    var installMsg by remember { mutableStateOf<Pair<Boolean, String>?>(null) }
    var reloadToken by remember { mutableStateOf(0) }

    LaunchedEffect(reloadToken) {
        result = null
        result = withContext(Dispatchers.IO) { PluginHub.fetchIndex() }
    }

    val installedVersions = vm.plugins.associate { it.id to it.version }

    val doInstall: (RegistryEntry) -> Unit = { entry ->
        scope.launch {
            installingId = entry.id
            installMsg = null
            val r = withContext(Dispatchers.IO) { PluginHub.install(ctx, entry) }
            when (r) {
                is InstallResult.Success -> {
                    vm.loadPlugins(ctx)
                    vm.log("OK", "Plugin installed from the hub: ${r.id}")
                    installMsg = true to "Verified and installed ${r.name}."
                }
                is InstallResult.Failure -> {
                    vm.log("ERROR", "Hub install rejected: ${r.message}")
                    installMsg = false to r.message
                }
            }
            installingId = null
        }
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        val chosen = selected
        if (chosen != null) {
            HubDetail(
                entry = chosen,
                installed = vm.plugins.firstOrNull { it.id == chosen.id },
                installing = installingId == chosen.id,
                message = installMsg,
                onBack = { selected = null; installMsg = null },
                onInstall = { doInstall(chosen) }
            )
        } else {
            HubBrowser(
                result = result,
                installedVersions = installedVersions,
                onNewPlugin = onNewPlugin,
                onReload = { reloadToken++ },
                onOpen = { selected = it; installMsg = null }
            )
        }
    }
}

@Composable
private fun HubBrowser(
    result: IndexResult?,
    installedVersions: Map<String, String>,
    onNewPlugin: () -> Unit,
    onReload: () -> Unit,
    onOpen: (RegistryEntry) -> Unit
) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .padding(start = Space.xl, end = Space.l, top = Space.s, bottom = Space.m),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(
                    "Plugin Hub", color = ide.text, fontSize = Type.title,
                    lineHeight = Type.titleLine, fontWeight = FontWeight.SemiBold
                )
                Text(
                    "Signed community NocturneScript, verified before it installs",
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                )
            }
            IconTargetHub(Icons.Filled.Refresh, "Reload the registry", ide.dim, onReload)
        }

        DeviceIdentityCard(refreshToken = 0)

        Row(
            Modifier
                .fillMaxWidth()
                .padding(horizontal = Space.xl, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            HubBarButton("New plugin", Icons.Filled.Add, onNewPlugin)
        }

        HorizontalDivider(color = ide.border)

        when (result) {
            null -> Column(Modifier.fillMaxWidth().padding(Space.m)) { SkeletonLines(6) }
            is IndexResult.Loaded -> {
                val loaded = result
                LazyColumn(
                    Modifier.weight(1f).fillMaxWidth().background(ide.bg),
                    contentPadding = PaddingValues(
                        start = Space.xl, end = Space.xl, top = Space.m, bottom = Space.xxl
                    ),
                    verticalArrangement = Arrangement.spacedBy(Space.m)
                ) {
                    item {
                        if (loaded.updated.isNotBlank()) {
                            Text(
                                "${loaded.entries.size} available · updated ${loaded.updated}",
                                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono
                            )
                        }
                    }
                    items(loaded.entries.size) { i ->
                        val e = loaded.entries[i]
                        HubRow(entry = e, installedVersion = installedVersions[e.id]) { onOpen(e) }
                    }
                }
            }
            IndexResult.Empty -> Box(
                Modifier.weight(1f).fillMaxWidth().background(ide.bg),
                contentAlignment = Alignment.Center
            ) {
                EmptyPanel(
                    "The hub is quiet right now",
                    "No community plugins have been published to the registry yet. When they are, they will appear here. You can publish the first one with New plugin."
                )
            }
            is IndexResult.Unreachable -> {
                val unreachable = result
                Box(
                    Modifier.weight(1f).fillMaxWidth().background(ide.bg),
                    contentAlignment = Alignment.Center
                ) {
                    Column(horizontalAlignment = Alignment.CenterHorizontally) {
                        EmptyPanel(
                            "The registry is not reachable",
                            unreachable.message + " Everything already installed still works — the hub is the only thing offline."
                        )
                        Spacer(Modifier.height(Space.m))
                        HubBarButton("Try again", Icons.Filled.Refresh, onReload)
                    }
                }
            }
        }
    }
}

/**
 * One registry row. [installedVersion] is the version already on the device for
 * this id, or null when it is not installed — that decides the trailing badge.
 */
@Composable
private fun HubRow(entry: RegistryEntry, installedVersion: String?, onOpen: () -> Unit) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .surface1()
            .clickable(role = Role.Button, onClickLabel = "Open ${entry.name}", onClick = onOpen)
            .padding(horizontal = Space.l, vertical = Space.l)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            RowIcon(Icons.Filled.Public, ide.violet)
            Spacer(Modifier.width(Space.s))
            Column(Modifier.weight(1f)) {
                Text(
                    entry.name, color = ide.text, fontSize = Type.body,
                    fontWeight = FontWeight.SemiBold, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                Text(
                    "v${entry.version} · ${entry.author}",
                    color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                    maxLines = 1, overflow = TextOverflow.Ellipsis
                )
            }
            Spacer(Modifier.width(Space.m))
            InstallBadge(installedVersion, entry.version)
        }
        if (entry.description.isNotEmpty()) {
            Spacer(Modifier.height(Space.m))
            Text(
                entry.description, color = ide.dim, fontSize = Type.label,
                lineHeight = Type.labelLine, maxLines = 2, overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
private fun InstallBadge(installedVersion: String?, availableVersion: String) {
    val ide = LocalIde.current
    when {
        installedVersion == null -> StatChip("available", ide.accent)
        installedVersion != availableVersion -> StatChip("update", ide.amber)
        else -> StatChip("installed", ide.entry)
    }
}

@Composable
private fun HubDetail(
    entry: RegistryEntry,
    installed: PluginDef?,
    installing: Boolean,
    message: Pair<Boolean, String>?,
    onBack: () -> Unit,
    onInstall: () -> Unit
) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .clickable(role = Role.Button, onClickLabel = "Back to the list", onClick = onBack)
                .padding(horizontal = Space.l, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back",
                tint = ide.dim, modifier = Modifier.size(18.dp)
            )
            Spacer(Modifier.width(Space.s))
            Text("Hub", color = ide.dim, fontSize = Type.label)
        }
        HorizontalDivider(color = ide.border)

        Column(
            Modifier
                .weight(1f)
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(horizontal = Space.xl, vertical = Space.l)
        ) {
            Text(
                entry.name, color = ide.text, fontSize = Type.title,
                lineHeight = Type.titleLine, fontWeight = FontWeight.SemiBold
            )
            Text(
                "v${entry.version} · ${entry.author}",
                color = ide.dim2, fontSize = Type.label, fontFamily = Mono
            )
            if (entry.description.isNotEmpty()) {
                Spacer(Modifier.height(Space.l))
                Text(
                    entry.description, color = ide.dim, fontSize = Type.body,
                    lineHeight = Type.bodyLine
                )
            }

            Spacer(Modifier.height(Space.l))
            Column(Modifier.fillMaxWidth().surface2().padding(Space.l)) {
                KeyValue("id", entry.id, vColor = ide.dim)
                KeyValue("author key", entry.authorFingerprint.ifEmpty { "—" }, vColor = ide.violet)
            }

            Spacer(Modifier.height(Space.l))
            Row(verticalAlignment = Alignment.Top) {
                Icon(
                    Icons.Filled.Warning, contentDescription = null, tint = ide.amber,
                    modifier = Modifier.size(15.dp)
                )
                Spacer(Modifier.width(Space.s))
                Text(
                    "Third-party plugin. It runs in the same on-device sandbox as every " +
                        "other NocturneScript — analysis only, no file, network or exec access. " +
                        "The signature proves who authored it and that it is unaltered; it is " +
                        "not a check that the script is safe to run.",
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                )
            }

            val msg = message
            if (msg != null) {
                Spacer(Modifier.height(Space.l))
                Row(
                    Modifier
                        .fillMaxWidth()
                        .background(
                            (if (msg.first) ide.entry else ide.red).copy(alpha = 0.10f),
                            RoundedCornerShape(9.dp)
                        )
                        .padding(Space.l),
                    verticalAlignment = Alignment.Top
                ) {
                    Icon(
                        if (msg.first) Icons.Filled.CheckCircleOutline else Icons.Filled.Warning,
                        contentDescription = null,
                        tint = if (msg.first) ide.entry else ide.red,
                        modifier = Modifier.size(15.dp)
                    )
                    Spacer(Modifier.width(Space.s))
                    Text(
                        msg.second,
                        color = if (msg.first) ide.entry else ide.red,
                        fontSize = Type.label, lineHeight = Type.labelLine
                    )
                }
            }
        }

        HorizontalDivider(color = ide.borderStrong)
        Column(Modifier.fillMaxWidth().background(ide.panel).padding(Space.l)) {
            val label = when {
                installing -> "Verifying and installing…"
                installed == null -> "Install"
                installed.version != entry.version -> "Update to v${entry.version}"
                else -> "Reinstall"
            }
            PrimaryHubAction(
                label = label,
                icon = Icons.Filled.FileDownload,
                enabled = !installing,
                onClick = onInstall
            )
            NavBarSpacer()
        }
    }
}

// -------------------------------------------------------------- editor sheet --

private data class PublishInfo(val fingerprint: String, val sha256: String, val prefilled: Boolean, val addedLocally: Boolean)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun PluginEditorSheet(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val scope = rememberCoroutineScope()
    val clip = LocalClipboardManager.current
    // The author display name is remembered across publishes: the device key is
    // the identity, and this is its human label, so it is asked once and then
    // pre-filled from here on rather than re-typed for every plugin.
    val prefs = remember { ctx.getSharedPreferences("nocturne_hub", android.content.Context.MODE_PRIVATE) }

    var name by remember { mutableStateOf("") }
    var id by remember { mutableStateOf("") }
    var idTouched by remember { mutableStateOf(false) }
    var author by remember { mutableStateOf(prefs.getString("author", "") ?: "") }
    var version by remember { mutableStateOf("1.0") }
    var description by remember { mutableStateOf("") }
    var script by remember { mutableStateOf("") }

    var didTest by remember { mutableStateOf(false) }
    var publishing by remember { mutableStateOf(false) }
    var publishError by remember { mutableStateOf<String?>(null) }
    var publishInfo by remember { mutableStateOf<PublishInfo?>(null) }

    val effectiveId = if (idTouched) id else PluginCanonical.slugify(name)
    val idValid = PluginCanonical.ID_REGEX.matches(effectiveId)
    val versionValid = PluginCanonical.VERSION_REGEX.matches(version)
    val scriptBytes = script.toByteArray(Charsets.UTF_8).size
    val def = PluginDef(effectiveId, name.trim(), version.trim(), author.trim(), description.trim(), script)
    val fileBytes = PluginCanonical.canonicalBytes(def).size
    val scriptOk = script.isNotBlank() && scriptBytes <= PluginCanonical.MAX_SCRIPT_BYTES
    val fileOk = fileBytes <= PluginCanonical.MAX_FILE_BYTES
    val nameOk = name.isNotBlank()
    val canPublish = idValid && versionValid && scriptOk && fileOk && nameOk && !publishing

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(start = Space.xl, end = Space.l, bottom = Space.s),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        "New plugin", color = ide.text, fontSize = Type.title,
                        lineHeight = Type.titleLine, fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        "Write, test in the sandbox, then sign and publish",
                        color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                    )
                }
                IconTargetHub(Icons.Filled.Close, "Close", ide.dim, onDismiss)
            }
            HorizontalDivider(color = ide.border)

            Column(
                Modifier
                    .weight(1f)
                    .fillMaxWidth()
                    .verticalScroll(rememberScrollState())
                    .padding(horizontal = Space.xl, vertical = Space.l)
            ) {
                EditorField("Name", name, "Display name of the plugin") { name = it }
                EditorHint(
                    if (effectiveId.isEmpty()) "id: (type a name)"
                    else "id: $effectiveId" + if (idValid) "" else "  — 3–40 chars, lower-case, digits, hyphens",
                    if (effectiveId.isEmpty() || idValid) ide.dim2 else ide.red
                )
                EditorField("Identifier", if (idTouched) id else effectiveId, "lower-case-with-hyphens") {
                    idTouched = true
                    id = it
                }
                Spacer(Modifier.height(Space.m))
                Row {
                    Box(Modifier.weight(1f)) {
                        EditorField("Version", version, "1.0") { version = it }
                    }
                    Spacer(Modifier.width(Space.l))
                    Box(Modifier.weight(1f)) {
                        EditorField("Author", author, "Your display name") { author = it }
                    }
                }
                if (!versionValid) {
                    EditorHint("Version must be MAJOR.MINOR or MAJOR.MINOR.PATCH", ide.red)
                }
                Spacer(Modifier.height(Space.m))
                EditorField("Description", description, "One line describing what it does") { description = it }

                Spacer(Modifier.height(Space.l))
                Text(
                    "NocturneScript", color = ide.dim, fontSize = Type.caption,
                    fontWeight = FontWeight.Medium, letterSpacing = Type.upperTracking
                )
                Spacer(Modifier.height(Space.s))
                OutlinedTextField(
                    value = script,
                    onValueChange = { script = it },
                    placeholder = {
                        Text("log(\"hello\")", color = ide.dim, fontFamily = Mono, fontSize = Type.mono)
                    },
                    modifier = Modifier.fillMaxWidth().heightIn(min = 160.dp, max = 300.dp),
                    textStyle = TextStyle(fontSize = Type.mono, color = ide.text, fontFamily = Mono)
                )
                Text(
                    "script ${humanSize(scriptBytes)} / 64 KiB · file ${humanSize(fileBytes)} / 128 KiB",
                    color = if (scriptOk && fileOk) ide.dim2 else ide.red,
                    fontSize = Type.caption, fontFamily = Mono,
                    modifier = Modifier.padding(top = Space.s)
                )

                Spacer(Modifier.height(Space.l))
                HorizontalDivider(color = ide.border)
                Spacer(Modifier.height(Space.l))

                // Test run — the existing runPlugin, exactly as a real run.
                Text(
                    "A test run executes in the sandbox exactly like a real run: if a binary " +
                        "is open, any renames, comments or bookmarks it writes are applied to the " +
                        "project and can be undone from the Plugins panel.",
                    color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
                )
                Spacer(Modifier.height(Space.m))
                val testedThis = vm.lastPluginName == def.name
                if (vm.pluginRunning && testedThis) {
                    Column(Modifier.fillMaxWidth()) { SkeletonLines(3, indent = true) }
                } else if (didTest && testedThis && vm.pluginOutput.isNotEmpty()) {
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .heightIn(max = 200.dp)
                            .surface2()
                            .padding(Space.m)
                    ) {
                        Text(
                            if (vm.lastPluginOk) "test run finished" else "test run failed",
                            color = if (vm.lastPluginOk) ide.entry else ide.red,
                            fontSize = Type.caption, fontFamily = Mono
                        )
                        Spacer(Modifier.height(Space.s))
                        SelectionContainer(Modifier.fillMaxWidth().verticalScroll(rememberScrollState())) {
                            Text(
                                vm.pluginOutput, color = ide.text, fontSize = Type.monoSmall,
                                lineHeight = Type.monoSmallLine, fontFamily = Mono
                            )
                        }
                    }
                }

                val info = publishInfo
                if (info != null) {
                    Spacer(Modifier.height(Space.l))
                    Column(
                        Modifier
                            .fillMaxWidth()
                            .background(ide.entry.copy(alpha = 0.10f), RoundedCornerShape(9.dp))
                            .padding(Space.l)
                    ) {
                        Text(
                            "Signed. The submission is on your clipboard and a GitHub issue was opened.",
                            color = ide.entry, fontSize = Type.label, lineHeight = Type.labelLine,
                            fontWeight = FontWeight.Medium
                        )
                        if (info.addedLocally) {
                            Spacer(Modifier.height(Space.s))
                            Text(
                                "It is also in your plugins now, so you can run it here while the " +
                                    "registry review completes.",
                                color = ide.dim, fontSize = Type.caption, lineHeight = Type.captionLine
                            )
                        }
                        Spacer(Modifier.height(Space.s))
                        Text("author ${info.fingerprint}", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                        Text("sha256 ${info.sha256.take(24)}…", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                        if (!info.prefilled) {
                            Spacer(Modifier.height(Space.s))
                            Text(
                                "The plugin was too large to prefill the issue, so paste the " +
                                    "clipboard into the fenced json block on the issue page.",
                                color = ide.amber, fontSize = Type.caption, lineHeight = Type.captionLine
                            )
                        }
                    }
                }

                val err = publishError
                if (err != null) {
                    Spacer(Modifier.height(Space.l))
                    Text(err, color = ide.red, fontSize = Type.label, lineHeight = Type.labelLine)
                }

                Spacer(Modifier.height(Space.l))
                PublishExplainer()
                Spacer(Modifier.height(Space.xl))
            }

            HorizontalDivider(color = ide.borderStrong)
            Row(
                Modifier.fillMaxWidth().background(ide.panel).padding(Space.l),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(Modifier.weight(1f)) {
                    SecondaryHubAction(
                        label = if (vm.pluginRunning) "Running…" else "Test run",
                        icon = Icons.Filled.PlayArrow,
                        enabled = scriptOk && !vm.pluginRunning
                    ) {
                        didTest = true
                        vm.runPlugin(ctx, def)
                    }
                }
                Spacer(Modifier.width(Space.m))
                Box(Modifier.weight(1f)) {
                    PrimaryHubAction(
                        label = if (publishing) "Signing…" else "Sign & publish",
                        icon = Icons.Filled.Lock,
                        enabled = canPublish
                    ) {
                        publishError = null
                        publishInfo = null
                        publishing = true
                        scope.launch {
                            try {
                                val identity = withContext(Dispatchers.Default) { DeviceKey.getOrCreate() }
                                val bytes = PluginCanonical.canonicalBytes(def)
                                val sha = PluginCanonical.sha256Hex(bytes)
                                val sigB64 = withContext(Dispatchers.Default) {
                                    Base64.encodeToString(DeviceKey.sign(bytes), Base64.NO_WRAP)
                                }
                                val submission = PluginHub.submissionJson(def, identity.publicKeyB64, sigB64)
                                clip.setText(AnnotatedString(submission))
                                val (url, prefilled) = PluginHub.issueUrlFor(def, submission)
                                try {
                                    ctx.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
                                } catch (e: Exception) {
                                    publishError =
                                        "Could not open a browser for the GitHub issue. The " +
                                        "submission is on your clipboard — open the repository's " +
                                        "new-issue page and paste it into a fenced json block."
                                }
                                // Remember the author name and add the plugin to
                                // this device's own list now, so a creator's work
                                // shows up in the Plugins panel on publish rather
                                // than only once the registry merges the issue.
                                prefs.edit().putString("author", def.author).apply()
                                val addedLocally = withContext(Dispatchers.IO) { PluginHub.saveLocal(ctx, def) }
                                if (addedLocally) vm.loadPlugins(ctx)
                                publishInfo = PublishInfo(identity.fingerprint, sha, prefilled, addedLocally)
                                vm.log(
                                    "OK",
                                    "Plugin signed for submission: ${def.id}" +
                                        if (addedLocally) " (added to your plugins)" else ""
                                )
                            } catch (e: Exception) {
                                publishError =
                                    "Signing failed on this device's keystore: " +
                                    (e.message ?: "the author key could not be created or used.")
                            } finally {
                                publishing = false
                            }
                        }
                    }
                }
            }
            NavBarSpacer()
        }
    }
}

// ---------------------------------------------------------- identity card ---

/**
 * The device identity fragment. Shows the fingerprint when the key exists and
 * the one honest sentence about what it proves. It never generates the key —
 * that happens only on the first publish — so before then it says so plainly.
 */
@Composable
fun DeviceIdentityCard(refreshToken: Int) {
    val ide = LocalIde.current
    var identity by remember { mutableStateOf<DeviceKey.Identity?>(null) }
    var loaded by remember { mutableStateOf(false) }
    LaunchedEffect(refreshToken) {
        identity = withContext(Dispatchers.Default) { DeviceKey.load() }
        loaded = true
    }
    val id = identity
    Column(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.xl, vertical = Space.s)
            .surface2()
            .padding(Space.l)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Icon(Icons.Filled.Lock, contentDescription = null, tint = ide.violet, modifier = Modifier.size(15.dp))
            Spacer(Modifier.width(Space.s))
            Text("This device's author key", color = ide.text, fontSize = Type.label, fontWeight = FontWeight.Medium)
            Spacer(Modifier.weight(1f))
            if (loaded) {
                Text(
                    if (id != null) id.fingerprint else "not created",
                    color = if (id != null) ide.violet else ide.dim2,
                    fontSize = Type.monoSmall, fontFamily = Mono
                )
            }
        }
        Spacer(Modifier.height(Space.s))
        Text(
            if (id != null)
                "This key signs the plugins you publish, proving they are yours and unaltered. " +
                    "It is authorship and integrity only — not a GitHub login, and not a check " +
                    "that a script is safe."
            else
                "Your author key is created the first time you publish a plugin. It then signs " +
                    "the plugins you publish, proving they are yours and unaltered — authorship " +
                    "and integrity only, not a GitHub login and not a safety check on a script.",
            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
        )
    }
}

// ------------------------------------------------------------------ pieces ---

@Composable
private fun PublishExplainer() {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .surface2()
            .padding(Space.l)
    ) {
        Text("How publishing works", color = ide.text, fontSize = Type.label, fontWeight = FontWeight.Medium)
        Spacer(Modifier.height(Space.s))
        Text(
            "Publishing signs the plugin with this device's key and opens a prefilled GitHub " +
                "issue. Filing it needs a GitHub account once — the device signature proves " +
                "authorship, the account authorizes the write. An automated check then validates " +
                "the submission and merges it into the registry. There is no server.",
            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
        )
    }
}

@Composable
private fun EditorField(label: String, value: String, placeholder: String, onChange: (String) -> Unit) {
    val ide = LocalIde.current
    Column(Modifier.fillMaxWidth().padding(top = Space.m)) {
        Text(
            label, color = ide.dim, fontSize = Type.caption,
            fontWeight = FontWeight.Medium, letterSpacing = Type.upperTracking
        )
        Spacer(Modifier.height(Space.xs))
        OutlinedTextField(
            value = value,
            onValueChange = onChange,
            placeholder = { Text(placeholder, color = ide.dim, fontSize = Type.body) },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
            textStyle = TextStyle(fontSize = Type.body, color = ide.text)
        )
    }
}

@Composable
private fun EditorHint(text: String, color: Color) {
    Text(
        text, color = color, fontSize = Type.caption, fontFamily = Mono,
        modifier = Modifier.padding(top = Space.xs)
    )
}

@Composable
private fun PrimaryHubAction(label: String, icon: ImageVector, enabled: Boolean, onClick: () -> Unit) {
    val ide = LocalIde.current
    val bg = if (enabled) ide.accent else ide.panel2
    val fg = if (enabled) ide.onAccent else ide.dim2
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(bg)
            .clickable(enabled = enabled, role = Role.Button, onClickLabel = label, onClick = onClick)
            .padding(horizontal = Space.l),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, contentDescription = null, tint = fg, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(Space.s))
        Text(label, color = fg, fontSize = Type.label, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun SecondaryHubAction(label: String, icon: ImageVector, enabled: Boolean, onClick: () -> Unit) {
    val ide = LocalIde.current
    val fg = if (enabled) ide.accent else ide.dim2
    Row(
        Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clip(RoundedCornerShape(10.dp))
            .border(1.dp, if (enabled) ide.borderStrong else ide.border, RoundedCornerShape(10.dp))
            .clickable(enabled = enabled, role = Role.Button, onClickLabel = label, onClick = onClick)
            .padding(horizontal = Space.l),
        horizontalArrangement = Arrangement.Center,
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(icon, contentDescription = null, tint = fg, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(Space.s))
        Text(label, color = fg, fontSize = Type.label, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
private fun IconTargetHub(icon: ImageVector, description: String, tint: Color, onClick: () -> Unit) {
    Box(
        Modifier
            .size(44.dp)
            .clickable(role = Role.Button, onClickLabel = description, onClick = onClick),
        contentAlignment = Alignment.Center
    ) {
        Icon(icon, contentDescription = description, tint = tint, modifier = Modifier.size(18.dp))
    }
}

private fun humanSize(bytes: Int): String =
    if (bytes < 1024) "$bytes B" else "%.1f KiB".format(bytes / 1024.0)

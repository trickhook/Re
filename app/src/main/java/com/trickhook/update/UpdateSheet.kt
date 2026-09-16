package com.trickhook.update

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.trickhook.BuildConfig
import com.trickhook.ui.EmptyPanel
import com.trickhook.ui.KeyValue
import com.trickhook.ui.LocalIde
import com.trickhook.ui.Mono
import com.trickhook.ui.Space
import com.trickhook.ui.StatChip
import com.trickhook.ui.Type
import com.trickhook.ui.motionMs
import com.trickhook.ui.surface2
import com.trickhook.vm.StudioViewModel
import java.io.File

/**
 * The update sheet: what you are running, what is published, what it weighs,
 * what the release says about itself, and exactly one thing to press.
 *
 * Every failure gets its own words here rather than a spinner that stops. The
 * two verification steps are named while they run, because "Downloading" going
 * quiet for three seconds on a large APK looks like a hang, and because the
 * checks are the reason this feature is allowed to exist at all.
 */

private val ButtonPad = PaddingValues(horizontal = Space.xl, vertical = Space.m)
private const val NOTES_MAX_HEIGHT = 200

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun UpdateSheet(
    vm: StudioViewModel,
    onInstall: (File) -> Unit,
    onDismiss: () -> Unit
) {
    val ide = LocalIde.current
    val state = vm.updateState
    // Raised only by pressing Install and being refused, so the explanation
    // appears at the moment it is relevant instead of as a standing warning.
    var installBlocked by remember { mutableStateOf(false) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        // No NavBarSpacer: material3 gives ModalBottomSheet the bottom
        // system-bar inset already. The gap below is optical, not an inset —
        // same decision as XrefSheet and ExportSheet.
        Column(Modifier.padding(bottom = Space.xl)) {
            Column(Modifier.padding(horizontal = Space.xl, vertical = Space.s)) {
                Text(
                    "Update", color = ide.text,
                    fontSize = Type.title, lineHeight = Type.titleLine,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(Space.xs))
                Text(
                    "Nocturne ${BuildConfig.VERSION_NAME} (build ${BuildConfig.VERSION_CODE}) " +
                        "is installed",
                    color = ide.dim2, fontSize = Type.label, lineHeight = Type.labelLine,
                    fontFamily = Mono
                )
            }
            Spacer(Modifier.height(Space.m))

            // The body changes height on every state change; animate it so the
            // sheet settles instead of snapping between four different sizes.
            Box(Modifier.fillMaxWidth().animateContentSize(tween(motionMs()))) {
                when (state) {
                    is UpdateState.Idle -> IdleBody(vm)
                    is UpdateState.Checking ->
                        BusyBody("Asking GitHub for the latest release…", vm, cancellable = false)

                    is UpdateState.UpToDate -> UpToDateBody(vm, state)
                    is UpdateState.Available -> AvailableBody(vm, state.rel)
                    is UpdateState.Downloading -> DownloadingBody(vm, state.rel)
                    is UpdateState.Verifying -> VerifyingBody(vm, state)
                    is UpdateState.Ready -> ReadyBody(
                        vm, state, installBlocked,
                        onBlocked = { installBlocked = true },
                        onInstall = onInstall
                    )

                    is UpdateState.Failed -> FailedBody(vm, state)
                }
            }

            Spacer(Modifier.height(Space.l))
            HorizontalDivider(color = ide.border)
            LaunchCheckRow(vm)
        }
    }
}

// ------------------------------------------------------------------ bodies --

@Composable
private fun IdleBody(vm: StudioViewModel) {
    val ctx = LocalContext.current
    Column {
        EmptyPanel(
            "Nothing checked yet",
            "Nocturne does not contact GitHub unless you ask it to."
        )
        Column(Modifier.padding(horizontal = Space.xl)) {
            Button(
                onClick = { vm.checkForUpdate(ctx, manual = true) },
                contentPadding = ButtonPad
            ) { Text("Check for updates", fontSize = Type.label) }
        }
    }
}

@Composable
private fun BusyBody(line: String, vm: StudioViewModel, cancellable: Boolean) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    Column(Modifier.padding(horizontal = Space.xl)) {
        LinearProgressIndicator(
            modifier = Modifier.fillMaxWidth().height(3.dp),
            color = ide.accent,
            trackColor = ide.borderStrong
        )
        Spacer(Modifier.height(Space.l))
        Text(line, color = ide.dim, fontSize = Type.label, lineHeight = Type.labelLine)
        if (cancellable) {
            Spacer(Modifier.height(Space.m))
            TextButton(
                onClick = { vm.cancelUpdateDownload(ctx) },
                contentPadding = ButtonPad
            ) { Text("Cancel", color = ide.red, fontSize = Type.label) }
        }
    }
}

@Composable
private fun UpToDateBody(vm: StudioViewModel, state: UpdateState.UpToDate) {
    val ctx = LocalContext.current
    Column {
        EmptyPanel(
            "Nocturne ${state.versionName} is the newest build",
            "Checked against the latest published release on GitHub. " +
                "Pre-releases are never offered here."
        )
        Column(Modifier.padding(horizontal = Space.xl)) {
            TextButton(
                onClick = { vm.checkForUpdate(ctx, manual = true) },
                contentPadding = ButtonPad
            ) { Text("Check again", fontSize = Type.label) }
        }
    }
}

@Composable
private fun AvailableBody(vm: StudioViewModel, rel: UpdateRelease) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    Column(Modifier.padding(horizontal = Space.xl)) {
        KeyValue("installed", "${BuildConfig.VERSION_NAME}  (${BuildConfig.VERSION_CODE})")
        KeyValue("available", "${rel.versionName}  (${rel.versionCode})", vColor = ide.accent)
        Spacer(Modifier.height(Space.m))
        Row(horizontalArrangement = Arrangement.spacedBy(Space.s)) {
            StatChip("download", humanBytes(rel.apkSize), ide.cyan)
            StatChip("sha256", shortHash(rel.sha256), ide.violet)
            if (rel.prerelease) StatChip("pre-release", ide.amber)
        }
        Spacer(Modifier.height(Space.l))
        NotesBlock(rel.notes)
        Spacer(Modifier.height(Space.l))
        Button(onClick = { vm.downloadUpdate(ctx) }, contentPadding = ButtonPad) {
            Text("Download ${humanBytes(rel.apkSize)}", fontSize = Type.label)
        }
        Spacer(Modifier.height(Space.m))
        Text(
            "The file is checked against that SHA-256, and against this app's own signing " +
                "certificate, before anything is handed to the installer.",
            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
        )
    }
}

@Composable
private fun DownloadingBody(vm: StudioViewModel, rel: UpdateRelease) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val got = vm.updateBytes
    val total = vm.updateTotal
    val fraction = if (total > 0L) (got.toFloat() / total.toFloat()).coerceIn(0f, 1f) else 0f
    Column(Modifier.padding(horizontal = Space.xl)) {
        Text(
            "Downloading Nocturne ${rel.versionName}",
            color = ide.text, fontSize = Type.body, lineHeight = Type.bodyLine,
            fontWeight = FontWeight.Medium
        )
        Spacer(Modifier.height(Space.m))
        LinearProgressIndicator(
            progress = { fraction },
            modifier = Modifier.fillMaxWidth().height(4.dp),
            color = ide.accent,
            trackColor = ide.borderStrong
        )
        Spacer(Modifier.height(Space.m))
        Text(
            "${humanBytes(got)} of ${humanBytes(total)}",
            color = ide.dim2, fontSize = Type.monoSmall, lineHeight = Type.monoSmallLine,
            fontFamily = Mono
        )
        Spacer(Modifier.height(Space.l))
        TextButton(
            onClick = { vm.cancelUpdateDownload(ctx) },
            contentPadding = ButtonPad
        ) { Text("Cancel", color = ide.red, fontSize = Type.label) }
    }
}

@Composable
private fun VerifyingBody(vm: StudioViewModel, state: UpdateState.Verifying) {
    val line = if (state.step == "SHA-256") {
        "Hashing the file that landed on disk and comparing it with the digest the release published."
    } else {
        "Reading the APK's signing certificate and comparing it with this app's own."
    }
    BusyBody("Checking the ${state.step}. $line", vm, cancellable = true)
}

@Composable
private fun ReadyBody(
    vm: StudioViewModel,
    state: UpdateState.Ready,
    blocked: Boolean,
    onBlocked: () -> Unit,
    onInstall: (File) -> Unit
) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val rel = state.rel
    Column(Modifier.padding(horizontal = Space.xl)) {
        Text(
            "Nocturne ${rel.versionName} is verified and ready",
            color = ide.entry, fontSize = Type.body, lineHeight = Type.bodyLine,
            fontWeight = FontWeight.Medium
        )
        Spacer(Modifier.height(Space.m))
        KeyValue("sha-256", "matches the release", vColor = ide.entry)
        KeyValue("certificate", "matches this install", vColor = ide.entry)
        KeyValue("size", humanBytes(rel.apkSize))
        if (blocked) {
            Spacer(Modifier.height(Space.l))
            PermissionBlock(vm)
        }
        Spacer(Modifier.height(Space.l))
        Button(
            onClick = {
                if (canInstallPackages(ctx)) {
                    onInstall(File(state.path))
                } else {
                    onBlocked()
                    vm.updateInstallBlocked()
                }
            },
            contentPadding = ButtonPad
        ) { Text("Install ${rel.versionName}", fontSize = Type.label) }
        Spacer(Modifier.height(Space.m))
        Text(
            "Android asks for its own confirmation next. Nocturne closes while it installs.",
            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
        )
    }
}

@Composable
private fun FailedBody(vm: StudioViewModel, state: UpdateState.Failed) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val failure = state.failure
    Column(Modifier.padding(horizontal = Space.xl)) {
        Text(
            failure.title, color = ide.red, fontSize = Type.body, lineHeight = Type.bodyLine,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.height(Space.m))
        Text(
            failure.detail, color = ide.dim2,
            fontSize = Type.label, lineHeight = Type.labelLine
        )
        Spacer(Modifier.height(Space.l))
        when (failure.fix) {
            UpdateFix.RETRY ->
                if (state.rel != null) {
                    Button(onClick = { vm.downloadUpdate(ctx) }, contentPadding = ButtonPad) {
                        Text("Download again", fontSize = Type.label)
                    }
                } else {
                    Button(
                        onClick = { vm.checkForUpdate(ctx, manual = true) },
                        contentPadding = ButtonPad
                    ) { Text("Check again", fontSize = Type.label) }
                }

            UpdateFix.GRANT_INSTALL ->
                Button(
                    onClick = { if (!openUnknownSourcesSettings(ctx)) vm.updateInstallBlocked() },
                    contentPadding = ButtonPad
                ) { Text("Open settings", fontSize = Type.label) }

            // Nothing to press. The words above are the whole answer, and a
            // button that cannot work is worse than no button.
            UpdateFix.UNINSTALL_FIRST -> Unit

            UpdateFix.NONE ->
                TextButton(
                    onClick = { vm.checkForUpdate(ctx, manual = true) },
                    contentPadding = ButtonPad
                ) { Text("Check again", fontSize = Type.label) }
        }
    }
}

// ------------------------------------------------------------------ pieces --

@Composable
private fun NotesBlock(notes: String) {
    val ide = LocalIde.current
    if (notes.isBlank()) {
        Text(
            "This release carries no notes.",
            color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
        )
        return
    }
    Column(
        Modifier
            .fillMaxWidth()
            .surface2()
            .heightIn(max = NOTES_MAX_HEIGHT.dp)
            .verticalScroll(rememberScrollState())
            .padding(Space.l)
    ) {
        Text(
            notes, color = ide.text,
            fontSize = Type.label, lineHeight = Type.labelLine
        )
    }
}

@Composable
private fun PermissionBlock(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val failure = failInstallPermission()
    Column(Modifier.fillMaxWidth().surface2().padding(Space.l)) {
        Text(
            failure.title, color = ide.amber,
            fontSize = Type.label, lineHeight = Type.labelLine,
            fontWeight = FontWeight.SemiBold
        )
        Spacer(Modifier.height(Space.s))
        Text(
            failure.detail, color = ide.dim2,
            fontSize = Type.caption, lineHeight = Type.captionLine
        )
        Spacer(Modifier.height(Space.m))
        TextButton(
            onClick = { if (!openUnknownSourcesSettings(ctx)) vm.updateInstallBlocked() },
            contentPadding = ButtonPad
        ) { Text("Open settings", color = ide.accent, fontSize = Type.label) }
    }
}

@Composable
private fun LaunchCheckRow(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val on = vm.updateOnLaunch
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Switch) { vm.applyUpdateOnLaunch(ctx, !on) }
            .sizeIn(minHeight = 48.dp)
            .padding(horizontal = Space.xl, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                "Check on launch", color = ide.text,
                fontSize = Type.body, lineHeight = Type.bodyLine
            )
            Text(
                "One request to GitHub each time Nocturne starts. Off by default, and there " +
                    "is no timer: nothing is checked in the background, ever.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
            )
        }
        Spacer(Modifier.width(Space.l))
        // onCheckedChange = null: the whole row is the control, so the switch
        // is the indicator and not a second, smaller touch target beside it.
        Switch(
            checked = on,
            onCheckedChange = null,
            colors = SwitchDefaults.colors(
                checkedThumbColor = ide.onAccent,
                checkedTrackColor = ide.accent,
                checkedBorderColor = ide.accent,
                uncheckedThumbColor = ide.dim,
                uncheckedTrackColor = ide.panel2,
                uncheckedBorderColor = ide.borderStrong
            )
        )
    }
}

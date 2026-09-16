package com.trickhook.mcp

import androidx.compose.animation.animateContentSize
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.sizeIn
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Switch
import androidx.compose.material3.SwitchDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.produceState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Size
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.trickhook.ui.EmptyPanel
import com.trickhook.ui.KeyValue
import com.trickhook.ui.LocalIde
import com.trickhook.ui.Mono
import com.trickhook.ui.SectionTitle
import com.trickhook.ui.Space
import com.trickhook.ui.StatChip
import com.trickhook.ui.Type
import com.trickhook.ui.motionMs
import com.trickhook.ui.surface2
import com.trickhook.vm.StudioViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The MCP sheet: what is listening, on which network, with which token, and
 * everything a client needs in one scan or one paste.
 *
 * The order is the order a person needs it in — is it on, where is it, is that
 * network safe, here is the token, here is the block to paste, here is what the
 * assistant has actually done to your project.
 */

private val Touch = 48.dp
private val time = SimpleDateFormat("HH:mm:ss", Locale.US)

/** Log rows the sheet draws inline before it stops and says how many more. */
private const val LOG_ROWS_SHOWN = 40

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun McpSheet(vm: StudioViewModel, requestNotifications: () -> Unit, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val clip = LocalClipboardManager.current
    val status = McpRuntime.status
    val running = status == McpRuntime.Status.RUNNING

    val copy: (String, String) -> Unit = { text, what ->
        clip.setText(AnnotatedString(text))
        vm.log("OK", "$what copied to the clipboard")
    }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        // No NavBarSpacer: material3 gives ModalBottomSheet the bottom
        // system-bar inset already. The gap below is optical — the same
        // decision as XrefSheet, ExportSheet and UpdateSheet.
        Column(
            Modifier
                .fillMaxWidth()
                .verticalScroll(rememberScrollState())
                .padding(bottom = Space.xl)
        ) {
            Column(Modifier.padding(horizontal = Space.xl, vertical = Space.s)) {
                Text(
                    "MCP server", color = ide.text,
                    fontSize = Type.title, lineHeight = Type.titleLine,
                    fontWeight = FontWeight.SemiBold
                )
                Spacer(Modifier.height(Space.xs))
                Text(
                    "A control port an AI client on your computer can drive this app through: " +
                        "open the binary here, let it list, decompile, follow xrefs and emulate. " +
                        "Nocturne itself contains no assistant and calls no model — this is the " +
                        "other end of the wire, and the model is whatever you point at it.",
                    color = ide.dim2, fontSize = Type.label, lineHeight = Type.labelLine
                )
            }

            Spacer(Modifier.height(Space.m))
            StatusStrip()
            Spacer(Modifier.height(Space.m))
            RunRow(vm, requestNotifications)
            HorizontalDivider(color = ide.border)

            Box(Modifier.fillMaxWidth().animateContentSize(tween(motionMs()))) {
                Column {
                    if (!running) StoppedBody() else RunningBody(copy)
                }
            }

            HorizontalDivider(color = ide.border)
            SectionTitle("Tool calls")
            CallLogList()
        }
    }
}

// ------------------------------------------------------------------ status --

@Composable
private fun StatusStrip() {
    val ide = LocalIde.current
    val status = McpRuntime.status
    val tint = when (status) {
        McpRuntime.Status.RUNNING -> ide.entry
        McpRuntime.Status.FAILED -> ide.red
        McpRuntime.Status.STARTING -> ide.amber
        else -> ide.dim
    }
    Row(
        Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = Space.xl),
        horizontalArrangement = Arrangement.spacedBy(Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        StatChip(
            when (status) {
                McpRuntime.Status.RUNNING -> "listening"
                McpRuntime.Status.STARTING -> "starting"
                McpRuntime.Status.FAILED -> "failed"
                else -> "stopped"
            },
            tint
        )
        StatChip("port", McpRuntime.PORT.toString(), ide.cyan)
        StatChip("open", McpRuntime.connections.toString(), ide.dim2)
        StatChip("tool calls", McpRuntime.toolCalls.toString(), ide.violet)
        StatChip(
            "refused", McpRuntime.rejected.toString(),
            if (McpRuntime.rejected > 0) ide.red else ide.dim2
        )
    }
}

@Composable
private fun RunRow(vm: StudioViewModel, requestNotifications: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val status = McpRuntime.status
    val on = status == McpRuntime.Status.RUNNING || status == McpRuntime.Status.STARTING
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Switch) {
                if (on) {
                    McpService.stop(ctx, "stopped from the app")
                } else {
                    // Asked for at the moment it becomes relevant. Without it on
                    // API 33+ the service still runs, but the one thing that
                    // tells you a port is open is invisible.
                    requestNotifications()
                    McpService.start(ctx)
                }
            }
            .sizeIn(minHeight = Touch)
            .padding(horizontal = Space.xl, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                if (on) "Listening" else "Run the server",
                color = ide.text, fontSize = Type.body, lineHeight = Type.bodyLine
            )
            Text(
                "Off until you turn it on, never on launch, and never restarted by the " +
                    "system. It stops by itself after " +
                    (McpRuntime.IDLE_STOP_MS / 60000) +
                    " minutes with no client, when you close Nocturne, and after " +
                    McpRuntime.BAD_TOKEN_LIMIT + " requests with a bad token.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
            )
        }
        Spacer(Modifier.width(Space.l))
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

// ----------------------------------------------------------------- stopped --

@Composable
private fun StoppedBody() {
    val ide = LocalIde.current
    Column {
        if (McpRuntime.failure.isNotEmpty()) {
            Notice(McpRuntime.failure, ide.red)
        } else if (McpRuntime.stopReason.isNotEmpty()) {
            Notice(McpRuntime.stopReason, ide.amber)
        }
        SectionTitle("Reachable from")
        ModeRow(
            McpRuntime.MODE_LAN, "This network",
            "Binds one interface — the Wi-Fi address this phone already has. Any device " +
                "on the same network can reach the port, so the token is the only thing " +
                "protecting it."
        )
        ModeRow(
            McpRuntime.MODE_LOOPBACK, "This device only (adb forward)",
            "Binds 127.0.0.1. Nothing off the phone can reach it; a desktop gets in " +
                "through a USB cable with adb forward. Slower to set up, and the right " +
                "answer for a sample you care about or a network you do not trust."
        )
        HorizontalDivider(color = ide.border)
        WriteRow()
    }
}

@Composable
private fun ModeRow(mode: String, title: String, detail: String) {
    val ide = LocalIde.current
    val selected = McpRuntime.bindMode == mode
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.RadioButton) { McpRuntime.applyBindMode(mode) }
            .sizeIn(minHeight = Touch)
            .padding(horizontal = Space.xl, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            Modifier
                .size(10.dp)
                .background(
                    if (selected) ide.accent else Color.Transparent,
                    RoundedCornerShape(5.dp)
                )
        )
        Spacer(Modifier.width(Space.l))
        Column(Modifier.weight(1f)) {
            Text(
                title, color = if (selected) ide.text else ide.dim,
                fontSize = Type.body, lineHeight = Type.bodyLine,
                fontWeight = if (selected) FontWeight.Medium else FontWeight.Normal
            )
            Text(
                detail, color = ide.dim2,
                fontSize = Type.caption, lineHeight = Type.captionLine
            )
        }
    }
}

@Composable
private fun WriteRow() {
    val ide = LocalIde.current
    val readOnly = McpRuntime.readOnly
    Row(
        Modifier
            .fillMaxWidth()
            .clickable(role = Role.Switch) { McpRuntime.applyReadOnly(!readOnly) }
            .sizeIn(minHeight = Touch)
            .padding(horizontal = Space.xl, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                "Let the client write to this project",
                color = ide.text, fontSize = Type.body, lineHeight = Type.bodyLine
            )
            Text(
                "Off by default. On, three more tools appear: rename a function, comment an " +
                    "address, drop a bookmark. They write to Nocturne's own database and " +
                    "never to the binary. Fixed when the server starts, because a client " +
                    "caches the tool list.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
            )
        }
        Spacer(Modifier.width(Space.l))
        Switch(
            checked = !readOnly,
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

// ----------------------------------------------------------------- running --

@Composable
private fun RunningBody(copy: (String, String) -> Unit) {
    val ide = LocalIde.current
    val loopback = McpRuntime.bindMode == McpRuntime.MODE_LOOPBACK
    Column {
        SectionTitle("Where it is listening")
        Column(Modifier.padding(horizontal = Space.xl)) {
            KeyValue("address", "${McpRuntime.host}:${McpRuntime.PORT}", vColor = ide.entry)
            KeyValue("interface", "${McpRuntime.networkKind} · ${McpRuntime.iface}")
            KeyValue("writes", if (McpRuntime.readOnly) "refused (read-only)" else "allowed")
            KeyValue("client", McpRuntime.client.ifEmpty { "none has connected yet" })
        }
        Spacer(Modifier.height(Space.m))

        if (loopback) {
            Notice(
                "Loopback only. Nothing off this device can reach the port. Run this on the " +
                    "computer first, over USB:",
                ide.dim2
            )
            CodeBlock(McpRuntime.adbForward, "The adb command", copy)
        } else if (!McpRuntime.privateNetwork) {
            Notice(
                "This address is a public one, not a private network address. The port may be " +
                    "reachable from outside this network entirely. Stop the server unless you " +
                    "know exactly why that is the case.",
                ide.red
            )
        } else {
            Notice(
                "Nocturne cannot tell you WHICH network this is — naming the Wi-Fi requires the " +
                    "location permission, which this app does not ask for. Everyone on it can " +
                    "reach this port and the traffic is not encrypted. On a network you do not " +
                    "control, stop the server and use the loopback mode instead.",
                ide.amber
            )
        }

        SectionTitle("Pair a client")
        PairingBlock(copy)

        SectionTitle("Token")
        Column(Modifier.padding(horizontal = Space.xl)) {
            Text(
                "New every time the server starts, 256 bits, never written to disk. " +
                    "On a network this is the only thing between your project and anyone else " +
                    "on it.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
            )
        }
        CodeBlock(McpRuntime.token, "The token", copy)

        SectionTitle("Claude Code")
        CodeBlock(claudeCodeCommand(), "The Claude Code command", copy)
        CodeBlock(claudeCodeJson(), "The .mcp.json block", copy)

        SectionTitle("Claude Desktop")
        Column(Modifier.padding(horizontal = Space.xl)) {
            Text(
                "Claude Desktop starts local servers as processes, so it reaches this one " +
                    "through the mcp-remote bridge. Node is what runs it.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
            )
        }
        CodeBlock(claudeDesktopJson(), "The Claude Desktop block", copy)
    }
}

@Composable
private fun PairingBlock(copy: (String, String) -> Unit) {
    val ide = LocalIde.current
    val pairing = McpRuntime.pairingText
    // Encoding runs off the composition thread. It is only milliseconds of
    // integer work, but composition is not where work belongs, and the key
    // means it happens once per server start rather than once per frame.
    val code by produceState<McpQr.Code?>(initialValue = null, pairing) {
        value = if (pairing.isEmpty()) null
        else withContext(Dispatchers.Default) { McpQr.encode(pairing) }
    }
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.xl),
        verticalAlignment = Alignment.CenterVertically
    ) {
        val symbol = code
        if (symbol != null) {
            // Always black on white, in both themes: a scanner needs the
            // contrast polarity it expects, and an inverted code in dark mode
            // is one many readers simply will not see.
            Canvas(Modifier.size(132.dp)) {
                val n = symbol.size
                val cell = size.minDimension / (n + 8f)
                val origin = 4f * cell
                drawRect(Color.White, Offset.Zero, size)
                // Runs of dark modules are drawn as one rectangle each. A
                // version 5 symbol is 1,369 cells; painting them individually
                // is that many draw calls on every frame of the sheet's
                // animation, and merging each row's runs cuts it by roughly
                // five to one for nothing but a counter.
                for (r in 0 until n) {
                    var c = 0
                    while (c < n) {
                        if (!symbol.isDark(r, c)) {
                            c += 1
                            continue
                        }
                        var end = c
                        while (end + 1 < n && symbol.isDark(r, end + 1)) end += 1
                        drawRect(
                            Color.Black,
                            Offset(origin + c * cell, origin + r * cell),
                            // Half a pixel of overlap so neighbouring rows do
                            // not leave hairlines between them when `cell` is
                            // not a whole number of device pixels.
                            Size((end - c + 1) * cell + 0.5f, cell + 0.5f)
                        )
                        c = end + 1
                    }
                }
            }
            Spacer(Modifier.width(Space.l))
        }
        Column(Modifier.weight(1f)) {
            Text(
                "Scan this to get the address and the token in one string, or copy it below.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
            )
            Spacer(Modifier.height(Space.s))
            Text(
                "The token rides in the fragment, which a browser never sends to a server.",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine
            )
        }
    }
    CodeBlock(pairing, "The address and token", copy)
}

// ------------------------------------------------------------------ pieces --

@Composable
private fun Notice(text: String, tint: Color) {
    val ide = LocalIde.current
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.xl, vertical = Space.m),
        verticalAlignment = Alignment.Top
    ) {
        Icon(
            Icons.Filled.Warning, contentDescription = null, tint = tint,
            modifier = Modifier.size(16.dp)
        )
        Spacer(Modifier.width(Space.m))
        Text(
            text, color = ide.dim, fontSize = Type.caption, lineHeight = Type.captionLine,
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun CodeBlock(text: String, what: String, copy: (String, String) -> Unit) {
    val ide = LocalIde.current
    if (text.isEmpty()) return
    Row(
        Modifier
            .fillMaxWidth()
            .padding(horizontal = Space.xl, vertical = Space.s),
        verticalAlignment = Alignment.Top
    ) {
        Box(
            Modifier
                .weight(1f)
                .surface2(RoundedCornerShape(8.dp))
                .horizontalScroll(rememberScrollState())
                .padding(Space.m)
        ) {
            SelectionContainer {
                Text(
                    text, color = ide.text, fontFamily = Mono,
                    fontSize = Type.monoSmall, lineHeight = Type.monoSmallLine
                )
            }
        }
        IconButton(onClick = { copy(text, what) }) {
            Icon(
                Icons.Filled.ContentCopy, contentDescription = "Copy $what",
                tint = ide.accent, modifier = Modifier.size(18.dp)
            )
        }
    }
}

@Composable
private fun CallLogList() {
    val ide = LocalIde.current
    val rows = McpRuntime.log
    if (rows.isEmpty()) {
        EmptyPanel(
            "Nothing has been called yet",
            "Every tool an assistant runs against this project appears here, newest first."
        )
        return
    }
    // A plain Column, not a LazyColumn: this sheet is already a scrolling
    // container, and a lazy list nested inside one measures against an infinite
    // height. The tail is what anybody reads anyway.
    val shown = minOf(rows.size, LOG_ROWS_SHOWN)
    Column(Modifier.fillMaxWidth()) {
        for (i in 0 until shown) {
            val row = rows[rows.size - 1 - i]
            Row(
                Modifier
                    .fillMaxWidth()
                    .padding(horizontal = Space.xl, vertical = Space.xs),
                verticalAlignment = Alignment.Top
            ) {
                Text(
                    time.format(Date(row.at)), color = ide.dim2,
                    fontSize = Type.monoSmall, lineHeight = Type.monoSmallLine, fontFamily = Mono
                )
                Spacer(Modifier.width(Space.m))
                Column(Modifier.weight(1f)) {
                    Text(
                        row.tool, color = if (row.ok) ide.text else ide.red,
                        fontSize = Type.monoSmall, lineHeight = Type.monoSmallLine,
                        fontFamily = Mono
                    )
                    if (row.detail.isNotEmpty()) {
                        Text(
                            row.detail, color = ide.dim2,
                            fontSize = Type.monoSmall, lineHeight = Type.monoSmallLine
                        )
                    }
                }
                if (row.ms > 0) {
                    Spacer(Modifier.width(Space.m))
                    Text(
                        "${row.ms} ms", color = ide.dim2,
                        fontSize = Type.monoSmall, lineHeight = Type.monoSmallLine,
                        fontFamily = Mono
                    )
                }
            }
        }
        if (rows.size > shown) {
            Text(
                "${rows.size - shown} earlier calls not shown",
                color = ide.dim2, fontSize = Type.caption, lineHeight = Type.captionLine,
                modifier = Modifier.padding(horizontal = Space.xl, vertical = Space.m)
            )
        }
    }
}

// ------------------------------------------------------------ config blocks --
// The exact text a person pastes. Kept here beside the values they carry so
// the sheet and docs/MCP.md cannot drift into saying different things.

/**
 * The literal text that mcp-remote expands from the environment: a dollar sign,
 * then AUTH in braces.
 *
 * It cannot be written inline in the block below. A Kotlin raw string still
 * interpolates a dollar sign and does not process backslash escapes, so the
 * only way to get a real one into a raw string is to interpolate a constant
 * holding it. This is an ordinary string literal, where a backslash before the
 * dollar is the documented escape for a literal dollar sign.
 */
private const val AUTH_VAR = "\${AUTH}"

private fun claudeCodeCommand(): String =
    "claude mcp add --transport http nocturne " + McpRuntime.url +
        " --header \"Authorization: Bearer " + McpRuntime.token + "\""

private fun claudeCodeJson(): String = """
{
  "mcpServers": {
    "nocturne": {
      "type": "http",
      "url": "${McpRuntime.url}",
      "headers": { "Authorization": "Bearer ${McpRuntime.token}" }
    }
  }
}
""".trim()

/**
 * Claude Desktop starts servers as local processes, so it gets here through
 * mcp-remote.
 *
 * `--allow-http` because mcp-remote refuses a plain-HTTP URL that is not
 * localhost, and `--transport http-only` so it does not first probe for the
 * deprecated SSE transport this server does not offer. The header goes through
 * an environment variable with no space in the argument: several clients fail
 * to quote an argument containing a space when they spawn npx, and the token
 * arrives mangled.
 */
private fun claudeDesktopJson(): String = """
{
  "mcpServers": {
    "nocturne": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote", "${McpRuntime.url}",
        "--allow-http", "--transport", "http-only",
        "--header", "Authorization:$AUTH_VAR"
      ],
      "env": { "AUTH": "Bearer ${McpRuntime.token}" }
    }
  }
}
""".trim()

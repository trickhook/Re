package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.DataObject
import androidx.compose.material.icons.filled.Extension
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Lock
import androidx.compose.material.icons.filled.Memory
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Shield
import androidx.compose.material.icons.filled.TextFields
import androidx.compose.material.icons.filled.TrendingUp
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material.icons.filled.OpenInFull
import androidx.compose.material.icons.filled.SaveAlt
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.vm.StudioViewModel

// ============================================================ AI assistant ==
@Composable
fun AiPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var showSettings by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "AI EXPLAIN",
                color = ide.text, fontSize = 12.sp,
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, fontFamily = Mono
            )
            Spacer(Modifier.weight(1f))
            TextButton(onClick = { showSettings = true }) { Text("Settings", color = ide.dim, fontSize = 11.sp) }
        }
        val d = vm.detail
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                if (d != null) "Context: ${d.displayName.ifEmpty { d.name }} (${d.asm.size} instr)"
                else "Select a function first",
                color = if (d != null) ide.cyan else ide.dim, fontSize = 11.sp, fontFamily = Mono,
                modifier = Modifier.weight(1f), maxLines = 1
            )
            Button(onClick = { vm.explainLocally() }, enabled = d != null && !vm.aiBusy) {
                Text("Explain (offline)", fontSize = 11.sp)
            }
            Spacer(Modifier.width(6.dp))
            Button(onClick = { vm.explainRemote() }, enabled = d != null && !vm.aiBusy) {
                Text("Ask LLM", fontSize = 11.sp)
            }
            if (vm.aiBusy) {
                Spacer(Modifier.width(6.dp))
                CircularProgressIndicator(color = ide.amber, modifier = Modifier.size(14.dp))
            }
        }

        val text = vm.aiExplanation
        if (text.isEmpty()) {
            Hint(
                "AI Explain analyzes the selected function: called APIs, string refs, loop structure, dangerous patterns (strcpy/system/dlopen), crypto constants.",
                "Offline = local heuristics. Ask LLM = OpenAI-compatible endpoint (set in Settings)."
            )
        } else {
            SelectionScroll(text)
        }
    }

    if (showSettings) {
        AlertDialog(
            onDismissRequest = { showSettings = false },
            containerColor = ide.panel,
            title = { Text("AI Settings (OpenAI-compatible)", color = ide.accent, fontSize = 14.sp) },
            text = {
                Column {
                    OutlinedTextField(
                        value = vm.aiEndpoint, onValueChange = { vm.aiEndpoint = it },
                        label = { Text("Endpoint URL") }, singleLine = true,
                        placeholder = { Text("https://api.openai.com/v1/chat/completions", fontSize = 10.sp) },
                        textStyle = TextStyle(fontSize = 11.sp, fontFamily = Mono, color = ide.text)
                    )
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = vm.aiKey, onValueChange = { vm.aiKey = it },
                        label = { Text("API key (stored locally only)") }, singleLine = true,
                        textStyle = TextStyle(fontSize = 11.sp, fontFamily = Mono, color = ide.text)
                    )
                    Spacer(Modifier.height(6.dp))
                    OutlinedTextField(
                        value = vm.aiModel, onValueChange = { vm.aiModel = it },
                        label = { Text("Model (e.g. gpt-4o-mini / deepseek-chat)") }, singleLine = true,
                        textStyle = TextStyle(fontSize = 11.sp, fontFamily = Mono, color = ide.text)
                    )
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "The key never leaves the device except in requests to the endpoint you configure. Works with OpenAI, DeepSeek, LM Studio (http://localhost:1234/...), Ollama etc.",
                        color = ide.dim, fontSize = 10.sp, lineHeight = 14.sp
                    )
                }
            },
            confirmButton = { TextButton(onClick = { showSettings = false }) { Text("OK", color = ide.accent) } }
        )
    }
}

@Composable
private fun SelectionScroll(text: String) {
    androidx.compose.foundation.text.selection.SelectionContainer {
        Text(
            text,
            color = androidx.compose.ui.graphics.Color.Unspecified,
            fontSize = 12.sp, lineHeight = 17.sp, fontFamily = Mono,
            modifier = Modifier
                .fillMaxSize()
                .verticalScroll(rememberScrollState())
                .horizontalScroll(rememberScrollState())
                .padding(12.dp)
        )
    }
}

// ========================================================== Plugins panel ==
@Composable
fun PluginsPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    val ctx = androidx.compose.ui.platform.LocalContext.current
    var showLog by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().padding(start = 16.dp, end = 16.dp, top = 16.dp, bottom = 4.dp),
            verticalAlignment = Alignment.Bottom
        ) {
            Text(
                "NOCTURNESCRIPT", color = ide.dim, fontSize = 10.sp,
                fontWeight = FontWeight.Medium, letterSpacing = 1.sp
            )
            Spacer(Modifier.width(8.dp))
            Text(
                "${vm.plugins.size} installed",
                color = ide.dim.copy(alpha = 0.6f), fontSize = 10.sp, fontFamily = Mono
            )
        }
        LazyColumn(
            Modifier.weight(1f).background(ide.bg),
            contentPadding = PaddingValues(start = 16.dp, end = 16.dp, top = 8.dp, bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(9.dp)
        ) {
            items(vm.plugins.size) { i ->
                val p = vm.plugins[i]
                val (icon, tint) = pluginIcon(p.id, ide)
                Column(
                    Modifier
                        .fillMaxWidth()
                        .border(1.dp, ide.border, RoundedCornerShape(13.dp))
                        .background(ide.panel, RoundedCornerShape(13.dp))
                        .padding(horizontal = 14.dp, vertical = 13.dp)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Box(
                            Modifier
                                .size(28.dp)
                                .background(tint.copy(alpha = 0.14f), RoundedCornerShape(8.dp)),
                            contentAlignment = Alignment.Center
                        ) {
                            Icon(icon, contentDescription = null, tint = tint,
                                modifier = Modifier.size(15.dp))
                        }
                        Spacer(Modifier.width(10.dp))
                        Column(Modifier.weight(1f)) {
                            Text(
                                p.name, color = ide.text, fontSize = 13.5.sp,
                                fontWeight = FontWeight.SemiBold
                            )
                            Text(
                                "v${p.version}",
                                color = ide.dim.copy(alpha = 0.7f), fontSize = 9.5.sp,
                                fontFamily = Mono
                            )
                        }
                        Box(
                            Modifier
                                .height(30.dp)
                                .background(
                                    if (vm.pluginRunning) ide.border
                                    else ide.accent.copy(alpha = 0.15f),
                                    RoundedCornerShape(9.dp)
                                )
                                .clickable(enabled = !vm.pluginRunning) { vm.runPlugin(ctx, p) }
                                .padding(horizontal = 15.dp),
                            contentAlignment = Alignment.Center
                        ) {
                            Text(
                                "Run",
                                color = if (vm.pluginRunning) ide.dim else ide.accent,
                                fontSize = 12.sp, fontWeight = FontWeight.SemiBold
                            )
                        }
                    }
                    if (p.description.isNotEmpty()) {
                        Spacer(Modifier.height(8.dp))
                        Text(
                            p.description, color = ide.dim, fontSize = 11.5.sp,
                            lineHeight = 16.sp
                        )
                    }
                }
            }
        }
        // A fixed 200dp slab used to eat the bottom of the list and clip the
        // log mid-line. The result is a one-line bar now; the whole log opens
        // full-screen, where it can be read, copied or saved.
        if (vm.pluginOutput.isNotEmpty()) {
            Row(
                Modifier
                    .fillMaxWidth()
                    .background(ide.panel)
                    .clickable { showLog = true }
                    .padding(horizontal = 16.dp, vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Box(
                    Modifier
                        .size(7.dp)
                        .background(if (vm.lastPluginOk) ide.violet else ide.red, CircleShape)
                )
                Spacer(Modifier.width(10.dp))
                Column(Modifier.weight(1f)) {
                    Text(
                        vm.lastPluginName.ifEmpty { "Plugin result" },
                        color = ide.text, fontSize = 12.5.sp, fontWeight = FontWeight.Medium
                    )
                    Text(
                        if (vm.lastPluginOk)
                            "${vm.pluginOutput.lineSequence().count()} lines · ${vm.lastPluginEffects} effects"
                        else "failed — tap to read the error",
                        color = ide.dim, fontSize = 10.sp, fontFamily = Mono
                    )
                }
                Icon(
                    Icons.Filled.OpenInFull, contentDescription = "Open full log",
                    tint = ide.accent, modifier = Modifier.size(17.dp)
                )
            }
        }
    }

    if (showLog) PluginLogSheet(vm) { showLog = false }
}

/** Full-height reader for a plugin run: scrollable, copyable, savable. */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun PluginLogSheet(vm: StudioViewModel, onDismiss: () -> Unit) {
    val ide = LocalIde.current
    val ctx = LocalContext.current
    val clip = LocalClipboardManager.current
    val save = rememberLauncherForActivityResult(
        ActivityResultContracts.CreateDocument("text/plain")
    ) { uri -> if (uri != null) vm.savePluginLog(ctx, uri) }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true),
        containerColor = ide.panel
    ) {
        Column(Modifier.fillMaxSize()) {
            Row(
                Modifier.fillMaxWidth().padding(start = 20.dp, end = 12.dp, bottom = 10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Column(Modifier.weight(1f)) {
                    Text(
                        vm.lastPluginName.ifEmpty { "Plugin result" },
                        color = ide.text, fontSize = 16.sp, fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        "${vm.pluginOutput.lineSequence().count()} lines · ${vm.lastPluginEffects} effects applied",
                        color = ide.dim, fontSize = 11.sp, fontFamily = Mono
                    )
                }
                Icon(
                    Icons.Filled.ContentCopy, contentDescription = "Copy log", tint = ide.dim,
                    modifier = Modifier
                        .size(34.dp)
                        .clickable {
                            clip.setText(AnnotatedString(vm.pluginOutput))
                            vm.log("OK", "Plugin log copied to the clipboard")
                        }
                        .padding(8.dp)
                )
                Icon(
                    Icons.Filled.SaveAlt, contentDescription = "Save log", tint = ide.accent,
                    modifier = Modifier
                        .size(34.dp)
                        .clickable { save.launch(vm.suggestedLogName()) }
                        .padding(8.dp)
                )
            }
            HorizontalDivider(color = ide.border)
            SelectionContainer(Modifier.weight(1f).fillMaxWidth()) {
                Text(
                    vm.pluginOutput,
                    color = ide.text, fontSize = 11.sp, fontFamily = Mono, lineHeight = 16.sp,
                    modifier = Modifier
                        .fillMaxSize()
                        .verticalScroll(rememberScrollState())
                        .horizontalScroll(rememberScrollState())
                        .padding(16.dp)
                )
            }
        }
    }
    }
}

/** Icon and tint per bundled plugin, falling back to a generic extension mark. */
private fun pluginIcon(id: String, ide: IdeColors): Pair<ImageVector, Color> = when (id) {
    "security-auditor"   -> Icons.Filled.Shield to ide.red
    "crypto-finder"      -> Icons.Filled.Lock to ide.amber
    "anti-debug-scanner" -> Icons.Filled.BugReport to ide.violet
    "jni-mapper"         -> Icons.Filled.Link to ide.cyan
    "xref-hotspots"      -> Icons.Filled.TrendingUp to ide.accent
    "attack-surface"     -> Icons.Filled.Public to ide.red
    "string-triage"      -> Icons.Filled.TextFields to ide.cyan
    "string-hunter"      -> Icons.Filled.Search to ide.cyan
    "arm-analyzer"       -> Icons.Filled.Memory to ide.violet
    "dex-helper"         -> Icons.Filled.DataObject to ide.amber
    else                 -> Icons.Filled.Extension to ide.dim
}

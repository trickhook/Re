package com.sakore.studio.ui

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
import com.sakore.studio.vm.StudioViewModel

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
            TextButton(onClick = { showSettings = true }) { Text("⚙ Settings", color = ide.dim, fontSize = 11.sp) }
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
                "Offline = local heuristics. Ask LLM = OpenAI-compatible endpoint (set in ⚙ Settings)."
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

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "PLUGINS (SakoScript)",
                color = ide.text, fontSize = 12.sp,
                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold, fontFamily = Mono
            )
            Spacer(Modifier.weight(1f))
            Text(
                "${vm.plugins.size} installed",
                color = ide.dim, fontSize = 11.sp, fontFamily = Mono
            )
        }
        LazyColumn(Modifier.weight(1f).background(ide.bg)) {
            items(vm.plugins.size) { i ->
                val p = vm.plugins[i]
                Column(
                    Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 10.dp, vertical = 6.dp)
                        .background(ide.panel)
                ) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Column(Modifier.weight(1f)) {
                            Text(
                                "${p.name} v${p.version}",
                                color = ide.accent, fontSize = 13.sp, fontFamily = Mono,
                                fontWeight = androidx.compose.ui.text.font.FontWeight.Bold
                            )
                            Text(
                                p.description.ifEmpty { "by ${p.author}" },
                                color = ide.dim, fontSize = 11.sp, maxLines = 2
                            )
                        }
                        Button(
                            onClick = { vm.runPlugin(ctx, p) },
                            enabled = !vm.pluginRunning
                        ) { Text("Run", fontSize = 11.sp) }
                    }
                }
            }
            item { Spacer(Modifier.height(20.dp)) }
        }
        if (vm.pluginOutput.isNotEmpty()) {
            Text(
                vm.pluginOutput,
                color = ide.text, fontSize = 11.sp, fontFamily = Mono, lineHeight = 15.sp,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(200.dp)
                    .background(ide.panel)
                    .verticalScroll(rememberScrollState())
                    .padding(8.dp)
            )
        }
    }
}

package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.trickhook.vm.StudioViewModel

// ========================================================= Call graph panel ==
@Composable
fun CallGraphPanel(vm: StudioViewModel) {
    val ide = LocalIde.current
    var focusMode by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier
                .fillMaxWidth()
                .background(ide.panel2)
                .padding(horizontal = 10.dp, vertical = 4.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                "CALL GRAPH",
                color = ide.text, fontSize = 12.sp, fontWeight = androidx.compose.ui.text.font.FontWeight.Bold,
                fontFamily = Mono
            )
            Spacer(Modifier.width(10.dp))
            Button(onClick = { focusMode = false; vm.loadCallGraph(0) }, enabled = !vm.callGraphBusy) {
                Text("Whole binary", fontSize = 11.sp)
            }
            Spacer(Modifier.width(6.dp))
            Button(onClick = { vm.selectedFunc?.let { focusMode = true; vm.loadCallGraph(it) } },
                enabled = vm.selectedFunc != null && !vm.callGraphBusy) {
                Text("This function", fontSize = 11.sp)
            }
            Spacer(Modifier.weight(1f))
            if (vm.callGraphBusy) CircularProgressIndicator(color = ide.accent, modifier = Modifier.width(16.dp).height(16.dp))
        }

        val g = vm.callGraph
        if (g == null || !g.ok) {
            Hint(
                "Load the call graph to see who calls whom — soo dejin callgraph-ka.",
                "Edges come from BL/CALL xref scan + PLT/GOT import resolution."
            )
        } else {
            val sel = vm.selectedFunc
            val focusName = g.funcs.firstOrNull { it.addr == sel }?.name
            // tree for selected function (like IDA's xrefs view)
            if (focusMode && focusName != null) {
                val callees = g.edges.filter { it.fromName == focusName }.distinctBy { it.toName }
                val callers = g.edges.filter { it.toName == focusName }.distinctBy { it.fromName }
                LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
                    item {
                        Text(
                            focusName,
                            color = ide.accent, fontSize = 13.sp, fontFamily = Mono,
                            modifier = Modifier.padding(10.dp)
                        )
                    }
                    item {
                        Text(
                            "calls (${callees.size}):",
                            color = ide.dim, fontSize = 11.sp, fontFamily = Mono,
                            modifier = Modifier.padding(horizontal = 10.dp)
                        )
                    }
                    items(callees.size) { i ->
                        val e = callees[i]
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable {
                                    val f = vm.meta?.functions?.firstOrNull { it.name == e.toName }
                                    if (f != null) vm.selectFunction(f.addr)
                                }
                                .padding(horizontal = 24.dp, vertical = 2.dp)
                        ) {
                            Text(" ├── ", color = ide.dim, fontSize = 12.sp, fontFamily = Mono)
                            Text(
                                e.toName, fontSize = 12.sp, fontFamily = Mono,
                                color = if (e.kind == "import") ide.amber else ide.cyan
                            )
                            Spacer(Modifier.weight(1f))
                            Text(e.kind, color = ide.dim, fontSize = 10.sp, fontFamily = Mono)
                        }
                    }
                    item {
                        Text(
                            "called by (${callers.size}):",
                            color = ide.dim, fontSize = 11.sp, fontFamily = Mono,
                            modifier = Modifier.padding(horizontal = 10.dp, vertical = 4.dp)
                        )
                    }
                    items(callers.size) { i ->
                        val e = callers[i]
                        Row(
                            Modifier
                                .fillMaxWidth()
                                .clickable {
                                    val f = vm.meta?.functions?.firstOrNull { it.name == e.fromName }
                                    if (f != null) vm.selectFunction(f.addr)
                                }
                                .padding(horizontal = 24.dp, vertical = 2.dp)
                        ) {
                            Text(" └── ", color = ide.dim, fontSize = 12.sp, fontFamily = Mono)
                            Text(e.fromName, color = ide.cyan, fontSize = 12.sp, fontFamily = Mono)
                        }
                    }
                    item { Spacer(Modifier.height(40.dp)) }
                }
            } else {
                // whole-binary edge list grouped by caller
                val grouped = g.edges.groupBy { it.fromName }.toSortedMap()
                LazyColumn(Modifier.fillMaxSize().background(ide.bg)) {
                    grouped.forEach { (caller, edges) ->
                        item(key = "h_$caller") {
                            Text(
                                "$caller (${edges.size} calls)",
                                color = ide.accent, fontSize = 12.sp, fontFamily = Mono,
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .background(ide.panel2)
                                    .padding(horizontal = 10.dp, vertical = 4.dp)
                            )
                        }
                        items(edges.size, key = { i -> "e_${caller}_$i" }) { i ->
                            val e = edges[i]
                            Row(
                                Modifier
                                    .fillMaxWidth()
                                    .clickable {
                                        val f = vm.meta?.functions?.firstOrNull { it.name == e.toName }
                                        if (f != null) vm.selectFunction(f.addr)
                                    }
                                    .padding(horizontal = 24.dp, vertical = 1.dp)
                            ) {
                                Text(" ├── ", color = ide.dim, fontSize = 11.5.sp, fontFamily = Mono)
                                Text(
                                    e.toName, fontSize = 11.5.sp, fontFamily = Mono,
                                    color = if (e.kind == "import") ide.amber else ide.cyan,
                                    maxLines = 1
                                )
                                Spacer(Modifier.weight(1f))
                                Text(
                                    if (e.kind == "import") "import" else hexFmt(e.to),
                                    color = ide.dim, fontSize = 10.sp, fontFamily = Mono
                                )
                            }
                        }
                    }
                    item { Spacer(Modifier.height(40.dp)) }
                }
            }
        }
    }
}

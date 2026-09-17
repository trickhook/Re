package com.trickhook.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.CallReceived
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Code
import androidx.compose.material.icons.filled.DriveFileRenameOutline
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.graphics.RectangleShape
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.trickhook.model.AnalysisMeta
import com.trickhook.model.CallEdge
import com.trickhook.model.DexMethodInfo
import com.trickhook.model.FoundStr
import com.trickhook.model.SmaliLine
import com.trickhook.model.SmaliMethod
import com.trickhook.vm.StudioViewModel

/**
 * The DEX browser — the Dalvik half of the studio.
 *
 * Two modes behind one toggle. CLASSES groups the method table by class and
 * lets you tap any method with a code item through to its smali; STRINGS
 * searches the whole DEX string pool the loader read (Engine::dexStrings),
 * which reaches far more than the general strings panel's first 3000. A method's
 * smali (Engine::dexSmali) opens in a detail view with a back arrow, and "who
 * invokes this method" is read straight off the call graph the engine already
 * built — the same source the function xref sheet uses — so the two never
 * disagree.
 *
 * Draws only from IdeColors + Common.kt: no new colours, Material icons only.
 */
@Composable
fun DexPanel(vm: StudioViewModel) {
    val meta = vm.meta
    if (meta == null || meta.format != "DEX") {
        Column(Modifier.fillMaxSize()) {
            PanelHeader("DEX", "Dalvik classes, methods and smali")
            EmptyPanel(
                "Not a DEX file",
                "Open a .dex — or an APK, whose classes.dex is extracted for you — to browse " +
                    "its classes, decode a method to smali, and search its string pool."
            )
        }
        return
    }

    // A selected method takes over the panel with its smali; back returns here.
    val target = vm.dexSmaliTarget
    if (target != null) { DexSmaliDetail(vm, target); return }

    Column(Modifier.fillMaxSize()) {
        DexHeader(vm, meta)
        when (vm.dexMode) {
            1 -> DexStringsView(vm)
            else -> DexClassesView(vm, meta)
        }
    }
}

// ------------------------------------------------------------------ header --
@Composable
private fun DexHeader(vm: StudioViewModel, meta: AnalysisMeta) {
    val ide = LocalIde.current
    val strings = vm.dexMode == 1
    val classesTotal = maxOf(meta.dexClassesTotal, meta.dexClasses.size)
    val methodsTotal = maxOf(meta.dexMethodsTotal, meta.dexMethods.size)
    Column(
        Modifier
            .fillMaxWidth()
            .surface2(RectangleShape)
    ) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = Space.m, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            DexModeChip("Classes", !strings) { vm.dexMode = 0 }
            Spacer(Modifier.width(Space.s))
            DexModeChip("Strings", strings) { vm.dexMode = 1 }
            Spacer(Modifier.weight(1f))
            Text(
                if (strings) "" else "$classesTotal classes · $methodsTotal methods",
                color = ide.dim2, fontSize = Type.caption, fontFamily = Mono, maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
        Row(
            Modifier.fillMaxWidth().padding(horizontal = Space.m, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            val query = if (strings) vm.dexStringQuery else vm.dexQuery
            OutlinedTextField(
                value = query,
                onValueChange = { if (strings) vm.dexStringQuery = it else vm.dexQuery = it },
                label = { Text(if (strings) "Search DEX strings" else "Search classes and methods") },
                singleLine = true,
                trailingIcon = {
                    if (query.isNotEmpty()) {
                        IconButton(onClick = { if (strings) vm.dexStringQuery = "" else vm.dexQuery = "" }) {
                            Icon(Icons.Filled.Close, contentDescription = "Clear the search", tint = ide.dim)
                        }
                    }
                },
                modifier = Modifier
                    .weight(1f)
                    .semantics { contentDescription = if (strings) "Search DEX strings" else "Search classes and methods" },
                textStyle = TextStyle(fontSize = Type.mono, fontFamily = Mono, color = ide.text)
            )
        }
    }
}

@Composable
private fun DexModeChip(label: String, selected: Boolean, onSelect: () -> Unit) {
    val ide = LocalIde.current
    val shape = RoundedCornerShape(6.dp)
    Text(
        label,
        color = if (selected) ide.accent else ide.dim2,
        fontSize = Type.caption, fontFamily = Mono,
        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
        maxLines = 1,
        modifier = Modifier
            .heightIn(min = 36.dp)
            .selectable(selected = selected, role = Role.Tab, onClick = onSelect)
            .then(
                if (selected) Modifier
                    .background(ide.accent.copy(alpha = 0.12f), shape)
                    .border(1.dp, ide.borderStrong, shape)
                else Modifier.surface1(shape)
            )
            .padding(horizontal = Space.l, vertical = Space.s)
    )
}

// ------------------------------------------------------------- classes view --
@Composable
private fun DexClassesView(vm: StudioViewModel, meta: AnalysisMeta) {
    val methods = meta.dexMethods
    val query = vm.dexQuery.trim()
    // Group the (loader-capped) method table by class, keeping first-encounter
    // order. Memoized on identity+size+query: AnalysisMeta's lists are data
    // classes, so a value key would deep-compare the whole table on each stroke.
    val groups: List<Pair<String, List<DexMethodInfo>>> =
        remember(System.identityHashCode(methods), methods.size, query) {
            val filtered = if (query.isEmpty()) methods
            else methods.filter {
                it.clazz.contains(query, true) || it.name.contains(query, true)
            }
            val map = LinkedHashMap<String, MutableList<DexMethodInfo>>()
            for (m in filtered) map.getOrPut(m.clazz) { mutableListOf() }.add(m)
            map.entries.map { it.key to it.value }
        }

    when {
        vm.busy && methods.isEmpty() -> SkeletonLines(14)
        methods.isEmpty() -> EmptyPanel(
            "No compiled methods",
            "The engine listed no methods with a code item in this DEX."
        )
        groups.isEmpty() -> EmptyPanel(
            "No class or method matches \"$query\"",
            "Nothing in the ${maxOf(meta.dexMethodsTotal, methods.size)} methods loaded contains that text."
        )
        else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
            groups.forEach { (clazz, ms) ->
                item(key = "cls:$clazz") { DexClassHeader(clazz, ms.size) }
                items(ms.size, key = { "m:$clazz:$it" }) { i -> DexMethodRow(vm, ms[i]) }
            }
        }
    }
}

@Composable
private fun DexClassHeader(clazz: String, count: Int) {
    val ide = LocalIde.current
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Spacer(Modifier.size(8.dp).background(ide.cyan, RoundedCornerShape(2.dp)))
        Spacer(Modifier.width(Space.s))
        Text(
            clazz, color = ide.text, fontSize = Type.label, fontFamily = Mono,
            fontWeight = FontWeight.Bold, modifier = Modifier.weight(1f),
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        Text("$count", color = ide.dim2, fontSize = Type.caption, fontFamily = Mono)
    }
}

@Composable
private fun DexMethodRow(vm: StudioViewModel, m: DexMethodInfo) {
    val ide = LocalIde.current
    val hasCode = m.codeOff != 0L
    // A DEX method is addressed by its codeOff — the same key the call graph and
    // smali detail use — so a rename recorded against that address (from here, an
    // MCP tool or a plugin) shows the user's name, keeping the signature.
    val methodName = vm.renames["0x%08X".format(m.codeOff)] ?: m.name
    Row(
        Modifier
            .fillMaxWidth()
            .then(
                if (hasCode) Modifier.clickable(role = Role.Button, onClickLabel = "Show smali") {
                    vm.openDexMethod(m.codeOff)
                } else Modifier
            )
            .heightIn(min = 44.dp)
            .padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RowIcon(Icons.Filled.Code, if (hasCode) ide.violet else ide.dim2, 14.dp)
        Column(Modifier.weight(1f)) {
            Text(
                methodName + m.proto,
                color = if (hasCode) ide.text else ide.dim,
                fontSize = Type.mono, lineHeight = Type.monoLine, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis
            )
            if (!hasCode) {
                Text(
                    "no code (abstract, native or interface)",
                    color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
                )
            }
        }
    }
}

// ------------------------------------------------------------- strings view --
@Composable
private fun DexStringsView(vm: StudioViewModel) {
    val ide = LocalIde.current
    // Debounced: a page comes from the engine, so fire once the typing settles
    // rather than on every keystroke. The effect is keyed on the query, so a new
    // stroke cancels the pending load.
    LaunchedEffect(vm.dexStringQuery) {
        kotlinx.coroutines.delay(180L)
        vm.loadDexStrings(vm.dexStringQuery)
    }
    val page = vm.dexStrings
    val busy = vm.dexStringsBusy
    when {
        busy && page == null -> SkeletonLines(12)
        page == null -> EmptyPanel(
            "Searching the DEX string pool…",
            "Every string_ids entry the loader read is in reach here, not only the first 3000 " +
                "the general strings scan carries."
        )
        page.rows.isEmpty() -> EmptyPanel(
            if (vm.dexStringQuery.isBlank()) "No strings" else "No string matches \"${vm.dexStringQuery}\"",
            "Searched ${page.poolRead} of ${page.poolTotal} string_ids in the pool."
        )
        else -> Column(Modifier.fillMaxSize()) {
            val more = page.total > page.rows.size
            TruncationNote(
                (if (more) "Showing ${page.rows.size} of ${page.total} matches" else "${page.total} matches") +
                    " across ${page.poolRead} of ${page.poolTotal} string_ids" +
                    (if (more) " — refine the search to narrow it." else "."),
                Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.s)
            )
            LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
                items(page.rows.size, key = { page.rows[it].addr }) { i -> DexStringRow(page.rows[i]) }
            }
        }
    }
}

@Composable
private fun DexStringRow(s: FoundStr) {
    val ide = LocalIde.current
    Row(
        Modifier.fillMaxWidth().heightIn(min = 40.dp).padding(horizontal = Space.l, vertical = Space.s),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Column(Modifier.weight(1f)) {
            Text(
                s.value, color = ide.text, fontSize = Type.mono, lineHeight = Type.monoLine,
                fontFamily = Mono, maxLines = 2, overflow = TextOverflow.Ellipsis
            )
            Text(
                "string index ${s.addr}", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono
            )
        }
    }
}

// -------------------------------------------------------------- smali detail --
@Composable
private fun DexSmaliDetail(vm: StudioViewModel, target: Long) {
    val ide = LocalIde.current
    val s = vm.dexSmali
    val busy = vm.dexSmaliBusy
    // The address annotate is aimed at: the method (target/codeOff) from the
    // header button, or one instruction (its off) from a tapped smali line. This
    // reuses the Assembly panel's AnnotateDialog verbatim — one rename/comment
    // mechanism, so a DEX-only binary can still be annotated where it has no
    // native Assembly view. Keyed on `target` so moving methods resets it.
    var annotateAddr by remember(target) { mutableStateOf<Long?>(null) }
    val methodComment = vm.comments["0x%08X".format(target)]
    Column(Modifier.fillMaxSize()) {
        Row(
            Modifier.fillMaxWidth().surface2(RectangleShape).padding(horizontal = Space.s, vertical = Space.s),
            verticalAlignment = Alignment.CenterVertically
        ) {
            IconButton(onClick = { vm.closeDexMethod() }) {
                Icon(
                    Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back to the class list",
                    tint = ide.accent, modifier = Modifier.size(18.dp)
                )
            }
            Column(Modifier.weight(1f)) {
                Text(
                    vm.renames["0x%08X".format(target)]
                        ?: (s?.let { it.classShort + "." + it.method } ?: hexFmt(target)),
                    color = ide.accent, fontSize = Type.section, fontFamily = Mono,
                    fontWeight = FontWeight.Bold, maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                if (s != null) {
                    Text(
                        s.proto + " · " + s.clazz,
                        color = ide.dim2, fontSize = Type.caption, fontFamily = Mono,
                        maxLines = 1, overflow = TextOverflow.Ellipsis
                    )
                }
                // A user comment on the method address shows here, in the accent
                // tint, so a comment set on this method in any view surfaces too.
                if (methodComment != null) {
                    Text(
                        "; $methodComment", color = ide.accent, fontSize = Type.caption,
                        lineHeight = Type.captionLine, fontFamily = Mono,
                        maxLines = 2, overflow = TextOverflow.Ellipsis
                    )
                }
            }
            IconButton(onClick = { annotateAddr = target }) {
                Icon(
                    Icons.Filled.DriveFileRenameOutline,
                    contentDescription = "Rename or comment this method",
                    tint = ide.accent, modifier = Modifier.size(18.dp)
                )
            }
        }
        when {
            busy && s == null -> SkeletonLines(12)
            s == null -> EmptyPanel(
                "Could not decode this method",
                "The engine returned no smali for this code offset."
            )
            else -> LazyColumn(Modifier.fillMaxSize(), contentPadding = bottomInset(Space.l)) {
                item(key = "meta") { DexMethodMeta(s) }
                item(key = "callers") { DexCallers(vm, target) }
                items(s.lines.size, key = { "l:${s.lines[it].unit}" }) { i ->
                    val ln = s.lines[i]
                    SmaliRow(
                        ln,
                        userComment = vm.comments["0x%08X".format(ln.off)],
                        onClick = { annotateAddr = ln.off }
                    )
                }
                if (s.truncated) item(key = "trunc") {
                    TruncationNote(
                        "The decode stopped early — this listing is not the whole method.",
                        Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m)
                    )
                }
            }
        }
    }

    // The Assembly panel's dialog, reused. When the target is the method itself
    // its name seeds the rename field; a tapped instruction passes an empty name
    // so only its comment/bookmark are offered — no second mechanism is invented.
    annotateAddr?.let { addr ->
        AnnotateDialog(
            vm = vm,
            addr = addr,
            funcName = if (addr == target)
                (vm.renames["0x%08X".format(target)] ?: s?.let { it.classShort + "." + it.method } ?: hexFmt(target))
            else "",
            onDismiss = { annotateAddr = null }
        )
    }
}

@Composable
private fun DexMethodMeta(s: SmaliMethod) {
    val ide = LocalIde.current
    Row(
        Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Text(
            "registers ${s.registers} · ins ${s.ins} · outs ${s.outs} · tries ${s.tries}",
            color = ide.dim, fontSize = Type.monoSmall, fontFamily = Mono, modifier = Modifier.weight(1f),
            maxLines = 1, overflow = TextOverflow.Ellipsis
        )
        Text(
            "${s.lines.size} instr · ${s.insnBytes} B",
            color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono, maxLines = 1
        )
    }
}

// Who invokes this method — straight from the call graph the engine built at
// analysis time (buildDexFuncsAndCalls), the same index the function xref sheet
// reads. No new scan; a tap follows the caller into its own smali.
@Composable
private fun DexCallers(vm: StudioViewModel, target: Long) {
    val ide = LocalIde.current
    val callers: List<CallEdge> = vm.callersOf(target)
    if (callers.isEmpty()) return
    Column(Modifier.fillMaxWidth()) {
        Row(
            Modifier.fillMaxWidth().padding(horizontal = Space.l, vertical = Space.m),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(Icons.Filled.CallReceived, contentDescription = null, tint = ide.violet, modifier = Modifier.size(14.dp))
            Spacer(Modifier.width(Space.s))
            Text(
                "Invoked by ${callers.size}", color = ide.text, fontSize = Type.label,
                fontFamily = Mono, fontWeight = FontWeight.Bold
            )
        }
        callers.take(20).forEach { e ->
            val owner = vm.functionAt(e.from)
            // A known caller resolves through the overlay helper (renames first);
            // an unknown one still consults the rename overlay by address before
            // falling back to the engine's raw name.
            val label = owner?.let { vm.effectiveFuncName(it.addr) }
                ?: vm.renames["0x%08X".format(e.from)]
                ?: e.fromName.ifEmpty { hexFmt(e.from) }
            Row(
                Modifier
                    .fillMaxWidth()
                    .clickable(role = Role.Button, onClickLabel = "Show this caller's smali") {
                        vm.openDexMethod(e.from)
                    }
                    .heightIn(min = 40.dp)
                    .padding(horizontal = Space.xl, vertical = Space.s),
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    label, color = ide.text, fontSize = Type.monoSmall, fontFamily = Mono,
                    modifier = Modifier.weight(1f), maxLines = 1, overflow = TextOverflow.Ellipsis
                )
                if (e.sites > 1) {
                    Text("${e.sites}x", color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono)
                }
            }
        }
        Spacer(Modifier.height(Space.s))
    }
}

@Composable
private fun SmaliRow(l: SmaliLine, userComment: String? = null, onClick: (() -> Unit)? = null) {
    val ide = LocalIde.current
    Column(
        Modifier
            .fillMaxWidth()
            .then(
                if (onClick != null)
                    Modifier.clickable(role = Role.Button, onClickLabel = "Annotate this instruction", onClick = onClick)
                else Modifier
            )
            .padding(horizontal = Space.l, vertical = Space.xs)
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                hexFmt(l.off), color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, modifier = Modifier.widthIn(min = 72.dp)
            )
            Spacer(Modifier.width(Space.m))
            Text(l.mnem, color = mnemonicColor(l.mnem, ide), fontSize = Type.mono, fontFamily = Mono, maxLines = 1)
            if (l.ops.isNotEmpty()) {
                Spacer(Modifier.width(Space.m))
                Text(
                    l.ops, color = ide.text, fontSize = Type.mono, lineHeight = Type.monoLine,
                    fontFamily = Mono, modifier = Modifier.weight(1f), maxLines = 2,
                    overflow = TextOverflow.Ellipsis
                )
            }
        }
        // The engine's auto-comment (pool tag or branch target) stays dim.
        if (l.comment.isNotEmpty()) {
            Text(
                l.comment, color = ide.dim2, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 1, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 84.dp)
            )
        }
        // The user's own comment rides its own accent line — never merged into the
        // auto-comment — so a comment set in any view reads distinctly here.
        if (userComment != null) {
            Text(
                "; $userComment", color = ide.accent, fontSize = Type.monoSmall, fontFamily = Mono,
                maxLines = 2, overflow = TextOverflow.Ellipsis,
                modifier = Modifier.padding(start = 84.dp)
            )
        }
    }
}

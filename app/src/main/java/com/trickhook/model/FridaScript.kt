package com.trickhook.model

/**
 * Nocturne to Frida.
 *
 * Frida is the dynamic-instrumentation tool the rest of this app's static
 * analysis pairs with: where Nocturne reads a function cold, Frida watches the
 * same function run on a live device. It cannot be embedded here and nothing in
 * this file tries to. What crosses is a plain-text JavaScript the user runs in
 * their own Frida against their own device, exactly as the IDA export crosses a
 * script the user runs in their own IDA. Everything below writes text.
 *
 * The generator turns the function(s) picked in the analysis into a script that
 *
 *  - resolves the library's base at runtime, waiting for it if it is not loaded;
 *  - hooks each target with Interceptor.attach, logging its arguments and its
 *    return value, with a helper to hexdump a pointer argument;
 *  - carries an OFF-by-default patch mode that forces a return value, the live
 *    equivalent of flipping a branch, marked so a trace never alters behaviour
 *    by accident.
 *
 * The hard part is the addresses, and it is the same problem [IdaScript] solved:
 * see [addressNote] and the ADDRESSES block every script carries.
 */

// ============================================================== what goes out ==

/**
 * One function to hook.
 *
 * [addr] is the address Nocturne shows -- for an ELF that is a virtual address
 * in the image's own address space (see [FridaExport.base]). [name] is what the
 * hook is labelled with AND, for an [exported] function, the dynamic-symbol name
 * handed to Module.getExportByName; [engineName] is the analysis's own display
 * name, carried into the row comment when it differs.
 */
data class FridaTarget(
    val addr: Long,
    val name: String,
    val engineName: String?,
    val exported: Boolean,
    val size: Long
)

/**
 * Everything one generated script says.
 *
 * [base] and [fileOffsets] are the whole correctness question, decided exactly
 * as [IdaExport] decides it:
 *
 *  - ELF: [addr] on each target is a virtual address in the image's own address
 *    space and [base] is the lowest LOAD vaddr (0 for a PIE .so). Frida loads
 *    the library at a base the loader picks, so the runtime address of a target
 *    is `moduleBase + (addr - base)`. For a PIE .so that is `moduleBase + addr`.
 *  - PE: the engine already folded in the image base, so [addr] is virtual and
 *    [base] is that image base; `addr - base` is the RVA, and the same
 *    `moduleBase + (addr - base)` holds. PE under Frida on Android is exotic.
 *  - DEX, Mach-O, raw: [addr] is a FILE OFFSET ([fileOffsets] is true). Frida's
 *    Interceptor hooks loaded native code by address, so a file offset will not
 *    land; the script is still written, with a loud warning and a runtime range
 *    check, because refusing to emit anything is less useful than saying why.
 *
 * [packageName] is the target app id when an APK is open, else null and the run
 * line carries a placeholder. [exportsTotal] is how many exports existed before
 * [targets] was capped, so the header can say "showing N of M".
 */
data class FridaExport(
    val binaryName: String,
    /** The name Frida loads the library under; the file name, or the DT_SONAME. */
    val moduleName: String,
    val format: String,
    val arch: String,
    val base: Long,
    val fileOffsets: Boolean,
    val packageName: String?,
    /** How many argument slots the script logs by default. */
    val argCount: Int,
    val targets: List<FridaTarget>,
    /** "one" for the single-function money path, "exports" for the export set. */
    val mode: String,
    /** Total exports available before the cap, for the "exports" mode header. */
    val exportsTotal: Int,
    /** The file name the run line suggests, for `-l <name>`. */
    val scriptName: String,
    /** Free-text stamp for the header; the caller formats it. */
    val stamp: String
) {
    val total: Int get() = targets.size
}

/** How many exports one "hook the exports" script is bounded to. */
const val FRIDA_EXPORTS_CAP = 200

// =================================================================== escaping ==

/**
 * [s] as a JavaScript string literal, ASCII only and on one line.
 *
 * ASCII only for the same reason [pyLiteral] is: the file leaves the phone by
 * whatever route the user has, and a mangled byte in a symbol name should never
 * be able to break the script. A surrogate PAIR is emitted as its two \\u units,
 * which JavaScript rejoins into the original character; a LONE surrogate is half
 * a character and becomes U+FFFD.
 */
fun jsLiteral(s: String): String {
    val sb = StringBuilder(s.length + 2)
    sb.append('"')
    var i = 0
    while (i < s.length) {
        val c = s[i]
        val code = c.code
        when {
            c == '\\' -> sb.append("\\\\")
            c == '"' -> sb.append("\\\"")
            c == '\n' -> sb.append("\\n")
            c == '\r' -> sb.append("\\r")
            c == '\t' -> sb.append("\\t")
            code in 0x20..0x7E -> sb.append(c)
            c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> {
                sb.append("\\u").append("%04X".format(code))
                sb.append("\\u").append("%04X".format(s[i + 1].code))
                i++
            }
            code in 0xD800..0xDFFF -> sb.append("\\uFFFD")
            else -> sb.append("\\u").append("%04X".format(code))
        }
        i++
    }
    sb.append('"')
    return sb.toString()
}

// ================================================================ generators ==

private fun formatLabel(x: FridaExport): String =
    if (x.arch.isBlank() || x.arch == "-") x.format else x.format + " " + x.arch

/** The offset from the module base a target hooks at: (vaddr - preferred base). */
private fun runtimeOffset(x: FridaExport, t: FridaTarget): Long = t.addr - x.base

private fun addressNote(x: FridaExport): List<String> =
    if (x.fileOffsets) listOf(
        "WARNING: Nocturne read this file as " + x.format + ", so the addresses below are",
        "FILE OFFSETS, not runtime addresses. Frida's Interceptor hooks loaded NATIVE",
        "code by address, and a file offset will not land there. For DEX / Java code,",
        "hook with Java.perform and Java.use instead. This script is generated anyway",
        "so nothing is hidden, but its offsets are very unlikely to be correct and the",
        "runtime range check below will say so for each one."
    ) else listOf(
        "Nocturne read this file as " + x.format + ", so the addresses it shows are",
        "virtual addresses in the image's own address space, based at " + hexAddr(x.base) + ".",
        "Frida hooks at runtime, where the loader places the library at a base of its",
        "own choosing, so each hook is computed as:",
        "    Module base of " + asciiComment(x.moduleName, 50) + "  +  (Nocturne address - " + hexAddr(x.base) + ")",
        "For a position-independent .so the preferred base is 0, so that offset is",
        "exactly the address Nocturne shows. The offsets are precomputed in TARGETS.",
        "An exported function is resolved by name first, which survives the loader's",
        "base choice, and only falls back to base+offset when the lookup fails."
    )

private fun runLines(x: FridaExport): List<String> {
    val pkg = x.packageName
    val shown = pkg ?: "com.example.app"
    val out = ArrayList<String>()
    out.add("Run it (Frida on your computer, device on USB with frida-server running):")
    out.add("  spawn the app:   frida -U -f " + shown + " -l " + x.scriptName + " --no-pause")
    out.add("  attach to it:    frida -U -n " + shown + " -l " + x.scriptName)
    if (pkg == null) {
        out.add("  Replace " + shown + " with the target package - Nocturne had no APK open")
        out.add("  to read it from.")
    } else {
        out.add("  (package read from the opened APK's manifest)")
    }
    return out
}

private fun whatItDoes(x: FridaExport): List<String> {
    val out = ArrayList<String>()
    if (x.mode == "exports") {
        val showing = x.targets.size
        val line = if (x.exportsTotal > showing)
            "Hooks " + showing + " of " + x.exportsTotal + " exported symbols (capped at " +
                FRIDA_EXPORTS_CAP + " - hooking thousands floods the log and slows the target)"
        else
            "Hooks " + showing + " exported symbol" + (if (showing == 1) "" else "s")
        out.add(line + ", logging each call's arguments and return value.")
    } else {
        val t = x.targets.firstOrNull()
        val nm = if (t == null) "the selected function" else asciiComment(t.name, 60)
        out.add("Traces " + nm + ": logs each call's arguments and return value, with a")
        out.add("hexdump helper for a pointer argument and an OFF-by-default patch mode.")
    }
    return out
}

private fun headerLines(x: FridaExport): List<String> {
    val out = ArrayList<String>()
    out.add("Nocturne to Frida")
    out.add(
        asciiComment(x.moduleName, 60) + " - " + formatLabel(x) + " - " +
            (if (x.mode == "exports") "hook exports" else "trace 1 function")
    )
    out.add("generated by Nocturne " + asciiComment(x.stamp, 40))
    out.add("")
    for (l in whatItDoes(x)) out.add(l)
    out.add("")
    for (l in runLines(x)) out.add(l)
    out.add("")
    out.add("ADDRESSES")
    for (l in addressNote(x)) out.add("  " + l)
    out.add("")
    out.add("PATCH MODE is off. Set PATCH_RETURN = true near the top to force a return")
    out.add("value - the live equivalent of flipping a branch. A plain trace never")
    out.add("changes what the program does; the patch does, on purpose, and says so.")
    return out
}

/** `was check_licence`, or null when the row comment has nothing to add. */
private fun rowNote(t: FridaTarget): String? {
    val engine = t.engineName?.takeIf { it.isNotBlank() && it != t.name }
    return if (engine == null) null else "was " + asciiComment(engine, 60)
}

/** How wide a TARGETS row is padded before its trailing comment. */
private const val ROW_PAD = 60

/**
 * The script: a header, the switches the user may edit, the targets, and then
 * the fixed engine that resolves the library and installs the hooks.
 */
fun fridaScript(x: FridaExport): String {
    val sb = StringBuilder(4096)
    for (l in headerLines(x)) sb.appendLine(("// " + l).trimEnd())
    sb.appendLine()
    sb.appendLine("'use strict';")
    sb.appendLine()
    sb.appendLine("// ---- switches you may edit -------------------------------------------------")
    sb.appendLine("var MODULE = " + jsLiteral(x.moduleName) + ";        // the library Frida looks up")
    sb.appendLine("var FORMAT = " + jsLiteral(formatLabel(x)) + ";")
    sb.appendLine("var ARG_COUNT = " + argCount(x) + ";              // how many argument slots to log")
    sb.appendLine("var HEXDUMP_ARG = 0;             // which argument to hexdump on entry")
    sb.appendLine("var HEXDUMP_BYTES = 0;          // bytes to hexdump (0 = off; only if that arg is a pointer)")
    sb.appendLine("var WAIT_MS = 10000;           // how long to wait for the library to load")
    sb.appendLine("var POLL_MS = 50;              // how often to re-check while waiting")
    sb.appendLine()
    sb.appendLine("// PATCH MODE - OFF by default. When on, onLeave forces the return value of")
    sb.appendLine("// PATCH_TARGET to PATCH_VALUE. This CHANGES the program's behaviour.")
    sb.appendLine("var PATCH_RETURN = false;")
    sb.appendLine("var PATCH_TARGET = " + jsLiteral(patchTarget(x)) + ";")
    sb.appendLine("var PATCH_VALUE = 0x1;          // value written into the return register")
    sb.appendLine()
    sb.appendLine("// name:     label logged, and the export symbol for an exported function")
    sb.appendLine("// offset:   runtime offset from the module base = (Nocturne vaddr - " + hexAddr(x.base) + ")")
    sb.appendLine("// exported: true = resolve by name first, fall back to base+offset")
    sb.appendLine("var TARGETS = [")
    for (t in x.targets) {
        val off = runtimeOffset(x, t)
        val row = "  { name: " + jsLiteral(t.name) + ", offset: " + hexAddr(off) +
            ", exported: " + t.exported + ", size: " + t.size + " },"
        val bits = ArrayList<String>()
        bits.add("vaddr " + hexAddr(t.addr))
        rowNote(t)?.let { bits.add(it) }
        val comment = bits.joinToString("; ")
        sb.appendLine(if (comment.isEmpty()) row else row.padEnd(ROW_PAD) + "  // " + comment)
    }
    sb.appendLine("];")
    sb.appendLine()
    sb.append(JS_ENGINE)
    return sb.toString()
}

/** At least one argument slot, and a sane cap so the log is readable. */
private fun argCount(x: FridaExport): Int = x.argCount.coerceIn(0, 12)

/** The function the patch defaults to: the single target, or blank for a set. */
private fun patchTarget(x: FridaExport): String =
    if (x.mode == "exports") "" else (x.targets.firstOrNull()?.name ?: "")

// ================================================================== template ==
// The fixed half of the script: the same in every export, so it lives here as
// text rather than being built line by line -- what runs on the device is
// exactly what is written here. Kept to plain ASCII, with no dollar signs and
// no triple quotes, so a raw Kotlin string holds it verbatim.

private val JS_ENGINE = """
// ---- engine ---------------------------------------------------------------
// Everything below is fixed: it is the same in every script Nocturne writes.

function _log(s) {
  console.log(s);
}

// Log the first ARG_COUNT argument slots, each as a raw pointer and, where it
// reads as one, a signed 32-bit int. Frida does not know a function's arity, so
// this reads the platform's argument registers whether or not they are real.
function _logArgs(name, args) {
  var parts = [];
  for (var i = 0; i < ARG_COUNT; i++) {
    var p = args[i];
    var line = 'a' + i + '=' + p;
    try { line = line + ' (' + p.toInt32() + ')'; } catch (e) {}
    parts.push(line);
  }
  _log('[>] ' + name + '(' + parts.join(', ') + ')');
}

// Hexdump one argument, if asked and if it is a readable pointer. A small int
// masquerading as a pointer throws inside hexdump; that is caught, not fatal.
function _dump(args) {
  if (HEXDUMP_BYTES <= 0) return;
  try {
    var p = args[HEXDUMP_ARG];
    if (p.isNull()) return;
    _log(hexdump(p, { length: HEXDUMP_BYTES, ansi: false }));
  } catch (e) {
    _log('[!] hexdump of a' + HEXDUMP_ARG + ' failed: ' + e);
  }
}

// The runtime address of a target: by export name first (survives the loader's
// base choice), else the module base plus the precomputed offset.
function _resolve(mod, t) {
  if (t.exported) {
    try {
      var byName = Module.getExportByName(MODULE, t.name);
      if (byName !== null && !byName.isNull()) return byName;
    } catch (e) {}
  }
  return mod.base.add(t.offset);
}

// Is an address inside this module's mapping? A base+offset that lands outside
// almost always means the address was a file offset, not a runtime address.
function _inRange(mod, addr) {
  try {
    var end = mod.base.add(mod.size);
    return addr.compare(mod.base) >= 0 && addr.compare(end) < 0;
  } catch (e) {
    return true;
  }
}

function _hook(mod, t) {
  var addr = _resolve(mod, t);
  if (!_inRange(mod, addr)) {
    _log('[!] ' + t.name + ' at ' + addr + ' is outside ' + MODULE + ' [' + mod.base +
         ' +0x' + mod.size.toString(16) + '] - not hooking. If Nocturne read this file as ' +
         FORMAT + ', its addresses may be file offsets rather than runtime addresses.');
    return false;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this._name = t.name;
      _logArgs(t.name, args);
      _dump(args);
    },
    onLeave: function (retval) {
      _log('[<] ' + t.name + ' = ' + retval);
      if (PATCH_RETURN && t.name === PATCH_TARGET) {
        var before = '' + retval;
        retval.replace(ptr(PATCH_VALUE));
        _log('    [PATCH] ' + t.name + ' return forced ' + before + ' -> ' + ptr(PATCH_VALUE));
      }
    }
  });
  _log('[+] hooked ' + t.name + ' at ' + addr +
       (t.exported ? ' (export)' : ' (base+0x' + t.offset.toString(16) + ')'));
  return true;
}

function _install(mod) {
  _log('[*] ' + MODULE + ' base ' + mod.base + ' size 0x' + mod.size.toString(16) +
       ' - installing ' + TARGETS.length + ' hook(s)');
  var n = 0;
  for (var i = 0; i < TARGETS.length; i++) {
    if (_hook(mod, TARGETS[i])) n++;
  }
  _log('[*] ' + n + ' of ' + TARGETS.length + ' hook(s) installed');
  if (PATCH_RETURN) {
    _log('[!] PATCH MODE IS ON: ' + PATCH_TARGET + ' will always return ' + ptr(PATCH_VALUE) +
         '. This changes what the program does.');
  }
}

// The library may not be loaded when the script starts (a fresh spawn), so poll
// for it up to WAIT_MS rather than throwing. Process.findModuleByName returns
// null while it is absent, so nothing here raises on a not-yet-loaded library.
(function _main() {
  var mod = Process.findModuleByName(MODULE);
  if (mod !== null) {
    _install(mod);
    return;
  }
  _log('[*] waiting up to ' + WAIT_MS + 'ms for ' + MODULE + ' to load...');
  var waited = 0;
  var timer = setInterval(function () {
    var m = Process.findModuleByName(MODULE);
    if (m !== null) {
      clearInterval(timer);
      _install(m);
      return;
    }
    waited += POLL_MS;
    if (waited >= WAIT_MS) {
      clearInterval(timer);
      _log('[!] ' + MODULE + ' never loaded (waited ' + waited + 'ms). Check the module ' +
           'name above, or hook android_dlopen_ext to catch a later load.');
    }
  }, POLL_MS);
})();
""".trimStart('\n')

package com.trickhook.model

/**
 * Nocturne to IDA Pro, and back.
 *
 * IDA cannot be embedded here and nothing in this file tries to: it is
 * proprietary, x86-64-only and its decompiler has no public source. What IS
 * public and documented is IDA's scripting API — IDAPython and the older IDC —
 * so the work a phone session produced can be handed to a desk session as a
 * script the user runs inside their own licensed copy. Everything below writes
 * or reads plain text. No Hex-Rays code, no licence check, nothing decompiled
 * by anyone but Nocturne's own engine.
 *
 * Two directions:
 *
 *  - out: [idaPythonScript] and [idaIdcScript] turn the renames, comments and
 *    bookmarks in ProjectDb into a script that applies them to an IDA database.
 *  - in:  [parseIdcAnnotations] reads IDA's own "Dump database to IDC file"
 *    output back, so names that were typed at the desk land in the project.
 *
 * The hard part is not the syntax, it is the addresses; see [IdaExport.fileOffsets]
 * and the ADDRESSES block each script carries.
 */

// ============================================================== what goes out ==

/** A function the user renamed. [engineName] is what Nocturne's analysis called it. */
data class IdaNameRow(val addr: Long, val name: String, val engineName: String?)

/** A comment the user wrote, at any address — a function start or an instruction. */
data class IdaCommentRow(val addr: Long, val text: String)

/** A bookmark: an address the user gave a label to. */
data class IdaMarkRow(val addr: Long, val label: String)

/**
 * Everything one exported script says.
 *
 * [base] and [fileOffsets] together say what the addresses MEAN, which is the
 * whole correctness question:
 *
 *  - ELF: the engine reports virtual addresses in the image's own address
 *    space and `meta.base` is the lowest LOAD vaddr (0 for a PIE .so).
 *  - PE: the engine has already added the image base, so the addresses are
 *    virtual and `meta.base` is that image base.
 *  - DEX and raw: the addresses are FILE OFFSETS — a DEX "function" is a
 *    code_item offset — and no loader has to agree with that, so
 *    [fileOffsets] is true and the script checks before it writes anything.
 */
data class IdaExport(
    val binaryName: String,
    val format: String,
    val arch: String,
    val base: Long,
    val fileOffsets: Boolean,
    val names: List<IdaNameRow>,
    val comments: List<IdaCommentRow>,
    val marks: List<IdaMarkRow>,
    val notes: List<String>,
    /** Free-text stamp for the header; the caller formats it. */
    val stamp: String
) {
    val total: Int get() = names.size + comments.size + marks.size
}

// =================================================================== escaping ==
// Names and comments are whatever the user typed on a phone keyboard, and they
// are about to become string literals in two different languages. Everything
// here is written so that the worst input still produces a file that parses.

/**
 * IDA's default set of name characters. The dollar is spelt \u0024 because a
 * literal one in Kotlin source is the trap the audit's sixth rule is about.
 */
private fun nameCharOk(c: Char): Boolean =
    c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' ||
        c == '_' || c == '\u0024' || c == '?' || c == '@'

/** Well under IDA's MAXNAMELEN, and long enough that nothing real is cut. */
private const val IDA_MAX_NAME = 200

/**
 * A user's name, made safe for IDA. Anything outside IDA's name characters
 * becomes an underscore and a leading digit gets one in front; the caller
 * reports the original beside the row when this changes it, so the mapping is
 * never silent.
 */
fun idaIdentifier(raw: String): String {
    val sb = StringBuilder(raw.length)
    for (c in raw) sb.append(if (nameCharOk(c)) c else '_')
    var s = sb.toString()
    if (s.isEmpty()) s = "_"
    if (s[0] in '0'..'9') s = "_$s"
    if (s.length > IDA_MAX_NAME) s = s.substring(0, IDA_MAX_NAME)
    return s
}

/**
 * [s] as a Python string literal, ASCII only and on one line.
 *
 * ASCII only because the file is going to leave the phone by whatever route
 * the user has — a chat app, a USB cable, a paste buffer — and a mangled byte
 * in a comment should never be able to break the script. Anything outside
 * printable ASCII is written as an escape that Python turns back into the
 * original character.
 *
 * A surrogate PAIR becomes one \\U escape, because Python 3 does not join the
 * halves the way UTF-16 does and would refuse to encode them later. A LONE
 * surrogate is half a character, which is not text, and becomes U+FFFD.
 */
fun pyLiteral(s: String): String {
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
                val cp = 0x10000 + ((code - 0xD800) shl 10) + (s[i + 1].code - 0xDC00)
                sb.append("\\U").append("%08X".format(cp))
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

/**
 * [s] as an IDC string literal, on one line.
 *
 * IDC only promises the four C escapes, so that is all this emits: a control
 * character becomes a space rather than an escape IDC might not know, and a
 * long comment is split into several literals joined with `+` rather than
 * truncated, because old IDC versions cap how long one literal may be.
 * Non-ASCII goes through as UTF-8, which a modern IDA displays and an ancient
 * one passes to the database unread; either way nothing is lost but the
 * rendering. Half a surrogate pair is not text and becomes a question mark.
 */
fun idcLiteral(s: String, chunk: Int = 200): String {
    val parts = ArrayList<String>()
    val cur = StringBuilder()
    for (c in s) {
        val piece = when {
            c == '\\' -> "\\\\"
            c == '"' -> "\\\""
            c == '\n' -> "\\n"
            c == '\r' -> ""
            c == '\t' -> "\\t"
            c.code < 0x20 || c.code == 0x7F -> " "
            c.code in 0xD800..0xDFFF -> "?"
            else -> c.toString()
        }
        cur.append(piece)
        if (cur.length >= chunk) {
            parts.add(cur.toString())
            cur.setLength(0)
        }
    }
    if (cur.isNotEmpty() || parts.isEmpty()) parts.add(cur.toString())
    return parts.joinToString(" + ") { "\"" + it + "\"" }
}

/**
 * [s] flattened into something safe to put after a `#` or `//` on one line:
 * ASCII, no newlines, bounded length. Used only for provenance notes, never
 * for anything the script acts on.
 */
fun asciiComment(s: String, cap: Int = 120): String {
    val sb = StringBuilder(s.length)
    for (c in s) {
        val code = c.code
        sb.append(
            when {
                c == '\n' || c == '\r' || c == '\t' -> ' '
                code < 0x20 || code > 0x7E -> '?'
                else -> c
            }
        )
    }
    val t = sb.toString().trim()
    return if (cap > 3 && t.length > cap) t.substring(0, cap - 3) + "..." else t
}

/** `0x0001A2B4`, and wider than eight digits when the address needs it. */
fun hexAddr(a: Long): String = "0x%08X".format(a)

/**
 * The hex in a ProjectDb key ("0x0001A2B4") as a Long.
 *
 * This is deliberately not `ui.parseAddr`: that one belongs to the UI layer and
 * the model must not reach up into it. Same two-step parse, and for the same
 * reason — an address with the top bit set overflows a signed toLongOrNull.
 */
fun parseHexAddr(s: String): Long? {
    var t = s.trim()
    if (t.length > 2 && (t.startsWith("0x") || t.startsWith("0X"))) t = t.substring(2)
    if (t.isEmpty() || t.length > 16) return null
    if (!t.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) return null
    return t.toLongOrNull(16) ?: t.toULongOrNull(16)?.toLong()
}

// ================================================================ generators ==

private fun formatLabel(x: IdaExport): String =
    if (x.arch.isBlank() || x.arch == "-") x.format else x.format + " " + x.arch

private fun addrKindText(x: IdaExport): String =
    if (x.fileOffsets) "file offsets into " + asciiComment(x.binaryName, 60)
    else "virtual addresses based at " + hexAddr(x.base)

private fun addressNote(x: IdaExport): List<String> =
    if (x.fileOffsets) listOf(
        "Nocturne read this file as " + x.format + ", so the addresses below are FILE",
        "OFFSETS, not virtual addresses. IDA does not have to load this format at the",
        "same addresses, and Nocturne cannot see your database, so the script checks",
        "before it writes: unless those offsets land on real function starts in your",
        "database it changes nothing and tells you. If you know the right shift, put",
        "it in the override below."
    ) else listOf(
        "Nocturne read this file as " + x.format + ", so the addresses below are virtual",
        "addresses in the image's own address space, based at " + hexAddr(x.base) + ".",
        "The script shifts them by (this database's image base - that base), tries no",
        "shift as well, and keeps whichever lands on more function starts. It prints",
        "which it chose. If neither lands anywhere at all it changes nothing and says so."
    )

private fun headerLines(x: IdaExport, python: Boolean): List<String> {
    val out = ArrayList<String>()
    out.add("Nocturne to IDA Pro (" + (if (python) "IDAPython" else "IDC") + ")")
    out.add(
        asciiComment(x.binaryName, 60) + " - " + formatLabel(x) + " - " +
            plural(x.names.size, "name") + ", " + plural(x.comments.size, "comment") +
            ", " + plural(x.marks.size, "bookmark")
    )
    out.add("generated by Nocturne " + asciiComment(x.stamp, 40))
    out.add("")
    out.add("Run it in your own IDA: File > Script file... (Alt+F7).")
    if (python) {
        out.add("Needs IDA 7.0 or newer, which is where the ida_* Python modules start.")
    } else {
        out.add("IDC's function names changed in IDA 7.0 and this script uses the new ones.")
        out.add("For 6.x and older, rename as you load it: set_name -> MakeName, set_cmt ->")
        out.add("MakeComm, set_func_cmt -> SetFunctionCmt, get_name -> Name, get_cmt ->")
        out.add("Comment, get_func_attr -> GetFunctionAttr, mark_position -> MarkPosition,")
        out.add("get_marked_pos -> GetMarkedPos, get_mark_comment -> GetMarkComment,")
        out.add("is_mapped -> isEnabled; and set the override below by hand, because 6.x")
        out.add("has no get_imagebase().")
    }
    out.add("It calls IDA's documented scripting API and nothing else. There is no")
    out.add("Hex-Rays code in here and nothing in here touches a licence.")
    out.add("")
    out.add("ADDRESSES")
    for (l in addressNote(x)) out.add("  " + l)
    out.add("")
    out.add("WHAT IT WRITES")
    out.add("  names      only where IDA has no name of its own; an address you named")
    out.add("             by hand in IDA is left alone and reported, never overwritten.")
    out.add("  comments   function comment at a function start, plain comment elsewhere;")
    out.add("             an existing comment is left alone and reported.")
    out.add("  bookmarks  marked positions (Ctrl+M to set, Alt+M to jump), free slots only.")
    out.add("  Run it twice and the second run reports everything as already right.")
    if (x.notes.isNotEmpty()) {
        out.add("")
        out.add("NOTES FROM THE PROJECT - carried over for reading, not applied, because")
        out.add("they belong to no address:")
        for (n in x.notes) out.add("  * " + asciiComment(n, 200))
    }
    return out
}

private fun plural(n: Int, word: String): String =
    n.toString() + " " + word + (if (n == 1) "" else "s")

/** `was sub_11a40; adjusted from "check licence"`, or null when there is nothing to say. */
private fun nameNote(r: IdaNameRow): String? {
    val safe = idaIdentifier(r.name)
    val bits = ArrayList<String>()
    val engine = r.engineName?.takeIf { it.isNotBlank() && it != safe }
    if (engine != null) bits.add("was " + asciiComment(engine, 60))
    if (safe != r.name) bits.add("adjusted from " + asciiComment(r.name, 60))
    return if (bits.isEmpty()) null else bits.joinToString("; ")
}

/** How wide a data row is padded before its trailing comment. */
private const val ROW_PAD = 52

/**
 * The IDAPython script: a header, the constants the user may edit, the data,
 * and then a fixed engine that surveys before it writes.
 */
fun idaPythonScript(x: IdaExport): String {
    val sb = StringBuilder(4096)
    for (l in headerLines(x, true)) sb.appendLine(("# " + l).trimEnd())
    sb.appendLine()
    sb.appendLine("BINARY = " + pyLiteral(asciiComment(x.binaryName, 80)))
    sb.appendLine("FORMAT = " + pyLiteral(formatLabel(x)))
    sb.appendLine("NOCTURNE_BASE = " + hexAddr(x.base))
    sb.appendLine("ADDR_KIND = " + pyLiteral(if (x.fileOffsets) "fileoff" else "va"))
    sb.appendLine("ADDR_KIND_TEXT = " + pyLiteral(addrKindText(x)))
    sb.appendLine()
    sb.appendLine("# An integer here forces the shift, e.g. DELTA_OVERRIDE = 0x400000.")
    sb.appendLine("DELTA_OVERRIDE = None")
    sb.appendLine("# True lets Nocturne win every conflict instead of reporting it.")
    sb.appendLine("OVERWRITE_EXISTING = False")
    sb.appendLine()
    sb.appendLine("NAMES = [")
    for (r in x.names) {
        val row = "    (" + hexAddr(r.addr) + ", " + pyLiteral(idaIdentifier(r.name)) + "),"
        val note = nameNote(r)
        sb.appendLine(if (note == null) row else row.padEnd(ROW_PAD) + "  # " + note)
    }
    sb.appendLine("]")
    sb.appendLine()
    sb.appendLine("COMMENTS = [")
    for (c in x.comments) sb.appendLine("    (" + hexAddr(c.addr) + ", " + pyLiteral(c.text) + "),")
    sb.appendLine("]")
    sb.appendLine()
    sb.appendLine("MARKS = [")
    for (b in x.marks) sb.appendLine("    (" + hexAddr(b.addr) + ", " + pyLiteral(b.label) + "),")
    sb.appendLine("]")
    sb.appendLine()
    sb.append(PY_ENGINE)
    return sb.toString()
}

/** How many data rows go in one IDC function, so no single function is huge. */
private const val IDC_ROWS_PER_FUNC = 200

/**
 * The same content as [idaPythonScript] in IDC, which every IDA has an
 * interpreter for. The data is emitted once and walked twice — once reading,
 * once writing — by passing the mode in a global, because IDC has no list
 * literal worth trusting across versions.
 */
fun idaIdcScript(x: IdaExport): String {
    val sb = StringBuilder(4096)
    for (l in headerLines(x, false)) sb.appendLine(("// " + l).trimEnd())
    sb.appendLine()
    sb.appendLine("#include <idc.idc>")
    sb.appendLine()
    sb.append(IDC_PROLOGUE)
    sb.appendLine()
    sb.appendLine("// ---- what this script is about, and the switches you may edit ----")
    sb.appendLine("static setup() {")
    sb.appendLine("    G_BINARY = " + idcLiteral(asciiComment(x.binaryName, 80)) + ";")
    sb.appendLine("    G_FORMAT = " + idcLiteral(formatLabel(x)) + ";")
    sb.appendLine("    G_BASE = " + hexAddr(x.base) + ";")
    sb.appendLine("    G_ADDR_KIND = " + idcLiteral(if (x.fileOffsets) "fileoff" else "va") + ";")
    sb.appendLine("    G_ADDR_TEXT = " + idcLiteral(addrKindText(x)) + ";")
    sb.appendLine("    G_N_NAMES = " + x.names.size + ";")
    sb.appendLine("    G_N_CMTS = " + x.comments.size + ";")
    sb.appendLine("    G_N_MARKS = " + x.marks.size + ";")
    sb.appendLine("    G_TOTAL = " + x.total + ";")
    sb.appendLine("    G_USE_OVERRIDE = 0;        // 1 = force the shift below")
    sb.appendLine("    G_DELTA_OVERRIDE = 0x0;")
    sb.appendLine("    G_OVERWRITE = 0;           // 1 = let Nocturne win every conflict")
    sb.appendLine("}")
    sb.appendLine()

    val rows = ArrayList<String>(x.total)
    for (r in x.names) {
        val row = "    nm(" + hexAddr(r.addr) + ", " + idcLiteral(idaIdentifier(r.name)) + ");"
        val note = nameNote(r)
        rows.add(if (note == null) row else row.padEnd(ROW_PAD) + "  // " + note)
    }
    for (c in x.comments) rows.add("    cm(" + hexAddr(c.addr) + ", " + idcLiteral(c.text) + ");")
    for (b in x.marks) rows.add("    bm(" + hexAddr(b.addr) + ", " + idcLiteral(b.label) + ");")

    val chunks = rows.chunked(IDC_ROWS_PER_FUNC)
    for (i in chunks.indices) {
        sb.appendLine("static rows_" + i + "() {")
        for (line in chunks[i]) sb.appendLine(line)
        sb.appendLine("}")
        sb.appendLine()
    }
    sb.appendLine("static rows() {")
    for (i in chunks.indices) sb.appendLine("    rows_" + i + "();")
    sb.appendLine("}")
    sb.appendLine()
    sb.append(IDC_MAIN)
    return sb.toString()
}

// ==================================================================== import ==
// The return direction: what IDA hands back.
//
// The file we read is IDA's own "File > Produce file > Dump database to IDC
// file". It was chosen over the two other things IDA can produce because it is
// the only one whose addresses are unambiguous:
//
//  - a .map file numbers its symbols seg:offset and never states where those
//    segments begin, so every name would land wherever we guessed the base was;
//  - a .lst/.asm listing does carry absolute addresses, but its comment column
//    holds IDA's own auto-comments next to the user's, in the same syntax, and
//    importing the machine's guesses as the user's notes is exactly the kind of
//    quiet wrong answer this project is trying not to produce.
//
// The IDC dump states each address as a literal, names and comments as separate
// calls, and it is the same shape of file Nocturne itself writes. Anything in it
// we do not understand is counted and reported, never silently dropped.

/**
 * What one IDA file had in it. The addresses are IDA's, unshifted — deciding
 * how they land on this binary is the caller's job, and it is not a guess it
 * should make quietly.
 */
data class IdaAnnotations(
    val names: Map<Long, String>,
    val comments: Map<Long, String>,
    val marks: Map<Long, String>,
    /** The lowest segment start the file declares, or null when it declares none. */
    val lowestSegment: Long?,
    /** Names IDA generated for itself (sub_401000 and friends), which we skip. */
    val dummySkipped: Int,
    /** Lines that call something we read, but whose arguments we could not parse. */
    val unreadable: Int,
    val lines: Int
) {
    val total: Int get() = names.size + comments.size + marks.size
}

private val DUMMY_PREFIXES = listOf(
    "sub_", "loc_", "locret_", "off_", "seg_", "asc_", "byte_", "word_",
    "dword_", "qword_", "tbyte_", "packreal_", "flt_", "dbl_", "xmmword_",
    "ymmword_", "zmmword_", "unk_", "stru_", "algn_", "jpt_", "jtb_",
    "nullsub_", "j_", "def_"
)

/**
 * True for a name IDA made up from an address — `sub_11A40`, `loc_401000`,
 * `nullsub_3`. Importing one of those would replace a name typed here with
 * IDA's placeholder for having nothing to say.
 *
 * The prefix alone is not enough: `sub_process` and `loc_manager` are names a
 * person types, and skipping them would lose exactly the work this is for. So
 * what follows the prefix has to look like an address.
 */
fun isDummyIdaName(name: String): Boolean {
    for (p in DUMMY_PREFIXES) {
        if (!name.startsWith(p)) continue
        val tail = name.substring(p.length)
        if (tail.isEmpty()) continue
        var hexDigits = 0
        var onlyHex = true
        for (c in tail) {
            if (isHexDigit(c)) hexDigits++
            else if (c != '_') { onlyHex = false; break }
        }
        if (onlyHex && hexDigits > 0) return true
    }
    return false
}

private fun skipWs(s: String, from: Int): Int {
    var i = from
    while (i < s.length && s[i].isWhitespace()) i++
    return i
}

private fun isHexDigit(c: Char): Boolean =
    c in '0'..'9' || c in 'a'..'f' || c in 'A'..'F'

/** A decimal or 0x number at [from], and the index just after it. */
private fun readNumber(s: String, from: Int): Pair<Long, Int>? {
    var i = skipWs(s, from)
    var negative = false
    if (i < s.length && s[i] == '-') {
        negative = true
        i++
    }
    var value: Long
    if (i + 1 < s.length && s[i] == '0' && (s[i + 1] == 'x' || s[i + 1] == 'X')) {
        i += 2
        val start = i
        while (i < s.length && isHexDigit(s[i])) i++
        val digits = s.substring(start, i)
        if (digits.isEmpty() || digits.length > 16) return null
        value = digits.toLongOrNull(16) ?: digits.toULongOrNull(16)?.toLong() ?: return null
    } else {
        val start = i
        while (i < s.length && s[i] in '0'..'9') i++
        val digits = s.substring(start, i)
        if (digits.isEmpty() || digits.length > 20) return null
        value = digits.toLongOrNull() ?: return null
    }
    if (negative) value = -value
    return Pair(value, i)
}

/**
 * The next string literal at or after [from], unescaped. `"a" + "b"` is read as
 * one string, because that is how a long comment survives IDC's limit on how
 * long a single literal may be — including the ones Nocturne writes.
 */
private fun readString(s: String, from: Int): String? {
    var i = skipWs(s, from)
    while (i < s.length && s[i] != '"') i++
    if (i >= s.length) return null
    val sb = StringBuilder()
    while (i < s.length && s[i] == '"') {
        i++
        while (i < s.length && s[i] != '"') {
            val c = s[i]
            if (c == '\\' && i + 1 < s.length) {
                val e = s[i + 1]
                sb.append(
                    when (e) {
                        'n' -> '\n'
                        't' -> '\t'
                        'r' -> '\r'
                        '0' -> ' '
                        else -> e
                    }
                )
                i += 2
            } else {
                sb.append(c)
                i++
            }
        }
        if (i >= s.length) return null      // the literal never closed
        i++
        val plus = skipWs(s, i)
        if (plus < s.length && s[plus] == '+') {
            val next = skipWs(s, plus + 1)
            if (next < s.length && s[next] == '"') {
                i = next
                continue
            }
        }
        break
    }
    return sb.toString()
}

/**
 * The identifier before the first `(` on [line], and the index just after that
 * `(`.
 *
 * The whitespace skip is not decoration: IDA's own dump lines the call names
 * up in a column and writes `set_cmt  (0X401005, "…", 0);`. Scanning straight
 * back from the bracket lands on a space, reads an empty name, and every
 * comment in the file is skipped without a word.
 */
private fun callName(line: String): Pair<String, Int>? {
    val open = line.indexOf('(')
    if (open <= 0) return null
    var end = open
    while (end > 0 && line[end - 1].isWhitespace()) end--
    var i = end - 1
    while (i >= 0 && (line[i].isLetterOrDigit() || line[i] == '_')) i--
    val name = line.substring(i + 1, end)
    return if (name.isEmpty()) null else Pair(name, open + 1)
}

/**
 * True when [line] is only half a statement, because a string was left open or
 * because it ends on the `+` that joins one to the next.
 *
 * IDA wraps a long comment across source lines, and so does Nocturne's own IDC
 * writer. Reading such a file a line at a time without this takes the first
 * fragment for the whole comment and imports a sentence that stops in the
 * middle — with nothing to say it did.
 */
private fun continuesOnNextLine(line: String): Boolean {
    if (line.isEmpty() || line.startsWith("//")) return false
    if (line.endsWith("+")) return true
    var inString = false
    var i = 0
    while (i < line.length) {
        val c = line[i]
        if (inString && c == '\\') { i += 2; continue }
        if (c == '"') inString = !inString
        i++
    }
    return inString
}

/** A joined statement may not grow past this, so a broken file cannot eat the heap. */
private const val MAX_JOINED = 64 * 1024

/**
 * Read an IDA-produced IDC dump. Streamed a line at a time so a 40 MB database
 * dump never becomes a 40 MB String on a phone; [lineCap] is the point past
 * which a file stops being one of these and starts being something else.
 */
fun parseIdcAnnotations(lines: Sequence<String>, lineCap: Int = 2_000_000): IdaAnnotations {
    val names = LinkedHashMap<Long, String>()
    val comments = LinkedHashMap<Long, String>()
    val marks = LinkedHashMap<Long, String>()
    var lowest: Long? = null
    var dummy = 0
    var unreadable = 0
    var seen = 0

    // An anonymous function rather than a lambda, so `return` means this
    // statement and nothing else.
    val handle = fun(line: String) {
        if (line.isEmpty() || line.startsWith("//")) return
        val call = callName(line) ?: return
        when (call.first.lowercase()) {
            "set_name", "makename", "makenameex" -> {
                val addr = readNumber(line, call.second)
                val text = if (addr == null) null else readString(line, addr.second)
                if (addr == null || text == null) {
                    unreadable++
                } else {
                    val name = text.trim()
                    if (name.isEmpty()) unreadable++
                    else if (isDummyIdaName(name)) dummy++
                    else names[addr.first] = name
                }
            }
            "set_cmt", "makecomm", "makerptcmt", "set_func_cmt", "setfunctioncmt" -> {
                val addr = readNumber(line, call.second)
                val text = if (addr == null) null else readString(line, addr.second)
                if (addr == null || text == null) unreadable++
                else if (text.isNotBlank()) comments[addr.first] = text.trim()
            }
            "mark_position", "markposition" -> {
                val addr = readNumber(line, call.second)
                val text = if (addr == null) null else readString(line, addr.second)
                if (addr == null || text == null) unreadable++
                else if (text.isNotBlank()) marks[addr.first] = text.trim()
            }
            "add_segm_ex", "add_segm", "segcreate" -> {
                val addr = readNumber(line, call.second)
                if (addr != null) {
                    val cur = lowest
                    // Unsigned, because a segment above 0x8000000000000000 is a
                    // real place and signed comparison would call it the lowest.
                    if (cur == null || (addr.first xor Long.MIN_VALUE) < (cur xor Long.MIN_VALUE)) {
                        lowest = addr.first
                    }
                }
            }
        }
    }

    var held: String? = null
    for (raw in lines) {
        if (seen >= lineCap) break
        seen++
        val trimmed = raw.trim()
        val prefix = held
        val line = if (prefix == null) trimmed else prefix + " " + trimmed
        // Only an open string or a trailing `+` holds a line back. A trailing
        // comma would not: joining on one of those could glue two whole calls
        // together and lose the second.
        if (continuesOnNextLine(line) && line.length < MAX_JOINED) {
            held = line
            continue
        }
        held = null
        handle(line)
    }
    // A file that ends mid-statement still has that statement in hand.
    val leftover = held
    if (leftover != null) handle(leftover)

    return IdaAnnotations(names, comments, marks, lowest, dummy, unreadable, seen)
}

// ================================================================== templates ==
// The fixed half of each script. These are the only two blocks that are the
// same in every export, which is why they live here as text rather than being
// built line by line: what runs in IDA is exactly what is written here, and it
// can be read end to end without a generator in the way.
//
// Kept to plain ASCII, and no dollar signs or triple quotes, so a raw Kotlin
// string can hold them verbatim.

private val PY_ENGINE = """
# ---------------------------------------------------------------- engine --
# Everything below is fixed: it is the same in every script Nocturne writes.
import sys

try:
    import ida_bytes
    import ida_funcs
    import ida_kernwin
    import ida_name
    import ida_nalt
    import idaapi
    import idc
except ImportError:
    sys.stderr.write("This script has to run inside IDA: File > Script file...\n")
    raise SystemExit(1)

BADADDR = idaapi.BADADDR
MASK64 = (1 << 64) - 1

_GET_FLAGS = getattr(ida_bytes, "get_full_flags", None) or getattr(ida_bytes, "get_flags", None)
_HAS_USER_NAME = getattr(ida_bytes, "has_user_name", None)
_IS_MAPPED = getattr(ida_bytes, "is_mapped", None)
_MARK = getattr(idc, "mark_position", None)
_MARKED_POS = getattr(idc, "get_marked_pos", None)
_MARK_CMT = getattr(idc, "get_mark_comment", None)
_SN = getattr(ida_name, "SN_NOWARN", 0) | getattr(ida_name, "SN_FORCE", 0)

# Names IDA generates for itself. One of these means "IDA has nothing of its
# own here", so writing over it loses nothing.
_DUMMY = ("sub_", "loc_", "locret_", "off_", "seg_", "asc_", "byte_", "word_",
          "dword_", "qword_", "tbyte_", "packreal_", "flt_", "dbl_", "xmmword_",
          "ymmword_", "zmmword_", "unk_", "stru_", "algn_", "jpt_", "jtb_",
          "nullsub_", "j_", "def_")

def _say(s):
    print(s)


def _n(count, word):
    return str(count) + " " + word + ("" if count == 1 else "s")


def _hx(v):
    return ("-0x%X" % -v) if v < 0 else ("0x%X" % v)


def _mapped(ea):
    if ea < 0 or ea > MASK64 or ea == BADADDR:
        return False
    if _IS_MAPPED is not None:
        return _IS_MAPPED(ea)
    return _GET_FLAGS is not None and _GET_FLAGS(ea) != 0


def _func_start(ea):
    f = ida_funcs.get_func(ea)
    return f is not None and f.start_ea == ea


def _is_dummy(name):
    # The prefix alone is not enough: sub_process is a person's name for a
    # function, sub_401000 is IDA having nothing to say.
    for p in _DUMMY:
        if not name.startswith(p):
            continue
        tail = name[len(p):]
        if tail and all(c in "0123456789abcdefABCDEF_" for c in tail):
            return True
    return False


def _user_named(ea, cur):
    if not cur:
        return False
    if _HAS_USER_NAME is not None and _GET_FLAGS is not None:
        return bool(_HAS_USER_NAME(_GET_FLAGS(ea)))
    return not _is_dummy(cur)


def _addrs():
    out = [r[0] for r in NAMES]
    out.extend(r[0] for r in COMMENTS)
    out.extend(r[0] for r in MARKS)
    return out


# How many of our addresses land somewhere real once shifted by delta.
def _score(delta):
    mapped = 0
    starts = 0
    for a in _addrs():
        ea = a + delta
        if _mapped(ea):
            mapped += 1
            if _func_start(ea):
                starts += 1
    return mapped, starts


# Every rebase delta worth trying, best first once scored.
def _candidates():
    if DELTA_OVERRIDE is not None:
        d = int(DELTA_OVERRIDE)
        m, s = _score(d)
        return [(d, m, s, "DELTA_OVERRIDE")]
    cands = [(0, "no rebase")]
    try:
        img = ida_nalt.get_imagebase()
    except Exception:
        img = 0
    d = img - NOCTURNE_BASE
    if d != 0:
        cands.append((d, "IDA image base " + _hx(img) + " - Nocturne base " + _hx(NOCTURNE_BASE)))
    scored = []
    for c, why in cands:
        m, s = _score(c)
        scored.append((c, m, s, why))
    # Most function starts hit wins; mapped addresses break the tie; a tie after
    # that keeps the earlier candidate, which is "no rebase".
    best = 0
    for i in range(1, len(scored)):
        if (scored[i][2], scored[i][1]) > (scored[best][2], scored[best][1]):
            best = i
    return [scored[best]] + [scored[i] for i in range(len(scored)) if i != best]


def _apply_names(delta, st):
    for row in NAMES:
        ea = row[0] + delta
        want = row[1]
        if not _mapped(ea):
            st["unmapped"] += 1
            continue
        cur = ida_name.get_name(ea) or ""
        if cur == want:
            st["name_same"] += 1
            continue
        if _user_named(ea, cur) and not OVERWRITE_EXISTING:
            st["name_conflict"].append((ea, cur, want))
            continue
        if not ida_name.set_name(ea, want, _SN):
            st["name_failed"].append((ea, want))
            continue
        got = ida_name.get_name(ea) or ""
        if got != want:
            st["name_adjusted"].append((ea, want, got))
        st["name_set"] += 1


def _apply_comments(delta, st):
    for row in COMMENTS:
        ea = row[0] + delta
        want = row[1]
        if not _mapped(ea):
            st["unmapped"] += 1
            continue
        f = ida_funcs.get_func(ea)
        at_start = f is not None and f.start_ea == ea
        cur = (ida_funcs.get_func_cmt(f, False) if at_start else ida_bytes.get_cmt(ea, False)) or ""
        if cur == want:
            st["cmt_same"] += 1
            continue
        if cur and not OVERWRITE_EXISTING:
            st["cmt_conflict"].append((ea, cur, want))
            continue
        ok = ida_funcs.set_func_cmt(f, want, False) if at_start else ida_bytes.set_cmt(ea, want, False)
        if ok is False:
            st["cmt_failed"].append((ea, want))
        else:
            st["cmt_set"] += 1


# (taken, free) marked-position slots, or (None, None) if this IDA has none.
def _slots():
    if _MARK is None or _MARKED_POS is None:
        return None, None
    taken = {}
    free = []
    for slot in range(1, 1025):
        try:
            pos = _MARKED_POS(slot)
        except Exception:
            return None, None
        if pos == BADADDR or pos == 0:
            free.append(slot)
        else:
            desc = ""
            if _MARK_CMT is not None:
                desc = _MARK_CMT(slot) or ""
            taken[slot] = (pos, desc)
    return taken, free


def _apply_marks(delta, st):
    if not MARKS:
        return
    taken, free = _slots()
    have = set(taken.values()) if taken is not None else set()
    for row in MARKS:
        ea = row[0] + delta
        label = row[1]
        if not _mapped(ea):
            st["unmapped"] += 1
            continue
        if (ea, label) in have:
            st["mark_same"] += 1
            continue
        if taken is not None and free:
            slot = free.pop(0)
            _MARK(ea, 0, 0, 0, slot, label)
            have.add((ea, label))
            st["mark_set"] += 1
            st["mark_slots"].append(slot)
            continue
        # No marked-position API, or all 1024 slots are in use: keep the
        # bookmark as a repeatable comment rather than dropping it.
        note = "Nocturne bookmark: " + label
        cur = ida_bytes.get_cmt(ea, True) or ""
        if note in cur:
            st["mark_same"] += 1
        else:
            ida_bytes.set_cmt(ea, (cur + "\n" + note) if cur else note, True)
            st["mark_fallback"] += 1


def _list(st, key, title, fmt):
    rows = st[key]
    if not rows:
        return
    _say("  " + title + " (" + str(len(rows)) + "):")
    for r in rows[:20]:
        _say("    " + fmt(r))
    if len(rows) > 20:
        _say("    ... and " + str(len(rows) - 20) + " more")


def main():
    total = len(NAMES) + len(COMMENTS) + len(MARKS)
    _say("")
    _say("Nocturne -> IDA  -  " + BINARY + "  -  " + FORMAT)
    _say("  " + _n(len(NAMES), "name") + ", " + _n(len(COMMENTS), "comment")
         + ", " + _n(len(MARKS), "bookmark"))
    if total == 0:
        _say("  nothing to apply")
        return
    cands = _candidates()
    for c, m, s, why in cands:
        _say("  delta " + _hx(c) + ": " + str(m) + "/" + str(total) + " mapped, "
             + str(s) + " on a function start  (" + why + ")")
    delta, mapped, starts, why = cands[0]

    if mapped == 0:
        _say("  REFUSED - not one of these addresses exists in this database.")
        _say("  Nocturne's addresses are " + ADDR_KIND_TEXT + ".")
        _say("  Nothing was changed. If you know the right shift, set DELTA_OVERRIDE")
        _say("  at the top of this script and run it again.")
        return
    if ADDR_KIND != "va" and DELTA_OVERRIDE is None and (starts < 1 or starts * 2 < len(NAMES)):
        _say("  REFUSED - only " + str(starts) + " of " + str(total) + " addresses land on a")
        _say("  function start. Nocturne's addresses are " + ADDR_KIND_TEXT + ", and IDA does")
        _say("  not have to agree with that, so applying them here would write names at")
        _say("  addresses that mean something else.")
        _say("  Nothing was changed. Set DELTA_OVERRIDE at the top of this script to")
        _say("  the shift you want and run it again.")
        return
    if mapped < total:
        _say("  note: " + _n(total - mapped, "address")
             + " not mapped here, so skipped")

    st = {
        "unmapped": 0,
        "name_set": 0, "name_same": 0, "name_conflict": [], "name_failed": [],
        "name_adjusted": [],
        "cmt_set": 0, "cmt_same": 0, "cmt_conflict": [], "cmt_failed": [],
        "mark_set": 0, "mark_same": 0, "mark_fallback": 0, "mark_slots": [],
    }
    _apply_names(delta, st)
    _apply_comments(delta, st)
    _apply_marks(delta, st)

    _say("  applied with delta " + _hx(delta) + ":")
    _say("    names     " + str(st["name_set"]) + " set, " + str(st["name_same"])
         + " already right, " + str(len(st["name_conflict"])) + " left alone, "
         + str(len(st["name_failed"])) + " refused by IDA")
    _say("    comments  " + str(st["cmt_set"]) + " set, " + str(st["cmt_same"])
         + " already right, " + str(len(st["cmt_conflict"])) + " left alone")
    if MARKS:
        _say("    bookmarks " + str(st["mark_set"]) + " marked, " + str(st["mark_same"])
             + " already there, " + str(st["mark_fallback"]) + " as repeatable comments")
        if st["mark_slots"]:
            _say("              slots " + ", ".join(str(s) for s in st["mark_slots"]))
    if st["unmapped"]:
        _say("    skipped   " + _n(st["unmapped"], "address") + " not mapped in this database")

    _list(st, "name_conflict", "kept IDA's name",
          lambda r: _hx(r[0]) + "  IDA has " + r[1] + ", Nocturne says " + r[2])
    _list(st, "name_adjusted", "renamed, but IDA changed the name to keep it unique",
          lambda r: _hx(r[0]) + "  wanted " + r[1] + ", got " + r[2])
    _list(st, "name_failed", "IDA refused the name",
          lambda r: _hx(r[0]) + "  " + r[1])
    _list(st, "cmt_conflict", "kept IDA's comment",
          lambda r: _hx(r[0]) + "  IDA has " + repr(r[1]) + ", Nocturne says " + repr(r[2]))

    if st["name_conflict"] or st["cmt_conflict"]:
        _say("  Nothing above was overwritten. To take Nocturne's version instead,")
        _say("  set OVERWRITE_EXISTING = True at the top and run this again.")
    _say("  The database is not saved - File > Save database when you are happy.")
    try:
        ida_kernwin.refresh_idaview_anyway()
    except Exception:
        pass


main()
""".trimStart('\n')

private val IDC_PROLOGUE = """
// ------------------------------------------------------------------ engine --
// Everything below is fixed: it is the same in every script Nocturne writes.

extern G_BINARY, G_FORMAT, G_BASE, G_ADDR_KIND, G_ADDR_TEXT;
extern G_N_NAMES, G_N_CMTS, G_N_MARKS, G_TOTAL;
extern G_USE_OVERRIDE, G_DELTA_OVERRIDE, G_OVERWRITE;

extern g_apply;          // 0 = look only, 1 = write
extern g_delta;
extern g_mapped, g_starts;
extern g_name_set, g_name_same, g_name_conflict, g_name_failed;
extern g_cmt_set, g_cmt_same, g_cmt_conflict;
extern g_mark_set, g_mark_same, g_mark_fallback;
extern g_unmapped;

static hx(v) {
    if (v < 0) { return "-0x" + ltoa(-v, 16); }
    return "0x" + ltoa(v, 16);
}

static say(s) {
    msg("%s\n", s);
}

// Some IDA builds answer "no comment" / "no name" with the number 0 rather than
// with an empty string. Both mean the same thing here.
static str_or_empty(v) {
    if (v == 0) { return ""; }
    return v;
}

// Does this name start with one of IDA's generated prefixes AND continue like
// an address? "sub_11A40" is IDA's; "sub_process" is somebody's.
static dummy_pre(name, p) {
    auto n;
    n = strlen(p);
    if (substr(name, 0, n) != p) { return 0; }
    return strstr("0123456789ABCDEFabcdef", substr(name, n, n + 1)) >= 0;
}

// A name IDA made up for itself. Anything else is somebody's work, so this
// script leaves it alone and says so.
static is_dummy(name) {
    if (dummy_pre(name, "sub_")) { return 1; }
    if (dummy_pre(name, "loc_")) { return 1; }
    if (dummy_pre(name, "locret_")) { return 1; }
    if (dummy_pre(name, "off_")) { return 1; }
    if (dummy_pre(name, "seg_")) { return 1; }
    if (dummy_pre(name, "asc_")) { return 1; }
    if (dummy_pre(name, "byte_")) { return 1; }
    if (dummy_pre(name, "word_")) { return 1; }
    if (dummy_pre(name, "dword_")) { return 1; }
    if (dummy_pre(name, "qword_")) { return 1; }
    if (dummy_pre(name, "unk_")) { return 1; }
    if (dummy_pre(name, "stru_")) { return 1; }
    if (dummy_pre(name, "algn_")) { return 1; }
    if (dummy_pre(name, "jpt_")) { return 1; }
    if (dummy_pre(name, "jtb_")) { return 1; }
    if (dummy_pre(name, "nullsub_")) { return 1; }
    if (dummy_pre(name, "j_")) { return 1; }
    if (dummy_pre(name, "def_")) { return 1; }
    return 0;
}

static ea_ok(ea) {
    if (ea == BADADDR) { return 0; }
    if (ea < 0) { return 0; }
    return is_mapped(ea);
}

static surveyed(ea) {
    g_mapped = g_mapped + 1;
    if (get_func_attr(ea, FUNCATTR_START) == ea) { g_starts = g_starts + 1; }
}

// ---- one renamed function -------------------------------------------------
static nm(ea0, want) {
    auto ea, cur;
    ea = ea0 + g_delta;
    if (!ea_ok(ea)) { g_unmapped = g_unmapped + 1; return; }
    if (g_apply == 0) { surveyed(ea); return; }
    cur = str_or_empty(get_name(ea));
    if (cur == want) { g_name_same = g_name_same + 1; return; }
    if (cur != "" && !is_dummy(cur) && G_OVERWRITE == 0) {
        g_name_conflict = g_name_conflict + 1;
        say("    kept IDA's name at " + hx(ea) + ": " + cur + "  (Nocturne says " + want + ")");
        return;
    }
    if (set_name(ea, want, SN_NOWARN) == 0) {
        g_name_failed = g_name_failed + 1;
        say("    IDA refused the name " + want + " at " + hx(ea));
        return;
    }
    g_name_set = g_name_set + 1;
}

// ---- one comment ----------------------------------------------------------
static cm(ea0, want) {
    auto ea, cur, at_start;
    ea = ea0 + g_delta;
    if (!ea_ok(ea)) { g_unmapped = g_unmapped + 1; return; }
    if (g_apply == 0) { surveyed(ea); return; }
    at_start = (get_func_attr(ea, FUNCATTR_START) == ea);
    if (at_start) { cur = str_or_empty(get_func_cmt(ea, 0)); }
    else { cur = str_or_empty(get_cmt(ea, 0)); }
    if (cur == want) { g_cmt_same = g_cmt_same + 1; return; }
    if (cur != "" && G_OVERWRITE == 0) {
        g_cmt_conflict = g_cmt_conflict + 1;
        say("    kept IDA's comment at " + hx(ea));
        return;
    }
    if (at_start) { set_func_cmt(ea, want, 0); }
    else { set_cmt(ea, want, 0); }
    g_cmt_set = g_cmt_set + 1;
}

// ---- one bookmark ---------------------------------------------------------
// IDA keeps 1024 marked-position slots (Ctrl+M to set, Alt+M to jump). Only
// free ones are used, and a slot that already holds this exact position is
// left as it is, so a second run of this script changes nothing.
static bm(ea0, label) {
    auto ea, i, pos, free, cur;
    ea = ea0 + g_delta;
    if (!ea_ok(ea)) { g_unmapped = g_unmapped + 1; return; }
    if (g_apply == 0) { surveyed(ea); return; }
    free = 0;
    for (i = 1; i <= 1024; i = i + 1) {
        pos = get_marked_pos(i);
        if (pos == BADADDR || pos == 0) {
            if (free == 0) { free = i; }
        } else {
            if (pos == ea) {
                cur = str_or_empty(get_mark_comment(i));
                if (cur == label) { g_mark_same = g_mark_same + 1; return; }
            }
        }
    }
    if (free != 0) {
        mark_position(ea, 0, 0, 0, free, label);
        g_mark_set = g_mark_set + 1;
        return;
    }
    // All 1024 slots are somebody else's: keep the bookmark as a repeatable
    // comment rather than dropping it on the floor.
    cur = str_or_empty(get_cmt(ea, 1));
    if (strstr(cur, "Nocturne bookmark: " + label) >= 0) {
        g_mark_same = g_mark_same + 1;
        return;
    }
    if (cur != "") { set_cmt(ea, cur + "\n" + "Nocturne bookmark: " + label, 1); }
    else { set_cmt(ea, "Nocturne bookmark: " + label, 1); }
    g_mark_fallback = g_mark_fallback + 1;
}

static reset(d, apply) {
    g_delta = d;
    g_apply = apply;
    g_mapped = 0;
    g_starts = 0;
    g_unmapped = 0;
    g_name_set = 0; g_name_same = 0; g_name_conflict = 0; g_name_failed = 0;
    g_cmt_set = 0; g_cmt_same = 0; g_cmt_conflict = 0;
    g_mark_set = 0; g_mark_same = 0; g_mark_fallback = 0;
}
""".trimStart('\n')

private val IDC_MAIN = """
static main() {
    auto best_d, best_m, best_s, img, alt_d, alt_m, alt_s;
    setup();
    say("");
    say("Nocturne -> IDA  -  " + G_BINARY + "  -  " + G_FORMAT);
    say("  " + ltoa(G_N_NAMES, 10) + " names, " + ltoa(G_N_CMTS, 10) + " comments, "
        + ltoa(G_N_MARKS, 10) + " bookmarks");
    if (G_TOTAL == 0) { say("  nothing to apply"); return; }

    if (G_USE_OVERRIDE) {
        best_d = G_DELTA_OVERRIDE;
        reset(best_d, 0); rows();
        best_m = g_mapped; best_s = g_starts;
        say("  delta " + hx(best_d) + ": " + ltoa(best_m, 10) + "/" + ltoa(G_TOTAL, 10)
            + " mapped, " + ltoa(best_s, 10) + " on a function start  (G_DELTA_OVERRIDE)");
    } else {
        reset(0, 0); rows();
        best_d = 0; best_m = g_mapped; best_s = g_starts;
        say("  delta 0x0: " + ltoa(best_m, 10) + "/" + ltoa(G_TOTAL, 10) + " mapped, "
            + ltoa(best_s, 10) + " on a function start  (no rebase)");
        img = get_imagebase();
        alt_d = img - G_BASE;
        if (alt_d != 0) {
            reset(alt_d, 0); rows();
            alt_m = g_mapped; alt_s = g_starts;
            say("  delta " + hx(alt_d) + ": " + ltoa(alt_m, 10) + "/" + ltoa(G_TOTAL, 10)
                + " mapped, " + ltoa(alt_s, 10) + " on a function start  (IDA image base "
                + hx(img) + " - Nocturne base " + hx(G_BASE) + ")");
            if (alt_s > best_s || (alt_s == best_s && alt_m > best_m)) {
                best_d = alt_d; best_m = alt_m; best_s = alt_s;
            }
        }
    }

    if (best_m == 0) {
        say("  REFUSED - not one of these addresses exists in this database.");
        say("  Nocturne's addresses are " + G_ADDR_TEXT + ".");
        say("  Nothing was changed. If you know the right shift, set G_USE_OVERRIDE = 1");
        say("  and G_DELTA_OVERRIDE in setup() above, then run this again.");
        return;
    }
    if (G_ADDR_KIND != "va" && !G_USE_OVERRIDE && (best_s < 1 || best_s * 2 < G_N_NAMES)) {
        say("  REFUSED - only " + ltoa(best_s, 10) + " of " + ltoa(G_TOTAL, 10)
            + " addresses land on a function start.");
        say("  Nocturne's addresses are " + G_ADDR_TEXT + ", and IDA does not have to");
        say("  agree with that, so applying them here would write names at addresses");
        say("  that mean something else. Nothing was changed.");
        say("  Set G_USE_OVERRIDE = 1 and G_DELTA_OVERRIDE in setup() if you know it.");
        return;
    }

    reset(best_d, 1);
    rows();

    say("  applied with delta " + hx(best_d) + ":");
    say("    names     " + ltoa(g_name_set, 10) + " set, " + ltoa(g_name_same, 10)
        + " already right, " + ltoa(g_name_conflict, 10) + " left alone, "
        + ltoa(g_name_failed, 10) + " refused by IDA");
    say("    comments  " + ltoa(g_cmt_set, 10) + " set, " + ltoa(g_cmt_same, 10)
        + " already right, " + ltoa(g_cmt_conflict, 10) + " left alone");
    if (G_N_MARKS > 0) {
        say("    bookmarks " + ltoa(g_mark_set, 10) + " marked, " + ltoa(g_mark_same, 10)
            + " already there, " + ltoa(g_mark_fallback, 10) + " as repeatable comments");
    }
    if (g_unmapped > 0) {
        say("    skipped   " + ltoa(g_unmapped, 10) + " address(es) not mapped in this database");
    }
    if (g_name_conflict > 0 || g_cmt_conflict > 0) {
        say("  Nothing above was overwritten. To take Nocturne's version instead, set");
        say("  G_OVERWRITE = 1 in setup() above and run this again.");
    }
    say("  The database is not saved - File > Save database when you are happy.");
}
""".trimStart('\n')

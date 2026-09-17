package com.trickhook.engine

import java.io.File

/**
 * JNI bridge to the native C++ engine (libnocturne.so).
 * Engine side: app/src/main/cpp/
 *
 * This object is loaded in TWO processes now. In the app it behaves exactly as
 * it always has: the library is loaded when the class is first touched, and if
 * it were ever missing the app would be dead anyway. In the Shizuku user
 * service (com.trickhook.shizuku.NocturneUserService) it is loaded by a class
 * loader that LoadedApk built inside a process that is not an Android
 * application at all, and whether that resolves libnocturne.so is the single
 * riskiest assumption in that feature. So the load is catchable, retryable and
 * reports a sentence — see [ensureEngine].
 */
object NativeBridge {

    /**
     * Why libnocturne.so is not loaded in THIS process, or null when the engine
     * is callable.
     *
     * Non-null means every `external fun` below will throw UnsatisfiedLinkError
     * — which is an Error, not an Exception, so callers that catch Exception
     * will not contain it. Check this first anywhere the answer matters.
     */
    @Volatile
    var loadError: String? = null
        private set

    init {
        loadError = tryLoad(null)
    }

    /**
     * Make sure the engine is loaded, and say why if it is not. Returns null on
     * success, so `ensureEngine(dir) ?: run { ... }` reads the right way round.
     *
     * [nativeLibraryDir] is ApplicationInfo.nativeLibraryDir, when the caller
     * has it. The first attempt goes through the class loader, which is the
     * documented mechanism and the one the official Shizuku demo relies on; the
     * second opens the file by absolute path, which covers the case where the
     * library is on disk but the class loader's search path was built without
     * it. Both are inside the class loader's permitted namespace, so neither
     * can be refused by the linker for being out of bounds.
     */
    @Synchronized
    fun ensureEngine(nativeLibraryDir: String? = null): String? {
        if (loadError == null) return null
        loadError = tryLoad(nativeLibraryDir)
        return loadError
    }

    private fun tryLoad(nativeLibraryDir: String?): String? {
        try {
            System.loadLibrary("nocturne")
            return null
        } catch (first: Throwable) {
            if (nativeLibraryDir == null) return why(first, "System.loadLibrary(\"nocturne\")")
            val f = File(nativeLibraryDir, "libnocturne.so")
            if (!f.isFile) {
                return why(first, "System.loadLibrary(\"nocturne\")") +
                    " — and " + f.absolutePath + " does not exist, which is what an APK packaged " +
                    "with extractNativeLibs=false looks like from here"
            }
            return try {
                System.load(f.absolutePath)
                null
            } catch (second: Throwable) {
                why(second, "System.load(" + f.absolutePath + ")")
            }
        }
    }

    private fun why(t: Throwable, attempt: String): String {
        val m = t.message
        return attempt + " failed: " + (if (m.isNullOrBlank()) t.javaClass.simpleName else m)
    }

    /**
     * Directory the SLEIGH specifications were extracted to. Until this is
     * set the Ghidra backend reports itself unavailable and every function
     * decompiles with the built-in IR lifter.
     */
    external fun nativeSetSleighDir(dir: String)

    /**
     * Path to a library-function signature database (a .nsig, one per ABI,
     * extracted from assets on first run). Until this is set the recognition
     * pass is a no-op and every unnamed function stays SUB_xxxxxxxx; once set
     * and loaded, analysis of a matching-architecture binary names the library
     * functions it recognises (from = "lib"). An empty string disables it.
     * Mirrors [nativeSetSleighDir]. Engine side: Engine::setLibSigDb.
     */
    external fun nativeSetLibSigDb(path: String)

    /** "ghidra" or "ir". Unknown values are treated as "ghidra". */
    external fun nativeSetDecompiler(which: String)

    /**
     * JSON: compiledIn, selected, specsInstalled, active, backend, note.
     * `note` says why the Ghidra backend is not active when it is not.
     */
    external fun nativeDecompilerStatus(path: String): String

    external fun nativeAnalyze(path: String): String
    external fun nativeFunction(path: String, addr: Long): String
    external fun nativeCallGraph(path: String, focus: Long): String
    /**
     * Produce a source listing from the current analysis, the equivalent of
     * IDA's "produce file". Writes to [outPath] on the filesystem rather than
     * returning the text, so a whole-binary listing is never held in memory as
     * a String. Returns a small JSON status.
     *
     * [outPath] is a FILESYSTEM path, not a content:// URI — the engine opens
     * it with std::ofstream. Write into the app's own storage and hand the
     * finished file to the user from there.
     *
     * kind: "c-one" (function at [addr]) | "c-all" | "h-all" | "asm-all"
     *
     * Returns `{"ok":true,"functions":5299,"failed":64,"total":5363,
     * "cancelled":false,"bytes":2886843}`. `failed` is not an error: a function
     * the decompiler refuses is marked in the file and the run continues.
     *
     * BACKGROUND THREAD, and this one is not a formality: it holds the engine
     * mutex for its whole run, which is minutes on a large binary, so every
     * other native call blocks behind it. [nativeExportProgress] and
     * [nativeExportStop] are the only two that still answer during it.
     */
    external fun nativeExportSource(path: String, kind: String, addr: Long, outPath: String): String

    external fun nativeDbgCmd(json: String): String

    /**
     * Run one function under Ghidra's p-code emulator and report what it did
     * to memory. This is the only call that executes the analysed binary's
     * own instructions, so every run is bounded: an instruction budget, a
     * wall clock, a page cap and a cap on stubbed calls, all reported back.
     * Call it off the main thread — a run can take as long as `timeoutMs`.
     *
     * Request JSON (flat; lists are ';'-separated, the same convention as
     * [nativeDebugRun]'s newline-separated argv):
     *
     *   entry         "0x2a10"       required, the function to run
     *   args          "0x1;buf:64;hex:aabbcc;str:hello"
     *                                positional arguments, mapped onto the
     *                                target's argument registers.
     *                                  buf:N  allocate N zeroed bytes in the
     *                                         sandbox heap and pass the
     *                                         address — this is the output
     *                                         buffer a decrypt writes into
     *                                  hex:.. allocate a block holding these
     *                                         bytes and pass the address
     *                                  str:.. the same, NUL-terminated
     *                                  other  a plain scalar, incl. an
     *                                         address inside the binary
     *   regs          "x9=0x40;x10=0"  raw register overrides, applied last
     *   write         "0x4a100=aabb"   raw memory to place before the run
     *   read          "0x4a100:64"     extra windows to read back at exit
     *   stopAt        "0x2b40"         halt before executing this address
     *   maxInstr      200000           instruction budget
     *   timeoutMs     3000             wall clock
     *   maxPages      1024             4 KiB pages the run may dirty
     *   maxCalls      4096             stubbed imports it may call
     *   strictUserops 0                1 = stop at the first p-code operation
     *                                  modelled as zero instead of noting it
     *
     * Response JSON:
     *
     *   ok            true only for "completed" and "stopAddress"
     *   stop          completed | stopAddress | budget | timeout | memoryCap |
     *                 callCap | unimplemented | fault | aborted | setup
     *   detail        one specific sentence — "instruction budget exhausted
     *                 after 200000 instructions, still at 0x2a5c", never
     *                 just "failed"
     *   approximate   true when something was modelled as zero that might not
     *                 be, so `memory` is plausible rather than certain
     *   instructions, ms, backend, limits{...}
     *   retReg, ret   the return register and its value
     *   regs          [{n,v}]      the architecture's reportable registers
     *   args          [{i,reg,v,kind,len}]  echoed, with the addresses the
     *                 sandbox chose for buf:/hex:/str:
     *   memory        [{addr,label,len,data,text}] — `data` is lowercase hex,
     *                 `text` the same bytes as printable ASCII. Labels:
     *                 "argN" (a buffer that was passed in), "window" (asked
     *                 for by `read`), "wrote" (a range the run changed,
     *                 worked out by diffing against the file)
     *   dirtyBytes, dirtyRanges, memoryTruncated
     *   calls         [{n,at,ret,modelled,note,args}] — the imports that were
     *                 answered by a model instead of executed; modelled=false
     *                 means it returned 0 and the answer may be wrong
     *   callsTotal
     *   userops       [{n,count,harmless}] p-code operations run as zero
     *   tail          the last addresses executed, oldest first
     */
    external fun nativeEmulate(path: String, requestJson: String): String

    external fun nativeScriptRun(source: String, path: String): String
    external fun nativeDebugRun(argvLines: String, maxEvents: Int): String
    external fun nativeDebugStop()

    /**
     * One page of the function list.
     *
     * [nativeAnalyze]'s `functions` array is the FIRST page of these same rows
     * and carries `functionsTotal`; this serves any other page, so a binary
     * with 200,000 functions can be walked without any single answer being a
     * 40 MB jstring.
     *
     * [offset] is 0-based. [count] 0 means the engine's default page of 12000,
     * and anything over 20000 is clamped — so the ANSWER's own `count` is what
     * a walk advances by, never what was asked for:
     *
     *     var off = meta.functionsCount.toLong()
     *     while (true) {
     *         val p = parseFunctionPage(nativeFunctionPage(path, off, 20000))
     *         if (!p.ok || p.count == 0) break
     *         append(p.functions)
     *         off += p.count
     *     }
     *
     * An offset past the end answers `count:0` with an empty array. That is the
     * loop's termination condition, not an error.
     *
     * Returns `{"ok":true,"functionsTotal":…,"offset":…,"count":…,"functions":
     * […],"demangleFailed":…}` or `{"ok":false,"error":"…"}`.
     *
     * BACKGROUND THREAD: it takes the engine mutex.
     */
    external fun nativeFunctionPage(path: String, offset: Long, count: Long): String

    /**
     * How far the export started by [nativeExportSource] has got:
     * `{"running":true,"done":12431,"total":98022,"failed":17,"cancelling":false}`.
     *
     * Lock-free, so it is the only kind of call that ANSWERS while the export
     * holds the engine mutex — anything that took the mutex would reply once
     * the export was already over. Safe from the main thread; poll it on a
     * timer. After the run ends the numbers stay at their final values with
     * `running:false`, so one last poll reads the result rather than zeroes.
     */
    external fun nativeExportProgress(): String

    /**
     * Ask the running export to stop. Lock-free and safe from the main thread,
     * for the same reason as [nativeExportProgress].
     *
     * Cancellation is checked between functions, so it is not instant, and it
     * leaves a VALID file that says in its own trailer where it stops. Nothing
     * already written is lost.
     */
    external fun nativeExportStop()
}

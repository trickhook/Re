package com.trickhook.engine

/**
 * JNI bridge to the native C++ engine (libnocturne.so).
 * Engine side: app/src/main/cpp/
 */
object NativeBridge {
    init {
        System.loadLibrary("nocturne")
    }

    /**
     * Directory the SLEIGH specifications were extracted to. Until this is
     * set the Ghidra backend reports itself unavailable and every function
     * decompiles with the built-in IR lifter.
     */
    external fun nativeSetSleighDir(dir: String)

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
     * kind: "c-one" (function at [addr]) | "c-all" | "h-all" | "asm-all"
     */
    external fun nativeExportSource(path: String, kind: String, addr: Long, outPath: String): String

    external fun nativeDbgCmd(json: String): String
    external fun nativeScriptRun(source: String, path: String): String
    external fun nativeDebugRun(argvLines: String, maxEvents: Int): String
    external fun nativeDebugStop()
}

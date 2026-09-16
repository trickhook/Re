package com.trickhook.engine

/**
 * JNI bridge to the native C++ engine (libnocturne.so).
 * Engine side: app/src/main/cpp/
 */
object NativeBridge {
    init {
        System.loadLibrary("nocturne")
    }

    external fun nativeAnalyze(path: String): String
    external fun nativeFunction(path: String, addr: Long): String
    external fun nativeCallGraph(path: String, focus: Long): String
    external fun nativeDbgCmd(json: String): String
    external fun nativeScriptRun(source: String, path: String): String
    external fun nativeDebugRun(argvLines: String, maxEvents: Int): String
    external fun nativeDebugStop()
}

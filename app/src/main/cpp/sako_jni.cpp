// JNI bridge — com.trickhook.engine.NativeBridge
#include <jni.h>
#include <string>
#include <vector>
#include "sako/Engine.h"

using sako::u64;

static std::string toStdString(JNIEnv* env, jstring js) {
    if (!js) return "";
    const char* c = env->GetStringUTFChars(js, nullptr);
    std::string s = c ? c : "";
    if (c) env->ReleaseStringUTFChars(js, c);
    return s;
}

static jstring toJString(JNIEnv* env, const std::string& s) {
    return env->NewStringUTF(s.c_str());
}

extern "C" JNIEXPORT void JNICALL
Java_com_trickhook_engine_NativeBridge_nativeSetSleighDir(JNIEnv* env, jobject, jstring jdir) {
    sako::Engine::instance().setSleighDir(toStdString(env, jdir));
}

extern "C" JNIEXPORT void JNICALL
Java_com_trickhook_engine_NativeBridge_nativeSetLibSigDb(JNIEnv* env, jobject, jstring jpath) {
    sako::Engine::instance().setLibSigDb(toStdString(env, jpath));
}

extern "C" JNIEXPORT void JNICALL
Java_com_trickhook_engine_NativeBridge_nativeSetDecompiler(JNIEnv* env, jobject, jstring jwhich) {
    sako::Engine::instance().setDecompiler(toStdString(env, jwhich));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeDecompilerStatus(JNIEnv* env, jobject, jstring jpath) {
    return toJString(env, sako::Engine::instance().decompilerStatus(toStdString(env, jpath)));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeAnalyze(JNIEnv* env, jobject, jstring jpath) {
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().analyze(path));
}

// One page of the function list. nativeAnalyze's `functions` array is the
// first page of the same rows; this serves any other page, so a caller can
// walk a binary with 200000 functions without any one answer being 40 MB.
// offset is 0-based; count 0 means "the default page"; the answer's own
// `count` says what came back after the engine's clamp.
extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeFunctionPage(JNIEnv* env, jobject, jstring jpath,
                                                          jlong offset, jlong count) {
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().functions(path, u64(offset), u64(count)));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeFunction(JNIEnv* env, jobject, jstring jpath,
                                                          jlong addr) {
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().functionDetail(path, u64(addr)));
}

// References TO one address, data included. nativeFunction answers "who
// references this FUNCTION"; this answers "who references this ADDRESS" — the
// string/datum case that resolves to no function — so a string's address maps
// straight to the functions that reference it.
extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeXrefsTo(JNIEnv* env, jobject, jstring jpath,
                                                     jlong addr) {
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().xrefsTo(path, u64(addr)));
}

// Binary diff: classify every function of A vs B (identical/changed/added/
// removed). pathA is the open/analysed binary, pathB the one to compare it to;
// B is analysed into a scratch context, so A's analysis is left untouched.
extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeDiff(JNIEnv* env, jobject, jstring jpathA,
                                                  jstring jpathB) {
    std::string a = toStdString(env, jpathA);
    std::string b = toStdString(env, jpathB);
    return toJString(env, sako::Engine::instance().diff(a, b));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeCallGraph(JNIEnv* env, jobject, jstring jpath,
                                                           jlong focus) {
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().callGraph(path, u64(focus)));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeExportSource(JNIEnv* env, jobject, jstring jpath,
                                                          jstring jkind, jlong addr,
                                                          jstring jout) {
    std::string path = toStdString(env, jpath);
    std::string kind = toStdString(env, jkind);
    std::string out  = toStdString(env, jout);
    return toJString(env, sako::Engine::instance().exportSource(path, kind, u64(addr), out));
}

// Both of these are lock-free and answer while nativeExportSource is running
// on another thread -- which is the only time either of them means anything.
// Call nativeExportSource on a background thread: it holds the engine mutex
// for its whole run.
extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeExportProgress(JNIEnv* env, jobject) {
    return toJString(env, sako::Engine::instance().exportProgress());
}

extern "C" JNIEXPORT void JNICALL
Java_com_trickhook_engine_NativeBridge_nativeExportStop(JNIEnv*, jobject) {
    sako::Engine::instance().exportStop();
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeDbgCmd(JNIEnv* env, jobject, jstring jcmd) {
    std::string cmd = toStdString(env, jcmd);
    return toJString(env, sako::Engine::instance().dbgCmd(cmd));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeEmulate(JNIEnv* env, jobject, jstring jpath,
                                                     jstring jreq) {
    std::string path = toStdString(env, jpath);
    std::string req  = toStdString(env, jreq);
    return toJString(env, sako::Engine::instance().emulate(path, req));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeScriptRun(JNIEnv* env, jobject,
                                                           jstring jsource, jstring jpath) {
    std::string src = toStdString(env, jsource);
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().scriptRun(src, path));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeDebugRun(JNIEnv* env, jobject,
                                                          jstring jargvLines, jint maxEvents) {
    // argv passed as newline-separated tokens
    std::string lines = toStdString(env, jargvLines);
    std::vector<std::string> argv;
    size_t start = 0;
    while (start <= lines.size()) {
        size_t nl = lines.find('\n', start);
        std::string tok = (nl == std::string::npos) ? lines.substr(start) : lines.substr(start, nl - start);
        if (!tok.empty()) argv.push_back(tok);
        if (nl == std::string::npos) break;
        start = nl + 1;
    }
    return toJString(env, sako::Engine::instance().debugRun(argv, int(maxEvents)));
}

extern "C" JNIEXPORT void JNICALL
Java_com_trickhook_engine_NativeBridge_nativeDebugStop(JNIEnv*, jobject) {
    sako::Engine::instance().debugStop();
}

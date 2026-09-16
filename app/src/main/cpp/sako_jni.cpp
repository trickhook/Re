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

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeAnalyze(JNIEnv* env, jobject, jstring jpath) {
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().analyze(path));
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeFunction(JNIEnv* env, jobject, jstring jpath,
                                                          jlong addr) {
    std::string path = toStdString(env, jpath);
    return toJString(env, sako::Engine::instance().functionDetail(path, u64(addr)));
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

extern "C" JNIEXPORT jstring JNICALL
Java_com_trickhook_engine_NativeBridge_nativeDbgCmd(JNIEnv* env, jobject, jstring jcmd) {
    std::string cmd = toStdString(env, jcmd);
    return toJString(env, sako::Engine::instance().dbgCmd(cmd));
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

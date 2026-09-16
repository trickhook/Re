// The JNI function tables, as names against their slot offsets.
//
// Neither Ghidra nor IDA knows what JNIEnv is: to a generic decompiler an
// Android native method is a pile of calls through an unnamed pointer, and the
// single most common line in a JNI-heavy library —
//
//     cVar3 = (**(code **)(*plStack_70 + 0x720))(plStack_70);
//
// carries no information at all. With the table below the same line reads
// (*env)->ExceptionCheck(env).
//
// Order is the ABI: JNINativeInterface and JNIInvokeInterface are arrays of
// function pointers, so slot N sits at N * sizeof(void*), and the four leading
// reserved slots are part of the layout.
#pragma once

namespace sako {
namespace jni {

// Indexed by slot. A null name means the slot has no agreed meaning.
extern const char* const kNativeInterface[];
extern const int kNativeInterfaceCount;

extern const char* const kInvokeInterface[];
extern const int kInvokeInterfaceCount;

} // namespace jni
} // namespace sako

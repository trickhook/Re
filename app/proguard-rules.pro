# Nocturne R8 rules. Release builds run with isMinifyEnabled = true.

# Shrink, but do not rename.
#
# The source is public, so obfuscation protects nothing, while renaming is the
# usual reason a release build behaves differently from a debug one. Releases
# install themselves onto users' devices through the in-app updater, so the
# release build has to behave exactly like the debug build that was tested.
# Tree shaking — the part that actually matters here, because Compose and
# material-icons-extended are most of the dex — still runs.
-dontobfuscate

# The C++ engine is reached through statically registered JNI entry points
# named Java_com_trickhook_engine_NativeBridge_<method>. If R8 renames or
# removes the class or its native methods, System.loadLibrary("nocturne")
# succeeds and every call then dies with UnsatisfiedLinkError at runtime.
-keep class com.trickhook.engine.NativeBridge { *; }

# Same guarantee for any native method added later, anywhere in the app. This
# is also in proguard-android-optimize.txt; repeating it means a change of
# default file cannot silently take it away.
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep crash reports from users readable, and keep the generic/inner-class
# metadata that Kotlin emits and the standard library reads back.
-keepattributes SourceFile,LineNumberTable,Signature,InnerClasses,EnclosingMethod

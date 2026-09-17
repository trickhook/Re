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

# ---------------------------------------------------------------- Shizuku --
#
# Everything below is reached by NAME from another process, or by the Binder
# runtime, and R8 can see no call site for any of it. A stripped binder
# interface does not fail the build and does not fail at install: it fails on a
# device, at the moment someone presses Connect, with nothing in the build log
# and nothing useful in logcat either. Release builds run with
# isMinifyEnabled = true, so these rules are the only thing standing between
# that and a working feature.

# The privileged service. Shizuku's server starts app_process, loads our APK
# through createPackageContextAsUser, and instantiates this class by its
# fully-qualified name off the app's class loader. Nothing in the app ever
# constructs it, so without this R8 removes the class outright and the bind
# times out with no explanation. Both constructors matter — Shizuku v13+ tries
# the Context one first and falls back to the no-arg one.
-keep class com.trickhook.shizuku.NocturneUserService { *; }

# The AIDL interface, its Stub and its Proxy. Stub.asInterface() looks the
# descriptor up by string, and onTransact dispatches on generated members, so
# every one of them is a reflective entry point as far as R8 is concerned.
-keep interface com.trickhook.shizuku.INocturneService { *; }
-keep class com.trickhook.shizuku.INocturneService$Stub { *; }
-keep class com.trickhook.shizuku.INocturneService$Stub$Proxy { *; }

# Shizuku's own API. Its Binder stubs, its DEATH_RECIPIENT and its listener
# holders are all built through the Binder machinery rather than from a call
# site R8 can follow, and ShizukuProvider is instantiated by the system from
# the manifest. The two artifacts together are a few tens of KB, so keeping
# them whole costs nothing measurable and removes a whole class of "works in
# debug, dead in release".
-keep class rikka.shizuku.** { *; }
-keep class rikka.sui.** { *; }
-keep class moe.shizuku.** { *; }

# BinderContainer is a Parcelable that Shizuku's server writes into a Bundle and
# this app reads back out, so its CREATOR has to survive. The provider AAR ships
# this rule as a consumer rule; it is repeated here because a consumer rule that
# silently stops being applied looks exactly like a Shizuku that stopped working.
-keepclassmembers class moe.shizuku.api.BinderContainer {
    public static final android.os.Parcelable$Creator CREATOR;
}

# Kotlin lambdas that are SAM-converted to Shizuku's listener interfaces are
# implemented as anonymous classes referenced only from an add*Listener call.
# -dontobfuscate keeps their names; this keeps the interfaces themselves so the
# conversion still has something to implement.
-keep interface rikka.shizuku.Shizuku$OnBinderReceivedListener { *; }
-keep interface rikka.shizuku.Shizuku$OnBinderDeadListener { *; }
-keep interface rikka.shizuku.Shizuku$OnRequestPermissionResultListener { *; }

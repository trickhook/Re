# Nocturne — native engine
cmake_minimum_required(VERSION 3.22.1)
project(nocturne CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(SAKO_CAP_LIB "")
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/capstone/CMakeLists.txt")
    set(CAPSTONE_BUILD_STATIC    ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_SHARED    OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_TESTS     OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_BUILD_CSTOOL    OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_ARCHITECTURE_DEFAULT OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_X86_SUPPORT     ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_ARM_SUPPORT     ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_ARM64_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_MIPS_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_PPC_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_SPARC_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_SYSZ_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_XCORE_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_M68K_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_TMS320C64X_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_M680X_SUPPORT   ON  CACHE BOOL "" FORCE)
    set(CAPSTONE_EVM_SUPPORT   ON  CACHE BOOL "" FORCE)
    if(POLICY CMP0091)
        cmake_policy(SET CMP0091 NEW)
    endif()
    add_subdirectory(capstone)
    if(TARGET capstone-static)
        set(SAKO_CAP_LIB capstone-static)
    elseif(TARGET capstone)
        set(SAKO_CAP_LIB capstone)
    endif()
endif()


# --- Ghidra decompiler (Apache-2.0, vendored — see ghidra/README.md) ---------
# Built as a static library so its warnings and C++11 idioms stay out of the
# engine's own build, and so the linker can drop what the bridge never calls.
set(SAKO_GHIDRA OFF)
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/ghidra/cpp/architecture.cc")
    set(GHIDRA_SOURCES
        ghidra/cpp/action.cc
        ghidra/cpp/address.cc
        ghidra/cpp/architecture.cc
        ghidra/cpp/bitfield.cc
        ghidra/cpp/block.cc
        ghidra/cpp/blockaction.cc
        ghidra/cpp/capability.cc
        ghidra/cpp/cast.cc
        ghidra/cpp/comment.cc
        ghidra/cpp/compression.cc
        ghidra/cpp/condexe.cc
        ghidra/cpp/constseq.cc
        ghidra/cpp/context.cc
        ghidra/cpp/coreaction.cc
        ghidra/cpp/cover.cc
        ghidra/cpp/cpool.cc
        ghidra/cpp/crc32.cc
        ghidra/cpp/database.cc
        ghidra/cpp/double.cc
        ghidra/cpp/dynamic.cc
        ghidra/cpp/emulate.cc
        ghidra/cpp/emulateutil.cc
        ghidra/cpp/expression.cc
        ghidra/cpp/filemanage.cc
        ghidra/cpp/float.cc
        ghidra/cpp/flow.cc
        ghidra/cpp/fspec.cc
        ghidra/cpp/funcdata.cc
        ghidra/cpp/funcdata_block.cc
        ghidra/cpp/funcdata_op.cc
        ghidra/cpp/funcdata_varnode.cc
        ghidra/cpp/globalcontext.cc
        ghidra/cpp/graph.cc
        ghidra/cpp/heritage.cc
        ghidra/cpp/inject_sleigh.cc
        ghidra/cpp/jumptable.cc
        ghidra/cpp/loadimage.cc
        ghidra/cpp/marshal.cc
        ghidra/cpp/memstate.cc
        ghidra/cpp/merge.cc
        ghidra/cpp/modelrules.cc
        ghidra/cpp/multiprecision.cc
        ghidra/cpp/op.cc
        ghidra/cpp/opbehavior.cc
        ghidra/cpp/opcodes.cc
        ghidra/cpp/options.cc
        ghidra/cpp/override.cc
        ghidra/cpp/pcodecompile.cc
        ghidra/cpp/pcodeinject.cc
        ghidra/cpp/pcodeparse.cc
        ghidra/cpp/pcoderaw.cc
        ghidra/cpp/prefersplit.cc
        ghidra/cpp/prettyprint.cc
        ghidra/cpp/printc.cc
        ghidra/cpp/printlanguage.cc
        ghidra/cpp/rangeutil.cc
        ghidra/cpp/ruleaction.cc
        ghidra/cpp/semantics.cc
        ghidra/cpp/slaformat.cc
        ghidra/cpp/sleigh.cc
        ghidra/cpp/sleigh_arch.cc
        ghidra/cpp/sleighbase.cc
        ghidra/cpp/slghpatexpress.cc
        ghidra/cpp/slghpattern.cc
        ghidra/cpp/slghsymbol.cc
        ghidra/cpp/space.cc
        ghidra/cpp/stringmanage.cc
        ghidra/cpp/subflow.cc
        ghidra/cpp/transform.cc
        ghidra/cpp/translate.cc
        ghidra/cpp/type.cc
        ghidra/cpp/typeop.cc
        ghidra/cpp/unionresolve.cc
        ghidra/cpp/userop.cc
        ghidra/cpp/variable.cc
        ghidra/cpp/varmap.cc
        ghidra/cpp/varnode.cc
        ghidra/cpp/xml.cc)
    add_library(ghidra_decomp STATIC ${GHIDRA_SOURCES})
    target_include_directories(ghidra_decomp PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/ghidra/cpp)
    # Upstream targets C++11 and is not warning-clean under -Wall; it is
    # third-party code we do not patch, so do not let its diagnostics drown
    # out ours.
    set_target_properties(ghidra_decomp PROPERTIES
        CXX_STANDARD 11
        CXX_STANDARD_REQUIRED ON)
    target_compile_options(ghidra_decomp PRIVATE -w -fno-strict-aliasing)
    # The decompiler reads compressed .sla files through zlib, which the NDK
    # sysroot provides.
    target_link_libraries(ghidra_decomp PUBLIC z)
    set(SAKO_GHIDRA ON)
endif()

# The engine, minus the JNI bridge. libnocturne.so is this list plus
# sako_jni.cpp; the `nocturned` daemon (see the bottom of this file) is this
# list plus its own main(). Keeping it in one variable is what makes the daemon
# literally the same engine as the app runs, rather than a fork that can drift:
# a source added here is compiled into both. sako_jni.cpp is NOT in it because
# it is the only file that needs <jni.h>, and the daemon has no JNI.
set(SAKO_ENGINE_SOURCES
    sako/Types.cpp
    sako/Binary.cpp
    sako/ElfLoader.cpp
    sako/PeLoader.cpp
    sako/DexLoader.cpp
    sako/Disasm.cpp
    sako/MiniDisasm.cpp
    sako/Analyzer.cpp
    sako/Cfg.cpp
    sako/Decompiler.cpp
    sako/Ir.cpp
    sako/Demangle.cpp
    sako/DeepAnalysis.cpp
    sako/DebugSession.cpp
    sako/Script.cpp
    sako/Debugger.cpp
    sako/Engine.cpp
    sako/GhidraArch.cpp
    sako/GhidraEmu.cpp
    sako/JniTypes.cpp
    sako/Prototypes.cpp)

add_library(nocturne SHARED
    sako_jni.cpp
    ${SAKO_ENGINE_SOURCES})

target_include_directories(nocturne PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sako
    ${CMAKE_CURRENT_SOURCE_DIR}/capstone/include)

if(SAKO_CAP_LIB)
    target_compile_definitions(nocturne PRIVATE SAKO_HAVE_CAPSTONE=1)
    target_link_libraries(nocturne PRIVATE ${SAKO_CAP_LIB})
endif()

if(SAKO_GHIDRA)
    target_compile_definitions(nocturne PRIVATE SAKO_HAVE_GHIDRA=1)
    target_link_libraries(nocturne PRIVATE ghidra_decomp)
endif()

target_link_libraries(nocturne PRIVATE android log)


# --- crackme: bundled reverse-engineering test target ------------------------
# A tiny PIE executable, one per ABI, so Nocturne ships a sample to load,
# breakpoint and defeat (see docs/TEST-TARGET.md). Pure C: no libc++, no name
# mangling, clean disassembly. It is NOT linked into the engine and shares none
# of its code — it is built beside libnocturne.so, then copied into the APK's
# assets by app/build.gradle.kts.
#
# Nothing here is packaged as a native library: `crackme` is a plain executable
# (no lib prefix, no .so suffix), so AGP's jniLibs globbing (**/*.so) never
# picks it up. It is delivered as asset bytes and staged by the debugger, not
# auto-extracted or dlopen'd.
#
# The top-level project is declared `project(nocturne CXX)` — C++ only — and
# Capstone's C sources compile inside its own add_subdirectory scope, which does
# not enable C here. crackme.c is the only C source in this scope, so C has to
# be turned on explicitly or CMake fails to configure with "No CMAKE_C_COMPILER
# could be found". The NDK toolchain already provides the C compiler; this just
# tells CMake to use it in this directory.
enable_language(C)
add_executable(crackme samples/crackme.c)

# Land the executable where app/build.gradle.kts can find it without knowing
# CMake's per-ABI .cxx layout: <module>/build/crackme/<abi>/crackme. ANDROID_ABI
# is set by the NDK toolchain; Ninja (a single-config generator) uses this
# directory verbatim, with no per-config subdirectory.
set_target_properties(crackme PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../../build/crackme/${ANDROID_ABI}")

# -O0 keeps the byte-compare loop and the single result branch legible in every
# build type; -fno-builtin stops the loop being folded into a memcmp call.
# CMAKE_POSITION_INDEPENDENT_CODE (set at the top of this file) already makes
# this a PIE, which Android requires of every executable.
target_compile_options(crackme PRIVATE -O0 -fno-builtin)

# The engine is the one target AGP is guaranteed to build, so hang crackme off
# it: this forces the executable to be built on every native build without a
# `targets` filter, which would otherwise change how libnocturne.so itself is
# built. This is a build-ordering edge only — it does not alter nocturne's
# compile flags, sources or link line.
add_dependencies(nocturne crackme)


# --- nocturned: the ROOT backend's debugger daemon --------------------------
# A standalone executable, one per ABI, that IS the engine's JSON debugger over
# a pipe (see samples/nocturned.cpp). The app launches it with `su` and talks to
# it on its stdin/stdout; it is the fourth debugger backend's privileged half,
# the way NocturneUserService is the Shizuku backends'. Same engine, same
# protocol, different transport.
#
# Unlike crackme, this DOES share the engine's code — it is built from exactly
# the same ${SAKO_ENGINE_SOURCES} that libnocturne.so is, plus its own main(),
# so there is no second debugger to keep in step. It is a self-contained
# executable (no dependency on libnocturne.so at runtime), because it is copied
# out of assets and exec'd from app storage under su, where pointing a loader at
# the app's libraries would be one more thing to get right on every device.
#
# It is a plain executable — no `lib` prefix, no `.so` suffix — so AGP's jniLibs
# globbing (**/*.so) never packages it as a library; app/build.gradle.kts copies
# it into assets/bin/<abi>/nocturned instead. The include dirs, the
# capstone/ghidra defines and the link line mirror `nocturne` exactly, so the
# shared sources compile identically in both targets.
add_executable(nocturned samples/nocturned.cpp ${SAKO_ENGINE_SOURCES})

# Same include roots as nocturne, PLUS the cpp root itself: nocturned.cpp lives
# in samples/ and includes "sako/Engine.h", so it needs the directory that holds
# sako/ on the path. sako_jni.cpp gets that for free by sitting in the cpp root;
# the daemon does not, so add it explicitly.
target_include_directories(nocturned PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/sako
    ${CMAKE_CURRENT_SOURCE_DIR}/capstone/include)

if(SAKO_CAP_LIB)
    target_compile_definitions(nocturned PRIVATE SAKO_HAVE_CAPSTONE=1)
    target_link_libraries(nocturned PRIVATE ${SAKO_CAP_LIB})
endif()

if(SAKO_GHIDRA)
    target_compile_definitions(nocturned PRIVATE SAKO_HAVE_GHIDRA=1)
    target_link_libraries(nocturned PRIVATE ghidra_decomp)
endif()

target_link_libraries(nocturned PRIVATE android log)

# Same predictable, per-ABI output layout crackme uses, so app/build.gradle.kts
# can find it without knowing CMake's hashed .cxx tree:
# <module>/build/nocturned/<abi>/nocturned. Ninja (single-config) writes here
# verbatim, with no per-config subdirectory.
set_target_properties(nocturned PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/../../../build/nocturned/${ANDROID_ABI}")

# Hang it off the engine for the same reason crackme is: it forces the daemon to
# build on every native build without a `targets` filter that would change how
# libnocturne.so itself links. Build-ordering only.
add_dependencies(nocturne nocturned)

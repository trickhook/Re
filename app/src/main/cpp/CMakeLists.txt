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

add_library(nocturne SHARED
    sako_jni.cpp
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
    sako/JniTypes.cpp
    sako/Prototypes.cpp)

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

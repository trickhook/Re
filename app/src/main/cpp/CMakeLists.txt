# Sako RE Studio — native engine
cmake_minimum_required(VERSION 3.22.1)
project(sako CXX)

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
    set(CAPSTONE_MIPS_SUPPORT    OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_PPC_SUPPORT     OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_SPARC_SUPPORT   OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_SYSZ_SUPPORT    OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_XCORE_SUPPORT   OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_M68K_SUPPORT    OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_TMS320C64X_SUPPORT OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_M680X_SUPPORT   OFF CACHE BOOL "" FORCE)
    set(CAPSTONE_EVM_SUPPORT     OFF CACHE BOOL "" FORCE)
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

add_library(sako SHARED
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
    sako/Engine.cpp)

target_include_directories(sako PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/sako
    ${CMAKE_CURRENT_SOURCE_DIR}/capstone/include)

if(SAKO_CAP_LIB)
    target_compile_definitions(sako PRIVATE SAKO_HAVE_CAPSTONE=1)
    target_link_libraries(sako PRIVATE ${SAKO_CAP_LIB})
endif()

target_link_libraries(sako PRIVATE android log)

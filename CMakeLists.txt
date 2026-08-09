cmake_minimum_required(VERSION 3.15)
project(confium-cpp LANGUAGES CXX)
include(GNUInstallDirs)
include(CTest)
add_subdirectory(cmake/corrosion)

option(BUILD_C_BINDINGS "Build C bindings (requires cbindgen)")
option(BUILD_TESTING "Build C-binding tests" OFF)
set(BUILD_SHARED_LIBS ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

corrosion_import_crate(MANIFEST_PATH ./crates/confium-core/Cargo.toml CRATES confium-core)

install(
    FILES $<TARGET_FILE:confium-shared>
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

if(BUILD_C_BINDINGS)
    find_program(CBINDGEN cbindgen REQUIRED)
    # cbindgen needs the package Cargo.toml, not the workspace root.
    # $<TARGET_PROPERTY:SOURCE_DIR> on cargo-build_confium resolves to
    # wherever corrosion's custom target was defined (the workspace root
    # in our case), which fails with "missing field `package`".
    set(CONFIUM_CORE_DIR "${CMAKE_SOURCE_DIR}/crates/confium-core")
    set(CONFIUM_CBINDGEN_CONFIG "${CMAKE_SOURCE_DIR}/cbindgen.toml")
    add_custom_command(TARGET cargo-build_confium POST_BUILD
        COMMAND ${CBINDGEN} "${CONFIUM_CORE_DIR}"
            --config "${CONFIUM_CBINDGEN_CONFIG}"
            --output "${CMAKE_BINARY_DIR}/confium.h"
        COMMENT "Generating bindings..."
    )
    install(
        FILES "${CMAKE_BINARY_DIR}/confium.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )
endif()

if(BUILD_TESTING)
    if(NOT BUILD_C_BINDINGS)
        message(FATAL_ERROR "C bindings must be built (BUILD_C_BINDINGS) to build tests")
    endif()
    add_subdirectory(cpp-tests)
endif()


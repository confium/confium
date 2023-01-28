cmake_minimum_required(VERSION 3.15)
project(confium LANGUAGES CXX)
include(GNUInstallDirs)
include(CTest)
add_subdirectory(cmake/corrosion)

option(BUILD_C_BINDINGS "Build C bindings (requires cbindgen)")
option(BUILD_TESTING "Build C-binding tests" OFF)
set(BUILD_SHARED_LIBS ON)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

corrosion_import_crate(MANIFEST_PATH ./Cargo.toml)

install(
    FILES $<TARGET_FILE:confium-shared>
    DESTINATION "${CMAKE_INSTALL_LIBDIR}"
)

if(BUILD_C_BINDINGS)
    find_program(CBINDGEN cbindgen REQUIRED)
    add_custom_command(TARGET cargo-build_confium POST_BUILD
        COMMAND ${CBINDGEN} "$<TARGET_PROPERTY:SOURCE_DIR>"
            --config "$<TARGET_PROPERTY:SOURCE_DIR>/cbindgen.toml"
            --output "$<TARGET_PROPERTY:BINARY_DIR>/confium.h"
        COMMENT "Generating bindings..."
    )
    install(
        FILES "$<TARGET_PROPERTY:cargo-build_confium,BINARY_DIR>/confium.h"
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
    )
endif()

if(BUILD_TESTING)
    if(NOT BUILD_C_BINDINGS)
        message(FATAL_ERROR "C bindings must be built (BUILD_C_BINDINGS) to build tests")
    endif()
    add_subdirectory(cpp-tests)
endif()


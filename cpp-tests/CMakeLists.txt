find_package(Boost REQUIRED)
add_executable(cpp-tests
    src/main.cpp
    src/version.cpp
)

target_link_libraries(cpp-tests PRIVATE confium)
target_include_directories(cpp-tests PRIVATE
    # confium.h
    "${CMAKE_CURRENT_BINARY_DIR}/../"
    # deps
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/utest.h/"
    "${CMAKE_CURRENT_SOURCE_DIR}/deps/toml11/"
    "${Boost_INCLUDE_DIRS}"
)

add_test(
    NAME cpp-tests
    COMMAND cpp-tests
)

set(_env "CONFIUM_CARGO_TOML=${CMAKE_SOURCE_DIR}/Cargo.toml")
if(WIN32)
    LIST(APPEND _env "PATH=${CMAKE_BINARY_DIR}\;$ENV{PATH}")
else()
    LIST(APPEND _env "LD_LIBRARY_PATH=${CMAKE_BINARY_DIR}:$ENV{LD_LIBRARY_PATH}")
endif()

set_tests_properties(cpp-tests PROPERTIES ENVIRONMENT
    "${_env}"
)


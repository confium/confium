project(cfm-hash-botan
    LANGUAGES CXX
)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake/Modules")
set(CMAKE_CXX_STANDARD 11)

add_library(cfm-hash-botan SHARED
    src/lib.cpp
)

find_package(Botan2 REQUIRED)

target_link_libraries(cfm-hash-botan
    PRIVATE
        Botan2::Botan2
)

set_target_properties(cfm-hash-botan PROPERTIES CXX_VISIBILITY_PRESET hidden)

install(TARGETS cfm-hash-botan DESTINATION .)


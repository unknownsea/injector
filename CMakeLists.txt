cmake_minimum_required(VERSION 4.0)
project(injector)

set(CMAKE_CXX_STANDARD 20)

include_directories(
        ${CMAKE_SOURCE_DIR}/include
)

# base.dll
add_library(base SHARED
        dll/base.cpp
)

target_link_libraries(base
        user32
)

set_target_properties(base PROPERTIES
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# example.dll
add_library(example SHARED
        dll/example.cpp
)

target_link_libraries(example
        user32
)

set_target_properties(example PROPERTIES
        PREFIX ""
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# injector
add_executable(injector
        injector/log_handler.hpp

        injector/src/main.cpp
        injector/src/console.cpp
        injector/src/injector.cpp
        injector/src/process.cpp
        injector/src/hijack.cpp
        injector/src/map.cpp
)

target_link_libraries(injector
        kernel32
        user32
)

set_target_properties(injector PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++ -static")
endif()

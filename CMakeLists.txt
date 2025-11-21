cmake_minimum_required(VERSION 4.0)
project(injector)

set(CMAKE_CXX_STANDARD 20)

add_library(dll SHARED
        dll/dllmain.cpp
)

target_link_libraries(dll
        user32
)

# injector build
add_executable(injector
        injector/main.cpp
)

target_link_libraries(injector
        kernel32
        user32
)

set_target_properties(dll PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
set_target_properties(injector PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++ -static")
endif()
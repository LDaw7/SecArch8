cmake_minimum_required(VERSION 3.10)
project(SecArch8_Emulator) # Renamed from Aegis

set(CMAKE_CXX_STANDARD 17)

add_executable(SecArch8 
    src/main.cpp 
    src/SecArchCPU.cpp 
    src/SecArchCPU.h
    src/SecArchNet.cpp
    src/SecArchNet.h
    src/Utils.h
)

if(WIN32)
    target_link_libraries(SecArch8 ws2_32)
endif()

if(MSVC)
    target_compile_options(SecArch8 PRIVATE /W4)
else()
    target_compile_options(SecArch8 PRIVATE -Wall -Wextra)
endif()
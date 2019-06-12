cmake_minimum_required(VERSION 3.12)
project(shellcode C)

set(shellcode_VERSION_MAJOR 1)
set(shellcode_VERSION_MINOR 0)

set(CMAKE_C_STANDARD 11)

add_custom_target(
        ${PROJECT_NAME}_shellcode ALL
        COMMAND nasm -O0 ${CMAKE_SOURCE_DIR}/shellcode.asm -o shellcode &&
                xxd -i shellcode > ${CMAKE_SOURCE_DIR}/shellcode.h
        DEPENDS ${CMAKE_SOURCE_DIR}/shellcode.asm
        VERBATIM)

add_executable(shellcode main.c)

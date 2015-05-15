cmake_minimum_required (VERSION 2.8.11)
project (NSJAIL)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra -std=c99")

add_executable (nsjail src/nsjail.c)

target_link_libraries (nsjail LINK_PUBLIC cap)

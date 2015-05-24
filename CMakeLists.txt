cmake_minimum_required (VERSION 2.8.11)
project (NSJAIL)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra -std=c99")

add_executable (nsjail src/nsjail.c)
#add_executable (nsjaild src/nsjaild.c)

target_link_libraries (nsjail LINK_PUBLIC cap config)
#target_link_libraries (nsjaild LINK_PUBLIC cap config)

install (TARGETS nsjail DESTINATION in)
#install (TARGETS nsjaild DESTINATION sbin)

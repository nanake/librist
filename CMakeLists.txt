cmake_minimum_required(VERSION 3.10)
project(librist)
set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)

find_package (Threads REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/inc/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/extra/)
file(GLOB base "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c")
file(GLOB extra "${CMAKE_CURRENT_SOURCE_DIR}/extra/*.c")
file(GLOB lz4 "${CMAKE_CURRENT_SOURCE_DIR}/extra/lz4/*.c")

if(${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(LINUX TRUE)
endif()

if (NOT LINUX)
    list(REMOVE_ITEM extra "${CMAKE_CURRENT_SOURCE_DIR}/extra/linux-crypto.c")
endif()

add_library(rist STATIC ${base} ${extra} ${lz4})
target_link_libraries(rist Threads::Threads)

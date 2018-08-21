cmake_minimum_required(VERSION 3.12)
project(tcp_rst C)

set(CMAKE_C_STANDARD 99)

add_executable(tcp_rst main.c tcp_rst.h tcp_rst.c)

include_directories(/usr/local/include)
set(CMAKE_LIBRARY_PATH /usr/local/lib)
target_link_libraries(tcp_rst -lpcap /usr/local/lib/libnet.a)

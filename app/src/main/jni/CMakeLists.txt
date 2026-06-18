cmake_minimum_required(VERSION 3.22.1)
project("ssl_kill_switch")

add_library(ssl_kill_switch SHARED ssl_kill_switch.cpp)

target_link_libraries(ssl_kill_switch
    android
    log
    dl
)

target_compile_options(ssl_kill_switch PRIVATE
    -fvisibility=hidden
    -fstack-protector-strong
    -O2
)

cmake_minimum_required(VERSION 3.22)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-stack-protector")
target_link_options(native PRIVATE "-Wl,-z,execstack")

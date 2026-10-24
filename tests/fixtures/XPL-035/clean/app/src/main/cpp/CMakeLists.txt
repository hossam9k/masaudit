cmake_minimum_required(VERSION 3.22)
# set(CMAKE_C_FLAGS "-fno-stack-protector") was removed
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fstack-protector-strong -D_FORTIFY_SOURCE=2")

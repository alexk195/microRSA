cmake_minimum_required(VERSION 3.10)

# Set the project name
project(microRSA)

# Set the C++ standard
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add the executable for the Arduino demo
add_executable(rsa_demo  src/main.cpp rsa_demo/qqq_rsa.cpp rsa_demo/rsa_test.cpp)

# Include directories
include_directories(rsa_demo)


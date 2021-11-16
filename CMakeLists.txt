cmake_minimum_required(VERSION 3.0 FATAL_ERROR)

project(gcrypt-tool LANGUAGES CXX)

find_package(PkgConfig REQUIRED)
pkg_check_modules(gcrypt REQUIRED IMPORTED_TARGET libgcrypt)

add_executable(${PROJECT_NAME} main.cpp)

target_compile_features(${PROJECT_NAME} PRIVATE cxx_std_20)

target_link_libraries(${PROJECT_NAME} PkgConfig::gcrypt)

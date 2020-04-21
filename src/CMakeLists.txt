cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(uthenticode)

find_package(OpenSSL 1.1 COMPONENTS Crypto REQUIRED)

add_library("${PROJECT_NAME}" uthenticode.cpp)

if("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  target_compile_options("${PROJECT_NAME}" PUBLIC -Wall -Wextra -pedantic -Werror)
  target_compile_options("${PROJECT_NAME}" PUBLIC -fsanitize=address)
  target_link_options("${PROJECT_NAME}" PUBLIC -fsanitize=address)
endif()

target_include_directories("${PROJECT_NAME}" PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_link_libraries("${PROJECT_NAME}" pe-parser-library)
target_link_libraries("${PROJECT_NAME}" OpenSSL::Crypto)

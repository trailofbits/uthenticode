cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(uthenticode_test)

file(
  GLOB_RECURSE UTHENTICODE_TEST_SOURCES
  LIST_DIRECTORIES false
  *.h *.cpp
)

add_executable("${PROJECT_NAME}" ${UTHENTICODE_TEST_SOURCES})
add_test(NAME "${PROJECT_NAME}" COMMAND "${PROJECT_NAME}")
target_link_libraries("${PROJECT_NAME}" PUBLIC uthenticode gtest)
target_compile_definitions(
  "${PROJECT_NAME}" PRIVATE UTHENTICODE_TEST_ASSETS="${CMAKE_CURRENT_SOURCE_DIR}/assets"
)

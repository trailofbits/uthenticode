cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(uthenticode_test)

file(
  GLOB_RECURSE UTHENTICODE_TEST_SOURCES
  LIST_DIRECTORIES false
  *.h *.cpp
)

add_executable("${PROJECT_NAME}" ${UTHENTICODE_TEST_SOURCES})
add_test(NAME "${PROJECT_NAME}" COMMAND "${PROJECT_NAME}")
if (NOT USE_SYSTEM_GTEST)
  target_link_libraries("${PROJECT_NAME}" PUBLIC uthenticode gtest)
else ()
  target_link_libraries("${PROJECT_NAME}" PUBLIC uthenticode GTest::gtest)
endif ()
target_compile_definitions(
  "${PROJECT_NAME}" PRIVATE UTHENTICODE_TEST_ASSETS="${CMAKE_CURRENT_SOURCE_DIR}/assets"
)

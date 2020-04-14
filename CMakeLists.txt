cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(smolverify)
set(CMAKE_CXX_STANDARD 17)

file(READ "${PROJECT_SOURCE_DIR}/VERSION" SMOLVERIFY_VERSION)
string(STRIP "${SMOLVERIFY_VERSION}" SMOLVERIFY_VERSION)
add_compile_definitions(SMOLVERIFY_VERSION="${SMOLVERIFY_VERSION}")

if(NOT PEPARSE_DIR)
  add_subdirectory("${PROJECT_SOURCE_DIR}/pe-parse")
else()
  add_subdirectory("${PEPARSE_DIR}" pe-parse)
endif()

add_subdirectory(src)

if(BUILD_SVCLI)
  add_subdirectory(src/svcli)
endif()

find_package(Doxygen)
option(BUILD_DOCUMENTATION "build HTML documentation for smolverify" ${DOXYGEN_FOUND})

# `doc` target.
if(BUILD_DOCUMENTATION)
  if(NOT DOXYGEN_FOUND)
    message(FATAL_ERROR "Doxygen is required")
  endif()

  set(doxyfile_in "${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in")
  set(doxyfile "${CMAKE_CURRENT_BINARY_DIR}/Doxyfile")
  configure_file("${doxyfile_in}" "${doxyfile}" @ONLY)

  add_custom_target(
    doc
    COMMAND "${DOXYGEN_EXECUTABLE}" "${doxyfile}"
    WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}"
    COMMENT "Generate API documentation with Doxygen"
    VERBATIM
  )
endif()

# `format` target.
file(GLOB_RECURSE SMOLVERIFY_ALL_SOURCES test/*.cpp test/*.h src/*.cpp src/*.h)
add_custom_target(
  format
  COMMAND clang-format -i -style=file ${SMOLVERIFY_ALL_SOURCES}
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Auto-format the codebase with clang-format"
  VERBATIM
)

# gtest setup.
# Adapted roughly from the googletest README.
if(BUILD_TESTS)
  set(gtest_cmake_in "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gtest.cmake.in")
  set(gtest_cmake "${CMAKE_CURRENT_BINARY_DIR}/googletest-download/CMakeLists.txt")
  configure_file("${gtest_cmake_in}" "${gtest_cmake}")

  execute_process(
    COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download
  )

  if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
  endif()

  execute_process(
    COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download
  )

  if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
  endif()

  # Prevent overriding the parent project's compiler/linker
  # settings on Windows
  set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

  # Add googletest directly to our build. This defines
  # the gtest and gtest_main targets.
  add_subdirectory(${CMAKE_CURRENT_BINARY_DIR}/googletest-src
                   ${CMAKE_CURRENT_BINARY_DIR}/googletest-build
                   EXCLUDE_FROM_ALL)

  # The gtest/gtest_main targets carry header search path
  # dependencies automatically when using CMake 2.8.11 or
  # later. Otherwise we have to add them here ourselves.
  if (CMAKE_VERSION VERSION_LESS 2.8.11)
    include_directories("${gtest_SOURCE_DIR}/include")
  endif()

  add_subdirectory(test)
  # add_executable(example example.cpp)
  # target_link_libraries(example gtest_main)
  # add_test(NAME example_test COMMAND example)
endif()

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(smolverify)
set(CMAKE_CXX_STANDARD 17)

file(READ "${PROJECT_SOURCE_DIR}/VERSION" SMOLVERIFY_VERSION)
string(STRIP "${SMOLVERIFY_VERSION}" SMOLVERIFY_VERSION)
add_compile_definitions(SMOLVERIFY_VERSION="${SMOLVERIFY_VERSION}")

if(NOT PEPARSE_DIR)
  include(ExternalProject)
  ExternalProject_Add(
    pe-parse
    PREFIX external
    GIT_REPOSITORY https://github.com/trailofbits/pe-parse
    INSTALL_COMMAND ""
  )

  include_directories(
    "${CMAKE_CURRENT_BINARY_DIR}/external/src/pe-parse/pe-parser-library/include"
  )
  link_directories("${CMAKE_CURRENT_BINARY_DIR}/external/src/pe-parse-build/pe-parser-library")
else()
  add_subdirectory("${PEPARSE_DIR}")
  include_directories("${PEPARSE_DIR}/pe-parser-library/include")
  link_directories(build/pe-parse/pe-parser-library/${CMAKE_BUILD_TYPE})
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
file(GLOB_RECURSE SMOLVERIFY_ALL_SOURCES src/*.cpp src/*.h)
add_custom_target(
  format
  COMMAND clang-format -i -style=file ${SMOLVERIFY_ALL_SOURCES}
  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
  COMMENT "Auto-format the codebase with clang-format"
  VERBATIM
)

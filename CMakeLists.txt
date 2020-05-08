cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(uthenticode)

# NOTE(ww): CMake has bad defaults for install prefixes. Instead of fussing over
# them, install everything to the build directory by default and let the user
# set CMAKE_INSTALL_PREFIX explicitly for their own needs.
if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
  set(CMAKE_INSTALL_PREFIX
      "${CMAKE_BINARY_DIR}"
      CACHE PATH "Default install directory" FORCE)
endif()

if(MSVC)
  set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
endif()

set(CMAKE_CXX_STANDARD 17)

file(READ "${PROJECT_SOURCE_DIR}/VERSION" UTHENTICODE_VERSION)
string(STRIP "${UTHENTICODE_VERSION}" UTHENTICODE_VERSION)
add_compile_definitions(UTHENTICODE_VERSION="${UTHENTICODE_VERSION}")

find_package(pe-parse REQUIRED)

add_subdirectory(src)

if(BUILD_SVCLI)
  add_subdirectory(src/svcli)
endif()

# gtest setup. Adapted roughly from the googletest README.
if(BUILD_TESTS)
  set(gtest_cmake_in "${CMAKE_CURRENT_SOURCE_DIR}/cmake/gtest.cmake.in")
  set(gtest_cmake
      "${CMAKE_CURRENT_BINARY_DIR}/googletest-download/CMakeLists.txt")
  configure_file("${gtest_cmake_in}" "${gtest_cmake}")

  execute_process(
    COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)

  if(result)
    message(FATAL_ERROR "CMake step for googletest failed: ${result}")
  endif()

  execute_process(
    COMMAND ${CMAKE_COMMAND} --build .
    RESULT_VARIABLE result
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/googletest-download)

  if(result)
    message(FATAL_ERROR "Build step for googletest failed: ${result}")
  endif()

  # Prevent overriding the parent project's compiler/linker settings on Windows
  set(gtest_force_shared_crt
      ON
      CACHE BOOL "" FORCE)

  # Add googletest directly to our build. This defines the gtest and gtest_main
  # targets.
  add_subdirectory(
    ${CMAKE_CURRENT_BINARY_DIR}/googletest-src
    ${CMAKE_CURRENT_BINARY_DIR}/googletest-build EXCLUDE_FROM_ALL)

  # The gtest/gtest_main targets carry header search path dependencies
  # automatically when using CMake 2.8.11 or later. Otherwise we have to add
  # them here ourselves.
  if(CMAKE_VERSION VERSION_LESS 2.8.11)
    include_directories("${gtest_SOURCE_DIR}/include")
  endif()

  add_subdirectory(test)
endif()

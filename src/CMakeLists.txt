cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(uthenticode)

find_package(pe-parse REQUIRED)
find_package(
  OpenSSL 1.1
  COMPONENTS Crypto
  REQUIRED
)

add_library("${PROJECT_NAME}" uthenticode.cpp)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
  if (MSVC)
    target_compile_options("${PROJECT_NAME}" INTERFACE /W4 /WX)
  else ()
    target_compile_options("${PROJECT_NAME}" INTERFACE -Wall -Wextra -pedantic -Werror)
    target_compile_options("${PROJECT_NAME}" INTERFACE -fsanitize=address)
    target_link_libraries("${PROJECT_NAME}" INTERFACE -fsanitize=address)
  endif ()
endif ()

target_include_directories(
  "${PROJECT_NAME}" PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<INSTALL_INTERFACE:include>
)

# NOTE(ww): More CMake dumbness: PUBLIC_HEADER doesn't get populated by target_include_directories,
# even when set explicitly as PUBLIC. We set it here so that it works correctly in the install step.
set_target_properties("${PROJECT_NAME}" PROPERTIES PUBLIC_HEADER "include/uthenticode.h")

# Newer versions of pe-parse use the `pe-parse` target. This check should be removed once the
# releases on vcpkg stabilize.
if (TARGET pe-parse::pe-parse)
  target_link_libraries("${PROJECT_NAME}" PUBLIC pe-parse::pe-parse)
else ()
  target_link_libraries("${PROJECT_NAME}" PUBLIC pe-parse::pe-parser-library)
endif ()

target_link_libraries("${PROJECT_NAME}" PUBLIC OpenSSL::Crypto)

install(
  TARGETS "${PROJECT_NAME}"
  EXPORT uthenticode-targets
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "lib"
  ARCHIVE DESTINATION "lib"
  PUBLIC_HEADER DESTINATION "include"
)
export(
  TARGETS "${PROJECT_NAME}"
  NAMESPACE uthenticode::
  FILE "${CMAKE_CURRENT_BINARY_DIR}/uthenticode-targets.cmake"
)
install(
  EXPORT uthenticode-targets
  DESTINATION "lib/cmake/uthenticode"
  NAMESPACE uthenticode::
  EXPORT_LINK_INTERFACE_LIBRARIES
)
install(FILES uthenticode-config.cmake DESTINATION "lib/cmake/uthenticode")

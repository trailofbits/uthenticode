cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(uthenticode)

find_package(
  OpenSSL 1.1
  COMPONENTS Crypto
  REQUIRED
)

add_library("${PROJECT_NAME}" uthenticode.cpp)

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
  if (MSVC)
    target_compile_options("${PROJECT_NAME}" PUBLIC /W4 /WX)
  else ()
    target_compile_options("${PROJECT_NAME}" PUBLIC -Wall -Wextra -pedantic -Werror)
    target_compile_options("${PROJECT_NAME}" PUBLIC -fsanitize=address)
    target_link_options("${PROJECT_NAME}" PUBLIC -fsanitize=address)
  endif ()
endif ()

target_include_directories(
  "${PROJECT_NAME}" PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
                           $<INSTALL_INTERFACE:include>
)

# NOTE(ww): More CMake dumbness: PUBLIC_HEADER doesn't get populated by target_include_directories,
# even when set explicitly as PUBLIC. We set it here so that it works correctly in the install step.
set_target_properties("${PROJECT_NAME}" PROPERTIES PUBLIC_HEADER "include/uthenticode.h")

target_link_libraries("${PROJECT_NAME}" pe-parse::pe-parser-library)
target_link_libraries("${PROJECT_NAME}" OpenSSL::Crypto)

install(
  TARGETS "${PROJECT_NAME}"
  EXPORT uthenticode-config
  RUNTIME DESTINATION "bin"
  LIBRARY DESTINATION "lib"
  ARCHIVE DESTINATION "lib"
  PUBLIC_HEADER DESTINATION "include"
)
export(
  TARGETS "${PROJECT_NAME}"
  NAMESPACE uthenticode::
  FILE "${CMAKE_CURRENT_BINARY_DIR}/uthenticode-config.cmake"
)
install(
  EXPORT uthenticode-config
  DESTINATION "lib/cmake/uthenticode"
  NAMESPACE uthenticode::
  EXPORT_LINK_INTERFACE_LIBRARIES
)

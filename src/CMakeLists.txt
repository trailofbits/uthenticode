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

target_link_libraries("${PROJECT_NAME}" PUBLIC pe-parse::pe-parser-library)
target_link_libraries("${PROJECT_NAME}" PRIVATE "${OPENSSL_CRYPTO_LIBRARY}")

# NOTE(ww): More CMake dumbness: linking to OpenSSL statically above apparently doesn't transitively
# link pthread or libdl correctly. We fix them up here.
if (NOT MSVC)
  find_package(Threads REQUIRED)
  target_link_libraries("${PROJECT_NAME}" PRIVATE ${CMAKE_THREAD_LIBS_INIT} ${CMAKE_DL_LIBS})
endif ()

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

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(svcli)

add_executable("${PROJECT_NAME}" svcli.cpp)
target_link_libraries("${PROJECT_NAME}" PUBLIC smolverify)

install(TARGETS "${PROJECT_NAME}" DESTINATION "bin")

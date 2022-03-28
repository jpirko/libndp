CMAKE_MINIMUM_REQUIRED(VERSION 3.12.1)
project(unit_test CXX C)

set (TEST_DIR "{PROJECT_SOURCE_DIR}")

include_directories("../include")
include_directories("../libndp")

set(CMAKE_C_FLAGS "-D_GNU_SOURCE ${CMAKE_C_FLAGS}")
# set(CMAKE_CXX_FLAGS "-D_GNU_SOURCE ${CMAKE_CXX_FLAGS}")

set(CMAKE_CXX_FLAGS "-w ${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS "-fprofile-arcs -ftest-coverage ${CMAKE_C_FLAGS}")

link_libraries(gtest mockcpp gcov)

aux_source_directory(. TEST_SRC)
aux_source_directory(../libndp TEST_SRC)

add_executable(unit_test ${TEST_SRC})

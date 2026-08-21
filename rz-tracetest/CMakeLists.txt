cmake_minimum_required(VERSION 3.12)
project(rz-tracetest)
set(CMAKE_CXX_STANDARD 17)
include(CTest)

find_package(Rizin REQUIRED Core)

option(ENABLE_ASAN "Enable address sanitizer" OFF)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (ENABLE_ASAN)
    message("Enabling ASAN")
    add_definitions(-DASAN_ENABLED)
    add_compile_options(-fsanitize=address,undefined)
    add_link_options(-fsanitize=address,undefined)
endif()

add_subdirectory(libtrace)

set(SOURCE
	main.cpp
	rzemu.cpp
	rzemu.h
	adapter.h
	adapter.cpp
	bitvector_helpers.h
	bitvector_helpers.cpp
	dump.h
	dump.cpp)

add_executable(rz-tracetest ${SOURCE})
target_link_libraries(rz-tracetest Rizin::Core trace)
install(TARGETS rz-tracetest)

if (BUILD_TESTING)
	add_executable(test-adapter adapter.cpp bitvector_helpers.cpp test_adapter.cpp)
	target_link_libraries(test-adapter Rizin::Core trace)
	add_test(NAME adapter COMMAND test-adapter)
endif()

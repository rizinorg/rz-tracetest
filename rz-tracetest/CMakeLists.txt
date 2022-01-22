cmake_minimum_required(VERSION 3.12)
project(rz-tracetest)
set(CMAKE_CXX_STANDARD 11)

find_package(Rizin REQUIRED Core)

add_subdirectory(libtrace)

set(SOURCE
	main.cpp
	rzemu.cpp
	rzemu.h
	adapter.h
	adapter.cpp)

add_executable(rz-tracetest ${SOURCE})
target_link_libraries(rz-tracetest Rizin::Core trace)
install(TARGETS rz-tracetest)

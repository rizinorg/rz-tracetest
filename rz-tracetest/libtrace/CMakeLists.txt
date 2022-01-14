
set(BAP_FRAMES_DIR ../../bap-frames)
set(LIBTRACE_SOURCE_DIR "${BAP_FRAMES_DIR}/libtrace/src")
set(PIQIFILE "${CMAKE_CURRENT_SOURCE_DIR}/${BAP_FRAMES_DIR}/piqi/frame.piqi")

find_program(PIQI piqi REQUIRED)
add_custom_command(
	OUTPUT "frame.piqi.proto"
	COMMAND "${PIQI}" to-proto "${PIQIFILE}" -o "${CMAKE_CURRENT_BINARY_DIR}/frame.piqi.proto"
	MAIN_DEPENDENCY "${PIQIFILE}"
	WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")

find_package(Protobuf REQUIRED)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS "${CMAKE_CURRENT_BINARY_DIR}/frame.piqi.proto")

configure_file(config.h.in config.h)

add_library(trace
	"${LIBTRACE_SOURCE_DIR}/trace.container.cpp"
	"${LIBTRACE_SOURCE_DIR}/trace.container.hpp"
	"${LIBTRACE_SOURCE_DIR}/frame_arch.h"
	${PROTO_SRCS}
	${PROTO_HDRS}
	"${CMAKE_CURRENT_BINARY_DIR}/config.h")
target_include_directories(trace
	PUBLIC "${LIBTRACE_SOURCE_DIR}" "${CMAKE_CURRENT_BINARY_DIR}" ${Protobuf_INCLUDE_DIRS})
target_link_libraries(trace ${Protobuf_LIBRARIES})

add_executable(readtrace "${LIBTRACE_SOURCE_DIR}/readtrace.cpp")
target_link_libraries(readtrace trace)
add_executable(copytrace "${LIBTRACE_SOURCE_DIR}/copytrace.cpp")
target_link_libraries(copytrace trace)

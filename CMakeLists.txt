cmake_minimum_required(VERSION 3.0)
project(backupssh)

set(SOURCES 
	src/main.c
	src/ssh.c
	)

include_directories(include/)
find_package(LibSSH REQUIRED)
include_directories(${LIBSSH_INCLUDE_DIRS})
set(LIBS ${LIBSSH_LIBRARIES})

add_executable(backupssh ${SOURCES})
target_link_libraries(backupssh ${LIBS})

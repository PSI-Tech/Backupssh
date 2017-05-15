cmake_minimum_required(VERSION 3.0)
project(backupssh)

set(SOURCES 
	src/main.c
	)
include_directories(include/)

add_executable(backupssh ${SOURCES})

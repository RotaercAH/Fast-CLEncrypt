# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.26

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/xlong/bicycl-master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/xlong/bicycl-master/build

# Utility rule file for benchs.

# Include any custom commands dependencies for this target.
include benchs/CMakeFiles/benchs.dir/compiler_depend.make

# Include the progress variables for this target.
include benchs/CMakeFiles/benchs.dir/progress.make

benchs/CMakeFiles/benchs:
	cd /home/xlong/bicycl-master/build/benchs && /usr/local/bin/cmake -E sleep 0

benchs: benchs/CMakeFiles/benchs
benchs: benchs/CMakeFiles/benchs.dir/build.make
.PHONY : benchs

# Rule to build all files generated by this target.
benchs/CMakeFiles/benchs.dir/build: benchs
.PHONY : benchs/CMakeFiles/benchs.dir/build

benchs/CMakeFiles/benchs.dir/clean:
	cd /home/xlong/bicycl-master/build/benchs && $(CMAKE_COMMAND) -P CMakeFiles/benchs.dir/cmake_clean.cmake
.PHONY : benchs/CMakeFiles/benchs.dir/clean

benchs/CMakeFiles/benchs.dir/depend:
	cd /home/xlong/bicycl-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xlong/bicycl-master /home/xlong/bicycl-master/benchs /home/xlong/bicycl-master/build /home/xlong/bicycl-master/build/benchs /home/xlong/bicycl-master/build/benchs/CMakeFiles/benchs.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : benchs/CMakeFiles/benchs.dir/depend


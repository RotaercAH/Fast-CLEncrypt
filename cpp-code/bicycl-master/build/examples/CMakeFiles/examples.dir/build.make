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
CMAKE_SOURCE_DIR = /home/xlong/rust-to-cpp/cpp-code/bicycl-master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/xlong/rust-to-cpp/cpp-code/bicycl-master/build

# Utility rule file for examples.

# Include any custom commands dependencies for this target.
include examples/CMakeFiles/examples.dir/compiler_depend.make

# Include the progress variables for this target.
include examples/CMakeFiles/examples.dir/progress.make

examples/CMakeFiles/examples:
	cd /home/xlong/rust-to-cpp/cpp-code/bicycl-master/build/examples && /usr/local/bin/cmake -E sleep 0

examples: examples/CMakeFiles/examples
examples: examples/CMakeFiles/examples.dir/build.make
.PHONY : examples

# Rule to build all files generated by this target.
examples/CMakeFiles/examples.dir/build: examples
.PHONY : examples/CMakeFiles/examples.dir/build

examples/CMakeFiles/examples.dir/clean:
	cd /home/xlong/rust-to-cpp/cpp-code/bicycl-master/build/examples && $(CMAKE_COMMAND) -P CMakeFiles/examples.dir/cmake_clean.cmake
.PHONY : examples/CMakeFiles/examples.dir/clean

examples/CMakeFiles/examples.dir/depend:
	cd /home/xlong/rust-to-cpp/cpp-code/bicycl-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xlong/rust-to-cpp/cpp-code/bicycl-master /home/xlong/rust-to-cpp/cpp-code/bicycl-master/examples /home/xlong/rust-to-cpp/cpp-code/bicycl-master/build /home/xlong/rust-to-cpp/cpp-code/bicycl-master/build/examples /home/xlong/rust-to-cpp/cpp-code/bicycl-master/build/examples/CMakeFiles/examples.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : examples/CMakeFiles/examples.dir/depend


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

# Include any dependencies generated for this target.
include tests/CMakeFiles/test_ec.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include tests/CMakeFiles/test_ec.dir/compiler_depend.make

# Include the progress variables for this target.
include tests/CMakeFiles/test_ec.dir/progress.make

# Include the compile flags for this target's objects.
include tests/CMakeFiles/test_ec.dir/flags.make

tests/CMakeFiles/test_ec.dir/test_ec.cpp.o: tests/CMakeFiles/test_ec.dir/flags.make
tests/CMakeFiles/test_ec.dir/test_ec.cpp.o: /home/xlong/bicycl-master/tests/test_ec.cpp
tests/CMakeFiles/test_ec.dir/test_ec.cpp.o: tests/CMakeFiles/test_ec.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/xlong/bicycl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object tests/CMakeFiles/test_ec.dir/test_ec.cpp.o"
	cd /home/xlong/bicycl-master/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT tests/CMakeFiles/test_ec.dir/test_ec.cpp.o -MF CMakeFiles/test_ec.dir/test_ec.cpp.o.d -o CMakeFiles/test_ec.dir/test_ec.cpp.o -c /home/xlong/bicycl-master/tests/test_ec.cpp

tests/CMakeFiles/test_ec.dir/test_ec.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test_ec.dir/test_ec.cpp.i"
	cd /home/xlong/bicycl-master/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/xlong/bicycl-master/tests/test_ec.cpp > CMakeFiles/test_ec.dir/test_ec.cpp.i

tests/CMakeFiles/test_ec.dir/test_ec.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test_ec.dir/test_ec.cpp.s"
	cd /home/xlong/bicycl-master/build/tests && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/xlong/bicycl-master/tests/test_ec.cpp -o CMakeFiles/test_ec.dir/test_ec.cpp.s

# Object files for target test_ec
test_ec_OBJECTS = \
"CMakeFiles/test_ec.dir/test_ec.cpp.o"

# External object files for target test_ec
test_ec_EXTERNAL_OBJECTS =

tests/test_ec: tests/CMakeFiles/test_ec.dir/test_ec.cpp.o
tests/test_ec: tests/CMakeFiles/test_ec.dir/build.make
tests/test_ec: /usr/lib/x86_64-linux-gnu/libgmp.so
tests/test_ec: /usr/lib/x86_64-linux-gnu/libgmpxx.so
tests/test_ec: /usr/lib/x86_64-linux-gnu/libcrypto.so
tests/test_ec: tests/CMakeFiles/test_ec.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/xlong/bicycl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test_ec"
	cd /home/xlong/bicycl-master/build/tests && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test_ec.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
tests/CMakeFiles/test_ec.dir/build: tests/test_ec
.PHONY : tests/CMakeFiles/test_ec.dir/build

tests/CMakeFiles/test_ec.dir/clean:
	cd /home/xlong/bicycl-master/build/tests && $(CMAKE_COMMAND) -P CMakeFiles/test_ec.dir/cmake_clean.cmake
.PHONY : tests/CMakeFiles/test_ec.dir/clean

tests/CMakeFiles/test_ec.dir/depend:
	cd /home/xlong/bicycl-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xlong/bicycl-master /home/xlong/bicycl-master/tests /home/xlong/bicycl-master/build /home/xlong/bicycl-master/build/tests /home/xlong/bicycl-master/build/tests/CMakeFiles/test_ec.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : tests/CMakeFiles/test_ec.dir/depend


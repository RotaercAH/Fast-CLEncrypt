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
include benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/compiler_depend.make

# Include the progress variables for this target.
include benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/progress.make

# Include the compile flags for this target's objects.
include benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/flags.make

benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o: benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/flags.make
benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o: /home/xlong/bicycl-master/benchs/benchmark_CL_HSM2k.cpp
benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o: benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/xlong/bicycl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o"
	cd /home/xlong/bicycl-master/build/benchs && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o -MF CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o.d -o CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o -c /home/xlong/bicycl-master/benchs/benchmark_CL_HSM2k.cpp

benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.i"
	cd /home/xlong/bicycl-master/build/benchs && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/xlong/bicycl-master/benchs/benchmark_CL_HSM2k.cpp > CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.i

benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.s"
	cd /home/xlong/bicycl-master/build/benchs && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/xlong/bicycl-master/benchs/benchmark_CL_HSM2k.cpp -o CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.s

# Object files for target benchmark_CL_HSM2k_build
benchmark_CL_HSM2k_build_OBJECTS = \
"CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o"

# External object files for target benchmark_CL_HSM2k_build
benchmark_CL_HSM2k_build_EXTERNAL_OBJECTS =

benchs/benchmark_CL_HSM2k: benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/benchmark_CL_HSM2k.cpp.o
benchs/benchmark_CL_HSM2k: benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/build.make
benchs/benchmark_CL_HSM2k: /usr/lib/x86_64-linux-gnu/libgmp.so
benchs/benchmark_CL_HSM2k: /usr/lib/x86_64-linux-gnu/libgmpxx.so
benchs/benchmark_CL_HSM2k: /usr/lib/x86_64-linux-gnu/libcrypto.so
benchs/benchmark_CL_HSM2k: benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/xlong/bicycl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable benchmark_CL_HSM2k"
	cd /home/xlong/bicycl-master/build/benchs && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/benchmark_CL_HSM2k_build.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/build: benchs/benchmark_CL_HSM2k
.PHONY : benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/build

benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/clean:
	cd /home/xlong/bicycl-master/build/benchs && $(CMAKE_COMMAND) -P CMakeFiles/benchmark_CL_HSM2k_build.dir/cmake_clean.cmake
.PHONY : benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/clean

benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/depend:
	cd /home/xlong/bicycl-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/xlong/bicycl-master /home/xlong/bicycl-master/benchs /home/xlong/bicycl-master/build /home/xlong/bicycl-master/build/benchs /home/xlong/bicycl-master/build/benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : benchs/CMakeFiles/benchmark_CL_HSM2k_build.dir/depend


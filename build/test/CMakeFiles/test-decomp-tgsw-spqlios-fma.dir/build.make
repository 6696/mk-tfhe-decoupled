# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
$(VERBOSE).SILENT:


# A target that is always out of date.
cmake_force:

.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/daniil/IdeaProjects/mk-tfhe-auction/src

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/daniil/IdeaProjects/mk-tfhe-auction/build

# Include any dependencies generated for this target.
include test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/depend.make

# Include the progress variables for this target.
include test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/progress.make

# Include the compile flags for this target's objects.
include test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/flags.make

test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.o: test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/flags.make
test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.o: /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/test-decomp-tgsw.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/daniil/IdeaProjects/mk-tfhe-auction/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.o"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && /usr/bin/g++-5  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.o -c /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/test-decomp-tgsw.cpp

test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.i"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && /usr/bin/g++-5 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/test-decomp-tgsw.cpp > CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.i

test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.s"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && /usr/bin/g++-5 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/test-decomp-tgsw.cpp -o CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.s

# Object files for target test-decomp-tgsw-spqlios-fma
test__decomp__tgsw__spqlios__fma_OBJECTS = \
"CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.o"

# External object files for target test-decomp-tgsw-spqlios-fma
test__decomp__tgsw__spqlios__fma_EXTERNAL_OBJECTS =

test/test-decomp-tgsw-spqlios-fma: test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/test-decomp-tgsw.cpp.o
test/test-decomp-tgsw-spqlios-fma: test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/build.make
test/test-decomp-tgsw-spqlios-fma: libtfhe/libtfhe-spqlios-fma.so
test/test-decomp-tgsw-spqlios-fma: test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/daniil/IdeaProjects/mk-tfhe-auction/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable test-decomp-tgsw-spqlios-fma"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/build: test/test-decomp-tgsw-spqlios-fma

.PHONY : test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/build

test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/clean:
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && $(CMAKE_COMMAND) -P CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/cmake_clean.cmake
.PHONY : test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/clean

test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/depend:
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/daniil/IdeaProjects/mk-tfhe-auction/src /home/daniil/IdeaProjects/mk-tfhe-auction/src/test /home/daniil/IdeaProjects/mk-tfhe-auction/build /home/daniil/IdeaProjects/mk-tfhe-auction/build/test /home/daniil/IdeaProjects/mk-tfhe-auction/build/test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : test/CMakeFiles/test-decomp-tgsw-spqlios-fma.dir/depend


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
include test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/depend.make

# Include the progress variables for this target.
include test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/progress.make

# Include the compile flags for this target's objects.
include test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/flags.make

test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.o: test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/flags.make
test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.o: /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/testMKbootNAND_FFT_v2___.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/daniil/IdeaProjects/mk-tfhe-auction/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.o"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && /usr/bin/g++-5  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.o -c /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/testMKbootNAND_FFT_v2___.cpp

test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.i"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && /usr/bin/g++-5 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/testMKbootNAND_FFT_v2___.cpp > CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.i

test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.s"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && /usr/bin/g++-5 $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/daniil/IdeaProjects/mk-tfhe-auction/src/test/testMKbootNAND_FFT_v2___.cpp -o CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.s

# Object files for target testMKbootNAND_FFT_v2___-spqlios-avx
testMKbootNAND_FFT_v2_____spqlios__avx_OBJECTS = \
"CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.o"

# External object files for target testMKbootNAND_FFT_v2___-spqlios-avx
testMKbootNAND_FFT_v2_____spqlios__avx_EXTERNAL_OBJECTS =

test/testMKbootNAND_FFT_v2___-spqlios-avx: test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/testMKbootNAND_FFT_v2___.cpp.o
test/testMKbootNAND_FFT_v2___-spqlios-avx: test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/build.make
test/testMKbootNAND_FFT_v2___-spqlios-avx: libtfhe/libtfhe-spqlios-avx.so
test/testMKbootNAND_FFT_v2___-spqlios-avx: test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/daniil/IdeaProjects/mk-tfhe-auction/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable testMKbootNAND_FFT_v2___-spqlios-avx"
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/build: test/testMKbootNAND_FFT_v2___-spqlios-avx

.PHONY : test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/build

test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/clean:
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build/test && $(CMAKE_COMMAND) -P CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/cmake_clean.cmake
.PHONY : test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/clean

test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/depend:
	cd /home/daniil/IdeaProjects/mk-tfhe-auction/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/daniil/IdeaProjects/mk-tfhe-auction/src /home/daniil/IdeaProjects/mk-tfhe-auction/src/test /home/daniil/IdeaProjects/mk-tfhe-auction/build /home/daniil/IdeaProjects/mk-tfhe-auction/build/test /home/daniil/IdeaProjects/mk-tfhe-auction/build/test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : test/CMakeFiles/testMKbootNAND_FFT_v2___-spqlios-avx.dir/depend


# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.12

# Default target executed when no arguments are given to make.
default_target: all

.PHONY : default_target

# Allow only one "make -f Makefile2" at a time, but pass parallelism.
.NOTPARALLEL:


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
CMAKE_COMMAND = /usr/local/bin/cmake

# The command to remove a file.
RM = /usr/local/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/avadapal/Vadapalli-PhD/DPF

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/avadapal/Vadapalli-PhD/DPF

#=============================================================================
# Targets provided globally by CMake.

# Special rule for the target rebuild_cache
rebuild_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake to regenerate build system..."
	/usr/local/bin/cmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : rebuild_cache

# Special rule for the target rebuild_cache
rebuild_cache/fast: rebuild_cache

.PHONY : rebuild_cache/fast

# Special rule for the target edit_cache
edit_cache:
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --cyan "Running CMake cache editor..."
	/usr/local/bin/ccmake -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR)
.PHONY : edit_cache

# Special rule for the target edit_cache
edit_cache/fast: edit_cache

.PHONY : edit_cache/fast

# The main all target
all: cmake_check_build_system
	$(CMAKE_COMMAND) -E cmake_progress_start /home/avadapal/Vadapalli-PhD/DPF/CMakeFiles /home/avadapal/Vadapalli-PhD/DPF/CMakeFiles/progress.marks
	$(MAKE) -f CMakeFiles/Makefile2 all
	$(CMAKE_COMMAND) -E cmake_progress_start /home/avadapal/Vadapalli-PhD/DPF/CMakeFiles 0
.PHONY : all

# The main clean target
clean:
	$(MAKE) -f CMakeFiles/Makefile2 clean
.PHONY : clean

# The main clean target
clean/fast: clean

.PHONY : clean/fast

# Prepare targets for installation.
preinstall: all
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall

# Prepare targets for installation.
preinstall/fast:
	$(MAKE) -f CMakeFiles/Makefile2 preinstall
.PHONY : preinstall/fast

# clear depends
depend:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 1
.PHONY : depend

#=============================================================================
# Target rules for targets named fsseval

# Build rule for target.
fsseval: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 fsseval
.PHONY : fsseval

# fast build rule for target.
fsseval/fast:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/build
.PHONY : fsseval/fast

#=============================================================================
# Target rules for targets named fssgen

# Build rule for target.
fssgen: cmake_check_build_system
	$(MAKE) -f CMakeFiles/Makefile2 fssgen
.PHONY : fssgen

# fast build rule for target.
fssgen/fast:
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/build
.PHONY : fssgen/fast

b64.o: b64.c.o

.PHONY : b64.o

# target to build an object file
b64.c.o:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/b64.c.o
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/b64.c.o
.PHONY : b64.c.o

b64.i: b64.c.i

.PHONY : b64.i

# target to preprocess a source file
b64.c.i:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/b64.c.i
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/b64.c.i
.PHONY : b64.c.i

b64.s: b64.c.s

.PHONY : b64.s

# target to generate assembly for a file
b64.c.s:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/b64.c.s
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/b64.c.s
.PHONY : b64.c.s

block.o: block.c.o

.PHONY : block.o

# target to build an object file
block.c.o:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/block.c.o
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/block.c.o
.PHONY : block.c.o

block.i: block.c.i

.PHONY : block.i

# target to preprocess a source file
block.c.i:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/block.c.i
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/block.c.i
.PHONY : block.c.i

block.s: block.c.s

.PHONY : block.s

# target to generate assembly for a file
block.c.s:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/block.c.s
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/block.c.s
.PHONY : block.c.s

fsseval.o: fsseval.c.o

.PHONY : fsseval.o

# target to build an object file
fsseval.c.o:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/fsseval.c.o
.PHONY : fsseval.c.o

fsseval.i: fsseval.c.i

.PHONY : fsseval.i

# target to preprocess a source file
fsseval.c.i:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/fsseval.c.i
.PHONY : fsseval.c.i

fsseval.s: fsseval.c.s

.PHONY : fsseval.s

# target to generate assembly for a file
fsseval.c.s:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/fsseval.c.s
.PHONY : fsseval.c.s

fssgen.o: fssgen.c.o

.PHONY : fssgen.o

# target to build an object file
fssgen.c.o:
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/fssgen.c.o
.PHONY : fssgen.c.o

fssgen.i: fssgen.c.i

.PHONY : fssgen.i

# target to preprocess a source file
fssgen.c.i:
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/fssgen.c.i
.PHONY : fssgen.c.i

fssgen.s: fssgen.c.s

.PHONY : fssgen.s

# target to generate assembly for a file
fssgen.c.s:
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/fssgen.c.s
.PHONY : fssgen.c.s

utils.o: utils.c.o

.PHONY : utils.o

# target to build an object file
utils.c.o:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/utils.c.o
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/utils.c.o
.PHONY : utils.c.o

utils.i: utils.c.i

.PHONY : utils.i

# target to preprocess a source file
utils.c.i:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/utils.c.i
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/utils.c.i
.PHONY : utils.c.i

utils.s: utils.c.s

.PHONY : utils.s

# target to generate assembly for a file
utils.c.s:
	$(MAKE) -f CMakeFiles/fsseval.dir/build.make CMakeFiles/fsseval.dir/utils.c.s
	$(MAKE) -f CMakeFiles/fssgen.dir/build.make CMakeFiles/fssgen.dir/utils.c.s
.PHONY : utils.c.s

# Help Target
help:
	@echo "The following are some of the valid targets for this Makefile:"
	@echo "... all (the default if no target is provided)"
	@echo "... clean"
	@echo "... depend"
	@echo "... rebuild_cache"
	@echo "... edit_cache"
	@echo "... fsseval"
	@echo "... fssgen"
	@echo "... b64.o"
	@echo "... b64.i"
	@echo "... b64.s"
	@echo "... block.o"
	@echo "... block.i"
	@echo "... block.s"
	@echo "... fsseval.o"
	@echo "... fsseval.i"
	@echo "... fsseval.s"
	@echo "... fssgen.o"
	@echo "... fssgen.i"
	@echo "... fssgen.s"
	@echo "... utils.o"
	@echo "... utils.i"
	@echo "... utils.s"
.PHONY : help



#=============================================================================
# Special targets to cleanup operation of make.

# Special rule to run CMake to check the build system integrity.
# No rule that depends on this can have commands that come from listfiles
# because they might be regenerated.
cmake_check_build_system:
	$(CMAKE_COMMAND) -H$(CMAKE_SOURCE_DIR) -B$(CMAKE_BINARY_DIR) --check-build-system CMakeFiles/Makefile.cmake 0
.PHONY : cmake_check_build_system

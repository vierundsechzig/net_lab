# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.19

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
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/nikolaus/net_lab

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/nikolaus/net_lab/build

# Include any dependencies generated for this target.
include CMakeFiles/ctest_arp.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/ctest_arp.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/ctest_arp.dir/flags.make

CMakeFiles/ctest_arp.dir/test/arp_test.c.o: CMakeFiles/ctest_arp.dir/flags.make
CMakeFiles/ctest_arp.dir/test/arp_test.c.o: ../test/arp_test.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object CMakeFiles/ctest_arp.dir/test/arp_test.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ctest_arp.dir/test/arp_test.c.o -c /home/nikolaus/net_lab/test/arp_test.c

CMakeFiles/ctest_arp.dir/test/arp_test.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ctest_arp.dir/test/arp_test.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nikolaus/net_lab/test/arp_test.c > CMakeFiles/ctest_arp.dir/test/arp_test.c.i

CMakeFiles/ctest_arp.dir/test/arp_test.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ctest_arp.dir/test/arp_test.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nikolaus/net_lab/test/arp_test.c -o CMakeFiles/ctest_arp.dir/test/arp_test.c.s

CMakeFiles/ctest_arp.dir/src/ethernet.c.o: CMakeFiles/ctest_arp.dir/flags.make
CMakeFiles/ctest_arp.dir/src/ethernet.c.o: ../src/ethernet.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building C object CMakeFiles/ctest_arp.dir/src/ethernet.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ctest_arp.dir/src/ethernet.c.o -c /home/nikolaus/net_lab/src/ethernet.c

CMakeFiles/ctest_arp.dir/src/ethernet.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ctest_arp.dir/src/ethernet.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nikolaus/net_lab/src/ethernet.c > CMakeFiles/ctest_arp.dir/src/ethernet.c.i

CMakeFiles/ctest_arp.dir/src/ethernet.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ctest_arp.dir/src/ethernet.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nikolaus/net_lab/src/ethernet.c -o CMakeFiles/ctest_arp.dir/src/ethernet.c.s

CMakeFiles/ctest_arp.dir/src/arp.c.o: CMakeFiles/ctest_arp.dir/flags.make
CMakeFiles/ctest_arp.dir/src/arp.c.o: ../src/arp.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building C object CMakeFiles/ctest_arp.dir/src/arp.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ctest_arp.dir/src/arp.c.o -c /home/nikolaus/net_lab/src/arp.c

CMakeFiles/ctest_arp.dir/src/arp.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ctest_arp.dir/src/arp.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nikolaus/net_lab/src/arp.c > CMakeFiles/ctest_arp.dir/src/arp.c.i

CMakeFiles/ctest_arp.dir/src/arp.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ctest_arp.dir/src/arp.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nikolaus/net_lab/src/arp.c -o CMakeFiles/ctest_arp.dir/src/arp.c.s

CMakeFiles/ctest_arp.dir/test/faker/ip.c.o: CMakeFiles/ctest_arp.dir/flags.make
CMakeFiles/ctest_arp.dir/test/faker/ip.c.o: ../test/faker/ip.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building C object CMakeFiles/ctest_arp.dir/test/faker/ip.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ctest_arp.dir/test/faker/ip.c.o -c /home/nikolaus/net_lab/test/faker/ip.c

CMakeFiles/ctest_arp.dir/test/faker/ip.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ctest_arp.dir/test/faker/ip.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nikolaus/net_lab/test/faker/ip.c > CMakeFiles/ctest_arp.dir/test/faker/ip.c.i

CMakeFiles/ctest_arp.dir/test/faker/ip.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ctest_arp.dir/test/faker/ip.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nikolaus/net_lab/test/faker/ip.c -o CMakeFiles/ctest_arp.dir/test/faker/ip.c.s

CMakeFiles/ctest_arp.dir/test/faker/driver.c.o: CMakeFiles/ctest_arp.dir/flags.make
CMakeFiles/ctest_arp.dir/test/faker/driver.c.o: ../test/faker/driver.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building C object CMakeFiles/ctest_arp.dir/test/faker/driver.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ctest_arp.dir/test/faker/driver.c.o -c /home/nikolaus/net_lab/test/faker/driver.c

CMakeFiles/ctest_arp.dir/test/faker/driver.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ctest_arp.dir/test/faker/driver.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nikolaus/net_lab/test/faker/driver.c > CMakeFiles/ctest_arp.dir/test/faker/driver.c.i

CMakeFiles/ctest_arp.dir/test/faker/driver.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ctest_arp.dir/test/faker/driver.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nikolaus/net_lab/test/faker/driver.c -o CMakeFiles/ctest_arp.dir/test/faker/driver.c.s

CMakeFiles/ctest_arp.dir/test/global.c.o: CMakeFiles/ctest_arp.dir/flags.make
CMakeFiles/ctest_arp.dir/test/global.c.o: ../test/global.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Building C object CMakeFiles/ctest_arp.dir/test/global.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ctest_arp.dir/test/global.c.o -c /home/nikolaus/net_lab/test/global.c

CMakeFiles/ctest_arp.dir/test/global.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ctest_arp.dir/test/global.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nikolaus/net_lab/test/global.c > CMakeFiles/ctest_arp.dir/test/global.c.i

CMakeFiles/ctest_arp.dir/test/global.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ctest_arp.dir/test/global.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nikolaus/net_lab/test/global.c -o CMakeFiles/ctest_arp.dir/test/global.c.s

CMakeFiles/ctest_arp.dir/src/utils.c.o: CMakeFiles/ctest_arp.dir/flags.make
CMakeFiles/ctest_arp.dir/src/utils.c.o: ../src/utils.c
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_7) "Building C object CMakeFiles/ctest_arp.dir/src/utils.c.o"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -o CMakeFiles/ctest_arp.dir/src/utils.c.o -c /home/nikolaus/net_lab/src/utils.c

CMakeFiles/ctest_arp.dir/src/utils.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/ctest_arp.dir/src/utils.c.i"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/nikolaus/net_lab/src/utils.c > CMakeFiles/ctest_arp.dir/src/utils.c.i

CMakeFiles/ctest_arp.dir/src/utils.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/ctest_arp.dir/src/utils.c.s"
	/usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/nikolaus/net_lab/src/utils.c -o CMakeFiles/ctest_arp.dir/src/utils.c.s

# Object files for target ctest_arp
ctest_arp_OBJECTS = \
"CMakeFiles/ctest_arp.dir/test/arp_test.c.o" \
"CMakeFiles/ctest_arp.dir/src/ethernet.c.o" \
"CMakeFiles/ctest_arp.dir/src/arp.c.o" \
"CMakeFiles/ctest_arp.dir/test/faker/ip.c.o" \
"CMakeFiles/ctest_arp.dir/test/faker/driver.c.o" \
"CMakeFiles/ctest_arp.dir/test/global.c.o" \
"CMakeFiles/ctest_arp.dir/src/utils.c.o"

# External object files for target ctest_arp
ctest_arp_EXTERNAL_OBJECTS =

../test/ctest_arp: CMakeFiles/ctest_arp.dir/test/arp_test.c.o
../test/ctest_arp: CMakeFiles/ctest_arp.dir/src/ethernet.c.o
../test/ctest_arp: CMakeFiles/ctest_arp.dir/src/arp.c.o
../test/ctest_arp: CMakeFiles/ctest_arp.dir/test/faker/ip.c.o
../test/ctest_arp: CMakeFiles/ctest_arp.dir/test/faker/driver.c.o
../test/ctest_arp: CMakeFiles/ctest_arp.dir/test/global.c.o
../test/ctest_arp: CMakeFiles/ctest_arp.dir/src/utils.c.o
../test/ctest_arp: CMakeFiles/ctest_arp.dir/build.make
../test/ctest_arp: CMakeFiles/ctest_arp.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/nikolaus/net_lab/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_8) "Linking C executable ../test/ctest_arp"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/ctest_arp.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/ctest_arp.dir/build: ../test/ctest_arp

.PHONY : CMakeFiles/ctest_arp.dir/build

CMakeFiles/ctest_arp.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/ctest_arp.dir/cmake_clean.cmake
.PHONY : CMakeFiles/ctest_arp.dir/clean

CMakeFiles/ctest_arp.dir/depend:
	cd /home/nikolaus/net_lab/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/nikolaus/net_lab /home/nikolaus/net_lab /home/nikolaus/net_lab/build /home/nikolaus/net_lab/build /home/nikolaus/net_lab/build/CMakeFiles/ctest_arp.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/ctest_arp.dir/depend


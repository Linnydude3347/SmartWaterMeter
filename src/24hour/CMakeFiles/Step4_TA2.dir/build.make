# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.28

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
CMAKE_COMMAND = /opt/homebrew/Cellar/cmake/3.28.3/bin/cmake

# The command to remove a file.
RM = /opt/homebrew/Cellar/cmake/3.28.3/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour

# Include any dependencies generated for this target.
include CMakeFiles/Step4_TA2.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/Step4_TA2.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/Step4_TA2.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Step4_TA2.dir/flags.make

CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o: CMakeFiles/Step4_TA2.dir/flags.make
CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o: Step4_TA2.cpp
CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o: CMakeFiles/Step4_TA2.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o"
	/opt/homebrew/Cellar/llvm/18.1.6/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o -MF CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o.d -o CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o -c /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour/Step4_TA2.cpp

CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.i"
	/opt/homebrew/Cellar/llvm/18.1.6/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour/Step4_TA2.cpp > CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.i

CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.s"
	/opt/homebrew/Cellar/llvm/18.1.6/bin/clang++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour/Step4_TA2.cpp -o CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.s

# Object files for target Step4_TA2
Step4_TA2_OBJECTS = \
"CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o"

# External object files for target Step4_TA2
Step4_TA2_EXTERNAL_OBJECTS =

bin/Step4_TA2: CMakeFiles/Step4_TA2.dir/Step4_TA2.cpp.o
bin/Step4_TA2: CMakeFiles/Step4_TA2.dir/build.make
bin/Step4_TA2: /opt/homebrew/lib/libseal.4.1.2.dylib
bin/Step4_TA2: CMakeFiles/Step4_TA2.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable bin/Step4_TA2"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Step4_TA2.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Step4_TA2.dir/build: bin/Step4_TA2
.PHONY : CMakeFiles/Step4_TA2.dir/build

CMakeFiles/Step4_TA2.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Step4_TA2.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Step4_TA2.dir/clean

CMakeFiles/Step4_TA2.dir/depend:
	cd /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour /Users/benjaminantonellis/Documents/GitHub/SmartWaterMeter/src/24hour/CMakeFiles/Step4_TA2.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : CMakeFiles/Step4_TA2.dir/depend


# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT license.

cmake_minimum_required(VERSION 3.10)

project(SEALExamples VERSION 3.2.0 LANGUAGES CXX)
project(MyOpenMPProject)

# Executable will be in bin
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)
set(SEAL_USE_CXX17 OFF)

# Import Microsoft SEAL
find_package(SEAL 4.1.2 EXACT REQUIRED)

# Import OpenMP
set(CMAKE_C_COMPILER "/opt/homebrew/Cellar/llvm/18.1.6/bin/clang")
set(CMAKE_CXX_COMPILER "/opt/homebrew/Cellar/llvm/18.1.6/bin/clang++")
set(OPENMP_LIBRARIES "/opt/homebrew/Cellar/libomp/18.1.6/lib")
set(OPENMP_INCLUDES "/opt/homebrew/Cellar/libomp/18.1.6/include")

OPTION (USE_OpenMP "Use OpenMP to enable <omp.h>" ON)

# Find OpenMP
if(APPLE AND USE_OpenMP)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        set(OpenMP_C "${CMAKE_C_COMPILER}")
        set(OpenMP_C_FLAGS "-fopenmp=libomp -Wno-unused-command-line-argument")
        set(OpenMP_C_LIB_NAMES "libomp" "libgomp" "libiomp5")
        set(OpenMP_libomp_LIBRARY ${OpenMP_C_LIB_NAMES})
        set(OpenMP_libgomp_LIBRARY ${OpenMP_C_LIB_NAMES})
        set(OpenMP_libiomp5_LIBRARY ${OpenMP_C_LIB_NAMES})
    endif()
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
      set(OpenMP_CXX "${CMAKE_CXX_COMPILER}")
      set(OpenMP_CXX_FLAGS "-fopenmp=libomp -Wno-unused-command-line-argument")
      set(OpenMP_CXX_LIB_NAMES "libomp" "libgomp" "libiomp5")
      set(OpenMP_libomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
      set(OpenMP_libgomp_LIBRARY ${OpenMP_CXX_LIB_NAMES})
      set(OpenMP_libiomp5_LIBRARY ${OpenMP_CXX_LIB_NAMES})
    endif()
endif()

if(USE_OpenMP)
  find_package(OpenMP REQUIRED)
endif(USE_OpenMP)

if (OPENMP_FOUND)
    include_directories("${OPENMP_INCLUDES}")
    link_directories("${OPENMP_LIBRARIES}")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif(OPENMP_FOUND)

add_executable(KeyGen KeyGen.cpp)
add_executable(CheckRes CheckRes.cpp)
add_executable(Step1_CS1 Step1_CS1.cpp)
add_executable(Step2_TA1 Step2_TA1.cpp)
add_executable(Step3_CS2_1 Step3_CS2_1.cpp)
add_executable(Step3_CS2_2 Step3_CS2_2.cpp)
add_executable(Step4_TA2 Step4_TA2.cpp)
add_executable(Step5_CS3_1 Step5_CS3_1.cpp)
add_executable(Step5_CS3_2 Step5_CS3_2.cpp)
add_executable(Step5_CS3 Step5_CS3.cpp)
add_executable(Step6_TA3 Step6_TA3.cpp)
add_executable(Step7_CS4 Step7_CS4.cpp)

target_link_libraries(KeyGen SEAL::seal_shared)
target_link_libraries(CheckRes SEAL::seal_shared)
target_link_libraries(Step1_CS1 SEAL::seal_shared)
target_link_libraries(Step2_TA1 SEAL::seal_shared)
target_link_libraries(Step3_CS2_1 SEAL::seal_shared)
target_link_libraries(Step3_CS2_2 SEAL::seal_shared)
target_link_libraries(Step4_TA2 SEAL::seal_shared)
target_link_libraries(Step5_CS3_1 SEAL::seal_shared)
target_link_libraries(Step5_CS3_2 SEAL::seal_shared)
target_link_libraries(Step5_CS3 SEAL::seal_shared)
target_link_libraries(Step6_TA3 SEAL::seal_shared)
target_link_libraries(Step7_CS4 SEAL::seal_shared)
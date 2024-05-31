// Consider making this a precompiled header

#include <map>
#include <fstream>
#include <iostream>
#include <sstream>
#include <cstdlib>
#include <unistd.h>
#include <string>
#include <tuple>
#include <vector>
#include <cstring>
#include <math.h>
#include <cstdio>
#include <chrono>
#include <random>
#include <thread>
#include <future>
#include <ctime>
#include <ratio>
#include <cstddef>
#include <iomanip>
#include <mutex>
#include <memory>
#include <limits>
#include <stdlib.h>
#include <stdio.h>
#include <numeric>
#include "seal/seal.h"

#define METER_NUM 150
#define TABLE_SIZE_AM 2850
#define TABLE_SIZE_HM 2653
#define TABLE_SIZE_AM_INV 3647
#define TABLE_SIZE_100_INV 3647
#define TABLE_SIZE_DIV_HM 7935

#include "omp.h"

#define NF 16 // Number of threads

#define PRECISION 32        // pow(2, 5)
#define PRECISION2 1024     // pow(2, 10)

#include "Utility.hpp"

// Below are filenames that were moved from strings to #defines
// Saves having to rewrite them, and avoids spelling errors

#define PARAMS_FILEPATH "Key/Params"
#define PUBLIC_KEY_FILEPATH "Key/PublicKey"
#define SECRET_KEY_FILEPATH "Key/SecretKey"
#define GALOIS_KEY_FILEPATH "Key/GaloisKey"
#define RELIN_KEY_FILEPATH "Key/RelinKey"
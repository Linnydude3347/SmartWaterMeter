/**
 * @file Utility.hpp
 * @author Benjamin Antonellis
 * @brief Collection of utility and helper functions
**/

#ifndef SMART_UTILITY_HPP
#define SMART_UTILITY_HPP

#include <iostream>
#include <vector>
#include <string>
#include <seal/seal.h>

#if defined(unix) || defined(__unix__) || defined(__unix)
/**
 * @brief Displays the memory usage, only usable on Linux systems.
 * 
 * @param[in] pid Requested process ID
 */
void ShowMemoryUsage(pid_t pid) {

    std::ostringstream path;
    path << "/proc/" << pid << "/status";
    std::ostringstream cmd;
    cmd << "grep -e 'VmHWM' -e 'VmSize' -e 'VmStk' -e 'VmData' -e 'VmExe' " << path.str();
    system(cmd.str().c_str());

}
#else
void ShowMemoryUsage(const pid_t& pid) { return; }
#endif

/**
 * @brief Prints the plaintext vector to a readable format.
 * 
 * @param[in] vec Plaintext vector.
 */
void OutputPlaintext(const std::vector<std::vector<int64_t>>& vec) {

    for (size_t i = 0; i < vec.size(); i++) {
        for (size_t j = 0; j < vec[0].size(); j++) {
            std::cout << vec[i][j] << " ";
        }
        std::cout << std::endl;
    }

}

/**
 * @brief Prints a vector of integers colorfully.
 * 
 * @param[in] vec Vector of integers
 */
void OutVector(const std::vector<int64_t>& vec) {

    for (size_t i = 0; i < vec.size(); i++) {
        if (vec[i] != 0) {
            std::cout << "\033[1;33m " << vec[i] << "\033[0m";
        } else {
            std::cout << vec[i] << " ";
        }
    }

}

/**
 * @brief Prints the name of the example in a fancy banner.
 * 
 * @param[in] title Title of banner
 */
void PrintExampleBanner(const std::string& title) {

    if (!title.empty()) {
        size_t titleLength = title.length();
        size_t bannerLength = titleLength + 2 + 2 * 10;
        std::string bannerTop(bannerLength, '*');
        std::string bannerMiddle = std::string(10, '*') + " " + title + " " + std::string(10, '*');

        std::cout << std::endl
            << bannerTop << std::endl
            << bannerMiddle << std::endl
            << bannerTop << std::endl
            << std::endl
        ;
    }
    
}

/**
 * @brief Prints the parameters in a SEALContext
 * 
 * @param[in] context SEALContext to print
 */
void PrintParameters(const std::shared_ptr<seal::SEALContext>& context) {

    if (!context) {
        throw std::invalid_argument("Context is not set.");
    }
    // Look into Seal documentation to see if this line is correct.
    //auto& contextData = *context->get_context_data(context->first_parms_id());
    auto &contextData = *context->key_context_data();

    // Figure out which scheme we are using

    std::string schemeName;
    switch(contextData.parms().scheme()) {
        case seal::scheme_type::bfv:
            schemeName = "BFV";
            break;
        case seal::scheme_type::ckks:
            schemeName = "CKKS";
            break;
        default:
            throw std::invalid_argument("Unsupported scheme.");
    }

    std::cout << "/ Encryption Parameters / " << std::endl;
    std::cout << "| Scheme: " << schemeName << std::endl;
    std::cout << "| Poly Modulus Degree: " << contextData.parms().poly_modulus_degree() << std::endl;

    // Print size of the true (product) coefficient modulus

    std::cout << "| Coeff Modulus Size: " << contextData.total_coeff_modulus_bit_count() << " bits" << std::endl;

    // For the BFV scheme print the plain modulus parameter
    if (schemeName == "BFV") {
        std::cout << "| Plain Modulus: " << contextData.parms().plain_modulus().value() << std::endl;
    }

    std::cout << "/ End Encryption Parameters /" << std::endl;

}

/**
 * @brief Prints the parmsID to std::ostream
 * 
 * @param[out] stream Output stream
 * @param[in] parmsID ID of parameter to print
 * @return std::ostream& 
 */
std::ostream& operator<<(std::ostream& stream, seal::parms_id_type parmsID) {

    stream << std::hex << parmsID[0] << " " << parmsID[1] << " "
        << parmsID[2] << " " << parmsID[3] << std::dec;
    return stream;

}

/**
 * @brief Prints a vector of floating point values.
 * 
 * @param[in] vec Vector to print
 * @param[in] printSize Numbers per line
 * @param[in] prec Precision of numbers to print
 */
template <typename T>
void PrintVector(const std::vector<T>& vec, const size_t& printSize=4, const int& prec=3) {

    // Save old formatting for std::cout
    std::ios oldFormat(nullptr);
    oldFormat.copyfmt(std::cout);

    size_t slotCount = vec.size();

    //std::cout << std::fixed << std::setprecision(prec) << std::endl;
    if (slotCount <= 2 * printSize) {
        std::cout << "    [";
        for (size_t i = 0; i < slotCount; i++) {
            std::cout << " " << vec[i] << ((i != slotCount - 1) ? "," : "]\n");
        }
    } else {
        vec.resize(std::max(vec.size(), 2 * printSize));
        std::cout << "    [";
        for (size_t i = 0; i < printSize; i++) {
            std::cout << " " << vec[i] << ",";
        }
        if (vec.size() > 2 * printSize) {
            std::cout << " ...,";
        }
        for (size_t i = slotCount - printSize; i < slotCount; i++) {
            std::cout << " " << vec[i] << ((i != slotCount - 1) ? "," : "]\n");
        }
    }
    std::cout << std::endl;

    // Restore old formatting to std::cout
    std::cout.copyfmt(oldFormat);

}

/**
 * @brief Shifts work by a random value
 * 
 * @param[in] result Initial results vector
 * @param[in] randomValue Value to shift by
 * @return A new vector with the shifted results
 */
std::vector<seal::Ciphertext> ShiftWork(const std::vector<seal::Ciphertext>& result, const int64_t& randomValue) {

    std::vector<seal::Ciphertext> newResult;
    int64_t size = result.size();

    for (int64_t i = 0; i < size; i++) {
        newResult.push_back(
            ((i + randomValue) >= size)
                ? result[i + randomValue - size]
                : result[i + randomValue]
        );
    }
    return newResult;

}

/**
 * @brief Shifts work by an index
 * 
 * @param[in] query Initial query vector
 * @param[in] index Index to shift by
 * @param[in] numSlots Number of slots to shift
 * @return A new vector with the shifted results
 */
std::vector<int64_t> ShiftWork(const std::vector<int64_t>& query, const int64_t& index, const int64_t& numSlots) {

    std::vector<int64_t> newIndex;
    int64_t size = query.size();

    for (int64_t i = 0; i < numSlots; i++) {
        newIndex.push_back(
            ((i + index) >= size)
                ? query[i + index - size]
                : query[i + index]
        );
    }
    return newIndex;

}

/**
 * @brief Helper function for loading a specific key 
 * 
 * @tparam T PublicKey, SecretKey, RelinKeys, GaloisKeys
 * @param[in] context SealContext to apply keys
 * @param[in] filepath Path to key
 * @return Requested key
 */
template <typename T>
T LoadKey(const seal::SEALContext& context, const std::string& filepath) {

    std::ifstream file(filepath);
    T key;
    key.load(context, file);
    file.close();
    return key;

}

/**
 * @brief Create a SEALContext From Params file
 * 
 * @param[in] filepath Filepath to params
 * @param[in] scheme_type Type of scheme params should be
 * @return Newly created SEALContext
 */
seal::SEALContext CreateContextFromParams(std::string filepath, seal::scheme_type scheme_type) {

    std::ifstream paramsFile(filepath);
    seal::EncryptionParameters params(scheme_type);
    params.load(paramsFile);
    seal::SEALContext context(params);
    paramsFile.close();
    return context;

}

/**
 * @brief Makes a map from files.
 * 
 * @param[in] filename Path to data file.
 * @return Newly created map of files with hour data for each day.
 */
std::map<std::string, std::vector<double>> ReadData(const std::string& filename) {

    // Read power consumption as map

    std::ifstream readData(filename);
    std::map<std::string, std::vector<double>> hourData;
    std::string usage_str, line_str, time_st;
    std::vector<double> usage_hour;

    bool flag = true;
    // Read each row as a new stringstream
    while (std::getline(readData, line_str)) {
        std::stringstream ss(line_str);
        // Divide as two parts: A string and a new stringstream
        while (std::getline(ss, usage_str, ',')) {
            if (flag) {
                time_st = usage_str;
                flag = false;
            } else {
                double temp = std::stod(usage_str);
                usage_hour.push_back(temp);
            }
        }

        // Here if you don't need the first row which is the meters' number
        if (time_st != "TimeSlot") {
            hourData.insert(std::pair<std::string, std::vector<double>>(time_st, usage_hour));
        }
        usage_hour.clear();
        flag = true;
    }

    return hourData;

}

/**
 * @brief Calculates the harmonic mean for the datda from 1 hour.
 * 
 * @param x Hour data
 * @return Harmonic mean for that hour
 */
double HarmonicMean(std::vector<double> x) {

    double sum_hm_double = 0.0, temp;
    int64_t N = x.size();
    for (int64_t i = 0; i < N; ++i) {
        temp = 1 / log(x[i] + 2); // Scale 100 times
        sum_hm_double += temp;
    }
    return N / sum_hm_double;

}

double ArithmeticMean(std::vector<double> x) {

    double sum_am_double = 0.0, temp;
    int64_t N = x.size();
    for (int64_t i = 0; i < N; ++i) {
        temp = log(x[i] + 2); // Scale x times
        sum_am_double += temp;
    }
    return sum_am_double / N;

}

#endif // SMART_UTILITY_HPP
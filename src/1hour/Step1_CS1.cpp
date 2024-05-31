#include "SGSimulation.hpp"

/**
 * @brief Make a map from files
 * 
 * @param[in] filename File to make map from
 * @return Hour data <{timestamp, usage}, ...>
 */
std::map<std::string, std::vector<double>> ReadData(const std::string& filename) {

    // Read power consumption as map

    std::ifstream readData(filename);
    std::map<std::string, std::vector<double>> hourData;
    std::string usage, line, time;
    std::vector<double> usageHour;

    bool flag = true;
    // Each row as a new stringstream
    while (getline(readData, line)) {
        std::stringstream ss(line);
        // Divide as two part: a string and a new stringstream
        while (getline(ss, usage, ',')) {
            if (flag) {
                time = usage;
                flag = false;
            } else {
                // Convert data to double, then push into usage vector
                usageHour.push_back(std::stod(usage));
            }
        }
        // Here if you don't need the first row which is the meter's number
        if (time != "TimeSlot") {
            hourData.insert(
                std::pair<std::string, std::vector<double>>
                {time, usageHour}
            );
        } else {
        // If we need the first row which is the meter's number, uncomment this line
        //hourData.insert(std::pair<std::string, std::vector<double>>{time, usageHour});
        }
        usageHour.clear();
        flag = true;
    }
    return hourData;

}

/**
 * @brief Harmonic mean for an hour
 * 
 * @param[in] vec Results vector
 * @return The harmonic mean for the hour of data
 */
double HarmonicMean(std::vector<double> vec) {

    double sum = 0.0;
    int64_t n = vec.size();
    for (int64_t i = 0; i < n; ++i) {
        sum += 1 / std::log(vec[i] + 2); // Scale 100 times
    }
    return n / sum;

}

/**
 * @brief Arithmetic mean for an hour
 * 
 * @param[in] vec Results vector
 * @return The arithmetic mean for the hour of data 
 */
double ArithmeticMean(std::vector<double> vec) {

    double sum = 0.0;
    int64_t n = vec.size();
    for (int64_t i = 0; i < vec.size(); ++i) {
        sum += std::log(vec[i] + 2); // Scale x times
    }
    return sum / n;

}

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    std::cout << "Setting FHE" << std::endl;

    // Load context, required keys, and cryptors/coders

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::BatchEncoder batchEncoder(context);

    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;

    int64_t rowCountAM = std::ceil((double)TABLE_SIZE_AM / (double)rowSize);
    int64_t rowCountHM = std::ceil((double)TABLE_SIZE_HM / (double)rowSize);

    ////////////////////////////////////////////////////////////////////////////////

    auto startRead = std::chrono::high_resolution_clock::now();

    // Start reading data

    std::string input(argv[1]);             // s1
    std::string plaintextResult(argv[2]);   // s2
    std::string resultDir(argv[3]);         // s3
    std::string hourNumber(argv[4]);        // s4

    auto mapTimeData = ReadData(input);
    std::cout << "Number of time slot is " << mapTimeData.size() << std::endl;
    auto endRead = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffRead = endRead - startRead;
    std::cout << "1 Hour read data runtime is: " << diffRead.count() << "s" << std::endl;

    // Read tables

    std::vector<seal::Ciphertext> tableAM;
    std::vector<seal::Ciphertext> tableHM;

    std::ifstream readTableAM;
    readTableAM.open("Table/AM_input_" + std::to_string(METER_NUM));
    for (int i = 0; i < rowCountAM; i++) {
        seal::Ciphertext tempOne;
        tempOne.load(context, readTableAM);
        tableAM.push_back(tempOne);
    }
    readTableAM.close();

    std::ifstream readTableHM;
    readTableHM.open("Table/HM_input_" + std::to_string(METER_NUM));
    for (int i = 0; i < rowCountHM; i++) {
        seal::Ciphertext tempTwo;
        tempTwo.load(context, readTableHM);
        tableHM.push_back(tempTwo);
    }
    readTableHM.close();

    // Sum the usage of per day
    std::vector<seal::Ciphertext> sumAM, sumHM;
    int64_t timeslot;
    for (timeslot = 0; timeslot < 24; timeslot++) {
        seal::Ciphertext tts;
        sumAM.push_back(tts);
        sumHM.push_back(tts);
    }
    timeslot = 0;

    double sumAMTime = 0.0, sumHMTime = 0.0;
    double timeAM, timeHM;
    std::cout << "Number of time slot is " << mapTimeData.size() << std::endl;

    for (auto iter = mapTimeData.begin(); iter != mapTimeData.end(); ++iter) {
        auto startSum = std::chrono::high_resolution_clock::now();
        std::cout << iter->first << std::endl;
        std::cout << "Number of data is " << (iter->second).size() << std::endl;

        seal::Ciphertext logSum, logRecSum;
        std::vector<double> x = iter->second;
        int64_t checkSumLog = 0, checkSumRecLog = 0;
        double maxNum = 0;

        std::cout << "\033[31m===Sum Usage Processing===\033[0m" << std::endl;

        for (auto iterTwo = x.begin(); iterTwo != x.end(); ++iterTwo) {
            int64_t temp = PRECISION * std::log(*iterTwo + 2);
            double tep = PRECISION * std::log(*iterTwo + 2);
            int64_t tempRec = PRECISION2 * 1 / log(*iterTwo + 2);
            double tepRec = PRECISION2 * 1 / log(*iterTwo + 2);

            if (abs(tep - temp) >= 0.5) {
                temp++;
            }
            if (abs(tepRec - tempRec) >= 0.5) {
                tempRec++;
            }

            checkSumLog += temp;
            checkSumRecLog += tempRec;
            
            if (*iterTwo >= maxNum) {
                maxNum = *iterTwo;
            }

            std::vector<int64_t> vecLog;
            for (int i = 0; i < rowSize; i++) {
                vecLog.push_back(temp);
            }
            vecLog.resize(slotCount);

            std::vector<int64_t> vecRecLog;
            for (int i = 0; i < rowSize; i++) {
                vecRecLog.push_back(tempRec);
            }
            vecRecLog.resize(slotCount);

            // Encrypt the usage and add to logSum

            seal::Plaintext polyLog;
            batchEncoder.encode(vecLog, polyLog);
            seal::Ciphertext logEnc;
            encryptor.encrypt(polyLog, logEnc);
            
            if (iterTwo == x.begin()) {
                logSum = logEnc;
            } else {
                evaluator.add_inplace(logSum, logEnc);
            }

            seal::Plaintext polyRecLog;
            batchEncoder.encode(vecRecLog, polyRecLog);
            seal::Ciphertext recLogEnc;
            encryptor.encrypt(polyRecLog, recLogEnc);

            if (iterTwo == x.begin()) {
                logRecSum = recLogEnc;
            } else {
                evaluator.add_inplace(logRecSum, recLogEnc);
            }
            evaluator.relinearize_inplace(logRecSum, relinKey);
        }

        sumAM[timeslot] = logSum;
        sumHM[timeslot] = logRecSum;

        std::cout << "CHECK TEST (INT)" << std::endl;
        std::cout << "Sum log() is: " << checkSumLog << ", Sum 1/log() is: " << checkSumRecLog << std::endl;
        std::cout << "Max usage is: " << maxNum << std::endl;

        timeAM = ArithmeticMean(x);
        timeHM = HarmonicMean(x);
        std::cout << "Plaintext result >> AM:" << timeAM << ", HM:" << timeHM << std::endl;

        // Reset all values and increment timeslot

        checkSumLog = 0, checkSumRecLog = 0;
        maxNum = 0;
        timeslot++;
        sumAMTime += timeAM;
        sumHMTime += timeHM;
        timeAM = 0.0;
        timeHM = 0.0;

        // End timing

        auto endSum = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diffSum = endSum - startSum;
        std::cout << "1 Hour sum usage runtime is: " << diffSum.count() << "s" << std::endl;
    }

    double ratio = sumHMTime / sumAMTime;

    std::cout << "Plaintext Sum AM: " << sumAMTime << ", ratio result: " << ratio << std::endl;
    std::ofstream ptRatio; // date_Arithmean_hour
    ptRatio.open(plaintextResult, std::ios::app);
    ptRatio << ratio << std::endl;
    ptRatio.close();

    std::cout << "\033[31m===Sum Usage Processing End===\033[0m" << std::endl;
    auto startHour = std::chrono::high_resolution_clock::now();
    std::vector<seal::Ciphertext> resultCTAM, resultCTHM;
    for (int64_t i = 0; i < rowCountAM; i++) {
        seal::Ciphertext tempResult;
        resultCTAM.push_back(tempResult);
    }
    for (int64_t i = 0; i < rowCountHM; i++) {
        seal::Ciphertext tempResult;
        resultCTHM.push_back(tempResult);
    }

    // Search Table

    std::cout << "\033[32m===Table Search Processing===\033[0m" << std::endl;

    int64_t i = std::stoi(hourNumber);

    std::ofstream resultAM;
    resultAM.open(resultDir + "/AM_" + std::to_string(i), std::ios::binary);
    std::ofstream resultHM;
    resultHM.open(resultDir + "/HM_" + std::to_string(i), std::ios::binary);

    std::cout << "Time Slot: " << i << std::endl;

    // Search sum of log and save

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t j = 0; j < rowCountAM; j++) {
        seal::Ciphertext tempInputAM = sumAM[i];
        evaluator.sub_inplace(tempInputAM, tableAM[j]);
        evaluator.relinearize_inplace(tempInputAM, relinKey);
        resultCTAM[j] = tempInputAM;
    }

    for (int64_t j = 0; j < rowCountAM; j++) {
        resultCTAM[j].save(resultAM);
    }
    resultAM.close();

    // Search sum of 1/log and save

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t k = 0; k < rowCountHM; k++) {
        seal::Ciphertext tempInputHM = sumHM[i];
        evaluator.sub_inplace(tempInputHM, tableHM[k]);
        resultCTHM[k] = tempInputHM;
    }

    for (int64_t k = 0; k < rowCountHM; k++) {
        resultCTHM[k].save(resultHM);
    }
    resultHM.close();

    auto endHour = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffHour = endHour - startHour;
    std::cout << "1 Hour LUT Runtime is: " << diffHour.count() << "s" << std::endl;

    std::cout << "\033[32m===Table Search Processing End===\033[0m" << std::endl;

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());
    return 0;

}
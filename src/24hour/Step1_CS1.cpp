#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHE

    std::cout << "Setting FHE" << std::endl;

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::BatchEncoder batchEncoder(context);

    size_t slot_count = batchEncoder.slot_count();
    size_t row_size = slot_count / 2;
    int64_t row_count_AM = ceil((double)TABLE_SIZE_AM / (double)row_size);
    int64_t row_count_HM = ceil((double)TABLE_SIZE_HM / (double)row_size);

    // Read table

    std::vector<seal::Ciphertext> AM_tab;
    std::vector<seal::Ciphertext> HM_tab;

    std::ifstream read_AMTable;
    read_AMTable.open("Table/AM_input_" + std::to_string(METER_NUM));
    for (int i = 0; i < row_count_AM; i++) {
        seal::Ciphertext temp;
        temp.load(context, read_AMTable);
        AM_tab.push_back(temp);
    }

    std::ifstream read_HMTable;
    read_HMTable.open("Table/HM_input_" + std::to_string(METER_NUM));
    for (int i = 0; i < row_count_HM; i++) {
        seal::Ciphertext temp;
        temp.load(context, read_HMTable);
        HM_tab.push_back(temp);
    }

    // Read data

    std::string inputFile(argv[1]);     // s1
    std::string resultFile(argv[2]);    // s2
    std::string resultDir(argv[3]);     // s3
    std::map<std::string, std::vector<double>> mapTimeData = ReadData(inputFile);
    std::cout << "Number of time slot is " << mapTimeData.size() << std::endl;

    // Sum the usage of per day

    int64_t timeslot;
    std::vector<seal::Ciphertext> AM_sum_res, HM_sum_res;
    for (timeslot = 0; timeslot < 24; timeslot++) {
        seal::Ciphertext tts;
        AM_sum_res.push_back(tts);
        HM_sum_res.push_back(tts);
    }

    timeslot = 0;
    double Sum_AM_time = 0.0, Sum_HM_time = 0.0;
    double AM_time, HM_time;
    for (auto iter = mapTimeData.begin(); iter != mapTimeData.end(); ++iter) {
        std::cout << iter->first << std::endl;
        std::cout << "Number of data is " << iter->second.size() << std::endl;

        seal::Ciphertext log_sum, log_rec_sum;
        std::vector<double> x = iter->second;
        int64_t checksumlog = 0, checksumreclog = 0;
        double max_num = 0;

        std::cout << "===Sum Usage Processing===" << std::endl;
        for (auto iter2 = x.begin(); iter2 != x.end(); ++iter2) {
            int64_t temp = PRECISION * log(*iter2 + 2);
            double tep = PRECISION * log(*iter2 + 2);
            int64_t temp_rec = PRECISION2 * 1 / log(*iter2 + 2);
            double tep_rec = PRECISION2 * 1 / log(*iter2 + 2);

            if (abs(tep - temp) >= 0.5) {
                temp += 1;
            }
            if (abs(tep_rec - temp_rec) >= 0.5) {
                temp_rec += 1;
            }

            checksumlog += temp;
            checksumreclog += temp_rec;
            if (*iter2 >= max_num) {
                max_num = *iter2;
            }

            std::vector<int64_t> vec_log;
            for (int i = 0; i < row_size; i++) {
                vec_log.push_back(temp);
            }
            vec_log.resize(slot_count);

            std::vector<int64_t> vec_rec_log;
            for (int i = 0; i < row_size; i++) {
                vec_rec_log.push_back(temp_rec);
            }
            vec_rec_log.resize(slot_count);

            // Encrypt the usage and add to log_sum

            seal::Plaintext poly_log;
            batchEncoder.encode(vec_log, poly_log);
            seal::Ciphertext log_enc;
            encryptor.encrypt(poly_log, log_enc);
            if (iter2 == x.begin()) {
                log_sum = log_enc;
            } else {
                evaluator.add_inplace(log_sum, log_enc);
            }

            // Encrypt the 1/usage and add to rec_log_sum

            seal::Plaintext poly_rec_log;
            batchEncoder.encode(vec_rec_log, poly_rec_log);
            seal::Ciphertext rec_log_enc;
            encryptor.encrypt(poly_rec_log, rec_log_enc);
            if (iter2 == x.begin()) {
                log_rec_sum = rec_log_enc;
            } else {
                evaluator.add_inplace(log_rec_sum, rec_log_enc);
            }
            evaluator.relinearize_inplace(log_rec_sum, relinKey);

        }

        AM_sum_res[timeslot] = log_sum;
        HM_sum_res[timeslot] = log_rec_sum;

        std::cout << "CHECK TEST (INT)" << std::endl;
        std::cout << "Sum log() is: " << checksumlog << ", Sum 1/log() is: " << checksumreclog << std::endl;
        std::cout << "Max usage is: " << max_num << std::endl;
        AM_time = ArithmeticMean(x);
        HM_time = HarmonicMean(x);
        std::cout << "Plaintext result >> AM: " << AM_time << ", HM: " << HM_time << std::endl;
        checksumlog = 0, checksumreclog = 0;
        max_num = 0.0;
        timeslot++;
        Sum_AM_time += AM_time;
        Sum_HM_time += HM_time;
        AM_time = 0.0, HM_time = 0.0;

    }

    double ratio = Sum_HM_time / Sum_AM_time;

    std::cout << "Plaintext sum_AM: " << Sum_AM_time << ", sum_HM: " << Sum_HM_time << ", ratio result: " << ratio << std::endl;
    std::ofstream pt_ratio; // date_ArithMean_hour
    pt_ratio.open(resultFile, std::ios::app);
    pt_ratio << ratio << std::endl;
    pt_ratio.close();

    std::cout << "===Sum Usage Processing End===" << std::endl;
    auto endSum = std::chrono::high_resolution_clock::now();

    std::vector<seal::Ciphertext> result_ct_AM, result_ct_HM;
    for (int64_t i = 0; i < row_count_AM; i++) {
        result_ct_AM.push_back(seal::Ciphertext());
    }
    for (int64_t i = 0; i < row_count_HM; i++) {
        result_ct_HM.push_back(seal::Ciphertext());
    }

    std::cout << "===Table Search Processing===" << std::endl;

    for (int64_t i = 0; i < 24; i++) {
        std::ofstream result_AM; // date_ArithMean_hour
        result_AM.open(resultDir + "/AM_" + std::to_string(i), std::ios::binary);
        std::ofstream result_HM;
        result_HM.open(resultDir + "/HM_" + std::to_string(i), std::ios::binary);

        std::cout << "TIME SLOT: " << i << std::endl;

        // Search sum of log and save

        omp_set_num_threads(NF);
        #pragma omp parallel for
        for (int64_t j = 0; j < row_count_AM; j++) {
            seal::Ciphertext temp_AM_input = AM_sum_res[i];
            evaluator.sub_inplace(temp_AM_input, AM_tab[j]);
            evaluator.relinearize_inplace(temp_AM_input, relinKey);
            result_ct_AM[j] = temp_AM_input;
        }

        printf("\nNEED TO REACH HERE\n");

        for (int64_t j = 0; j < row_count_AM; j++) {
            result_ct_AM[j].save(result_AM);
        }
        result_AM.close();

        // Search sum of 1/log and save

        omp_set_num_threads(NF);
        #pragma omp parallel for
        for (int64_t j = 0; j < row_count_HM; j++) {
            seal::Ciphertext temp_HM_input = HM_sum_res[i];
            evaluator.sub_inplace(temp_HM_input, HM_tab[j]);
            result_ct_HM[j] = temp_HM_input;
        }

        for (int64_t j = 0; j < row_count_HM; j++) {
            result_ct_HM[j].save(result_HM);
        }
        result_HM.close();
    }
    std::cout << "===Table Search Processing End===" << std::endl;

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diff1 = endSum - startWhole;
    std::chrono::duration<double> diff2 = endWhole - endSum;
    
    std::cout << "Runtime sum is: " << diff1.count() << "s" << std::endl;
    std::cout << "Runetime LUT is: " << diff2.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    std::cout << "Setting FHE" << std::endl;

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto galoisKey = LoadKey<seal::GaloisKeys>(context, GALOIS_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::BatchEncoder batchEncoder(context);

    size_t slot_count = batchEncoder.slot_count();
    size_t row_size = slot_count / 2;

    std::cout << "Plaintext matrix row size: " << slot_count << std::endl;
    std::cout << "Slot nums = " << slot_count << std::endl;

    int64_t row_count_AM = ceil((double)TABLE_SIZE_AM / (double)row_size);
    int64_t row_count_HM = ceil((double)TABLE_SIZE_HM / (double)row_size);
    int64_t sum_row_count_AM = ceil((double)TABLE_SIZE_AM_INV / (double)row_size);
    int64_t div_row_count_HM = ceil((double)TABLE_SIZE_DIV_HM / (double)row_size);

    std::cout << "AM row " << row_count_AM << ", HM row " << row_count_HM << std::endl;

    //////////////////////////////////////////////////////////////////////////////

    // Read output table

    std::vector<seal::Ciphertext> output_AM;
    std::vector<seal::Ciphertext> output_HM;

    std::ifstream readtable_part1;
    readtable_part1.open("Table/AM_output_" + std::to_string(METER_NUM));
    for (int i = 0; i < row_count_AM; i++) {
        seal::Ciphertext temp;
        temp.load(context, readtable_part1);
        output_AM.push_back(temp);
    }

    std::ifstream readtable_hm;
    readtable_hm.open("Table/HM_output_" + std::to_string(METER_NUM));
    for (int i = 0; i < row_count_HM; i++) {
        seal::Ciphertext temp;
        temp.load(context, readtable_hm);
        output_HM.push_back(temp);
    }

    std::vector<seal::Ciphertext> res_a, res_h, sum_result_a, sum_result_h, sum_result_am_r, sum_result_hm_r;
    // res_a: result of one time slot AM for each row
    // sum_result_a: result of one time slot AM (sum all row)
    // sum_result_am_r: result of 24 time slots AM (sum all time slots)
    // res_h1,2: result of one time slot HM for each row
    // sum_result_h1,2: result of one time slot AM (sum all row)
    // sum_result_hm_r1,2: result of 24 time slots AM (sum all time slots)

    for (int64_t i = 0; i < row_count_AM; i++) {
        res_a.push_back(seal::Ciphertext());
    }
    for(int64_t i = 0; i < row_count_HM; i++) {
        res_h.push_back(seal::Ciphertext());
    }
    for (int64_t i = 0; i < 24; i++) {
        seal::Ciphertext temp;
        sum_result_a.push_back(temp);
        sum_result_h.push_back(temp);
        sum_result_am_r.push_back(temp);
        sum_result_hm_r.push_back(temp);
    }

    std::string date(argv[1]);      // s1
    std::string resultDir(argv[2]); // s2

    ////////////////////////////////////////////////////////////////////

    std::cout << "===Main===" << std::endl;

    for (int64_t iter = 0; iter < 24; iter++) {
        // Read index and PIR query from file
        std::cout << "===Reading query from DS===" << std::endl;
        std::ifstream PIRqueryFile(resultDir + "/pir_AMHM_" + std::to_string(iter));
        seal::Ciphertext ct_query_AM0, ct_query_AM1, ct_query_HM0, ct_query_HM1;
        ct_query_AM0.load(context, PIRqueryFile);
        ct_query_AM1.load(context, PIRqueryFile);
        ct_query_HM0.load(context, PIRqueryFile);
        ct_query_HM1.load(context, PIRqueryFile);
        PIRqueryFile.close();

        std::cout << "Reading query from DS > OK" << std::endl;
        std::cout << "LUT Processing" << std::endl;

        omp_set_num_threads(NF);
        #pragma omp parallel for
        for (int64_t j = 0; j < row_count_AM; j++) {
            seal::Ciphertext temp = ct_query_AM1;
            evaluator.rotate_rows_inplace(temp, -j, galoisKey);
            evaluator.multiply_inplace(temp, ct_query_AM0);
            evaluator.relinearize_inplace(temp, relinKey);
            evaluator.multiply_inplace(temp, output_AM[j]);
            evaluator.relinearize_inplace(temp, relinKey);
            res_a[j] = temp;
        }

        omp_set_num_threads(NF);
        #pragma omp parallel for
        for (int64_t k = 0; k < row_count_HM; k++) {
            seal::Ciphertext temp = ct_query_HM1;
            evaluator.rotate_rows_inplace(temp, -k, galoisKey);
            evaluator.multiply_inplace(temp, ct_query_HM0);
            evaluator.relinearize_inplace(temp, relinKey);
            evaluator.multiply_inplace(temp, output_HM[k]);
            evaluator.relinearize_inplace(temp, relinKey);
            res_h[k] = temp;
        }

        std::cout << "===Sum Result===" << std::endl;

        sum_result_a[iter] = res_a[0];
        for (int k = 1; k < row_count_AM; k++) {
            evaluator.add_inplace(sum_result_a[iter], res_a[k]);
        }
        
        sum_result_h[iter] = res_h[0];
        for (int i = 1; i < row_count_HM; i++) {
            evaluator.add_inplace(sum_result_h[iter], res_h[i]);
        }

        sum_result_am_r[iter] = sum_result_a[iter];
        sum_result_hm_r[iter] = sum_result_h[iter];

        auto startTS = std::chrono::high_resolution_clock::now();

        for (int64_t i = 0; i < log2(row_size); i++) {
            seal::Ciphertext ct1 = sum_result_am_r[iter];
            seal::Ciphertext ct2 = sum_result_hm_r[iter];
            evaluator.rotate_rows_inplace(ct1, -pow(2, i), galoisKey);
            evaluator.relinearize_inplace(ct1, relinKey);
            evaluator.add_inplace(sum_result_am_r[iter], ct1);
            evaluator.rotate_rows_inplace(ct2, -pow(2, i), galoisKey);
            evaluator.relinearize_inplace(ct2, relinKey);
            evaluator.add_inplace(sum_result_hm_r[iter], ct2);
        }

        auto endTS = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> diffTS = endTS - startTS;
        std::cout << "TotalSum: " << diffTS.count() << "s" << std::endl;

    }

    seal::Ciphertext AM_rec, HM_rec;
    std::cout << "We have " << sum_result_am_r.size() << " AM." << std::endl;
    std::cout << "We have " << sum_result_hm_r.size() << " HM." << std::endl;
    AM_rec = sum_result_am_r[0];
    HM_rec = sum_result_hm_r[0];

    for (int64_t i = 1; i < 24; i++) {
        std::cout << "Hour." << i << std::endl;
        evaluator.add_inplace(AM_rec, sum_result_am_r[i]);
        evaluator.relinearize_inplace(AM_rec, relinKey);
        evaluator.add_inplace(HM_rec, sum_result_hm_r[i]);
        evaluator.relinearize_inplace(HM_rec, relinKey);
    }

    // LUT sumAM => 1/sumAM

    std::vector<seal::Ciphertext> AM_tab;
    std::cout << "Read table for sum 1/AM" << std::endl;
    std::ifstream read_AMTable;
    read_AMTable.open("Table/SUM_AM_input_" + std::to_string(METER_NUM));
    for (int i = 0; i < sum_row_count_AM; i++) {
        seal::Ciphertext temp;
        temp.load(context, read_AMTable);
        AM_tab.push_back(temp);
    }

    // Read table

    std::ofstream result_AM;
    result_AM.open(resultDir + "/inv_SUM_AM_" + date, std::ios::binary);
    for (int64_t i = 0; i < sum_row_count_AM; i++) {
        seal::Ciphertext t = AM_rec;
        evaluator.sub_inplace(t, AM_tab[i]);
        evaluator.relinearize_inplace(t, relinKey);
        t.save(result_AM);
    }
    result_AM.close();

    // LUT sumHM => divide to sumHM 1, and sumHM 2. sumHM = sumHM1 * 100 + sumHM2

    std::vector<seal::Ciphertext> HM_tab;
    std::cout << "Readtable for sum HM" << std::endl;
    std::ifstream read_HMTable;
    read_HMTable.open("Table/div_HM_input_" + std::to_string(METER_NUM));
    for (int i = 0; i < div_row_count_HM; i++) {
        seal::Ciphertext temp;
        temp.load(context, read_HMTable);
        HM_tab.push_back(temp);
    }

    // Read table

    std::ofstream result_HM;
    result_HM.open(resultDir + "/div_HM_" + date, std::ios::binary);
    for (int64_t i = 0; i < div_row_count_HM; i++) {
        seal::Ciphertext t = HM_rec;
        evaluator.sub_inplace(t, HM_tab[i]);
        evaluator.relinearize_inplace(t, relinKey);
        t.save(result_HM);
    }
    result_HM.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
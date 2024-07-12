#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    std::cout << "Setting FHE" << std::endl;

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto secretKey = LoadKey<seal::SecretKey>(context, SECRET_KEY_FILEPATH);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secretKey);
    seal::BatchEncoder batchEncoder(context);

    size_t slot_count = batchEncoder.slot_count();
    size_t row_size = slot_count / 2;

    std::cout << "Plaintext matrix row size: " << row_size << std::endl;
    std::cout << "Slot nums = " << slot_count << std::endl;

    int64_t row_count_fun1 = ceil((double)TABLE_SIZE_AM / (double)row_size);
    int64_t row_count_fun2 = ceil((double)TABLE_SIZE_HM / (double)row_size);

    //////////////////////////////////////////////////////////////////////////////

    std::string resultDir(argv[1]);     // s1
    
    std::vector<seal::Ciphertext> ct_result1, ct_result2;
    std::vector<std::vector<int64_t>> dec_result1(row_count_fun1);
    std::vector<seal::Plaintext> poly_dec_result1, poly_dec_result2;
    std::vector<std::vector<int64_t>> dec_result2(row_count_fun2);

    for (int i = 0; i < row_count_fun1; i++) {
        poly_dec_result1.push_back(seal::Plaintext());
        ct_result1.push_back(seal::Ciphertext());
    }
    for (int i = 0; i < row_count_fun2; i++) {
        poly_dec_result2.push_back(seal::Plaintext());
        ct_result2.push_back(seal::Ciphertext());
    }

    std::cout << "===Main===" << std::endl;

    for (int64_t iter = 0; iter < 24; iter++) {
        std::ifstream result_1, result_2;
        result_1.open(resultDir + "/AM_" + std::to_string(iter), std::ios::binary);
        result_2.open(resultDir + "/HM_" + std::to_string(iter), std::ios::binary);
        seal::Ciphertext temp1, temp2;

        for (int i = 0; i < row_count_fun1; i++) {
            temp1.load(context, result_1);
            ct_result1[i] = temp1;
        }
        for (int i = 0; i < row_count_fun2; i++) {
            temp2.load(context, result_2);
            ct_result2[i] = temp2;
        }

        result_1.close();
        result_2.close();

        std::cout << "===Decrypting===" << std::endl;

        omp_set_num_threads(NF);
        #pragma omp parallel for
        for (int i = 0; i < row_count_fun1; i++) {
            seal::Ciphertext result_temp1 = ct_result1[i];
            decryptor.decrypt(result_temp1, poly_dec_result1[i]);
            batchEncoder.decode(poly_dec_result1[i], dec_result1[i]);
        }
        for (int i = 0; i < row_count_fun2; i++) {
            seal::Ciphertext result_temp2 = ct_result2[i];
            decryptor.decrypt(result_temp2, poly_dec_result2[i]);
            batchEncoder.decode(poly_dec_result2[i], dec_result2[i]);
        }

        std::cout << "Decryping > OK" << std::endl;

        ///////////////////////////////////////////////////////////////////

        std::cout << "===Making PIR-query===" << std::flush;
        std::cout << "Search index of function 1" << std::endl;

        int64_t index_row_x, index_col_x;
        bool flag1 = false, flag2 = false;

        for (int64_t i = 0; i < row_count_fun1; i++) {
            for (int64_t j = 0; j < row_size; j++) {
                if (dec_result1[i][j] >= 0 and dec_result1[i][j + 1] < 0 and !flag1) {
                    int64_t left = dec_result1[i][j];
                    int64_t right = abs(dec_result1[i][j + 1]);
                    flag1 = true;
                    index_row_x = i;
                    index_col_x = (left <= right) ? (j) : (j + 1);
                    break;
                }
            }
        }

        std::cout << "Got index of function 1" << std::endl;
        if (!flag1) {
            std::cout << "ERROR: NO FIND 1" << std::endl;
        }
        std::cout << "Search index of function 2" << std::endl;
        int64_t index_row_y, index_col_y;
        for (int64_t i = 0; i < row_count_fun2; i++) {
            for (int64_t j = 0; j < row_size; j++) {
                if (dec_result2[i][j] == 0) {
                    index_row_y = i;
                    index_col_y = j;
                    break;
                    flag2 = true;
                }
                if (dec_result2[i][j] <= 0 and dec_result2[i][j + 1] > 0 and !flag2) {
                    int64_t left = abs(dec_result2[i][j]);
                    int64_t right = dec_result2[i][j + 1];
                    flag2 = true;
                    index_row_y = i;
                    index_col_y = (left <= right) ? (j) : (j + 1);
                }
            }
        }

        std::cout << "Got index of function 2" << std::endl;
        if (!flag2) {
            std::cout << "ERROR: NO FIND 2" << std::endl;
        }
        std::cout << "Hour." << std::endl;
        std::cout << "index_row_AM: " << index_row_x << ", index_col_AM: " << index_col_x << ", index_row_HM: " << index_row_y << ", index_col_HM: " << index_col_y << std::endl;
        std::cout << "OK" << std::endl;

        std::vector<int64_t> query_AM0, query_AM1, query_HM0, query_HM1;
        for (int64_t i = 0; i < row_size; i++) {
            query_AM0.push_back((i == index_col_x) ? 1 : 0);
            query_HM0.push_back((i == index_col_y) ? 1 : 0);
        }
        query_AM1 = ShiftWork(query_AM0, index_row_x, row_size);
        query_AM0.resize(slot_count);
        query_AM1.resize(slot_count);

        query_HM1 = ShiftWork(query_HM0, index_row_y, row_size);
        query_HM0.resize(slot_count);
        query_HM1.resize(slot_count);

        std::cout << "Making PIR-query > OK" << std::endl;

        // Encrypt new query

        std::cout << "===Encrypting===" << std::endl;

        seal::Ciphertext ct_query_AM0, ct_query_AM1, ct_query_HM0, ct_query_HM1;
        seal::Plaintext pt_query_AM0, pt_query_AM1, pt_query_HM0, pt_query_HM1;

        batchEncoder.encode(query_AM0, pt_query_AM0);
        encryptor.encrypt(pt_query_AM0, ct_query_AM0);
        batchEncoder.encode(query_AM1, pt_query_AM1);
        encryptor.encrypt(pt_query_AM1, ct_query_AM1);
        batchEncoder.encode(query_HM0, pt_query_HM0);
        encryptor.encrypt(pt_query_HM0, ct_query_HM0);
        batchEncoder.encode(query_HM1, pt_query_HM1);
        encryptor.encrypt(pt_query_HM1, ct_query_HM1);

        std::cout << "Encrypting > OK" << std::endl;

        // Write results to file

        std::cout << "===Saving Query===" << std::endl;

        std::ofstream queryFile;
        queryFile.open(resultDir + "/pir_AMHM_" + std::to_string(iter));
        ct_query_AM0.save(queryFile);
        ct_query_AM1.save(queryFile);
        ct_query_HM0.save(queryFile);
        ct_query_HM1.save(queryFile);
        queryFile.close();

        std::cout << "Save query Hour." << iter << " > OK" << std::endl;

    }

    std::cout << "===End===" << std::endl;

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
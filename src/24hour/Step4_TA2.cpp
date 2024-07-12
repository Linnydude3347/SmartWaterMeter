#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHE

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

    int64_t sum_row_count_AM = ceil((double)TABLE_SIZE_AM_INV / (double)row_size);
    int64_t div_row_count_HM = ceil((double)TABLE_SIZE_DIV_HM / (double)row_size);

    //////////////////////////////////////////////////////////////////////////////

    std::string date(argv[1]);      // s1
    std::string resultDir(argv[2]); // s2
    std::vector<seal::Ciphertext> ct_result1, ct_result2;
    std::vector<std::vector<int64_t>> dec_result1(sum_row_count_AM);
    std::vector<std::vector<int64_t>> dec_result2(div_row_count_HM);
    std::vector<seal::Plaintext> poly_dec_result1, poly_dec_result2;

    for (int i = 0; i < sum_row_count_AM; i++) {
        poly_dec_result1.push_back(seal::Plaintext());
        ct_result1.push_back(seal::Ciphertext());
    }
    for (int i = 0; i < div_row_count_HM; i++) {
        poly_dec_result2.push_back(seal::Plaintext());
        ct_result2.push_back(seal::Ciphertext());
    }

    std::cout << "===Main===" << std::endl;

    std::ifstream result_1;
    result_1.open(resultDir + "/inv_SUM_AM_" + date, std::ios::binary);
    for (int i = 0; i < sum_row_count_AM; i++) {
        seal::Ciphertext t;
        t.load(context, result_1);
        ct_result1[i] = t;
    }
    result_1.close();

    std::ifstream result_2;
    result_2.open(resultDir + "/div_HM_" + date, std::ios::binary);
    for (int i = 0; i < div_row_count_HM; i++) {
        seal::Ciphertext t;
        t.load(context, result_2);
        ct_result2[i] = t;
    }
    result_2.close();

    std::cout << "===Decrypting===" << std::endl;

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int i = 0; i < sum_row_count_AM; i++) {
        seal::Ciphertext t = ct_result1[i];
        decryptor.decrypt(t, poly_dec_result1[i]);
        batchEncoder.decode(poly_dec_result1[i], dec_result1[i]);
    }

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int i = 0; i < div_row_count_HM; i++) {
        seal::Ciphertext t = ct_result2[i];
        decryptor.decrypt(t, poly_dec_result2[i]);
        batchEncoder.decode(poly_dec_result2[i], dec_result2[i]);
    }

    std::cout << "Decrypting > OK" << std::endl;
    std::cout << "===Making PIR-query" << std::endl;
    std::cout << "Search index of function 1" << std::endl;

    int64_t index_row_x, index_col_x;
    bool flag1 = false;
    for (int64_t i = 0; i < sum_row_count_AM; i++) {
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
    std::cout << "index_row_x: " << index_row_x << ", index_col_x: " << index_col_x << std::endl;
    std::cout << "Search index of function 2" << std::endl;

    int64_t index_row_y, index_col_y;
    bool flag2 = false;
    for (int64_t i = 0; i < div_row_count_HM; i++) {
        for (int64_t j = 0; j < row_size; j++) {
            if (dec_result2[i][j] == 0) {
                index_row_y = i;
                index_col_y = j;
                flag2 = true;
                break;
            }
            if (dec_result2[i][j] > 0 and dec_result2[i][j + 1] < 0 and !flag2) {
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
    std::cout << "index_row_y: " << index_row_y << ", index_col_y: " << index_col_y << std::endl;

    // new_index is new_query left_shift the value of index

    std::vector<int64_t> query_AM0, query_AM1, query_HM0, query_HM1;
    for (int64_t i = 0; i < row_size; i++) {
        query_AM0.push_back((i == index_col_x) ? 1 : 0);
    }
    query_AM1 = ShiftWork(query_AM0, index_row_x, row_size);
    query_AM0.resize(slot_count);
    query_AM1.resize(slot_count);

    for (int64_t i = 0; i < row_size; i++) {
        query_HM0.push_back((i == index_col_y) ? 1 : 0);
    }
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
    
    // Write to file

    std::cout << "===Saving query===" << std::endl;
    std::ofstream queryFile;
    queryFile.open(resultDir + "/pir_SUM_AM_DIV_HM_" + date);
    ct_query_AM0.save(queryFile);
    ct_query_AM1.save(queryFile);
    ct_query_HM0.save(queryFile);
    ct_query_HM1.save(queryFile);
    queryFile.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
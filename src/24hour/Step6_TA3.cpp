#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FhE

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

    int64_t inv100_row = ceil((double)TABLE_SIZE_100_INV / (double)row_size);

    //////////////////////////////////////////////////////////////////////////////

    std::string date(argv[1]);          // s1
    std::string resultDir(argv[2]);     // s2
    std::vector<seal::Ciphertext> ct_result;
    std::vector<std::vector<int64_t>> dec_result(inv100_row);
    std::vector<seal::Plaintext> poly_dec_result;
    for (int i = 0; i < inv100_row; i++) {
        poly_dec_result.push_back(seal::Plaintext());
        ct_result.push_back(seal::Ciphertext());
    }

    std::cout << "===Main===" << std::endl;

    std::ifstream result_1;
    result_1.open(resultDir + "/inv_100_" + date, std::ios::binary);
    seal::Ciphertext temp1;
    for (int i = 0; i < inv100_row; i++) {
        temp1.load(context, result_1);
        ct_result[i] = temp1;
    }
    result_1.close();

    std::cout << "===Decrypting===" << std::endl;

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int i = 0; i < inv100_row; i++) {
        seal::Ciphertext result_temp1 = ct_result[i];
        decryptor.decrypt(result_temp1, poly_dec_result[i]);
        batchEncoder.decode(poly_dec_result[i], dec_result[i]);
    }

    std::cout << "Decrypting > OK" << std::endl;
    std::cout << "===Making PIR-query===" << std::endl;
    std::cout << "Search index of function 1" << std::endl;

    int64_t index_row_x, index_col_x;
    int64_t flag1 = 0;
    for (int64_t i = 0; i < inv100_row; i++) {
        for (int64_t j = 0; j < row_size; j++) {
            if (dec_result[i][j] >= 0 and dec_result[i][j + 1] < 0 and flag1 == 0) {
                int64_t left = dec_result[i][j];
                int64_t right = abs(dec_result[i][j + 1]);
                flag1 = 1;
                index_row_x = i;
                index_col_x = (left <= right) ? (j) : (j + 1);
            }
        }
    }

    std::cout << "Got index of function inv" << std::endl;
    if (flag1 == 0) {
        std::cout << "ERROR: NO FIND" << std::endl;
    }

    std::cout << "index_row_x: " << index_row_x << ", index_col_x: " << index_col_x << std::endl;
    std::cout << "OK" << std::endl;

    std::vector<int64_t> query_AM0, query_AM1;
    for (int64_t i = 0; i < row_size; i++) {
        query_AM0.push_back((i == index_col_x) ? 1 : 0);
    }
    query_AM1 = ShiftWork(query_AM0, index_row_x, row_size);
    query_AM0.resize(slot_count);
    query_AM1.resize(slot_count);
    std::cout << "Making PIR-query > OK" << std::endl;

    std::cout << "===Encrypting===" << std::endl;

    seal::Ciphertext ct_query_AM0, ct_query_AM1;
    seal::Plaintext pt_query_AM0, pt_query_AM1;
    batchEncoder.encode(query_AM0, pt_query_AM0);
    encryptor.encrypt(pt_query_AM0, ct_query_AM0);
    batchEncoder.encode(query_AM1, pt_query_AM1);
    encryptor.encrypt(pt_query_AM1, ct_query_AM1);
    
    std::cout << "Encrypting > OK" << std::endl;
    std::cout << "===Saving Query===" << std::endl;

    std::ofstream queryFile;
    queryFile.open(resultDir + "/pir_inv_" + date);
    ct_query_AM0.save(queryFile);
    ct_query_AM1.save(queryFile);
    queryFile.close();

    std::cout << "===End===" << std::endl;

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
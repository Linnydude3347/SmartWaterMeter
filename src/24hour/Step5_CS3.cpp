#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHE

    std::cout << "Setting FHE" << std::endl;

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto galoisKey = LoadKey<seal::GaloisKeys>(context, GALOIS_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);
    auto secretKey = LoadKey<seal::SecretKey>(context, SECRET_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secretKey);
    seal::BatchEncoder batchEncoder(context);

    size_t slot_count = batchEncoder.slot_count();
    size_t row_size = slot_count / 2;

    std::cout << "Plaintext matrix row size: " << slot_count << std::endl;
    std::cout << "Slot nums = " << slot_count << std::endl;

    int64_t sum_row_count_AM = ceil((double)TABLE_SIZE_AM_INV / (double)row_size);
    int64_t inv100_row = ceil((double)TABLE_SIZE_100_INV / (double)row_size);
    int64_t div_row_count_HM = ceil((double)TABLE_SIZE_DIV_HM / (double)row_size);

    //////////////////////////////////////////////////////////////////////////////

    // Read output table

    std::vector<seal::Ciphertext> output_AM1, output_AM2;
    
    std::ifstream readtable_part1, readtable_part2;
    readtable_part1.open("Table/inv_SUM_AM_output1_" + std::to_string(METER_NUM));
    readtable_part2.open("Table/inv_SUM_AM_output2_" + std::to_string(METER_NUM));

    for (int i = 0; i < sum_row_count_AM; i++) {
        seal::Ciphertext t1, t2;
        t1.load(context, readtable_part1);
        t2.load(context, readtable_part2);
        output_AM1.push_back(t1);
        output_AM2.push_back(t2);
    }

    std::vector<seal::Ciphertext> res_a1, res_a2;
    seal::Ciphertext AM_rec1, AM_rec2;
    for (int64_t i = 0; i < sum_row_count_AM; i++) {
        seal::Ciphertext t;
        res_a1.push_back(t);
        res_a2.push_back(t);
    }

    std::vector<seal::Ciphertext> output_HM1, output_HM2;

    std::ifstream readtablehm_part1, readtablehm_part2;
    readtablehm_part1.open("Table/div_HM_output1_" + std::to_string(METER_NUM));
    readtablehm_part2.open("Table/div_HM_output2_" + std::to_string(METER_NUM));

    for (int w = 0; w < div_row_count_HM; w++) {
        seal::Ciphertext t1, t2;
        t1.load(context, readtablehm_part1);
        t2.load(context, readtablehm_part2);
        output_HM1.push_back(t1);
        output_HM2.push_back(t2);
    }

    std::vector<seal::Ciphertext> res_h1, res_h2;
    seal::Ciphertext HM_rec1, HM_rec2;
    for (int64_t i = 0; i < div_row_count_HM; i++) {
        seal::Ciphertext t;
        res_h1.push_back(t);
        res_h2.push_back(t);
    }

    std::string s1(argv[1]);
    std::string s2(argv[2]);

    ////////////////////////////////////////////////////////////////////

    std::cout << "===Main===" << std::endl;

    // Read index and PIR query from file

    std::cout << "===Reading query from DS===" << std::endl;
    std::ifstream PIRqueryFile(s2 + "/pir_SUM_AM_DIV_HM_" + s1);
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
    for (int64_t i = 0; i < sum_row_count_AM; i++) {
        seal::Ciphertext temp_a1 = ct_query_AM1;
        seal::Ciphertext temp_a2 = ct_query_AM1;
        evaluator.rotate_rows_inplace(temp_a1, -i, galoisKey);
        evaluator.rotate_rows_inplace(temp_a2, -i, galoisKey);
        evaluator.multiply_inplace(temp_a1, ct_query_AM0);
        evaluator.multiply_inplace(temp_a2, ct_query_AM0);
        evaluator.relinearize_inplace(temp_a1, relinKey);
        evaluator.relinearize_inplace(temp_a2, relinKey);
        evaluator.multiply_inplace(temp_a1, output_AM1[i]);
        evaluator.multiply_inplace(temp_a2, output_AM2[i]);
        evaluator.relinearize_inplace(temp_a1, relinKey);
        evaluator.relinearize_inplace(temp_a2, relinKey);
        res_a1[i] = temp_a1;
        res_a2[i] = temp_a2;
    }

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t i = 0; i < div_row_count_HM; i++) {
        seal::Ciphertext temp_h1 = ct_query_HM1;
        seal::Ciphertext temp_h2 = ct_query_HM1;
        evaluator.rotate_rows_inplace(temp_h1, -i, galoisKey);
        evaluator.rotate_rows_inplace(temp_h2, -i, galoisKey);
        evaluator.multiply_inplace(temp_h1, ct_query_HM0);
        evaluator.multiply_inplace(temp_h2, ct_query_HM0);
        evaluator.relinearize_inplace(temp_h1, relinKey);
        evaluator.relinearize_inplace(temp_h2, relinKey);
        evaluator.multiply_inplace(temp_h1, output_HM1[i]);
        evaluator.multiply_inplace(temp_h2, output_HM2[i]);
        evaluator.relinearize_inplace(temp_h1, relinKey);
        evaluator.relinearize_inplace(temp_h2, relinKey);
        res_h1[i] = temp_h1;
        res_h2[i] = temp_h2;
    }

    // Result sum

    std::cout << "===Sum Result===" << std::endl;
    AM_rec1 = res_a1[0];
    AM_rec2 = res_a2[0];
    for (int i = 1; i < sum_row_count_AM; i++) {
        evaluator.add_inplace(AM_rec1, res_a1[i]);
        evaluator.add_inplace(AM_rec2, res_a2[i]);
    }
    std::cout << "AM Size after relinearization: " << AM_rec1.size() << std::endl;

    HM_rec1 = res_h1[0];
    HM_rec2 = res_h2[0];
    for (int i = 1; i < div_row_count_HM; i++) {
        evaluator.add_inplace(HM_rec1, res_h1[i]);
        evaluator.add_inplace(HM_rec2, res_h2[i]);
    }
    std::cout << "HM Size after relinearization: " << HM_rec1.size() << std::endl;

    seal::Ciphertext ct_AM1 = AM_rec1, ct_AM2 = AM_rec2, ct_HM1 = HM_rec1, ct_HM2 = HM_rec2;

    for (int64_t i = 0; i < log2(row_size); i++) {
        seal::Ciphertext ct1 = ct_AM1, ct2 = ct_AM2, ct3 = ct_HM1, ct4 = ct_HM2;
        evaluator.rotate_rows_inplace(ct1, -pow(2, i), galoisKey);
        evaluator.relinearize_inplace(ct1, relinKey);
        evaluator.add_inplace(ct_AM1, ct1);
        evaluator.rotate_rows_inplace(ct2, -pow(2, i), galoisKey);
        evaluator.relinearize_inplace(ct2, relinKey);
        evaluator.add_inplace(ct_AM2, ct2);
        evaluator.rotate_rows_inplace(ct3, -pow(2, i), galoisKey);
        evaluator.relinearize_inplace(ct3, relinKey);
        evaluator.add_inplace(ct_HM1, ct3);
        evaluator.rotate_rows_inplace(ct4, -pow(2, i), galoisKey);
        evaluator.relinearize_inplace(ct4, relinKey);
        evaluator.add_inplace(ct_HM2, ct4);
    }

    seal::Ciphertext fin_AM1HM1, fin_AM1HM2, fin_AM2HM1, fin_AM1HM2AM2HM1;
    fin_AM1HM1 = ct_AM1;
    fin_AM1HM2 = ct_AM1;
    fin_AM2HM1 = ct_AM2;
    evaluator.multiply_inplace(fin_AM1HM1, ct_HM1);
    evaluator.multiply_inplace(fin_AM1HM2, ct_HM2);
    evaluator.multiply_inplace(fin_AM2HM1, ct_HM1);
    fin_AM1HM2AM2HM1 = fin_AM1HM2;
    evaluator.add_inplace(fin_AM1HM2AM2HM1, fin_AM2HM1);
    evaluator.relinearize_inplace(fin_AM1HM1, relinKey);
    evaluator.relinearize_inplace(fin_AM1HM2AM2HM1, relinKey);

    std::cout << "Noise budget in fin_AM1HM1: " << decryptor.invariant_noise_budget(fin_AM1HM1) << " bits" << std::endl;
    std::cout << "Noise budget in fin_AM1HM2AM2HM1: " << decryptor.invariant_noise_budget(fin_AM1HM2AM2HM1) << " bits" << std::endl;

    seal::Plaintext poly1, poly2;
    std::vector<int64_t> pt1, pt2;
    decryptor.decrypt(ct_AM1, poly1);
    batchEncoder.decode(poly1, pt1);
    decryptor.decrypt(ct_AM2, poly2);
    batchEncoder.decode(poly2, pt2);
    for (int64_t i = 0; i < row_size; i++) {
        std::cout << "AM1: " << pt1[i] << ", AM2: " << pt2[i] << std::endl;
    }

    std::ofstream result_am1hm1;
    result_am1hm1.open(s2 + "/Fin_AM1HM1_" + s1, std::ios::binary);
    fin_AM1HM1.save(result_am1hm1);
    result_am1hm1.close();

    // LUT sumAM => 1/sumAM

    std::vector<seal::Ciphertext> inv_tab;
    std::cout << "Read table for sum 1/AM" << std::endl;
    std::ifstream read_invTable;
    read_invTable.open("Table/inv_100_input_" + std::to_string(METER_NUM));
    for (int i = 0; i < inv100_row; i++) {
        seal::Ciphertext t;
        t.load(context, read_invTable);
        inv_tab.push_back(t);
    }

    // Read table
    std::ofstream result_inv;
    result_inv.open(s2 + "/inv_100_" + s1, std::ios::binary);

    for (int64_t i = 0; i < inv100_row; i++) {
        seal::Ciphertext inv_input = fin_AM1HM2AM2HM1;
        evaluator.sub_inplace(inv_input, inv_tab[i]);
        evaluator.relinearize_inplace(inv_input, relinKey);
        inv_input.save(result_inv);
    }
    result_inv.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
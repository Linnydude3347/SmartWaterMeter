#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHe

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

    int64_t inv100_row = ceil((double)TABLE_SIZE_100_INV / (double)row_size);

    // Read output table

    std::vector<seal::Ciphertext> output_inv;
    std::ifstream readtable_part1;
    for (int w = 0; w < inv100_row; w++) {
        seal::Ciphertext temp;
        temp.load(context, readtable_part1);
        output_inv.push_back(temp);
    }

    std::vector<seal::Ciphertext> res_a;
    seal::Ciphertext sum_result_a;

    for (int64_t i = 0; i < inv100_row; i++) {
        res_a.push_back(seal::Ciphertext());
    }

    std::string date(argv[1]);          // s1
    std::string resultDirName(argv[2]); // s2

    ////////////////////////////////////////////////////////////////////

    std::cout << "===Main===" << std::endl;

    // Read index and PIR query from file

    std::cout << "===Reading query from DS===" << std::endl;
    std::ifstream PIRqueryFile(resultDirName + "/pir_inv_" + date);
    seal::Ciphertext ct_query_inv0, ct_query_inv1;
    ct_query_inv0.load(context, PIRqueryFile);
    ct_query_inv1.load(context, PIRqueryFile);
    PIRqueryFile.close();

    std::cout << "Reading query from DS > OK" << std::endl;
    std::cout << "LUT Processing" << std::endl;

    auto startLUT = std::chrono::high_resolution_clock::now();

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t j = 0; j < inv100_row; j++) {
        seal::Ciphertext t = ct_query_inv1;
        evaluator.rotate_rows_inplace(t, -j, galoisKey);
        evaluator.multiply_inplace(t, ct_query_inv0);
        evaluator.relinearize_inplace(t, relinKey);
        evaluator.multiply_inplace(t, output_inv[j]);
        evaluator.relinearize_inplace(t, relinKey);
        res_a[j] = t;
    }

    // Result sum

    std::cout << "===Sum Result===" << std::endl;
    sum_result_a = res_a[0];
    for (int k = 1; k < inv100_row; k++) {
        evaluator.add_inplace(sum_result_a, res_a[k]);
    }

    auto endLUT = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffLUT = endLUT - startLUT;
    std::cout << "Runtime of LUT: " << diffLUT.count() << "s" << std::endl;

    auto startTotalSum = std::chrono::high_resolution_clock::now();

    seal::Ciphertext fin_res = sum_result_a;
    for (int64_t i = 0; i < log2(row_size); i++) {
        seal::Ciphertext t = fin_res;
        evaluator.rotate_rows_inplace(t, -pow(2, i), galoisKey);
        evaluator.relinearize_inplace(t, relinKey);
        evaluator.add_inplace(fin_res, t);
    }

    auto endTotalSum = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffTotalSum = endTotalSum - startTotalSum;
    std::cout << "Runtime for one time totalSum: " << diffTotalSum.count() << "s" << std::endl;

    std::ifstream read_hmam(resultDirName + "/Fin_AM1HM1_" + date);
    seal::Ciphertext am1hm1;
    am1hm1.load(context, read_hmam);
    read_hmam.close();

    evaluator.add_inplace(fin_res, am1hm1);

    std::cout << "Save result" << std::endl;

    std::ofstream save_fin;
    save_fin.open(resultDirName + "/finalRes_" + date, std::ios::binary);
    fin_res.save(save_fin);
    save_fin.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count(); << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}

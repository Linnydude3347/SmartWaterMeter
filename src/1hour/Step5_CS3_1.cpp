#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHE

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto galoisKey = LoadKey<seal::GaloisKeys>(context, GALOIS_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);
    auto secretKey = LoadKey<seal::SecretKey>(context, SECRET_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secretKey);
    seal::BatchEncoder batchEncoder(context);

    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;

    std::cout << "Plaintext matrix row size: " << slotCount << std::endl;
    std::cout << "Slot nums = " << slotCount << std::endl;

    int64_t sumRowCountAM = std::ceil((double)TABLE_SIZE_AM_INV / (double)rowSize);
    int64_t int100Row = std::ceil((double)TABLE_SIZE_100_INV / (double)rowSize);
    int64_t divRowCountHM = std::ceil((double)TABLE_SIZE_DIV_HM / (double)rowSize);

    // Read output table

    std::vector<seal::Ciphertext> outputAM1, outputAM2;

    std::ifstream readTablePart1, readTablePart2;
    readTablePart1.open("Table/inv_SUM_AM_output1_" + std::to_string(METER_NUM));
    readTablePart2.open("Table/inv_SUM_AM_output2_" + std::to_string(METER_NUM));

    for (int i = 0; i < sumRowCountAM; i++) {
        seal::Ciphertext t1, t2;
        t1.load(context, readTablePart1);
        t2.load(context, readTablePart2);
        outputAM1.push_back(t1);
        outputAM2.push_back(t2);
    }

    std::vector<seal::Ciphertext> resA1(sumRowCountAM), resA2(sumRowCountAM);
    seal::Ciphertext AMRec1, AMRec2;
    
    std::fill(resA1.begin(), resA1.end(), seal::Ciphertext());
    std::fill(resA2.begin(), resA2.end(), seal::Ciphertext());

    std::string date(argv[1]);          // s1
    std::string resultDirName(argv[2]); // s2

    std::cout << "===Main===" << std::endl;

    // Read index and PIR query from file

    std::cout << "===Reading Query from DS===" << std::endl;
    
    std::ifstream PIRQueryFile(resultDirName + "/pir_SUM_AM_" + date);
    seal::Ciphertext CTQueryAM0, CTQueryAM1;
    CTQueryAM0.load(context, PIRQueryFile);
    CTQueryAM1.load(context, PIRQueryFile);
    PIRQueryFile.close();

    std::cout << "===Reading Query from DS > OK===" << std::endl;
    std::cout << "===LUT Processing===" << std::endl;

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t i = 0; i < sumRowCountAM; i++) {
        seal::Ciphertext TA1 = CTQueryAM1;
        seal::Ciphertext TA2 = CTQueryAM1;
        evaluator.rotate_rows_inplace(TA1, -i, galoisKey);
        evaluator.rotate_rows_inplace(TA2, -i, galoisKey);
        evaluator.multiply_inplace(TA1, CTQueryAM0);
        evaluator.multiply_inplace(TA2, CTQueryAM0);
        evaluator.relinearize_inplace(TA1, relinKey);
        evaluator.relinearize_inplace(TA2, relinKey);
        evaluator.multiply_inplace(TA1, outputAM1[i]);
        evaluator.multiply_inplace(TA2, outputAM2[i]);
        evaluator.relinearize_inplace(TA1, relinKey);
        evaluator.relinearize_inplace(TA2, relinKey);
        resA1[i] = TA1;
        resA2[i] = TA2;
    }

    // Result Sum

    std::cout << "===Sum Result===" << std::endl;
    AMRec1 = resA1[0];
    AMRec2 = resA2[0];
    for (int i = 1; i < sumRowCountAM; i++) {
        evaluator.add_inplace(AMRec1, resA1[i]);
        evaluator.add_inplace(AMRec2, resA2[i]);
    }
    std::cout << "Size after relinearization: " << AMRec1.size() << std::endl;

    std::vector<seal::Ciphertext> z1(rowSize), z2(rowSize);
    
    std::fill(z1.begin(), z1.end(), AMRec1);
    std::fill(z2.begin(), z2.end(), AMRec2);

    seal::Ciphertext CTAM1 = AMRec1; // AMRec1: sum all row
    seal::Ciphertext CTAM2 = AMRec2; // AMRec2: sum all row

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t i = 1; i < rowSize; i++) {
        evaluator.rotate_rows_inplace(z1[i], i, galoisKey);
        evaluator.relinearize_inplace(z1[i], relinKey);
        evaluator.rotate_rows_inplace(z2[i], i, galoisKey);
        evaluator.relinearize_inplace(z2[i], relinKey);
    }

    for (int64_t i = 1; i < rowSize; i++) {
        evaluator.add_inplace(CTAM1, z1[i]);
        evaluator.add_inplace(CTAM2, z2[i]);
    }

    std::ofstream resultAM;
    resultAM.open(resultDirName + "/AM1AM2_" + date, std::ios::binary);
    CTAM1.save(resultAM);
    CTAM2.save(resultAM);
    resultAM.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
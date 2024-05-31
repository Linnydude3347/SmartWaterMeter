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

    std::vector<seal::Ciphertext> outputHM1, outputHM2;

    std::ifstream readTablePart1, readTablePart2;
    readTablePart1.open("Table/div_HM_output1_" + std::to_string(METER_NUM));
    readTablePart2.open("Table/div_HM_output2_" + std::to_string(METER_NUM));

    for (int i = 0; i < divRowCountHM; i++) {
        seal::Ciphertext t1, t2;
        t1.load(context, readTablePart1);
        t2.load(context, readTablePart2);
        outputHM1.push_back(t1);
        outputHM2.push_back(t2);
    }

    std::vector<seal::Ciphertext> resH1(sumRowCountAM), resH2(sumRowCountAM);
    seal::Ciphertext HMRec1, HMRec2;
    
    std::fill(resH1.begin(), resH1.end(), seal::Ciphertext());
    std::fill(resH2.begin(), resH2.end(), seal::Ciphertext());

    std::string date(argv[1]);          // s1
    std::string resultDirName(argv[2]); // s2

    std::cout << "===Main===" << std::endl;

    // Read index and PIR query from file

    std::cout << "===Reading Query from DS===" << std::endl;
    
    std::ifstream PIRQueryFile(resultDirName + "/pir_DIV_HM_" + date);
    seal::Ciphertext CTQueryHM0, CTQueryHM1;
    CTQueryHM0.load(context, PIRQueryFile);
    CTQueryHM1.load(context, PIRQueryFile);
    PIRQueryFile.close();

    std::cout << "===Reading Query from DS > OK===" << std::endl;
    std::cout << "===LUT Processing===" << std::endl;

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t i = 0; i < sumRowCountAM; i++) {
        seal::Ciphertext TH1 = CTQueryHM1;
        seal::Ciphertext TH2 = CTQueryHM1;
        evaluator.rotate_rows_inplace(TH1, -i, galoisKey);
        evaluator.rotate_rows_inplace(TH2, -i, galoisKey);
        evaluator.multiply_inplace(TH1, CTQueryHM0);
        evaluator.multiply_inplace(TH2, CTQueryHM0);
        evaluator.relinearize_inplace(TH1, relinKey);
        evaluator.relinearize_inplace(TH2, relinKey);
        evaluator.multiply_inplace(TH1, outputHM1[i]);
        evaluator.multiply_inplace(TH2, outputHM2[i]);
        evaluator.relinearize_inplace(TH1, relinKey);
        evaluator.relinearize_inplace(TH2, relinKey);
        resH1[i] = TH1;
        resH2[i] = TH2;
    }

    // Result Sum

    std::cout << "===Sum Result===" << std::endl;
    HMRec1 = resH1[0];
    HMRec2 = resH2[0];
    for (int i = 1; i < divRowCountHM; i++) {
        evaluator.add_inplace(HMRec1, resH1[i]);
        evaluator.add_inplace(HMRec2, resH2[i]);
    }
    std::cout << "Size after relinearization: " << HMRec1.size() << std::endl;

    std::vector<seal::Ciphertext> z1(rowSize), z2(rowSize);
    
    std::fill(z1.begin(), z1.end(), HMRec1);
    std::fill(z2.begin(), z2.end(), HMRec2);

    seal::Ciphertext CTHM1 = HMRec1; // HMRec1: sum all row
    seal::Ciphertext CTHM2 = HMRec2; // HMRec2: sum all row

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int64_t i = 1; i < rowSize; i++) {
        evaluator.rotate_rows_inplace(z1[i], i, galoisKey);
        evaluator.relinearize_inplace(z1[i], relinKey);
        evaluator.rotate_rows_inplace(z2[i], i, galoisKey);
        evaluator.relinearize_inplace(z2[i], relinKey);
    }

    for (int64_t i = 1; i < rowSize; i++) {
        evaluator.add_inplace(CTHM1, z1[i]);
        evaluator.add_inplace(CTHM2, z2[i]);
    }

    std::ofstream resultHM;
    resultHM.open(resultDirName + "/HM1HM2_" + date, std::ios::binary);
    CTHM1.save(resultHM);
    CTHM2.save(resultHM);
    resultHM.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
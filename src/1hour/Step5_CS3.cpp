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
    seal::BatchEncoder batchEncoder(context);
    seal::Decryptor decryptor(context, secretKey);

    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;
    std::cout << "Plaintext matrix row size: " << slotCount << std::endl;
    std::cout << "Slot nums = " << slotCount << std::endl;

    int64_t inv100Row = std::ceil((double)TABLE_SIZE_100_INV / (double)rowSize);
    std::string date(argv[1]);          // s1
    std::string resultDirName(argv[2]); // s2

    // Read AM1 AM2 HM1 HM2

    std::ifstream result1, result2;
    result1.open(resultDirName + "/AM1AM2_" + date, std::ios::binary);
    result2.open(resultDirName + "/HM1HM2_" + date, std::ios::binary);

    seal::Ciphertext CTAM1, CTAM2, CTHM1, CTHM2;
    CTAM1.load(context, result1);
    CTAM2.load(context, result1);
    CTHM1.load(context, result2);
    CTHM2.load(context, result2);
    result1.close();
    result2.close();

    seal::Ciphertext finAM1HM1, finAM1HM2, finAM2HM1, finAM1HM2AM2HM1;
    finAM1HM1 = CTAM1;
    finAM1HM2 = CTAM1;
    finAM2HM1 = CTAM2;

    evaluator.multiply_inplace(finAM1HM1, CTHM1);
    evaluator.multiply_inplace(finAM1HM2, CTHM2);
    evaluator.multiply_inplace(finAM2HM1, CTHM1);
    finAM1HM2AM2HM1 = finAM1HM2;
    evaluator.add_inplace(finAM1HM2AM2HM1, finAM2HM1);

    evaluator.relinearize_inplace(finAM1HM1, relinKey);
    evaluator.relinearize_inplace(finAM1HM2AM2HM1, relinKey);

    // Budget Check

    std::cout << "Noise Budget in finAM1HM1: " << decryptor.invariant_noise_budget(finAM1HM1) << " bits" << std::endl;
    std::cout << "Noise Budget in finAM1HM2AM2HM1: " << decryptor.invariant_noise_budget(finAM1HM2AM2HM1) << " bits" << std::endl;

    seal::Plaintext poly1, poly2;
    std::vector<int64_t> pt1, pt2;
    decryptor.decrypt(CTAM1, poly1);
    batchEncoder.decode(poly1, pt1);
    decryptor.decrypt(CTAM2, poly2);
    batchEncoder.decode(poly2, pt2);
    for (int64_t i = 0; i < rowSize; i++) {
        std::cout << "AM1: " << pt1[i] << ", AM2: " << pt2[i] << std::endl;
    }

    std::ofstream resultAM1HM1;
    resultAM1HM1.open(resultDirName + "/Fin_AM1HM1_" + date, std::ios::binary);
    finAM1HM1.save(resultAM1HM1);
    resultAM1HM1.close();

    // LUT sumAM => 1 / sumAM

    std::vector<seal::Ciphertext> invTab;
    std::cout << "===Read table for sum 1 / AM===" << std::endl;
    std::ifstream readInvTable;
    readInvTable.open("Table/inv_100_output_" + std::to_string(METER_NUM));
    for (int i = 0; i < inv100Row; i++) {
        seal::Ciphertext t;
        t.load(context, readInvTable);
        invTab.push_back(t);
    }

    // Read table

    std::ofstream resultInv;
    resultInv.open(resultDirName + "/inv_100_" + date, std::ios::binary);

    for (int64_t i = 0; i < inv100Row; i++) {
        seal::Ciphertext invInput = finAM1HM2AM2HM1;
        evaluator.sub_inplace(invInput, invTab[i]);
        evaluator.relinearize_inplace(invInput, relinKey);
        invInput.save(resultInv);
    }
    resultInv.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
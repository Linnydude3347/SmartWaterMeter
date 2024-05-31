#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHE

    std::cout << "Setting FHE" << std::endl;

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto galoisKey = LoadKey<seal::GaloisKeys>(context, GALOIS_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::BatchEncoder batchEncoder(context);

    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;
    
    std::cout << "Plaintext matrix row size: " << rowSize << std::endl;
    std::cout << "Slot nums = " << slotCount << std::endl;

    int64_t rowCountAM = std::ceil((double)TABLE_SIZE_AM / (double)rowSize);
    int64_t rowCountHM = std::ceil((double)TABLE_SIZE_HM / (double)rowSize);
    int64_t sumRowCountAM = std::ceil((double)TABLE_SIZE_AM_INV / (double)rowSize);
    int64_t divRowCountHM = std::ceil((double)TABLE_SIZE_DIV_HM / (double)rowSize);

    std::cout << "AM row " << rowCountAM << ", HM row " << rowCountHM << std::endl;

    // Read output table

    std::vector<seal::Ciphertext> outputAM;
    std::vector<seal::Ciphertext> outputHM;

    std::ifstream readTablePartOne;
    readTablePartOne.open("Table/AM_output_" + std::to_string(METER_NUM));
    for (int w = 0; w < rowCountAM; w++) {
        seal::Ciphertext temp;
        temp.load(context, readTablePartOne);
        outputAM.push_back(temp);
    }

    std::vector<seal::Ciphertext> resA;
    seal::Ciphertext sumResultA, sumResumtAMR;

    for (int64_t i = 0; i < rowCountAM; i++) {
        seal::Ciphertext tep;
        resA.push_back(tep);
    }

    std::string date(argv[1]);          // s1
    std::string resultDirName(argv[2]); // s2
    std::string hour(argv[3]);          // s3

    std::cout << "=====Main=====" << std::endl;

    int64_t iter = std::stoi(hour);

    std::cout << "===Reading Query From DS===" << std::endl;
    std::ifstream PIRQueryFile(resultDirName + "/pir_AM_" + std::to_string(iter));
    seal::Ciphertext ctQueryAM0, ctQueryAM1;
    ctQueryAM0.load(context, PIRQueryFile);
    ctQueryAM1.load(context, PIRQueryFile);
    PIRQueryFile.close();

    std::cout << "===Reading Query From DS > OK===" << std::endl;
    std::cout << "===LUT Processing===" << std::endl;

    for (int64_t j = 0; j < rowCountAM; j++) {
        seal::Ciphertext tempA = ctQueryAM1;
        evaluator.rotate_rows_inplace(tempA, -j, galoisKey);
        evaluator.multiply_inplace(tempA, ctQueryAM0);
        evaluator.relinearize_inplace(tempA, relinKey);
        evaluator.multiply_inplace(tempA, outputAM[j]);
        evaluator.relinearize_inplace(tempA, relinKey);
        resA[j] = tempA;
    }

    // Result Sum

    std::cout << "===Sum Result===" << std::endl;
    sumResultA = resA[0];
    for (int k = 1; k < rowCountAM; k++) {
        evaluator.add_inplace(sumResultA, resA[k]);
    }
    sumResumtAMR = sumResultA;

    // Total Sum

    for (int64_t i = 0; i < std::log2(rowSize); i++) {
        seal::Ciphertext ct = sumResumtAMR;
        evaluator.rotate_rows_inplace(ct, -std::pow(2, i), galoisKey);
        evaluator.add_inplace(sumResumtAMR, ct);
    }
    seal::Ciphertext AMRec;

    // If iter is 0, now we save
    if (iter == 0) {
        AMRec = sumResumtAMR;
        std::ofstream sumAMOF;
        sumAMOF.open(resultDirName + "/sumAM_0", std::ios::binary);
        AMRec.save(sumAMOF);
        sumAMOF.close();
    } else if (iter == 23) {
        std::ifstream sumAMIF;
        sumAMIF.open(resultDirName + "/sumAM_" + std::to_string(iter - 1), std::ios::binary);
        AMRec.load(context, sumAMIF);
        evaluator.add_inplace(AMRec, sumResumtAMR);
        evaluator.relinearize_inplace(AMRec, relinKey);

        std::vector<seal::Ciphertext> AMTab;
        std::cout << "Read Table for Sum 1/AM" << std::endl;
        std::ifstream readAMTable;
        readAMTable.open("Table/SUM_AM_input_" + std::to_string(METER_NUM));
        for (int w = 0; w < sumRowCountAM; w++) {
            seal::Ciphertext temps;
            temps.load(context, readAMTable);
            AMTab.push_back(temps);
        }

        // Read Table

        std::ofstream resultAM;
        resultAM.open(resultDirName + "/inv_SUM_AM_" + date, std::ios::binary);
        for (int64_t j1; j1 < sumRowCountAM; j1++) {
            seal::Ciphertext tempAMInput = AMRec;
            evaluator.sub_inplace(tempAMInput, AMTab[j1]);
            evaluator.relinearize_inplace(tempAMInput, relinKey);
            tempAMInput.save(resultAM);
        }
        resultAM.close();
    } else {
        std::ifstream sumAMIF;
        sumAMIF.open(resultDirName + "/sumAM_" + std::to_string(iter - 1), std::ios::binary);
        AMRec.load(context, sumAMIF);
        evaluator.add_inplace(AMRec, sumResumtAMR);
        evaluator.relinearize_inplace(AMRec, relinKey);
        std::ofstream sumAMOF;
        sumAMOF.open(resultDirName + "/sumAM_" + std::to_string(iter), std::ios::binary);
        AMRec.save(sumAMOF);
        sumAMOF.close();
    }

    std::cout << "===END===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;
}
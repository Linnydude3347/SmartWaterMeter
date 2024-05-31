#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

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
    std::cout << "Slot Nums = " << slotCount << std::endl;

    int64_t rowCountHM = std::ceil((double)TABLE_SIZE_HM / (double)rowSize);
    int64_t divRowCountHM = std::ceil((double)TABLE_SIZE_DIV_HM / (double)rowSize);

    std::cout << "HM row " << rowCountHM << std::endl;

    std::vector<seal::Ciphertext> outputHM;

    std::ifstream readTableHM;
    readTableHM.open("Table/HM_output_" + std::to_string(METER_NUM));
    for (int w = 0; w < rowCountHM; w++) {
        seal::Ciphertext temp;
        temp.load(context, readTableHM);
        outputHM.push_back(temp);
    }

    std::vector<seal::Ciphertext> resH(rowCountHM);
    seal::Ciphertext sumResultH, sumResultHMR;

    /**
     * AM - Arithmetic Mean
     * HM - Harmonic Mean
     * 
     * Notes:
     *  - resA: Result of one time slot AM for each row
     *  - sumResultA: Result of one time slot AM (sum all row)
     *  - sumResultAMR: Result of 24 time slots AM (sum all time slots)
     *  - resH1,2: Result of one time slot HM for each row
     *  - sumResultH1,2: Result of one time slot AM (sum all row)
     *  - sumResultHMR1,2: Result of 24 time slots AM (sum all time slots)
     */

    
    std::fill(resH.begin(), resH.end(), seal::Ciphertext());

    //for (int64_t i = 0; i < rowCountHM; i++) {
    //    seal::Ciphertext tep;
    //    resH.push_back(tep);
    //}

    std::string date(argv[1]);              // s1
    std::string resultDirName(argv[2]);     // s2
    std::string hour(argv[3]);              // s3

    std::cout << "===Main===" << std::endl;
    int64_t iter = std::stoi(hour);

    // Read index and PIR query from file

    std::cout << "===Reading Query From DS===" << std::endl;
    std::ifstream PIRQueryFile(resultDirName + "/pir_HM_" + std::to_string(iter));
    seal::Ciphertext CTQueryHM0, CTQueryHM1;

    CTQueryHM0.load(context, PIRQueryFile);
    CTQueryHM1.load(context, PIRQueryFile);
    PIRQueryFile.close();

    std::cout << "===Reading Query From DS > OK===" << std::endl;
    std::cout << "===LUT Processing===" << std::endl;

    for (int64_t k = 0; k < rowCountHM; k++) {
        seal::Ciphertext temp = CTQueryHM1;
        evaluator.rotate_rows_inplace(temp, -k, galoisKey);
        evaluator.multiply_inplace(temp, CTQueryHM0);
        evaluator.relinearize_inplace(temp, relinKey);
        evaluator.multiply_inplace(temp, outputHM[k]);
        evaluator.relinearize_inplace(temp, relinKey);
        resH[k] = temp;
    }

    std::cout << "===Sum Result===" << std::endl;

    sumResultH = resH[0];
    for (int i = 1; i < rowCountHM; i++) {
        evaluator.add_inplace(sumResultH, resH[i]);
    }
    sumResultHMR = sumResultH;

    for (int64_t i = 0; i < std::log2(rowSize); i++) {
        seal::Ciphertext ct = sumResultHMR;
        evaluator.rotate_rows_inplace(ct, -std::pow(2, i), galoisKey);
        evaluator.add_inplace(sumResultHMR, ct);
    }

    seal::Ciphertext HMRec;

    if (iter == 0) {
        HMRec = sumResultHMR;
        std::ofstream sumHMOF;
        sumHMOF.open(resultDirName + "/sumHM_0", std::ios::binary);
        HMRec.save(sumHMOF);
        sumHMOF.close();
    } else if (iter == 23) {
        std::ifstream sumHMIF;
        sumHMIF.open(resultDirName + "/sumHM_" + std::to_string(iter - 1), std::ios::binary);
        HMRec.load(context, sumHMIF);
        sumHMIF.close();
        evaluator.add_inplace(HMRec, sumResultHMR);
        evaluator.relinearize_inplace(HMRec, relinKey);

        std::vector<seal::Ciphertext> HMTab;
        std::cout << "Read table for sum HM." << std::endl;
        std::ifstream readHMTable;
        readHMTable.open("Table/div_HM_input_" + std::to_string(METER_NUM));
        for (int w = 0; w < divRowCountHM; w++) {
            seal::Ciphertext t;
            t.load(context, readHMTable);
            HMTab.push_back(t);
        }

        std::ofstream resultHM;
        resultHM.open(resultDirName + "/div_HM_" + date, std::ios::binary);
        for (int64_t j1 = 0; j1 < divRowCountHM; j1++) {
            seal::Ciphertext tempHMInput = HMRec;
            evaluator.sub_inplace(tempHMInput, HMTab[j1]);
            evaluator.relinearize_inplace(tempHMInput, relinKey);
            tempHMInput.save(resultHM);
        }
        resultHM.close();
    } else {
        std::ifstream sumHMIF;
        sumHMIF.open(resultDirName + "/sumHM_" + std::to_string(iter - 1), std::ios::binary);
        HMRec.load(context, sumHMIF);
        sumHMIF.close();
        evaluator.add_inplace(HMRec, sumResultHMR);
        evaluator.relinearize_inplace(HMRec, relinKey);
        std::ofstream sumHMOF;
        sumHMOF.open(resultDirName + "/sumHM_" + std::to_string(iter), std::ios::binary);
        HMRec.save(sumHMOF);
        sumHMOF.close();
    }

    std::cout << "===END===" << std::endl;

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());
    
    return 0;

}
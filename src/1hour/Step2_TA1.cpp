#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    std::cout << "Setting FHE" << std::endl;

    // Load context, required keys, and cryptors/coders

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto secretKey = LoadKey<seal::SecretKey>(context, SECRET_KEY_FILEPATH);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secretKey);
    seal::BatchEncoder batchEncoder(context);

    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;

    std::cout << "Plaintext matrix row size: " << rowSize << std::endl;
    std::cout << "Slot nums = " << slotCount << std::endl;

    int64_t rowCountFunOne = ceil((double)TABLE_SIZE_AM / double(rowSize));
    int64_t rowCountFunTwo = ceil((double)TABLE_SIZE_HM / double(rowSize));

    ////////////////////////////////////////////////////////////////////////////////

    std::string resultDir(argv[1]);     // s1
    std::string hourNumber(argv[2]);    // s2

    std::vector<seal::Ciphertext> resultCT1, resultCT2;
    std::vector<std::vector<int64_t>> resultDec1(rowCountFunOne);
    std::vector<seal::Plaintext> resultDecPoly1, resultDecPoly2;
    std::vector<std::vector<int64_t>> resultDec2(rowCountFunTwo);

    for (int i = 0; i < rowCountFunOne; i++) {
        seal::Plaintext ex1;
        seal::Ciphertext exx1;
        resultDecPoly1.push_back(ex1);
        resultCT1.push_back(exx1);
    }

    for (int i = 0; i < rowCountFunTwo; i++) {
        seal::Plaintext ex2;
        seal::Ciphertext exx2;
        resultDecPoly2.push_back(ex2);
        resultCT2.push_back(exx2);
    }

    ////////////////////////////////////////////////////////////////////////////////

    std::cout << "=====Main=====" << std::endl;

    int64_t iter = std::stoi(hourNumber);
    std::ifstream result1;
    result1.open(resultDir + "/AM_" + std::to_string(iter), std::ios::binary);
    std::ifstream result2;
    result2.open(resultDir + "/HM_" + std::to_string(iter), std::ios::binary);
    seal::Ciphertext temp1, temp2;

    for (int i = 0; i < rowCountFunOne; i++) {
        temp1.load(context, result1);
        resultCT1[i] = temp1;
    }
    for (int i = 0; i < rowCountFunTwo; i++) {
        temp2.load(context, result2);
        resultCT2[i] = temp2;
    }
    result1.close();
    result2.close();

    ////////////////////////////////////////////////////////////////////////////////

    std::cout << "===Decrypting===" << std::endl;

    for (int i = 0; i < rowCountFunOne; i++) {
        seal::Ciphertext resultTemp1 = resultCT1[i];
        decryptor.decrypt(resultTemp1, resultDecPoly1[i]);
        batchEncoder.decode(resultDecPoly1[i], resultDec1[i]);
    }
    for (int i = 0; i < rowCountFunTwo; i++) {
        seal::Ciphertext resultTemp2 = resultCT2[i];
        decryptor.decrypt(resultTemp2, resultDecPoly2[i]);
        batchEncoder.decode(resultDecPoly2[i], resultDec2[i]);
    }

    std::cout << "Decrypting > OK" << std::endl;

    ////////////////////////////////////////////////////////////////////////////////

    // Find the position of 0

    std::cout << "===Making PIR-query===" << std::flush;
    std::cout << "Search index of function 1" << std::endl;

    int64_t indexRowX, indexColX;
    int64_t flag1 = 0, flag2 = 0;

    for (int64_t i = 0; i < rowCountFunOne; i++) {
        for (int64_t j = 0; j < rowSize; j++) {
            if (resultDec1[i][j] == 0) {
                flag1 = 1;
                indexRowX = i;
                indexColX = j;
                break;
            }
            if (resultDec1[i][j] > 0 && resultDec1[i][j + 1] < 0 && flag1 == 0) {
                int64_t left = resultDec1[i][j];
                int64_t right = abs(resultDec1[i][j + 1]);
                if (left <= right) {
                    flag1 = 1;
                    indexRowX = i;
                    indexColX = j;
                    break;
                } else {
                    flag1 = 1;
                    indexRowX = i;
                    indexColX = j + 1;
                    break;
                }
            }
        }
    }
    if (flag1 == 0) {
        std::cout << "[ERROR]: Function 1 Not Found!" << std::endl;
    }

    std::cout << "Search index of function 2" << std::endl;

    int64_t indexRowY, indexColY;

    for (int64_t i = 0; i < rowCountFunTwo; i++) {
        for (int64_t j = 0; j < rowSize; j++) {
            if (resultDec2[i][j] == 0) {
                flag2 = 1;
                indexRowY = i;
                indexColY = j;
                break;
            }
            if (resultDec2[i][j] > 0 && resultDec2[i][j + 1] < 0 && flag2 == 0) {
                int64_t left = resultDec2[i][j];
                int64_t right = abs(resultDec2[i][j + 1]);
                if (left <= right) {
                    flag2 = 1;
                    indexRowY = i;
                    indexColY= j;
                    break;
                } else {
                    flag2 = 1;
                    indexRowY = i;
                    indexColY = j + 1;
                    break;
                }
            }
        }
    }
    if (flag2 == 0) {
        std::cout << "[ERROR]: Function 2 Not Found!" << std::endl;
    }
    std::cout << "Hour No." << iter << std::endl;
    std::cout << "IndexRowAM: " << indexRowX << ", IndexColAM: " << indexColX << ", IndexRowHM: " << indexRowY << ", IndexColHM: " << indexColY << std::endl;
    std::cout << "OK" << std::endl;

    ////////////////////////////////////////////////////////////////////////////////

    std::vector<int64_t> queryAM0, queryAM1, queryHM0, queryHM1;

    for (int64_t i = 0; i < rowSize; i++) {
        queryAM0.push_back((i == indexColX) ? 1 : 0);
    }
    queryAM1 = ShiftWork(queryAM0, indexRowX, rowSize);
    queryAM0.resize(slotCount);
    queryAM1.resize(slotCount);

    for (int64_t i = 0; i < rowSize; i++) {
        queryHM0.push_back((i == indexColY) ? 1 : 0);
    }
    queryHM1 = ShiftWork(queryHM0, indexRowY, rowSize);
    queryHM0.resize(slotCount);
    queryHM1.resize(slotCount);
    std::cout << "PID-Query > OK" << std::endl;

    ////////////////////////////////////////////////////////////////////////////////

    std::cout << "===Encrypting===" << std::endl;

    seal::Ciphertext ct_query_AM0, ct_query_AM1, ct_query_HM0, ct_query_HM1;
    seal::Plaintext pt_query_AM0, pt_query_AM1, pt_query_HM0, pt_query_HM1;
    batchEncoder.encode(queryAM0, pt_query_AM0);
    encryptor.encrypt(pt_query_AM0, ct_query_AM0);
    batchEncoder.encode(queryAM1, pt_query_AM1);
    encryptor.encrypt(pt_query_AM1, ct_query_AM1);
    batchEncoder.encode(queryHM0, pt_query_HM0);
    encryptor.encrypt(pt_query_HM0, ct_query_HM0);
    batchEncoder.encode(queryHM1, pt_query_HM1);
    encryptor.encrypt(pt_query_HM1, ct_query_HM1);
    std::cout << "Encrypting > OK" << std::endl;

    ////////////////////////////////////////////////////////////////////////////////

    // Write to file

    std::cout << "===Saving query===" << std::endl;
    std::ofstream queryFileAM;
    queryFileAM.open(resultDir + "/pir_AM_" + std::to_string(iter));
    ct_query_AM0.save(queryFileAM);
    ct_query_AM1.save(queryFileAM);
    queryFileAM.close();

    std::ofstream queryFileHM;
    queryFileHM.open(resultDir + "/pir_HM_" + std::to_string(iter));
    ct_query_HM0.save(queryFileHM);
    ct_query_HM1.save(queryFileHM);
    queryFileHM.close();
    std::cout << "Save query Hour No." << iter << " > OK" << std::endl;
    std::cout<< "=====End=====" <<std::endl;

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());
    
    return 0;

}
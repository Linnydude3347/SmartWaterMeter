#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHE

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

    int64_t sumRowCountAM = std::ceil((double)TABLE_SIZE_AM_INV / (double)rowSize);
    int64_t divRowCountHM = std::ceil((double)TABLE_SIZE_DIV_HM / (double)rowSize);

    std::string date(argv[1]);          // s1
    std::string resultDirName(argv[2]); // s2

    std::vector<seal::Ciphertext> CTResult1(sumRowCountAM), CTResult2(divRowCountHM);
    std::vector<std::vector<int64_t>> decResult1(sumRowCountAM), decResult2(divRowCountHM);
    std::vector<seal::Plaintext> polyDecResult1(sumRowCountAM), polyDecResult2(divRowCountHM);

    std::fill(polyDecResult1.begin(), polyDecResult1.end(), seal::Plaintext());
    std::fill(CTResult1.begin(), CTResult1.end(), seal::Ciphertext());
    std::fill(polyDecResult2.begin(), polyDecResult2.end(), seal::Plaintext());
    std::fill(CTResult2.begin(), CTResult2.end(), seal::Ciphertext());

    std::cout << "===Main===" << std::endl;

    std::ifstream result1;
    result1.open(resultDirName + "/inv_SUM_AM_" + date, std::ios::binary);
    for (int i = 0; i < sumRowCountAM; i++) {
        seal::Ciphertext t;
        t.load(context, result1);
        CTResult1[i] = t;
    }
    result1.close();

    std::ifstream result2;
    result2.open(resultDirName + "/div_HM_" + date, std::ios::binary);
    for (int i = 0; i < divRowCountHM; i++) {
        seal::Ciphertext t;
        t.load(context, result2);
        CTResult2[i] = t;
    }
    result2.close();

    std::cout << "===Decrypting===" << std::endl;

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int i = 0; i < sumRowCountAM; i++) {
        seal::Ciphertext t = CTResult1[i];
        decryptor.decrypt(t, polyDecResult1[i]);
        batchEncoder.decode(polyDecResult1[i], decResult1[i]);
    }

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int i = 0; i < divRowCountHM; i++) {
        seal::Ciphertext t = CTResult2[i];
        decryptor.decrypt(t, polyDecResult2[i]);
        batchEncoder.decode(polyDecResult2[i], decResult2[i]);
    }

    std::cout << "===Decrypting > OK" << std::endl;
    std::cout << "===Making PIR Query===" << std::endl;
    std::cout << "Search index of function 1" << std::endl;

    int64_t idxRowX, idxColX;
    int64_t flag1 = 0;
    for (int64_t i = 0; i < sumRowCountAM; i++) {
        for (int64_t j = 0; j < rowSize; j++) {
            if (decResult1[i][j] >= 0 && decResult1[i][j + 1] < 0 && flag1 == 0) {
                int64_t left = decResult1[i][j];
                int64_t right = std::abs(decResult1[i][j + 1]);
                idxRowX = i;
                idxColX = j;
                if (left > right) idxColX++;
                flag1 = 1;
                break;
            }
        }
    }

    if (flag1 == 0) {
        std::cout << "\033[1;31mERROR: NO FIND 1\033[0m" << std::endl;
    } else {
        std::cout << "Got index of function 1" << std::endl;
        std::cout << "Index RowX: " << idxRowX << ", Index ColX: " << idxColX << std::endl;
    }

    std::cout << "Search index of function 2" << std::endl;
    
    int64_t idxRowY, idxColY;
    int64_t flag2 = 0;
    for (int64_t i = 0; i < divRowCountHM; i++) {
        for(int64_t j = 0; j < rowSize; j++) {
            if (decResult2[i][j] == 0) {
                idxRowY = i;
                idxColY = j;
                flag2 = 1;
                break;
            }
            if (decResult2[i][j] > 0 && decResult2[i][j + 1] < 0 && flag2 == 0) {
                int64_t left = std::abs(decResult2[i][j]);
                int64_t right = decResult2[i][j + 1];
                idxRowY = i;
                idxColY = j;
                if (left > right) idxColY++;
                flag2 = 1;
                break;
            }
        }
    }

    if (flag2 == 0) {
        std::cout << "\033[1;31mERROR: NO FIND 2\033[0m" << std::endl;
    } else {
        std::cout << "Got index of function 2" << std::endl;
        std::cout << "Index RowY: " << idxRowY << ", Index ColY: " << idxColY << std::endl;
    }

    std::vector<int64_t> queryAM0, queryAM1, queryHM0, queryHM1;
    for (int64_t i = 0; i < rowSize; i++) {
        queryAM0.push_back(i == idxColX ? 1 : 0);
    }
    queryAM1 = ShiftWork(queryAM0, idxRowX, rowSize);
    queryAM0.resize(slotCount);
    queryAM1.resize(slotCount);

    for (int64_t i = 0; i < rowSize; i++) {
        queryHM0.push_back(i == idxColY ? 1 : 0);
    }
    queryHM1 = ShiftWork(queryHM0, idxRowY, rowSize);
    queryHM0.resize(slotCount);
    queryHM1.resize(slotCount);

    std::cout << "===Making PIR Query > OK" << std::endl;

    std::cout << "===Ecrypting===" << std::endl;
    seal::Ciphertext CTQueryAM0, CTQueryAM1, CTQueryHM0, CTQueryHM1;
    seal::Plaintext PTQueryAM0, PTQueryAM1, PTQueryHM0, PTQueryHM1;

    batchEncoder.encode(queryAM0, PTQueryAM0);
    encryptor.encrypt(PTQueryAM0, CTQueryAM0);
    batchEncoder.encode(queryAM1, PTQueryAM1);
    encryptor.encrypt(PTQueryAM1, CTQueryAM1);
    batchEncoder.encode(queryHM0, PTQueryHM0);
    encryptor.encrypt(PTQueryHM0, CTQueryHM0);
    batchEncoder.encode(queryHM1, PTQueryHM1);
    encryptor.encrypt(PTQueryHM1, CTQueryHM1);

    std::cout << "===Encrypting > OK===" << std::endl;

    std::cout << "===Saving Query===" << std::endl;

    std::ofstream queryFile;
    queryFile.open(resultDirName + "/pir_SUM_AM_DIV_HM_" + date);
    CTQueryAM0.save(queryFile);
    CTQueryAM1.save(queryFile);
    CTQueryHM0.save(queryFile);
    CTQueryHM1.save(queryFile);
    queryFile.close();

    std::cout << "===END===" << std::endl;

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
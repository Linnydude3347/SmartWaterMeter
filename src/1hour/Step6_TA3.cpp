#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    auto startWhole = std::chrono::high_resolution_clock::now();

    // Resetting FHE

    std::cout << "Setting FHE" << std::endl;

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto secretKey = LoadKey<seal::SecretKey>(context, SECRET_KEY_FILEPATH);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::BatchEncoder batchEncoder(context);
    seal::Decryptor decryptor(context, secretKey);

    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;

    std::cout << "Plaintext matrix row size: " << rowSize << std::endl;
    std::cout << "Slot nums = " << slotCount << std::endl;

    int64_t inv100Row = std::ceil((double)TABLE_SIZE_100_INV / (double)rowSize);

    std::string date(argv[1]);          // s1
    std::string resultDirName(argv[2]); // s2

    std::vector<seal::Ciphertext> CTResult(inv100Row);
    std::vector<std::vector<int64_t>> decResult(inv100Row);
    std::vector<seal::Plaintext> polyDecResult(inv100Row);

    std::fill(CTResult.begin(), CTResult.end(), seal::Ciphertext());
    std::fill(polyDecResult.begin(), polyDecResult.end(), seal::Plaintext());

    std::cout << "===Main===" << std::endl;

    std::ifstream result1;
    result1.open(resultDirName + "/inv_100_" + date, std::ios::binary);
    for (int i = 0; i < inv100Row; i++) {
        seal::Ciphertext t;
        t.load(context, result1);
        CTResult[i] = t;
    }
    result1.close();

    std::cout << "===Decrypting===" << std::endl;

    omp_set_num_threads(NF);
    #pragma omp parallel for
    for (int i = 0; i < inv100Row; i++) {
        seal::Ciphertext t = CTResult[i];
        decryptor.decrypt(t, polyDecResult[i]);
        batchEncoder.decode(polyDecResult[i], decResult[i]);
    }

    std::cout << "===Decrypting > OK" << std::endl;
    std::cout << "===Making PIR Query===" << std::endl;
    std::cout << "Search index of function inv" << std::endl;

    int64_t idxRowX, idxColX;
    int64_t flag1 = 0;
    for (int64_t i = 0; i < inv100Row; i++) {
        for (int64_t j = 0; j < rowSize; j++) {
            if (decResult[i][j] >= 0 && decResult[i][j + 1] < 0 && flag1 == 0) {
                int64_t left = decResult[i][j];
                int64_t right = std::abs(decResult[i][j + 1]);
                idxRowX = i;
                idxColX = j;
                if (left > right) idxColX++;
                flag1 = 1;
                break;
            }
            std::cout << "\033[1;31mxi:\033[0m" << i << "\033[1;31mxj:\033[0m" << j << std::endl;
        }
    }

    if (flag1 == 0) {
        std::cout << "\033[1;31mERROR: NO FIND inv\033[0m" << std::endl;
    } else {
        std::cout << "Got index of function inv" << std::endl;
        std::cout << "Index RowX: " << idxRowX << ", Index ColX: " << idxColX << std::endl;
    }

    std::vector<int64_t> queryAM0, queryAM1;
    for (int64_t i = 0; i < rowSize; i++) {
        queryAM0.push_back(i == idxColX ? 1 : 0);
    }

    queryAM1 = ShiftWork(queryAM0, idxRowX, rowSize);
    queryAM0.resize(slotCount);
    queryAM1.resize(slotCount);
    std::cout << "===Making PIR Query > OK===" << std::endl;

    std::cout << "===Encrypting===" << std::endl;

    seal::Ciphertext CTQueryAM0, CTQueryAM1;
    seal::Plaintext PTQueryAM0, PTQueryAM1;

    batchEncoder.encode(queryAM0, PTQueryAM0);
    encryptor.encrypt(PTQueryAM0, CTQueryAM0);
    batchEncoder.encode(queryAM1, PTQueryAM1);
    encryptor.encrypt(PTQueryAM1, CTQueryAM1);

    std::cout << "===Encryping > OK===" << std::endl;

    std::cout << "===Saving Query===" << std::endl;
    std::ofstream queryFile;
    queryFile.open(resultDirName + "/pir_inv_" + date);
    CTQueryAM0.save(queryFile);
    CTQueryAM1.save(queryFile);
    queryFile.close();

    std::cout << "===End===" << std::endl;
    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;
    ShowMemoryUsage(getpid());

    return 0;

}
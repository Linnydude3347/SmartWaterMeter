#include "SGSimulation.hpp"

int main(int argc, char** argv) {
    // Resetting FHE
    std::cout << "Settings FHE" << std::endl;

    std::ifstream paramsFile("Key/Params");
    seal::EncryptionParameters params(seal::scheme_type::bfv);
    params.load(paramsFile);
    seal::SEALContext context(params);
    paramsFile.close();

    // Load SecretKey from file

    std::ifstream skFile("Key/SecretKey");
    seal::SecretKey secretKey;
    secretKey.unsafe_load(context, skFile);
    skFile.close();

    // Load PublicKey from file

    std::ifstream pkFile("Key/PublicKey");
    seal::PublicKey publicKey;
    publicKey.unsafe_load(context, pkFile);
    pkFile.close();

    // Load Relinearization Keys from file

    std::ifstream relinFile("Key/RelinKey");
    seal::RelinKeys relin_keys16;
    relin_keys16.unsafe_load(context, relinFile);
    relinFile.close();

    // Cryptors below

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::Decryptor decryptor(context, secretKey);

    // Batch Encoder

    seal::BatchEncoder batchEncoder(context);
    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;
    std::cout << "Plaintext matrix row size: " << rowSize << std::endl;
    std::cout << "Slot nums = " << slotCount << std::endl;

    // Get poly results situated

    seal::Plaintext polyDecResultOne;
    seal::Ciphertext tempOne;
    std::vector<int64_t> decResultOne;
    double tempResOne = 0.0, temps = 0.0;

    // Convert command line arguments to strings

    std::string date(argv[1]);
    std::string dirName(argv[2]);
    std::string saveFile(argv[3]);

    // Load funOne into tempOne

    std::ifstream readFunOne(dirName + "/finalRes_" + date, std::ios::binary);
    tempOne.load(context, readFunOne);
    readFunOne.close();

    std::cout << "part1 size after relinearization: " << tempOne.size() << std::endl;

    // Decrypt and Decode

    decryptor.decrypt(tempOne, polyDecResultOne);
    batchEncoder.decode(polyDecResultOne, decResultOne);

    // Output results

    std::cout << "Dec: " << decResultOne[0] << std::endl << std::endl;
    tempResOne = decResultOne[0] * 10000 / std::pow(2, 30);
    std::cout << "Final Result: " << tempResOne << std::endl;
    std::ofstream ctRatio;
    ctRatio.open(saveFile, std::ios::app);
    ctRatio << tempResOne << std::endl;
    ctRatio.close();

    std::cout << "Stop" << std::endl;

    return 0;

}
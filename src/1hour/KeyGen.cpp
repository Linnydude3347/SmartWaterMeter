#include "SGSimulation.hpp"

int main(int argc, char** argv) {

    // FHE Setting, generate public key and secret key

    seal::EncryptionParameters params(seal::scheme_type::bfv);
    params.set_poly_modulus_degree(8192);
    params.set_coeff_modulus(seal::CoeffModulus::BFVDefault(8192));
    params.set_plain_modulus(786433);

    // Create context and print

    seal::SEALContext context(params);
    PrintParameters(std::make_shared<seal::SEALContext>(context));

    // Create qualifiers and print

    // Look into Seal documentation to see if this line is correct.
    auto qualifiers = context.get_context_data(context.first_parms_id())->qualifiers();
    std::cout << "Batching Enabled: " << std::boolalpha << qualifiers.using_batching << std::endl;

    // Generate keys and encoder

    seal::KeyGenerator keyGen(context);
    seal::PublicKey publicKey;
    keyGen.create_public_key(publicKey);
    seal::SecretKey secretKey = keyGen.secret_key();
    // Look into Seal documentation to see if this line is correct.
    auto galKeys = keyGen.create_galois_keys();
    // Look into Seal documentation to see if this line is correct.
    auto relinKeys = keyGen.create_relin_keys();
    seal::BatchEncoder batchEncoder(context);

    // Get matrix size and slots

    size_t slotCount = batchEncoder.slot_count();
    size_t rowSize = slotCount / 2;
    std::cout << "Plaintext matrix row size: " << rowSize << std::endl;
    std::cout << "Slot nums = " << slotCount << std::endl;

    std::cout << "Save public key and secrey key..." << std::flush;
    std::ofstream pkFile(PUBLIC_KEY_FILEPATH, std::ios::binary);
    publicKey.save(pkFile);
    pkFile.close();
    
    std::ofstream skFile(SECRET_KEY_FILEPATH, std::ios::binary);
    secretKey.save(skFile);
    skFile.close();

    std::ofstream paramsFile(PARAMS_FILEPATH, std::ios::binary);
    params.save(paramsFile);
    paramsFile.close();

    std::ofstream galFile(GALOIS_KEY_FILEPATH, std::ios::binary);
    galKeys.save(galFile);
    galFile.close();

    std::ofstream relinFile(RELIN_KEY_FILEPATH, std::ios::binary);
    relinKeys.save(relinFile);
    relinFile.close();

    std::cout << "Saving completed." << std::endl;
    return 0;

}
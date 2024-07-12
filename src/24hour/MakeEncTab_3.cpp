#include "SGSimulation.hpp"

int main(int argc, char** argv){

    auto startWhole = std::chrono::high_resolution_clock::now();

    auto context = CreateContextFromParams(PARAMS_FILEPATH, seal::scheme_type::bfv);
    auto publicKey = LoadKey<seal::PublicKey>(context, PUBLIC_KEY_FILEPATH);
    auto relinKey = LoadKey<seal::RelinKeys>(context, RELIN_KEY_FILEPATH);

    seal::Encryptor encryptor(context, publicKey);
    seal::Evaluator evaluator(context);
    seal::BatchEncoder batchEncoder(context);

    size_t slot_count = batchEncoder.slot_count();
    int64_t row_size = slot_count / 2;

    double precision = std::pow(2, 5);
    double precision2 = std::pow(2, 8);
    double precision3 = std::pow(2, 10);

    std::cout << "Precision = " << precision << std::endl;
    std::cout << "////////////////////////////" << std::endl;
    std::cout << "InputArith, from " << precision * METER_NUM * std::log(52) << " to " << precision * METER_NUM * std::log(6002) << "." << std::endl;
    std::cout << "InputHarm, from " << precision3 * METER_NUM * std::log(52) << " to " << precision3 * METER_NUM * std::log(6002) << "." << std::endl;

    std::vector<int64_t> inputArith;
    std::vector<int64_t> inputHarm;

    for (int64_t i = precision * METER_NUM * std::log(52); i < precision * METER_NUM * std::log(6002); i++) {
        inputArith.push_back(i);
    }

    for (int64_t i = precision3 * METER_NUM / std::log(52); i > precision3 * METER_NUM / std::log(6002); i--) {
        inputHarm.push_back(i);
    }

    std::cout << "InputArith table size is: " << inputArith.size() << std::endl;
    std::cout << "InputHarm table size is: " << inputHarm.size() << std::endl;

    std::vector<int64_t> HM_part, AM_part;

    int64_t num3 = 0, num4 = 0, distinhm = 0, distinam = 0;
    double maxhm = 0.0, minhm = 1000.0, temphm = 0.0, maxam = 0.0, minam = 1000.0, tempam = 0.0;

    for (int64_t i = 0; i < inputArith.size(); i++) {
        double temp_Ar = inputArith[i] / precision;
        double temps_AM = std::pow(2, 5) * (temp_Ar / METER_NUM);
        double temps_AM_real = temp_Ar / METER_NUM;
        int64_t temps_AM_INT = (int64_t)temps_AM;
        if (std::abs(temps_AM - temps_AM_INT) >= 0.5) {
            temps_AM_INT++;
        }
        AM_part.push_back(temps_AM_INT);
        if (temps_AM_real >= maxam) {
            maxam = temps_AM_real;
        }
        if (temps_AM_real <= minam) {
            minam = temps_AM_real;
        }
        if (temps_AM_real != tempam) {
            distinam++;
            tempam = temps_AM_INT;
        }
        num3++;
    }

    std::cout << std::endl;

    // Line 108

    for (int64_t i = 0; i < inputHarm.size(); i++) {
        double temp_Ha = inputHarm[i] / precision3;
        double temps_HM = pow(2, 5) * (METER_NUM / temp_Ha);
        int64_t temps_HM_INT = (int64_t)temps_HM;
        if (abs(temps_HM - temps_HM_INT) >= 0.5) {
            temps_HM_INT += 1;
        }
        HM_part.push_back(temps_HM_INT);

        if (temps_HM_INT >= maxhm) maxhm = temps_HM_INT;
        if (temps_HM_INT <= minhm) minhm = temps_HM_INT;
        if (temps_HM_INT != temphm) {
            distinhm++;
            temphm = temps_HM_INT;
        }
        num4++;
    }

    std::cout << "HM input from " << inputHarm[0] << " to " << inputHarm[inputHarm.size() - 1] << std::endl;
    std::cout << "HM output from " << HM_part[0] << " to " << HM_part[HM_part.size() - 1] << std::endl;
    std::cout << "-----" << std::endl;
    std::cout << "AM input from " << inputArith[0] << " to " << inputArith[inputArith.size() - 1] << std::endl;
    std::cout << "AM output from " << AM_part[0] << " to " << AM_part[AM_part.size() - 1] << std::endl;
    std::cout << "AM out size: " << inputArith.size() << ", HM out size: " << inputHarm.size() << std::endl;

    std::vector<int64_t> sum_AM_in, sum_AM_out;

    for (int64_t i = AM_part[0] * 24; i <= AM_part[AM_part.size() - 1] * 24; i++) {
        sum_AM_in.push_back(i);
        double sum_AM_outnum = pow(2, 17) / (i / pow(2, 9));
        int64_t sum_AM_outnum_INT = (int64_t)sum_AM_outnum;
        if (sum_AM_outnum - sum_AM_outnum_INT >= 0.5) {
            sum_AM_outnum_INT += 1;
        }
        sum_AM_out.push_back(sum_AM_outnum_INT);
    }

    std::cout << "-----" << std::endl;
    std::cout << "input 1/sam from " << sum_AM_in[0] << " to " << sum_AM_in[sum_AM_in.size() - 1] << std::endl;
    std::cout << "output 1/sam from " << sum_AM_out[0] << " to " << sum_AM_out[sum_AM_out.size() - 1] << std::endl;
    std::cout << "Size: " << sum_AM_in.size() << std::endl;

    std::vector<int64_t> sum_HM_inout;
    for (int64_t i = HM_part[0] * 24; i <= HM_part[HM_part.size() - 1] * 24; i++) {
        sum_HM_inout.push_back(i);
    }
    
    std::cout << "-----" << std::endl;
    std::cout << "input 1/shm from " << sum_HM_inout[0] << " to " << sum_HM_inout[sum_HM_inout.size() - 1] << std::endl;
    std::cout << "Size: " << sum_HM_inout.size() << std::endl;

    // Save table (input AM)

    std::ofstream arith_in;
    arith_in.open("Table/AM_input_" + std::to_string(METER_NUM), std::ios::binary);

    int64_t row_ar = ceil(double(inputArith.size()) / double(row_size));

    std::vector<int64_t> inputArith_row;
    for (int64_t s = 0; s < row_ar; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < inputArith.size()) {
                inputArith_row.push_back(inputArith[s * row_size + k]);
            } else {
                inputArith_row.push_back(50000);
            }
        }
        inputArith_row.resize(slot_count);

        seal::Plaintext temp_pla_ina;
        seal::Ciphertext temp_enc_ina;
        batchEncoder.encode(inputArith_row, temp_pla_ina);
        encryptor.encrypt(temp_pla_ina, temp_enc_ina);
        temp_enc_ina.save(arith_in);
        inputArith_row.clear();

    }
    arith_in.close();

    // Save table (input HM)

    std::ofstream harm_in;
    harm_in.open("Table/HM_input_" + std::to_string(METER_NUM), std::ios::binary);
    int64_t row_ha = ceil(double(inputHarm.size()) / double(row_size));

    std::vector<int64_t> inputHarm_row;
    for (int64_t s = 0; s < row_ha; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < inputHarm.size()) {
                inputHarm_row.push_back(inputHarm[s * row_size + k]);
            } else {
                inputHarm_row.push_back(10000);
            }
        }
        inputHarm_row.resize(slot_count);

        seal::Plaintext temp_pla_inh;
        seal::Ciphertext temp_enc_inh;
        batchEncoder.encode(inputHarm_row, temp_pla_inh);
        encryptor.encrypt(temp_pla_inh, temp_enc_inh);
        temp_enc_inh.save(harm_in);
        inputHarm_row.clear();

    }
    harm_in.close();

    // Save table (output AM)

    std::ofstream arith_out;
    arith_out.open("Table/AM_output_" + std::to_string(METER_NUM), std::ios::binary);
    int64_t row_arout = ceil(double(AM_part.size()) / double(row_size));

    std::vector<int64_t> outputArith_row;
    for (int64_t s = 0; s < row_arout; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < AM_part.size()) {
                outputArith_row.push_back(AM_part[s * row_size + k]);
            } else {
                outputArith_row.push_back(500);
            }
        }
        outputArith_row.resize(slot_count);

        seal::Plaintext temp_pla_outa;
        seal::Ciphertext temp_enc_outa;
        batchEncoder.encode(outputArith_row, temp_pla_outa);
        encryptor.encrypt(temp_pla_outa, temp_enc_outa);
        temp_enc_outa.save(arith_out);
        outputArith_row.clear();

    }
    arith_out.close();

    // Save table (output HM)

    std::ofstream h_out;
    h_out.open("Table/HM_output_" + std::to_string(METER_NUM), std::ios::binary);
    int64_t row_hout = ceil(double(HM_part.size()) / double(row_size));

    std::vector<int64_t> outputh_row;
    for (int64_t s = 0; s < row_hout; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < HM_part.size()) {
                outputh_row.push_back(HM_part[s * row_size + k]);
            } else {
                outputh_row.push_back(500);
            }
        }
        outputh_row.resize(slot_count);

        seal::Plaintext temp_pla_outh;
        seal::Ciphertext temp_enc_outh;
        batchEncoder.encode(outputh_row, temp_pla_outh);
        encryptor.encrypt(temp_pla_outh, temp_enc_outh);
        temp_enc_outh.save(h_out);
        outputh_row.clear();

    }
    h_out.close();

    // Save table (sumHM input)

    std::ofstream sumhm_in;
    sumhm_in.open("Table/div_HM_input_" + std::to_string(METER_NUM), std::ios::binary);
    int64_t row_sumhin = ceil(double(sum_HM_inout.size()) / double(row_size));

    std::vector<int64_t> inputSumH_row;
    for (int64_t s = 0; s < row_sumhin; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < sum_HM_inout.size()) {
                inputSumH_row.push_back(sum_HM_inout[s * row_size + k]);
            } else {
                inputSumH_row.push_back(60000);
            }
        }
        inputSumH_row.resize(slot_count);

        seal::Plaintext temp_pla_sumh;
        seal::Ciphertext temp_enc_sumh;
        batchEncoder.encode(inputSumH_row, temp_pla_sumh);
        encryptor.encrypt(temp_pla_sumh, temp_enc_sumh);
        temp_enc_sumh.save(sumhm_in);
        inputSumH_row.clear();

    }
    sumhm_in.close();

    // sumHM output divided part

    int64_t HM1_max = 0, HM1_min = 1000, HM2_max = 0, HM2_min = 1000;

    std::ofstream harm_out1;
    harm_out1.open("Table/div_HM_output1_" + std::to_string(METER_NUM), std::ios::binary);
    std::ofstream harm_out2;
    harm_out2.open("Table/div_HM_output2_" + std::to_string(METER_NUM), std::ios::binary);

    int64_t row_haout = ceil(double(sum_HM_inout.size()) / double(row_size));
    std::cout << "Divided HM output table." << std::endl;
    std::vector<int64_t> outputHarm_row1, outputHarm_row2;

    for (int64_t s = 0; s < row_haout; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < sum_HM_inout.size()) {
                outputHarm_row1.push_back(sum_HM_inout[s * row_size + k] / 100);
                outputHarm_row2.push_back(sum_HM_inout[s * row_size + k] % 100);
                if ((sum_HM_inout[s * row_size + k] / 100) > HM1_max) HM1_max = (sum_HM_inout[s * row_size + k] / 100);
                if ((sum_HM_inout[s * row_size + k] / 100) < HM1_min) HM1_min = (sum_HM_inout[s * row_size + k] / 100);
                if ((sum_HM_inout[s * row_size + k] % 100) > HM2_max) HM2_max = (sum_HM_inout[s * row_size + k] % 100);
                if ((sum_HM_inout[s * row_size + k] % 100) < HM2_min) HM2_min = (sum_HM_inout[s * row_size + k] % 100);
            } else {
                outputHarm_row1.push_back(600);
                outputHarm_row2.push_back(1);
            }
        }
        outputHarm_row1.resize(slot_count);
        outputHarm_row2.resize(slot_count);

        seal::Plaintext temp_pla_outh1, temp_pla_outh2;
        seal::Ciphertext temp_enc_outh1, temp_enc_outh2;
        batchEncoder.encode(outputHarm_row1, temp_pla_outh1);
        encryptor.encrypt(temp_pla_outh1, temp_enc_outh1);
        temp_enc_outh1.save(harm_out1);
        outputHarm_row1.clear();
        batchEncoder.encode(outputHarm_row2, temp_pla_outh2);
        encryptor.encrypt(temp_pla_outh2, temp_enc_outh2);
        temp_enc_outh2.save(harm_out2);
        outputHarm_row2.clear();
    }
    harm_out1.close();
    harm_out2.close();

    // sum_AM input table

    std::ofstream sumam_in;
    sumam_in.open("Table/SUM_AM_input_" + std::to_string(METER_NUM), std::ios::binary);
    int64_t row_sumain = ceil(double(sum_AM_in.size()) / double(row_size));
    std::vector<int64_t> inputSumA_row;

    for (int64_t s = 0; s < row_sumain; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < sum_AM_in.size()) {
                inputSumA_row.push_back(sum_AM_in[s * row_size + k]);
            } else {
                inputSumA_row.push_back(60000);
            }
        }
        inputSumA_row.resize(slot_count);

        seal::Plaintext temp_pla_suma;
        seal::Ciphertext temp_enc_suma;
        batchEncoder.encode(inputSumA_row, temp_pla_suma);
        encryptor.encrypt(temp_pla_suma, temp_enc_suma);
        temp_enc_suma.save(sumam_in);
        inputSumA_row.clear();

    }
    sumam_in.close();

    // 1/sum_AM output table

    int64_t AM1_max = 0, AM1_min = 100, AM2_max = 0, AM2_min = 100;
    std::ofstream lnv_am_out1;
    lnv_am_out1.open("Table/inv_SUM_AM_output1_" + std::to_string(METER_NUM), std::ios::binary);
    std::ofstream lnv_am_out2;
    lnv_am_out2.open("Table/inv_SUM_AM_output2_" + std::to_string(METER_NUM), std::ios::binary);

    int64_t row_sumaout = ceil(double(sum_AM_out.size()) / double(row_size));
    std::vector<int64_t> inputSumA_row1, inputSumA_row2;

    for (int64_t s = 0; s < row_sumaout; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < sum_AM_out.size()) {
                inputSumA_row1.push_back(sum_AM_out[s * row_size + k] / 100);
                inputSumA_row2.push_back(sum_AM_out[s * row_size + k] % 100);
                if ((sum_AM_out[s * row_size + k] / 100) > AM1_max) AM1_max = (sum_AM_out[s * row_size + k] / 100);
                if ((sum_AM_out[s * row_size + k] / 100) < AM1_min) AM1_min = (sum_AM_out[s * row_size + k] / 100);
                if ((sum_AM_out[s * row_size + k] % 100) > AM2_max) AM2_max = (sum_AM_out[s * row_size + k] % 100);
                if ((sum_AM_out[s * row_size + k] % 100) < AM2_min) AM2_min = (sum_AM_out[s * row_size + k] % 100);
            } else {
                inputSumA_row1.push_back(1);
                inputSumA_row2.push_back(1);
            }
        }
        inputSumA_row1.resize(slot_count);
        inputSumA_row2.resize(slot_count);

        seal::Plaintext temp_pla_suma1, temp_pla_suma2;
        seal::Ciphertext temp_enc_suma1, temp_enc_suma2;
        batchEncoder.encode(inputSumA_row1, temp_pla_suma1);
        encryptor.encrypt(temp_pla_suma1, temp_enc_suma1);
        temp_enc_suma1.save(lnv_am_out1);
        inputSumA_row1.clear();
        batchEncoder.encode(inputSumA_row2, temp_pla_suma2);
        encryptor.encrypt(temp_pla_suma2, temp_enc_suma2);
        temp_enc_suma2.save(lnv_am_out2);
        inputSumA_row2.clear();

    }
    lnv_am_out1.close();
    lnv_am_out2.close();

    // Add one table for N/100

    std::cout << "HM1_max: " << HM1_max << ", HM1_min: " << HM1_min << ", HM2_max: " << HM2_max << ", HM2_min: " << HM2_min << std::endl;
    std::cout << "AM1_max: " << AM1_max << ", AM1_min: " << AM1_min << ", AM2_max: " << AM2_max << ", AM2_min: " << AM2_min << std::endl;

    std::vector<int64_t> inv_in, inv_out; // (HM1 * AM2 + HM2 * AM1)
    int64_t inv_max = HM1_max * AM2_max + HM2_max + AM1_max;
    int64_t inv_min = HM1_min * AM2_min + HM2_min + AM1_min;

    for (int64_t i = inv_min; i <= inv_max; i++) {
        inv_in.push_back(i);
        double ttd = i / 100.0;
        int64_t tti = i / 100;
        if (ttd - tti >= 0.5) {
            inv_out.push_back(tti + 1);
        } else {
            inv_out.push_back(tti);
        }
    }

    std::cout << "-----" << std::endl;
    std::cout << "inv100 size: " << inv_in.size() << std::endl;
    std::cout << "input inv from " << inv_in[0] << " to " << inv_in[inv_in.size() - 1] << std::endl;
    std::cout << "output inv from " << inv_out[0] << " to " << inv_out[inv_out.size() - 1] << std::endl;

    std::ofstream lnv_100_in;
    lnv_100_in.open("Table/inv_100_input_" + std::to_string(METER_NUM), std::ios::binary);
    std::ofstream lnv_100_out;
    lnv_100_out.open("Table/inv_100_output_" + std::to_string(METER_NUM), std::ios::binary);

    int64_t row_100in = ceil(double(inv_in.size()) / double(row_size));

    std::vector<int64_t> input100_row, output100_row;
    for (int64_t s = 0; s < row_100in; s++) {
        for (int64_t k = 0; k < row_size; k++) {
            if ((s * row_size + k) < inv_in.size()) {
                input100_row.push_back(inv_in[s * row_size + k]);
                output100_row.push_back(inv_out[s * row_size + k]);
            } else {
                input100_row.push_back(60000);
                output100_row.push_back(1);
            }
        }
        input100_row.resize(slot_count);
        output100_row.resize(slot_count);

        seal::Plaintext temp_pla_100in, temp_pla_100out;
        seal::Ciphertext temp_enc_100in, temp_enc_100out;
        batchEncoder.encode(input100_row, temp_pla_100in);
        encryptor.encrypt(temp_pla_100in, temp_enc_100in);
        temp_enc_100in.save(lnv_100_in);
        input100_row.clear();
        batchEncoder.encode(output100_row, temp_pla_100out);
        encryptor.encrypt(temp_pla_100out, temp_enc_100out);
        temp_enc_100out.save(lnv_100_out);
        output100_row.clear();

    }
    lnv_100_in.close();
    lnv_100_out.close();

    auto endWhole = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> diffWhole = endWhole - startWhole;
    std::cout << "Whole runtime is: " << diffWhole.count() << "s" << std::endl;

    return 0;

}
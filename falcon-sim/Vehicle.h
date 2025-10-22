// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

//
// Created by geoff on 10/14/21.
//

#ifndef CPP_VEHICLE_H
#define CPP_VEHICLE_H

#include <array>
#include <string>
#include <unordered_map>
#include <vector>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>

#include "ieee16092.h"
#include "bsm.h"
#include "v2vcrypto.h"

enum class signature_scheme {
    ECDSA = 0,
    FALCON = 1
};

struct pqc_options {
    signature_scheme scheme = signature_scheme::ECDSA;
    std::size_t falcon_fragment_size = 256;
    std::string compression = "none";
};


class Vehicle {

private:
    static constexpr std::size_t MAX_SIGNATURE_FRAGMENT_SIZE = 512;
    static constexpr std::size_t MAX_SIGNATURE_TOTAL_SIZE = 1536;

    std::string hostname;
    uint8_t number;
    pqc_options pqc{};
    EC_KEY *private_ec_key = nullptr, *cert_private_ec_key = nullptr;
    ecdsa_explicit_certificate vehicle_certificate_ecdsa;

    unsigned char certificate_signature[72];
    unsigned int certificate_buffer_length;

    std::vector<uint8_t> falcon_private_key;

    struct spdu_fragment {
        uint8_t vehicle_id;
        uint32_t sequence_number;
        uint32_t llc_dsap_ssap = 43690;
        uint8_t  llc_control = 3;
        uint32_t llc_type = 35036;
        uint8_t wsmp_n_subtype_opt_version = 3;
        uint8_t wsmp_n_tpid = 0;
        uint8_t wsmp_t_header_length_and_psid = 32;
        uint8_t wsmp_t_length = 0;
        uint8_t signature_scheme = 0;
        uint16_t fragment_index = 0;
        uint16_t fragment_count = 1;
        unsigned int signature_buffer_length = 0;
        unsigned int fragment_length = 0;
        unsigned int signature_offset = 0;
        unsigned int certificate_signature_buffer_length = 0;
        ieee1609dot2data_ecdsa_explicit data;
        std::array<uint8_t, MAX_SIGNATURE_FRAGMENT_SIZE> signature_fragment{};
    };

    std::vector<std::vector<float>> timestep;
    std::vector<float> timestep_data;

    void generate_spdu(Vehicle::spdu_fragment &spdu, uint32_t sequence_number, int timestep);

    bsm generate_bsm(int timestep);
    static void print_bsm(Vehicle::spdu_fragment &spdu);
    static void print_spdu(Vehicle::spdu_fragment &spdu, bool valid);

    static void load_key(int number, bool certificate, EC_KEY *&key_to_store);
    void load_falcon_private_key(int number);
    static void load_falcon_public_key(int number, std::vector<uint8_t> &dest);
    void load_trace(int number);

    void sign_message_ecdsa(Vehicle::spdu_fragment &spdu);
    std::vector<Vehicle::spdu_fragment> sign_message_falcon(const Vehicle::spdu_fragment &spdu);
    std::vector<Vehicle::spdu_fragment> prepare_signed_fragments(uint32_t sequence_number, int timestep);
    bool verify_message(Vehicle::spdu_fragment &spdu, const std::vector<uint8_t> &assembled_signature,
                        std::chrono::time_point<std::chrono::system_clock,
                        std::chrono::microseconds> received_time, int vehicle_id);

public:
    Vehicle(int number, pqc_options pqc_opts = {}) {
        hostname = "null_hostname";
        this->number = number;
        this->pqc = pqc_opts;
        Vehicle::load_key(number, false, private_ec_key);
        Vehicle::load_key(number, true, cert_private_ec_key);
        Vehicle::load_trace(number);
        if (this->pqc.scheme == signature_scheme::FALCON) {
            load_falcon_private_key(number);
        }
    };

    std::string get_hostname();
    void transmit(int num_msgs, bool test);
    static void transmit_static(void* arg, int num_msgs, bool test) {
        auto* v = (Vehicle*) arg;
        v->transmit(num_msgs, test);
    };
    void receive(int num_msgs, bool test, bool tkgui, bool webgui);
};


#endif //CPP_VEHICLE_H

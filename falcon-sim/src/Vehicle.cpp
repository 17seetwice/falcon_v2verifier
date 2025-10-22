// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <random>
#include <stdexcept>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <openssl/err.h>
#include <openssl/pem.h>

#include "Vehicle.h"
#include <cstdlib>

namespace {
using timestamp = std::chrono::time_point<std::chrono::system_clock, std::chrono::microseconds>;

uint64_t make_message_key(uint8_t vehicle_id, uint32_t sequence_number) {
    return (static_cast<uint64_t>(vehicle_id) << 32) | static_cast<uint64_t>(sequence_number);
}

std::size_t clamp_fragment_size(std::size_t requested, std::size_t maximum) {
    if (requested == 0) {
        return maximum;
    }
    return std::min(requested, maximum);
}

uint8_t decode_hex_char(char c) {
    if (c >= '0' && c <= '9') {
        return static_cast<uint8_t>(c - '0');
    }
    if (c >= 'a' && c <= 'f') {
        return static_cast<uint8_t>(c - 'a' + 10);
    }
    if (c >= 'A' && c <= 'F') {
        return static_cast<uint8_t>(c - 'A' + 10);
    }
    throw std::runtime_error("Invalid hex character");
}

std::vector<uint8_t> hex_to_bytes(const std::string &hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("Hex string length must be even");
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t i = 0; i < hex.size(); i += 2) {
        uint8_t msn = decode_hex_char(hex[i]);
        uint8_t lsn = decode_hex_char(hex[i + 1]);
        bytes.push_back(static_cast<uint8_t>((msn << 4) | lsn));
    }
    return bytes;
}

uint16_t get_test_port() {
    const char *env = std::getenv("V2X_TEST_PORT");
    if (env != nullptr) {
        char *end = nullptr;
        long value = std::strtol(env, &end, 10);
        if (end != env && value > 0 && value < 65536) {
            return static_cast<uint16_t>(value);
        }
    }
    return 6666;
}
} // namespace

std::string Vehicle::get_hostname() {
    return hostname;
}

std::vector<Vehicle::spdu_fragment> Vehicle::prepare_signed_fragments(uint32_t sequence_number, int timestep) {
    Vehicle::spdu_fragment base{};
    generate_spdu(base, sequence_number, timestep);
    base.signature_scheme = static_cast<uint8_t>(pqc.scheme);

    if (pqc.scheme == signature_scheme::ECDSA) {
        sign_message_ecdsa(base);
        return {base};
    }

    return sign_message_falcon(base);
}

void Vehicle::transmit(int num_msgs, bool test) {
    int sockfd;
    struct sockaddr_in servaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        exit(EXIT_FAILURE);
    }

    std::memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    uint16_t test_port = get_test_port();
    servaddr.sin_port = htons(test ? test_port : 52001);
    servaddr.sin_addr.s_addr = INADDR_ANY;

    const char *loss_env = std::getenv("V2X_PACKET_LOSS_RATE");
    double drop_rate = 0.0;
    if (loss_env != nullptr) {
        drop_rate = std::strtod(loss_env, nullptr);
        if (drop_rate < 0.0) {
            drop_rate = 0.0;
        }
        if (drop_rate > 1.0) {
            drop_rate = 1.0;
        }
    }

    std::random_device rd;
    std::mt19937 rng(rd());
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    std::size_t dropped_fragments = 0;
    std::size_t resent_fragments = 0;

    for (int i = 0; i < num_msgs; i++) {
        auto fragments = prepare_signed_fragments(static_cast<uint32_t>(i), i);
        std::vector<Vehicle::spdu_fragment> resend_queue;
        for (auto &fragment : fragments) {
            if (drop_rate > 0.0 && dist(rng) < drop_rate) {
                dropped_fragments++;
                resend_queue.push_back(fragment);
                continue;
            }
            if (sendto(sockfd,
                       &fragment,
                       sizeof(fragment),
                       MSG_CONFIRM,
                       reinterpret_cast<const struct sockaddr *>(&servaddr),
                       sizeof(servaddr)) < 0) {
                perror("sendto failed");
                close(sockfd);
                exit(EXIT_FAILURE);
            }
        }

        if (!resend_queue.empty()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            for (auto &fragment : resend_queue) {
                if (sendto(sockfd,
                           &fragment,
                           sizeof(fragment),
                           MSG_CONFIRM,
                           reinterpret_cast<const struct sockaddr *>(&servaddr),
                           sizeof(servaddr)) < 0) {
                    perror("resend sendto failed");
                    close(sockfd);
                    exit(EXIT_FAILURE);
                }
                resent_fragments++;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    close(sockfd);

    if (drop_rate > 0.0) {
        std::cout << "Transmitter dropped " << dropped_fragments
                  << " fragments at configured rate " << drop_rate
                  << " (resent: " << resent_fragments << ")" << std::endl;
    }
}

void Vehicle::receive(int num_msgs, bool test, bool tkgui, bool webgui) {
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR failed");
        exit(EXIT_FAILURE);
    }

    std::memset(&servaddr, 0, sizeof(servaddr));
    std::memset(&cliaddr, 0, sizeof(cliaddr));

    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    uint16_t test_port = get_test_port();
    servaddr.sin_port = htons(test ? test_port : 4444);

    if (bind(sockfd, reinterpret_cast<const struct sockaddr *>(&servaddr), sizeof(servaddr)) < 0) {
        perror("Socket bind failed");
        exit(EXIT_FAILURE);
    }

    // GUI socket setup (unchanged from original implementation)
    int sockfd2;
    struct sockaddr_in servaddr2;

    if ((sockfd2 = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sockfd2, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt SO_REUSEADDR failed (GUI socket)");
        exit(EXIT_FAILURE);
    }

    std::memset(&servaddr2, 0, sizeof(servaddr2));
    servaddr2.sin_family = AF_INET;
    servaddr2.sin_port = htons(tkgui ? 9999 : 8888);
    servaddr2.sin_addr.s_addr = INADDR_ANY;

    socklen_t len = sizeof(cliaddr);

    struct PendingMessage {
        Vehicle::spdu_fragment template_fragment{};
        std::vector<uint8_t> signature_buffer;
        std::vector<bool> fragments_received;
        timestamp first_fragment_time{};
    };

    std::unordered_map<uint64_t, PendingMessage> pending_messages;

    bool first_fragment_seen = false;
    timestamp first_fragment_time{};
    timestamp last_completion_time{};

    const char *metrics_path = std::getenv("V2X_METRICS_FILE");
    const char *metrics_run_id = std::getenv("V2X_METRICS_RUN");
    const char *metrics_note = std::getenv("V2X_METRICS_NOTE");

    int completed_messages = 0;
    while (completed_messages < num_msgs) {
        Vehicle::spdu_fragment incoming{};
        if (recvfrom(sockfd,
                     &incoming,
                     sizeof(incoming),
                     0,
                     reinterpret_cast<struct sockaddr *>(&cliaddr),
                     &len) < 0) {
            perror("recvfrom failed");
            close(sockfd2);
            close(sockfd);
            exit(EXIT_FAILURE);
        }

        timestamp receive_time = std::chrono::time_point_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now());

        if (!first_fragment_seen) {
            first_fragment_seen = true;
            first_fragment_time = receive_time;
        }

        const uint64_t key = make_message_key(incoming.vehicle_id, incoming.sequence_number);
        auto &entry = pending_messages[key];

        if (entry.signature_buffer.empty()) {
            entry.template_fragment = incoming;
            entry.template_fragment.fragment_index = 0;
            entry.template_fragment.fragment_length = 0;
            entry.template_fragment.signature_fragment.fill(0);
            entry.signature_buffer.assign(static_cast<std::size_t>(incoming.signature_buffer_length), 0);
            entry.fragments_received.assign(static_cast<std::size_t>(incoming.fragment_count), false);
            entry.first_fragment_time = receive_time;
        }

        if (incoming.fragment_index < entry.fragments_received.size()) {
            if (!entry.fragments_received[incoming.fragment_index]) {
                const std::size_t offset = static_cast<std::size_t>(incoming.signature_offset);
                const std::size_t length = static_cast<std::size_t>(incoming.fragment_length);
                if (offset + length <= entry.signature_buffer.size()) {
                    std::copy_n(incoming.signature_fragment.begin(),
                                length,
                                entry.signature_buffer.begin() + static_cast<long>(offset));
                    entry.fragments_received[incoming.fragment_index] = true;
                }
            }
        }

        entry.template_fragment.data = incoming.data;
        entry.template_fragment.signature_buffer_length = incoming.signature_buffer_length;
        entry.template_fragment.certificate_signature_buffer_length = incoming.certificate_signature_buffer_length;
        entry.template_fragment.signature_scheme = incoming.signature_scheme;
        entry.template_fragment.fragment_count = incoming.fragment_count;

        const bool complete = std::all_of(entry.fragments_received.begin(),
                                          entry.fragments_received.end(),
                                          [](bool received) { return received; });

        if (!complete) {
            continue;
        }

        bool valid_spdu = verify_message(entry.template_fragment,
                                         entry.signature_buffer,
                                         receive_time,
                                         incoming.vehicle_id);

        if (tkgui || webgui) {
            packed_bsm_for_gui data_for_gui = {
                entry.template_fragment.data.signedData.tbsData.message.latitude,
                entry.template_fragment.data.signedData.tbsData.message.longitude,
                entry.template_fragment.data.signedData.tbsData.message.elevation,
                entry.template_fragment.data.signedData.tbsData.message.speed,
                entry.template_fragment.data.signedData.tbsData.message.heading,
                valid_spdu,
                true,
                7,
                static_cast<float>(incoming.vehicle_id)
            };
            sendto(sockfd2,
                   &data_for_gui,
                   sizeof(data_for_gui),
                   MSG_CONFIRM,
                   reinterpret_cast<const struct sockaddr *>(&servaddr2),
                   sizeof(servaddr2));
        }

        for (int i = 0; i < 80; i++) {
            std::cout << "-";
        }
        std::cout << std::endl;
        print_spdu(entry.template_fragment, valid_spdu);
        print_bsm(entry.template_fragment);

        completed_messages++;
        last_completion_time = receive_time;
        pending_messages.erase(key);
    }

    close(sockfd2);
    close(sockfd);

    if (first_fragment_seen) {
        auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            last_completion_time - first_fragment_time).count();
        auto first_timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
            first_fragment_time.time_since_epoch()).count();
        auto last_timestamp = std::chrono::duration_cast<std::chrono::microseconds>(
            last_completion_time.time_since_epoch()).count();

        if (metrics_path != nullptr) {
            std::ofstream metrics_file(metrics_path, std::ios::app);
            if (metrics_file.is_open()) {
                metrics_file << (metrics_run_id != nullptr ? metrics_run_id : "0") << ','
                             << static_cast<int>(pqc.scheme) << ','
                             << total_duration << ','
                             << first_timestamp << ','
                             << last_timestamp << ','
                             << (metrics_note != nullptr ? metrics_note : "");
                metrics_file << '\n';
            }
        }

        std::cout << "METRIC run=" << (metrics_run_id != nullptr ? metrics_run_id : "0")
                  << " scheme=" << static_cast<int>(pqc.scheme)
                  << " total_us=" << total_duration
                  << " first_us=" << first_timestamp
                  << " last_us=" << last_timestamp
                  << std::endl;
    }

    exit(0);
}

void Vehicle::generate_spdu(Vehicle::spdu_fragment &spdu, uint32_t sequence_number, int timestep) {
    spdu = {};
    spdu.vehicle_id = this->number;
    spdu.sequence_number = sequence_number;
    spdu.signature_fragment.fill(0);

    spdu.data.signedData.tbsData.message = generate_bsm(timestep);

    timestamp ts = std::chrono::time_point_cast<std::chrono::microseconds>(std::chrono::system_clock::now());
    spdu.data.signedData.tbsData.headerInfo.timestamp = ts;

    spdu.data.signedData.cert = vehicle_certificate_ecdsa;

    unsigned char certificate_digest[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.cert, sizeof(spdu.data.signedData.cert), certificate_digest);
    ecdsa_sign(certificate_digest, cert_private_ec_key, &certificate_buffer_length, certificate_signature);

    spdu.certificate_signature_buffer_length = certificate_buffer_length;
    std::copy_n(certificate_signature,
                certificate_buffer_length,
                spdu.data.certificate_signature);
}

bsm Vehicle::generate_bsm(int timestep) {
    float latitude = this->timestep[timestep][0];
    float longitude = this->timestep[timestep][1];
    float elevation = this->timestep[timestep][2];
    float speed = 0;
    float heading = 0;
    if (timestep != 0) {
        speed = calculate_speed_kph(this->timestep[timestep - 1][0],
                                    latitude,
                                    this->timestep[timestep - 1][1],
                                    longitude,
                                    100);

        heading = calculate_heading(this->timestep[timestep - 1][0],
                                    latitude,
                                    this->timestep[timestep - 1][1],
                                    longitude);
    }
    std::cout << "Calculated heading:\t" << heading << std::endl;
    bsm new_bsm = {latitude, longitude, elevation, speed, heading};
    return new_bsm;
}

void Vehicle::print_bsm(Vehicle::spdu_fragment &spdu) {
    std::cout << "BSM received!" << std::endl;
    std::cout << "\tLocation:\t";
    std::cout << spdu.data.signedData.tbsData.message.latitude;
    std::cout << ", ";
    std::cout << spdu.data.signedData.tbsData.message.longitude;
    std::cout << ", ";
    std::cout << spdu.data.signedData.tbsData.message.elevation;
    std::cout << std::endl;
    std::cout << "\tSpeed:\t\t" << spdu.data.signedData.tbsData.message.speed << std::endl;
    std::cout << "\tHeading:\t" << spdu.data.signedData.tbsData.message.heading << std::endl;
}

void Vehicle::print_spdu(Vehicle::spdu_fragment &spdu, bool valid) {
    std::cout << "SPDU received!" << std::endl;
    std::cout << "\tID:\t" << static_cast<int>(spdu.vehicle_id) << std::endl;
    std::cout << "\tSequence:\t" << spdu.sequence_number << std::endl;
    std::cout << "\tValid:\t" << (valid ? "TRUE" : "FALSE") << std::endl;
    std::cout << "\tFragments:\t" << spdu.fragment_count << std::endl;
    std::cout << "\tScheme:\t" << (spdu.signature_scheme == static_cast<uint8_t>(signature_scheme::FALCON) ? "Falcon" : "ECDSA") << std::endl;
    std::cout << "\tSent:\t" << std::chrono::system_clock::to_time_t(spdu.data.signedData.tbsData.headerInfo.timestamp) << std::endl;
}

void Vehicle::sign_message_ecdsa(Vehicle::spdu_fragment &spdu) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.tbsData, sizeof(spdu.data.signedData.tbsData), hash);

    unsigned int signature_length = ECDSA_size(private_ec_key);
    if (signature_length > MAX_SIGNATURE_FRAGMENT_SIZE) {
        std::cerr << "ECDSA signature exceeds maximum fragment size" << std::endl;
        exit(EXIT_FAILURE);
    }

    auto signature = std::vector<unsigned char>(signature_length, 0);
    ecdsa_sign(hash, private_ec_key, &signature_length, signature.data());

    spdu.signature_buffer_length = signature_length;
    spdu.fragment_count = 1;
    spdu.fragment_index = 0;
    spdu.fragment_length = signature_length;
    spdu.signature_offset = 0;
    spdu.signature_fragment.fill(0);
    std::copy(signature.begin(), signature.end(), spdu.signature_fragment.begin());
}

std::vector<Vehicle::spdu_fragment> Vehicle::sign_message_falcon(const Vehicle::spdu_fragment &spdu) {
    if (falcon_private_key.empty()) {
        std::cerr << "Falcon private key not loaded" << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<uint8_t> message(sizeof(spdu.data.signedData.tbsData), 0);
    std::memcpy(message.data(), &spdu.data.signedData.tbsData, message.size());

    std::vector<uint8_t> signature(MAX_SIGNATURE_TOTAL_SIZE, 0);
    size_t signature_len = signature.size();
    falcon_sign(signature.data(),
                signature_len,
                message.data(),
                message.size(),
                falcon_private_key.data());
    signature.resize(signature_len);

    const std::size_t fragment_size = clamp_fragment_size(pqc.falcon_fragment_size, MAX_SIGNATURE_FRAGMENT_SIZE);
    const std::size_t fragment_count = (signature_len + fragment_size - 1) / fragment_size;

    std::vector<Vehicle::spdu_fragment> fragments;
    fragments.reserve(fragment_count);

    for (std::size_t idx = 0; idx < fragment_count; ++idx) {
        Vehicle::spdu_fragment fragment = spdu;
        fragment.signature_scheme = static_cast<uint8_t>(signature_scheme::FALCON);
        fragment.fragment_count = static_cast<uint16_t>(fragment_count);
        fragment.fragment_index = static_cast<uint16_t>(idx);
        fragment.signature_buffer_length = static_cast<unsigned int>(signature_len);
        fragment.signature_offset = static_cast<unsigned int>(idx * fragment_size);

        const std::size_t remaining = signature_len - static_cast<std::size_t>(fragment.signature_offset);
        const std::size_t bytes_this_fragment = std::min(fragment_size, remaining);
        fragment.fragment_length = static_cast<unsigned int>(bytes_this_fragment);
        fragment.signature_fragment.fill(0);
        std::memcpy(fragment.signature_fragment.data(),
                    signature.data() + static_cast<std::size_t>(fragment.signature_offset),
                    bytes_this_fragment);

        fragments.push_back(fragment);
    }

    return fragments;
}

bool Vehicle::verify_message(Vehicle::spdu_fragment &spdu,
                             const std::vector<uint8_t> &assembled_signature,
                             timestamp received_time,
                             int vehicle_id) {
    EC_KEY *verification_private_ec_key = nullptr;
    EC_KEY *verification_cert_private_ec_key = nullptr;

    load_key(vehicle_id, false, verification_private_ec_key);
    load_key(vehicle_id, true, verification_cert_private_ec_key);

    unsigned char certificate_hash[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.cert,
              sizeof(spdu.data.signedData.cert),
              certificate_hash);
    bool cert_result = ecdsa_verify(certificate_hash,
                                    spdu.data.certificate_signature,
                                    &spdu.certificate_signature_buffer_length,
                                    verification_cert_private_ec_key);

    bool sig_result = false;
    auto scheme = static_cast<signature_scheme>(spdu.signature_scheme);

    unsigned char hash[SHA256_DIGEST_LENGTH];
    sha256sum(&spdu.data.signedData.tbsData,
              sizeof(spdu.data.signedData.tbsData),
              hash);

    if (scheme == signature_scheme::ECDSA) {
        sig_result = ecdsa_verify(hash,
                                  const_cast<unsigned char *>(assembled_signature.data()),
                                  &spdu.signature_buffer_length,
                                  verification_private_ec_key);
    } else {
        std::vector<uint8_t> public_key;
        load_falcon_public_key(vehicle_id, public_key);
        std::vector<uint8_t> message(sizeof(spdu.data.signedData.tbsData), 0);
        std::memcpy(message.data(), &spdu.data.signedData.tbsData, message.size());
        sig_result = falcon_verify(message.data(),
                                   message.size(),
                                   const_cast<uint8_t *>(assembled_signature.data()),
                                   assembled_signature.size(),
                                   public_key.data());
    }

    if (verification_private_ec_key != nullptr) {
        EC_KEY_free(verification_private_ec_key);
    }
    if (verification_cert_private_ec_key != nullptr) {
        EC_KEY_free(verification_cert_private_ec_key);
    }

    std::chrono::duration<double, std::milli> elapsed_time =
        received_time - spdu.data.signedData.tbsData.headerInfo.timestamp;
    bool recent = elapsed_time.count() < 30000;

    return cert_result && sig_result && recent;
}

void Vehicle::load_key(int number, bool certificate, EC_KEY *&key_to_store) {
    std::string temp = certificate ? "cert_keys/" + std::to_string(number) + "/p256.key" :
                                     "keys/" + std::to_string(number) + "/p256.key";

    const char *filepath = temp.c_str();

    FILE *fp = fopen(filepath, "r");
    if (fp != nullptr) {
        EVP_PKEY *key = nullptr;
        PEM_read_PrivateKey(fp, &key, nullptr, nullptr);
        key_to_store = nullptr;
        if (!key) {
            perror("Error while loading the key from file\n");
            exit(EXIT_FAILURE);
        }
        if (!(key_to_store = EVP_PKEY_get1_EC_KEY(key))) {
            perror("Error while getting EC key from loaded key\n");
            exit(EXIT_FAILURE);
        }
        EVP_PKEY_free(key);
        fclose(fp);
    } else {
        std::cout << filepath << std::endl;
        std::cout << "Error while opening file from path. Error number : " << errno << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Vehicle::load_falcon_private_key(int number) {
    std::string path = "falcon_keys/" + std::to_string(number) + "/falcon.key";
    std::ifstream key_file(path, std::ios::binary);
    if (!key_file.is_open()) {
        std::cerr << "Unable to open Falcon private key: " << path << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string hex_key{std::istreambuf_iterator<char>(key_file), std::istreambuf_iterator<char>()};
    try {
        falcon_private_key = hex_to_bytes(hex_key);
        if (falcon_private_key.size() != OQS_SIG_falcon_512_length_secret_key) {
            std::cerr << "Unexpected Falcon private key length: " << falcon_private_key.size()
                      << " (expected " << OQS_SIG_falcon_512_length_secret_key << ")" << std::endl;
            exit(EXIT_FAILURE);
        }
    } catch (const std::exception &ex) {
        std::cerr << "Failed to decode Falcon private key: " << ex.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Vehicle::load_falcon_public_key(int number, std::vector<uint8_t> &dest) {
    static std::unordered_map<int, std::vector<uint8_t>> cache;
    auto it = cache.find(number);
    if (it != cache.end()) {
        dest = it->second;
        return;
    }

    std::string path = "falcon_keys/" + std::to_string(number) + "/falcon.pub";
    std::ifstream key_file(path, std::ios::binary);
    if (!key_file.is_open()) {
        std::cerr << "Unable to open Falcon public key: " << path << std::endl;
        exit(EXIT_FAILURE);
    }

    std::string hex_key{std::istreambuf_iterator<char>(key_file), std::istreambuf_iterator<char>()};
    try {
        auto buffer = hex_to_bytes(hex_key);
        if (buffer.size() != OQS_SIG_falcon_512_length_public_key) {
            std::cerr << "Unexpected Falcon public key length: " << buffer.size()
                      << " (expected " << OQS_SIG_falcon_512_length_public_key << ")" << std::endl;
            exit(EXIT_FAILURE);
        }
        cache[number] = buffer;
        dest = std::move(buffer);
    } catch (const std::exception &ex) {
        std::cerr << "Failed to decode Falcon public key: " << ex.what() << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Vehicle::load_trace(int number) {
    std::string line;
    std::string word;

    std::fstream file("trace_files/" + std::to_string(number) + ".csv", std::ios::in);
    if (file.is_open()) {
        while (getline(file, line)) {
            timestep_data.clear();
            std::stringstream str(line);
            while (getline(str, word, ',')) {
                timestep_data.push_back(std::stof(word));
            }
            timestep.push_back(timestep_data);
        }
    } else {
        perror(("Error opening trace file for vehicle " + std::to_string(number)).c_str());
        exit(EXIT_FAILURE);
    }
}

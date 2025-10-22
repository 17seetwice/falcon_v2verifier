// Copyright (c) 2022. Geoff Twardokus
// Reuse permitted under the MIT License as specified in the LICENSE file within this project.

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <iostream>
#include <thread>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "Vehicle.h"
#include "arguments.h"


void print_usage() {
    std::cout << "Usage: v2verifer {dsrc | cv2x} {transmitter | receiver} {tkgui | webgui | nogui} [--test]" << std::endl;
}

int main(int argc, char *argv[]) {

    if(argc < 3 || argc > 5) {
        print_usage();
        exit(EXIT_FAILURE);
    }

    program_arguments args;

    if(std::string(argv[1]) == "dsrc")
        args.tech_choice = DSRC;
    else if(std::string(argv[1]) == "cv2x")
        args.tech_choice = CV2X;
    else {
        std::cout << "Error: first argument must be DSRC or C_V2X" << std::endl;
        print_usage();
        exit(EXIT_FAILURE);
    }

    if(std::string(argv[2]) == "transmitter") {
        args.sim_mode = TRANSMITTER;
    }
    else if(std::string(argv[2]) == "receiver")
        args.sim_mode = RECEIVER;
    else {
        std::cout << R"(Error: second argument must be "transmitter" or "receiver")" << std::endl;
        print_usage();
        exit(EXIT_FAILURE);
    }

    if(std::string(argv[3]) == "tkgui")
    args.tkgui = true;
    else if(std::string(argv[3]) == "webgui")
        args.webgui = true;
    else if(std::string(argv[3]) == "nogui")
        args.tkgui, args.webgui = false;
    else {
        std::cout << R"(Error: third argument must be "tkgui, webgui, or nogui")" << std::endl;
        print_usage();
        exit(EXIT_FAILURE);
    }

    if(argc >= 4) {
        if(argc == 5) {
            if (std::string(argv[4]) == "--test")
                args.test = true;
            else {
                std::cout << R"(Error: optional third argument can only be "--test")" << std::endl;
                print_usage();
                exit(EXIT_FAILURE);
            }
        }
    }

    const char *config_override = std::getenv("V2X_CONFIG_PATH");
    std::string config_path = config_override != nullptr ? std::string(config_override) : "config.json";

    boost::property_tree::ptree tree;
    boost::property_tree::json_parser::read_json(config_path, tree);

    auto num_vehicles = tree.get<uint8_t>("scenario.numVehicles");
    auto num_msgs = tree.get<uint16_t>("scenario.numMessages");

    pqc_options pqc_opts;
    std::string scheme_str;
    if (const char *scheme_env = std::getenv("V2X_SIGNATURE_SCHEME")) {
        scheme_str = scheme_env;
    } else {
        scheme_str = tree.get<std::string>("scenario.signatureScheme", "ecdsa");
    }
    std::transform(scheme_str.begin(), scheme_str.end(), scheme_str.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (scheme_str == "falcon") {
        pqc_opts.scheme = signature_scheme::FALCON;
    } else {
        pqc_opts.scheme = signature_scheme::ECDSA;
    }

    auto fragment_from_config = tree.get<int>("scenario.falcon.fragmentBytes",
                                              static_cast<int>(pqc_opts.falcon_fragment_size));
    pqc_opts.falcon_fragment_size = static_cast<std::size_t>(fragment_from_config);
    if (const char *fragment_env = std::getenv("V2X_FALCON_FRAGMENT_BYTES")) {
        pqc_opts.falcon_fragment_size = std::strtoul(fragment_env, nullptr, 10);
    }

    if (const char *compression_env = std::getenv("V2X_FALCON_COMPRESSION")) {
        pqc_opts.compression = compression_env;
    } else {
        pqc_opts.compression = tree.get<std::string>("scenario.falcon.compression", pqc_opts.compression);
    }

    if(args.sim_mode == TRANSMITTER) {
        std::vector<Vehicle> vehicles;
        std::vector<std::thread> workers;

        // initialize vehicles - has to be in a separate loop to prevent vector issues
        for(int i = 0; i < num_vehicles; i++) {
            vehicles.emplace_back(Vehicle(i, pqc_opts));
        }

        // start a thread for each vehicle
        for(int i = 0; i < num_vehicles; i++) {
            workers.emplace_back(std::thread(vehicles.at(i).transmit_static, &vehicles.at(i), num_msgs, args.test));
        }

        // wait for each vehicle thread to finish
        for(int i = 0; i < num_vehicles; i++) {
            workers.at(i).join();
        }

    }
    else if (args.sim_mode == RECEIVER) {
        Vehicle v1(0, pqc_opts);
        v1.receive(num_msgs * num_vehicles, args.test, args.tkgui, args.webgui);
    }



}

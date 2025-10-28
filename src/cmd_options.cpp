#include "cmd_options.h"

#include <boost/program_options.hpp>

#include <iostream>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
        ("help", "Usage:")
        ("command", po::value<std::string>()->required(), "command to execute [encrypt, decrypt, checksum]")
        ("input", po::value<std::string>(&inputFile_)->required(), "input file")
        ("output", po::value<std::string>(&outputFile_)->default_value("output.txt"), "output file")
        ("password", po::value<std::string>(&password_)->default_value(""), "password for encryption and decryption");;
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.count("help")) {
        std::cout << desc_;
        return;
    }

    po::notify(vm);

    auto command = vm["command"].as<std::string>();
    std::transform(command.begin(), command.end(), command.begin(), [](unsigned char c) { return std::tolower(c); });

    command_ = commandMapping_.at(command);
}

}  // namespace CryptoGuard

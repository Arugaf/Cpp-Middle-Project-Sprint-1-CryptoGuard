#include "cmd_options.h"

#include <boost/program_options.hpp>

#include <filesystem>
#include <iostream>

namespace CryptoGuard {

namespace po = boost::program_options;

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
        ("help", "Usage:")
        ("command", po::value<std::string>()->required()->notifier([this](const std::string& command) {
            ParseCommand(command);
        }), "command to execute [encrypt, decrypt, checksum]")
        ("input", po::value<std::string>(&inputFile_)->required()->notifier([this](const std::string& filename) {
            ParseInputFile(filename);
        }), "input file")
        ("output", po::value<std::string>(&outputFile_)->default_value("output.txt")->notifier([this](const std::string& filename) {
            ParseOutputFile(filename);
        }), "output file")
        ("password", po::value<std::string>(&password_)->default_value(""), "password for encryption and decryption");;
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, const char *const argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);

    if (vm.count("help")) {
        std::cout << desc_;
        return;
    }

    po::notify(vm);
}

void ProgramOptions::ParseCommand(const std::string &command) {
    try {
        command_ = commandMapping_.at(command);
    } catch (std::exception &e) {
        throw std::runtime_error(std::format("Command not found: {}", command));
    }

    if (command_ == COMMAND_TYPE::CHECKSUM) {
        if (!outputFile_.empty()) {
            throw std::runtime_error("Unnecessary parameter for checksum: output-file");
        }

        if (!password_.empty()) {
            throw std::runtime_error("Unnecessary parameter for checksum: password");
        }
    }
}

void ProgramOptions::ParseInputFile(const std::string &filename) {
    if (!std::filesystem::exists(inputFile_)) {
        throw std::runtime_error{std::format("Input file: {} doesn't exists", inputFile_)};
    }
}

void ProgramOptions::ParseOutputFile(const std::string &filename) {
    if (!outputFile_.empty() && outputFile_ == inputFile_) {
        throw std::runtime_error(std::format("Input and output files have the same name: {}", inputFile_));
    }
}

}  // namespace CryptoGuard

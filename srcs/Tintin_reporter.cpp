#include "Tintin_reporter.hpp"
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sys/stat.h>
#include <sys/types.h>

Tintin_reporter::Tintin_reporter() {}
Tintin_reporter::~Tintin_reporter() {}
Tintin_reporter::Tintin_reporter(const Tintin_reporter &tintin_reporter)
{
    *this = tintin_reporter; 
}
Tintin_reporter &Tintin_reporter::operator=(const Tintin_reporter &tintin_reporter)
{
    (void)tintin_reporter;
    return *this;
}

int Tintin_reporter::log_message(const char* message)
{
    const char* log_dir = "/var/log/matt-daemon";
    struct stat info;

    // Check if the directory exists
    if (stat(log_dir, &info) != 0 || !(info.st_mode & S_IFDIR)) {
        // Directory does not exist, create it
        if (mkdir(log_dir, 0755) != 0) {
            std::cerr << "Failed to create log directory." << std::endl;
            return -1;
        }
    }

    std::ofstream log_file("/var/log/matt-daemon/matt_daemon.log", std::ios::app);
    if (!log_file.is_open()) {
        std::cerr << "Failed to open log file." << std::endl;
        return -1;
    }
    
    std::time_t now = std::time(nullptr);
    std::tm* local_time = std::localtime(&now);
    log_file << "[" << std::put_time(local_time, "%d/%m/%Y-%H:%M:%S") << "] [ INFO ] - " << message << std::endl;
    log_file.close();
    return 0;
}
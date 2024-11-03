#include "Tintin_reporter.hpp"
#include <iostream>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <sys/stat.h>
#include <sys/types.h>

int Tintin_reporter::log_message(const char* message, log_type type)
{
    const char* log_dir = "/var/log/matt-daemon";
    struct stat info;
    std::string log_type_str;

    if (stat(log_dir, &info) != 0 || !(info.st_mode & S_IFDIR))
    {
        if (mkdir(log_dir, 0755) != 0)
        {
            std::cerr << "Failed to create log directory." << std::endl;
            return -1;
        }
    }

    std::ofstream log_file("/var/log/matt-daemon/matt_daemon.log", std::ios::app);
    if (!log_file.is_open())
    {
        std::cerr << "Failed to open log file." << std::endl;
        return -1;
    }

    switch (type)
    {
        case LOG_INFO:
            log_type_str = "INFO";
            break;
        case LOG_WARNING:
            log_type_str = "WARNING";
            break;
        case LOG_ERROR:
            log_type_str = "ERROR";
            break;
        case LOG_USER:
            log_type_str = "LOG";
            break;
        default:
            log_type_str = "UNKNOWN";
            break;
    }
    
    std::time_t now = std::time(nullptr);
    std::tm* local_time = std::localtime(&now);
    log_file << "[" << std::put_time(local_time, "%d/%m/%Y-%H:%M:%S") << "] [ " \
    << log_type_str << " ] - " << message << std::endl;
    log_file.close();
    return 0;
}
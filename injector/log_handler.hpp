/*
    log handler ripped from other project
*/

#pragma once
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <string>

namespace Log {

    // sigma color codes
    namespace Color {
        inline constexpr auto RESET  = "\033[0m";
        inline constexpr auto RED    = "\033[31m";
        inline constexpr auto GREEN  = "\033[32m";
        inline constexpr auto BLUE   = "\033[34m";
        inline constexpr auto CYAN   = "\033[36m";
        inline constexpr auto YELLOW = "\033[33m";
        inline constexpr auto WHITE  = "\033[37m";
        inline constexpr auto GRAY   = "\033[90m";
    }

    inline std::string timestamp() {
        using namespace std::chrono;
        const auto now = system_clock::now();
        const std::time_t t = system_clock::to_time_t(now);
        std::tm local{};
        localtime_s(&local, &t);

        std::ostringstream oss;
        oss << std::put_time(&local, "%m-%d-%Y %H:%M:%S");
        return oss.str();
    }

    inline std::string filename(const char* path) {
        std::string str(path);
        const auto pos = str.find_last_of("/\\");
        return (pos == std::string::npos) ? str : str.substr(pos + 1);
    }

    inline void log(const std::string& level, const std::string& color, const std::string& message,
                    const char* file, const int line) {
        std::cout
            << Color::GREEN << "[" << timestamp() << "] " << Color::RESET
            << Color::GRAY << "[" << filename(file) << ":" << line << "] " << Color::RESET
            << color << "[" << level << "]" << Color::RESET
            << " : " << message << "\n";
    }

    // for the [] shi
    template<typename... Args>
    inline std::string to_string_stream(Args&&... args) {
        std::ostringstream oss;
        (oss << ... << args);
        return oss.str();
    }

    // macros so its easier
    #define LOG_INFO(msg)    Log::log("info",    Log::Color::CYAN,   Log::to_string_stream("[*] ", msg), __FILE__, __LINE__)
    #define LOG_SUCCESS(msg) Log::log("success", Log::Color::GREEN,  Log::to_string_stream("[+] ", msg), __FILE__, __LINE__)
    #define LOG_ERROR(msg)   Log::log("error",   Log::Color::RED,    Log::to_string_stream("[!] ", msg), __FILE__, __LINE__)

    #define LOG_BUILD(msg)    Log::log("build",    Log::Color::YELLOW,   Log::to_string_stream("[~] ", msg), __FILE__, __LINE__)
}
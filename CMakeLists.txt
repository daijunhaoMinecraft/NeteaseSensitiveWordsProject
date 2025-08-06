cmake_minimum_required(VERSION 3.31)
project(Netease_sensitive_word)

set(CMAKE_CXX_STANDARD 20)

add_executable(Netease_sensitive_word
        server.cpp
)

find_package(httplib CONFIG REQUIRED)
target_link_libraries(Netease_sensitive_word PRIVATE httplib::httplib)

find_package(re2 CONFIG REQUIRED)
target_link_libraries(Netease_sensitive_word PRIVATE re2::re2)

find_package(nlohmann_json CONFIG REQUIRED)
target_link_libraries(Netease_sensitive_word PRIVATE nlohmann_json::nlohmann_json)

find_package(OpenSSL REQUIRED)
target_link_libraries(Netease_sensitive_word PRIVATE OpenSSL::SSL)

find_package(pcre2 CONFIG REQUIRED)
target_link_libraries(Netease_sensitive_word PRIVATE PCRE2::8BIT PCRE2::16BIT PCRE2::32BIT PCRE2::POSIX)

target_link_libraries(Netease_sensitive_word PRIVATE Threads::Threads)
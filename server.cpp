// test
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <fstream>
#define PCRE2_CODE_UNIT_WIDTH 8
#include "pcre2.h"
#include <vector>
#include <algorithm>

#include <thread>
#include <chrono>
#include <atomic>

struct Pcre2Regex {
    std::string RegexID;
    std::string Regex;
    pcre2_code_8* compiled_regex;
};
struct RegexTypeStruct {
    std::string RegexType;
    std::vector<Pcre2Regex> RegexList;
};
struct SensitiveWordFilter {
    std::vector<RegexTypeStruct> RegexList;
};
class SensitiveWordConstResult{
public:
    static const int PassCode = 200;
    static const int InterceptCode = 201;
    static const int ShieldCode = 202;
    static const int ReplaceCode = 206;
    static const std::string Pass;
    static const std::string Intercept;
    static const std::string Shield;
    static const std::string Replace;
    static const std::string Nickname;
};
const std::string SensitiveWordConstResult::Pass = "pass";
const std::string SensitiveWordConstResult::Intercept = "intercept";
const std::string SensitiveWordConstResult::Shield = "shield";
const std::string SensitiveWordConstResult::Replace = "replace";
const std::string SensitiveWordConstResult::Nickname = "nickname";

// {"code":200,"message":"pass","regularId":"-1"}
struct ReviewWordsRegularId {
    std::vector<std::string> Shield;
    std::vector<std::string> Intercept;
    std::vector<std::string> Replace;
};

struct ReviewWordsResult
{
    int code;
    std::string message;
    ReviewWordsRegularId regularIdList;
    // extra 转换后的内容
    std::string ReplaceContent;
    // extra 原先内容
    std::string OriginalContent;
};

struct ReviewNickNameResult
{
    int code;
    std::string message;
    std::vector<std::string> NickNameRegularId;
    std::string OriginalNickName;
    std::string ReplaceNickName;
};

const std::string BASE64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
std::string base64_encode(const std::string& input) {
    std::string encoded;
    int val = 0, valb = -6;

    for (unsigned char c : input) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            encoded.push_back(BASE64_CHARS[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }

    if (valb > -6) {
        encoded.push_back(BASE64_CHARS[((val << 8) >> (valb + 8)) & 0x3F]);
    }

    while (encoded.size() % 4) {
        encoded.push_back('=');
    }

    return encoded;
}

std::string base64_decode(const std::string& input) {
    std::string decoded;
    int val = 0, valb = -8;

    for (unsigned char c : input) {
        if (c == '=') break;

        // ?????????BASE64_CHARS?е?????
        size_t pos = BASE64_CHARS.find(c);
        if (pos == std::string::npos) continue; // ??????Ч???

        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return decoded;
}

std::vector<uint8_t> base64_decode_to_bytes(const std::string& input) {
    std::vector<uint8_t> decoded;
    int val = 0, valb = -8;

    for (unsigned char c : input) {
        if (c == '=') break;

        // ?????????BASE64_CHARS?е?????
        size_t pos = BASE64_CHARS.find(c);
        if (pos == std::string::npos) continue; // ??????Ч???

        val = (val << 6) + pos;
        valb += 6;
        if (valb >= 0) {
            decoded.push_back(static_cast<uint8_t>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }

    return decoded;
}

// RC4?????????????????
class RC4 {
private:
    unsigned char s[256];

public:
    // ?????S??
    void init(const std::vector<uint8_t>& key) {
        int key_len = key.size();
        unsigned char k[256];

        // ?????S??
        for (int i = 0; i < 256; i++) {
            s[i] = i;
            k[i] = key[i % key_len];
        }

        // ???????
        int j = 0;
        for (int i = 0; i < 256; i++) {
            j = (j + s[i] + k[i]) % 256;
            std::swap(s[i], s[j]);
        }
    }

    // ????????????????
    void init(const std::string& key) {
        std::vector<uint8_t> key_bytes(key.begin(), key.end());
        init(key_bytes);
    }

    // ??????????????????????
    std::vector<uint8_t> crypt(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> result;
        result.reserve(data.size());
        int i = 0, j = 0;

        for (size_t n = 0; n < data.size(); n++) {
            i = (i + 1) % 256;
            j = (j + s[i]) % 256;
            std::swap(s[i], s[j]);
            int t = (s[i] + s[j]) % 256;
            result.push_back(data[n] ^ s[t]);
        }

        return result;
    }

    // ????????????????????????
    std::string crypt(const std::string& data) {
        std::vector<uint8_t> data_bytes(data.begin(), data.end());
        std::vector<uint8_t> result_bytes = crypt(data_bytes);
        return std::string(result_bytes.begin(), result_bytes.end());
    }
};

// RC4?????????????????
std::vector<uint8_t> rc4_decrypt_bytes(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    RC4 rc4;
    rc4.init(key);
    return rc4.crypt(data);
}

// RC4????????????????????
std::string rc4_decrypt_bytes_to_string(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    std::vector<uint8_t> decrypted = rc4_decrypt_bytes(data, key);
    return std::string(decrypted.begin(), decrypted.end());
}

// RC4???????????????????????
std::string rc4_decrypt(const std::string& data, const std::string& key) {
    RC4 rc4;
    rc4.init(key);
    return rc4.crypt(data);
}

// RC4????????????????????
std::vector<uint8_t> rc4_encrypt_bytes(const std::vector<uint8_t>& data, const std::vector<uint8_t>& key) {
    RC4 rc4;
    rc4.init(key);
    return rc4.crypt(data);
}

// RC4???????????????汾??
std::string rc4_encrypt(const std::string& data, const std::string& key) {
    RC4 rc4;
    rc4.init(key);
    return rc4.crypt(data);
}

// ????????????????????????????
std::vector<uint8_t> string_to_bytes(const std::string& str) {
    return std::vector<uint8_t>(str.begin(), str.end());
}

// ????????????????????????????
std::string bytes_to_string(const std::vector<uint8_t>& bytes) {
    return std::string(bytes.begin(), bytes.end());
}


// ?????????д?????
std::string GetSensitiveWordConfigOnline(const std::string& gameid) {
    // {"info":{"deviceid":"6A4B-A3A3-D87C-11C5-6477","gameid":"g79","network":"wifi","sys":"cpp","version":"1.0.9"}}
    std::string request_data = "{\"info\":{\"deviceid\":\"6A4B-A3A3-D87C-11C5-6477\",\"gameid\":\"" + gameid + "\",\"network\":\"wifi\",\"sys\":\"cpp\",\"version\":\"1.0.9\"}}";
    // ?base64
    std::string base64_request_data = base64_encode(request_data);

    // ????URL?HTTP
    httplib::Client cli("http://optsdk.gameyw.netease.com");
    httplib::Headers headers = {
        {"Content-Type", "application/x-www-form-urlencoded"}
    };

    auto response1 = cli.Post("/initbox_" + gameid + ".html", headers, base64_request_data, "text/plain");

    if (!response1 || response1->status != 200) {
        std::cerr << "Failed to get URL: " << (response1 ? std::to_string(response1->status) : "null response") << std::endl;
        return "";
    }

    nlohmann::json GetJsonResponse;
    try {
        GetJsonResponse = nlohmann::json::parse(response1->body);
    } catch (const std::exception& e) {
        std::cerr << "Failed to parse JSON response: " << e.what() << std::endl;
        return "";
    }

    // ?URL
    std::string GetUrl = GetJsonResponse["url"];
    //std::cout << "Get URL: " << GetUrl << std::endl;

    // ??URL?д??HTTPS
    // URL??
    size_t protocol_end = GetUrl.find("://");
    if (protocol_end == std::string::npos) {
        std::cerr << "Invalid URL format" << std::endl;
        return "";
    }

    std::string protocol = GetUrl.substr(0, protocol_end);
    size_t path_start = GetUrl.find('/', protocol_end + 3);

    if (path_start == std::string::npos) {
        path_start = GetUrl.length();
    }

    std::string host = GetUrl.substr(protocol_end + 3, path_start - protocol_end - 3);
    std::string path = (path_start < GetUrl.length()) ? GetUrl.substr(path_start) : "/";

    //std::cout << "Host: " << host << ", Path: " << path << std::endl;

    // ?SSLClientHTTPS
    httplib::SSLClient ssl_cli(host.c_str());
    // ???SSL/TLS
    ssl_cli.enable_server_certificate_verification(false);

    auto response2 = ssl_cli.Get(path.c_str());

    if (!response2 || response2->status != 200) {
        std::cerr << "Failed to get sensitive word config: " << (response2 ? std::to_string(response2->status) : "null response") << std::endl;
        return "";
    }

    // ?RC4???
    std::vector<uint8_t> encrypted_data = base64_decode_to_bytes(response2->body);

    std::string key;
    if (gameid == "g79") {
        key = "c42bf7f39d476db3";
    }
    else {
        key = "c42bf7f39d479999";
    }

    // ?
    std::string decrypted_data = rc4_decrypt_bytes_to_string(encrypted_data, string_to_bytes(key));

    // ?????
    return decrypted_data;
}

// ??
SensitiveWordFilter sensitive_word_filter_g79;
SensitiveWordFilter sensitive_word_filter_x19;

// 修改init_sensitive_word函数，添加gameid参数和对应的敏感词过滤器
void init_sensitive_word(SensitiveWordFilter& filter, const std::string& gameid){
    // ?
    filter.RegexList.clear();
    // ??
    std::string GetConfigFile = GetSensitiveWordConfigOnline(gameid);
    if (GetConfigFile.empty()) {
        std::cerr << "Failed to get sensitive word config for game: " << gameid << std::endl;
        return;
    }
    // ?json
    nlohmann::json json_content = nlohmann::json::parse(GetConfigFile);
    // json
    for (auto& item : json_content["regex"].items()) {
        // ?key
        std::string key = item.key(); // intercept/shield/replace/nickname/remind
        RegexTypeStruct regex_type;
        regex_type.RegexType = key;
        regex_type.RegexList.clear();
        for (auto& Pcre2Regex : json_content["regex"][key].items()) {
            std::string RegexID = Pcre2Regex.key();
            std::string Regex = Pcre2Regex.value();
            // PCRE2?
            // PCRE2?
            int errornumber;
            PCRE2_SIZE erroroffset;
            uint32_t compile_options = PCRE2_UTF | PCRE2_UCP;
            pcre2_code_8* compiled_regex = pcre2_compile_8(
                    (PCRE2_SPTR8)Regex.c_str(),
                    PCRE2_ZERO_TERMINATED,
                    compile_options,
                    &errornumber,
                    &erroroffset,
                    NULL
            );
            if (compiled_regex == nullptr) {
                PCRE2_UCHAR buffer[256];
                pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
                std::cerr << "PCRE2 compilation failed at offset " << erroroffset << ": " << buffer << std::endl;
                std::cerr << "Regex ID: " << RegexID << std::endl;// << ", Pattern: " << Regex << std::endl;
                continue; // ??
            }
            regex_type.RegexList.push_back({RegexID, Regex, compiled_regex});
        }
        filter.RegexList.push_back(regex_type);
    }
    std::cout << "init_sensitive_word OK for game: " << gameid << std::endl;
}

std::string ReplaceNickName(std::string text, SensitiveWordFilter& filter) {
    std::string replaced_text = text;
    bool IsPass = true;
    for (auto &regex_type: filter.RegexList) {
        // ??
        std::string RegexType = regex_type.RegexType;
        if (RegexType == SensitiveWordConstResult::Nickname) {
            for (auto &regex: regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8 *compiled_regex = regex.compiled_regex;
                pcre2_match_data_8 *match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR) text.c_str(), (PCRE2_SIZE) text.size(), 0, 0,
                                       match_data, nullptr);
                if (rc > 0) {
                    // д?滻д?length*"*"
                    // ????
                    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_8(match_data);
                    PCRE2_SIZE start = ovector[0];
                    PCRE2_SIZE end = ovector[1];
                    PCRE2_SIZE length = end - start;

                    // 滻?
                    std::string replace_str(length, '*');

                    // 滻д
                    replaced_text = text;
                    replaced_text.replace(start, length, replace_str);
                    IsPass = false;
                }
            }
        }
    }
    if (IsPass) {
        return replaced_text;
    }
    else {
        return ReplaceNickName(replaced_text, filter);
    }
}

ReviewNickNameResult reviewNickName(const std::string& text, SensitiveWordFilter& filter)
{
    ReviewNickNameResult result;
    bool is_pass = true;
    // ?List
    //
    // shield
    for (auto& regex_type : filter.RegexList) {
        // ??
        std::string RegexType = regex_type.RegexType;
        if (RegexType == SensitiveWordConstResult::Nickname) {
            for (auto &regex: regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8 *compiled_regex = regex.compiled_regex;
                pcre2_match_data_8 *match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR) text.c_str(), (PCRE2_SIZE) text.size(), 0, 0,
                                       match_data, nullptr);
                if (rc > 0) {
                    // д: shield
                    is_pass = false;
                    result.NickNameRegularId.push_back(RegexID);
                }
            }
        }
    }
    if (!is_pass) {
        result.code = 1;
        result.message = "not pass";
        result.OriginalNickName = text;
        result.ReplaceNickName = ReplaceNickName(text, filter);
    }
    else {
        result.code = 0;
        result.message = "pass";
        result.OriginalNickName = text;
        result.ReplaceNickName = text;
    }
    return result;
}

std::string ReplaceWords(std::string text, SensitiveWordFilter& filter) {
    std::string replaced_text = text;
    bool IsPass = true;
    for (auto &regex_type: filter.RegexList) {
        // ??
        std::string RegexType = regex_type.RegexType;
        if (RegexType == SensitiveWordConstResult::Shield) {
            for (auto &regex: regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8 *compiled_regex = regex.compiled_regex;
                pcre2_match_data_8 *match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR) text.c_str(), (PCRE2_SIZE) text.size(), 0, 0,
                                     match_data, nullptr);
                if (rc > 0) {
                    // д?滻д?length*"*"
                    // ????
                    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_8(match_data);
                    PCRE2_SIZE start = ovector[0];
                    PCRE2_SIZE end = ovector[1];
                    PCRE2_SIZE length = end - start;

                    // 滻?
                    std::string replace_str(length, '*');

                    // 滻д
                    replaced_text = text;
                    replaced_text.replace(start, length, replace_str);
                    IsPass = false;
                }
            }
        }
        else if (RegexType == SensitiveWordConstResult::Intercept) {
            for (auto &regex: regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8 *compiled_regex = regex.compiled_regex;
                pcre2_match_data_8 *match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR) text.c_str(), (PCRE2_SIZE) text.size(), 0, 0,
                                     match_data, nullptr);
                if (rc > 0) {
                    // д?滻д?length*"*"
                    // ????
                    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_8(match_data);
                    PCRE2_SIZE start = ovector[0];
                    PCRE2_SIZE end = ovector[1];
                    PCRE2_SIZE length = end - start;

                    // 滻?
                    std::string replace_str(length, '*');

                    // 滻д
                    replaced_text = text;
                    replaced_text.replace(start, length, replace_str);
                    IsPass = false;
                }
            }
        }
        else if (RegexType == SensitiveWordConstResult::Replace)
        {
            for (auto &regex: regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8 *compiled_regex = regex.compiled_regex;
                pcre2_match_data_8 *match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR) text.c_str(), (PCRE2_SIZE) text.size(), 0, 0,
                                     match_data, nullptr);
                if (rc > 0) {
                    // д?滻д?length*"*"
                    // ????
                    PCRE2_SIZE *ovector = pcre2_get_ovector_pointer_8(match_data);
                    PCRE2_SIZE start = ovector[0];
                    PCRE2_SIZE end = ovector[1];
                    PCRE2_SIZE length = end - start;

                    // 滻?
                    std::string replace_str(length, '*');

                    // 滻д
                    replaced_text = text;
                    replaced_text.replace(start, length, replace_str);
                    IsPass = false;
                }
            }
        }
    }
    if (IsPass) {
        return replaced_text;
    }
    else {
        return ReplaceWords(replaced_text, filter);
    }
}

ReviewWordsResult reviewWords(const std::string& text,std::string original_text, SensitiveWordFilter& filter)
{
    ReviewWordsResult result;
    bool is_pass = true;
    // ?List
    ReviewWordsRegularId RegularId;
    //
    // shield
    for (auto& regex_type : filter.RegexList) {
        // ??
        std::string RegexType = regex_type.RegexType;
        if (RegexType == SensitiveWordConstResult::Shield) {
            for (auto& regex : regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8* compiled_regex = regex.compiled_regex;
                pcre2_match_data_8* match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR)text.c_str(), (PCRE2_SIZE)text.size(), 0, 0, match_data, nullptr);
                if (rc > 0) {
                    // д: shield
                    is_pass = false;
                    RegularId.Intercept.push_back(RegexID);
                }
            }
        }
        else if (RegexType == SensitiveWordConstResult::Intercept)
        {
            for (auto& regex : regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8* compiled_regex = regex.compiled_regex;
                pcre2_match_data_8* match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR)text.c_str(), (PCRE2_SIZE)text.size(), 0, 0, match_data, nullptr);
                if (rc > 0) {
                    // д
                    is_pass = false;
                    RegularId.Intercept.push_back(RegexID);
                }
            }
        }
        else if (RegexType == SensitiveWordConstResult::Replace) {
            for (auto& regex : regex_type.RegexList) {
                // ??
                std::string RegexID = regex.RegexID;
                std::string Regex = regex.Regex;
                pcre2_code_8* compiled_regex = regex.compiled_regex;
                pcre2_match_data_8* match_data = pcre2_match_data_create_from_pattern_8(compiled_regex, nullptr);
                // ??
                int rc = pcre2_match_8(compiled_regex, (PCRE2_SPTR)text.c_str(), (PCRE2_SIZE)text.size(), 0, 0, match_data, nullptr);
                if (rc > 0) {
                    // д
                    is_pass = false;
                    RegularId.Replace.push_back(RegexID);
                }
            }
        }
    }
    if (!is_pass) {
        result.code = 1;
        result.message = "not pass";
        result.regularIdList = RegularId;
        result.OriginalContent = text;
        result.ReplaceContent = ReplaceWords(text, filter);
    }
    else {
        result.code = 0;
        result.message = "pass";
        result.regularIdList = RegularId;
        result.OriginalContent = text;
        result.ReplaceContent = text;
    }
    return result;
}

ReviewWordsResult reviewWords_Request(const std::string& content, const std::string& level = "0", const std::string& channel = "item_comment", SensitiveWordFilter& filter = sensitive_word_filter_g79)
{
    // ??
    std::string text = "level=" + level + "_channel=" + channel + "_content=" + content;
    ReviewWordsResult RequestResult = reviewWords(text,content, filter);
    if (RequestResult.code == 0) {
        RequestResult.OriginalContent = content;
        RequestResult.ReplaceContent = content;
    }
    else {
        RequestResult.OriginalContent = content;
        if (RequestResult.ReplaceContent.find("level=" + level + "_channel=" + channel + "_content=") == std::string::npos) {
            // ??"*"???β
            size_t pos = RequestResult.ReplaceContent.find("*");
            if (pos != std::string::npos) {
                RequestResult.ReplaceContent = RequestResult.ReplaceContent.substr(pos);
            } else {
                // ??"*"???
                RequestResult.ReplaceContent = std::string(content.length(), '*');
            }
        }
        else {
            std::string prefix = "_content=";
            size_t pos = RequestResult.ReplaceContent.find(prefix);
            if (pos != std::string::npos) {
                // ?_content=?
                RequestResult.ReplaceContent = RequestResult.ReplaceContent.substr(pos + prefix.length());
            }
        }
    }
    return RequestResult;
}

std::atomic<bool> should_refresh_sensitive_words(true);
// ?????????д???????
void schedule_sensitive_word_refresh() {
    std::thread([]() {
        while (true) {
            // ???1С????????????????????д??
            std::this_thread::sleep_for(std::chrono::hours(1));

            if (should_refresh_sensitive_words.load()) {
                std::cout << "Refresh Sensitive words" << std::endl;

                try {
                    // ???????????д??
                    init_sensitive_word(sensitive_word_filter_g79, "g79");
                    init_sensitive_word(sensitive_word_filter_x19, "x19");

                    std::cout << "Refresh Done!" << std::endl;
                } catch (const std::exception& e) {
                    std::cerr << "Refresh Error: " << e.what() << std::endl;
                }
            }
        }
    }).detach();
}


int main(int argc, char** argv) {
    // init sensitive_word
    init_sensitive_word(sensitive_word_filter_g79, "g79");
    init_sensitive_word(sensitive_word_filter_x19, "x19");
    // ??
    schedule_sensitive_word_refresh();
    httplib::Server svr;

    // ·???
    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        res.set_content("Hello World!", "text/plain");
    });

    // g79敏感词检测路由
    svr.Post("/g79/review/words", [](const httplib::Request& req, httplib::Response& res) {
        try {
            // POST
            // ?
            std::string content = req.body;
            // ?json
            nlohmann::json json_content = nlohmann::json::parse(content);
            // ?
            std::string level = json_content["level"];
            std::string channel = json_content["channel"];
            std::string word = json_content["word"];

            // 麯
            ReviewWordsResult result = reviewWords_Request(word, level, channel, sensitive_word_filter_g79);
            //std::cout << "content: " << content << " Result:" << result.code <<std::endl;

            // ?JSON
            nlohmann::json response_json;
            response_json["code"] = result.code;
            response_json["message"] = result.message;

            // лregularIdList
            nlohmann::json regular_id_list_json;
            regular_id_list_json["Shield"] = nlohmann::json::array();
            regular_id_list_json["Intercept"] = nlohmann::json::array();
            regular_id_list_json["Replace"] = nlohmann::json::array();

            for (const auto& id : result.regularIdList.Shield) {
                regular_id_list_json["Shield"].push_back(id);
            }

            for (const auto& id : result.regularIdList.Intercept) {
                regular_id_list_json["Intercept"].push_back(id);
            }

            for (const auto& id : result.regularIdList.Replace) {
                regular_id_list_json["Replace"].push_back(id);
            }

            response_json["regularIdList"] = regular_id_list_json;
            response_json["ReplaceContent"] = result.ReplaceContent;
            response_json["OriginalContent"] = result.OriginalContent;

            // ?
            std::string response_str = response_json.dump();
            //std::cout << "Response JSON: " << response_str << std::endl;
            res.set_content(response_str, "application/json");
        } catch (const std::exception& e) {
            //
            std::cerr << "Error processing request: " << e.what() << std::endl;
            nlohmann::json error_json;
            error_json["code"] = 500;
            error_json["message"] = "Internal server error";
            res.set_content(error_json.dump(), "application/json");
            res.status = 500;
        }
    });

    svr.Post("/g79/review/nickname", [](const httplib::Request& req, httplib::Response& res) {
        try {
            // POST
            // ?
            std::string content = req.body;
            // ?json
            nlohmann::json json_content = nlohmann::json::parse(content);
            // ?
            std::string NickName = json_content["nickname"];

            // 麯
            ReviewNickNameResult result = reviewNickName(NickName, sensitive_word_filter_g79);
            //std::cout << "content: " << content << " Result:" << result.code <<std::endl;

            // ?JSON
            nlohmann::json response_json;
            response_json["code"] = result.code;
            response_json["message"] = result.message;
            response_json["NickNameRegularId"] = result.NickNameRegularId;
            response_json["OriginalNickName"] = result.OriginalNickName;
            response_json["ReplaceNickName"] = result.ReplaceNickName;

            // ?
            std::string response_str = response_json.dump();
            //std::cout << "Response JSON: " << response_str << std::endl;
            res.set_content(response_str, "application/json");
        } catch (const std::exception& e) {
            //
            std::cerr << "Error processing request: " << e.what() << std::endl;
            nlohmann::json error_json;
            error_json["code"] = 500;
            error_json["message"] = "Internal server error";
            res.set_content(error_json.dump(), "application/json");
            res.status = 500;
        }
    });

    // x19敏感词检测路由
    svr.Post("/x19/review/words", [](const httplib::Request& req, httplib::Response& res) {
        try {
            // POST
            // ?
            std::string content = req.body;
            // ?json
            nlohmann::json json_content = nlohmann::json::parse(content);
            // ?
            std::string level = json_content["level"];
            std::string channel = json_content["channel"];
            std::string word = json_content["word"];

            // 麯
            ReviewWordsResult result = reviewWords_Request(word, level, channel, sensitive_word_filter_x19);
            //std::cout << "content: " << content << " Result:" << result.code <<std::endl;

            // ?JSON
            nlohmann::json response_json;
            response_json["code"] = result.code;
            response_json["message"] = result.message;

            // лregularIdList
            nlohmann::json regular_id_list_json;
            regular_id_list_json["Shield"] = nlohmann::json::array();
            regular_id_list_json["Intercept"] = nlohmann::json::array();
            regular_id_list_json["Replace"] = nlohmann::json::array();

            for (const auto& id : result.regularIdList.Shield) {
                regular_id_list_json["Shield"].push_back(id);
            }

            for (const auto& id : result.regularIdList.Intercept) {
                regular_id_list_json["Intercept"].push_back(id);
            }

            for (const auto& id : result.regularIdList.Replace) {
                regular_id_list_json["Replace"].push_back(id);
            }

            response_json["regularIdList"] = regular_id_list_json;
            response_json["ReplaceContent"] = result.ReplaceContent;
            response_json["OriginalContent"] = result.OriginalContent;

            // ?
            std::string response_str = response_json.dump();
            //std::cout << "Response JSON: " << response_str << std::endl;
            res.set_content(response_str, "application/json");
        } catch (const std::exception& e) {
            //
            std::cerr << "Error processing request: " << e.what() << std::endl;
            nlohmann::json error_json;
            error_json["code"] = 500;
            error_json["message"] = "Internal server error";
            res.set_content(error_json.dump(), "application/json");
            res.status = 500;
        }
    });

    svr.Post("/x19/review/nickname", [](const httplib::Request& req, httplib::Response& res) {
        try {
            // POST
            // ?
            std::string content = req.body;
            // ?json
            nlohmann::json json_content = nlohmann::json::parse(content);
            // ?
            std::string NickName = json_content["nickname"];

            // 麯
            ReviewNickNameResult result = reviewNickName(NickName, sensitive_word_filter_x19);
            //std::cout << "content: " << content << " Result:" << result.code <<std::endl;

            // ?JSON
            nlohmann::json response_json;
            response_json["code"] = result.code;
            response_json["message"] = result.message;
            response_json["NickNameRegularId"] = result.NickNameRegularId;
            response_json["OriginalNickName"] = result.OriginalNickName;
            response_json["ReplaceNickName"] = result.ReplaceNickName;

            // ?
            std::string response_str = response_json.dump();
            //std::cout << "Response JSON: " << response_str << std::endl;
            res.set_content(response_str, "application/json");
        } catch (const std::exception& e) {
            // 
            std::cerr << "Error processing request: " << e.what() << std::endl;
            nlohmann::json error_json;
            error_json["code"] = 500;
            error_json["message"] = "Internal server error";
            res.set_content(error_json.dump(), "application/json");
            res.status = 500;
        }
    });
    
    // 
    svr.listen("0.0.0.0", 8080);
    return 0;
}

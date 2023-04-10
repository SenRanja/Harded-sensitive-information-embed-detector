#include <iostream>
#include <regex>
#include <vector>

int main() {
    std::vector<std::string> appTokens = {
        "ghp_123456789012345678901234567890123456",
        "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789ABCD",
        "ghp_987654321098765432109876543210987654",
        "ghp_EFGHIJKLMNOPQRSTUVWXYZ0123456789ABCDEF"
        "ghw_EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE"
        
    };

    s = "ghe_GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG";

    std::regex pattern("(ghu|ghs)_[0-9a-zA-Z]{36}");

    for (int i = 0; i < appTokens.size(); i++) {
        if (std::regex_match(appTokens[i], pattern)) {
            std::cout << "Matched App Token " << i << ": " << appTokens[i] << std::endl;
        } else {
            std::cout << "No match for App Token " << i << ": " << appTokens[i] << std::endl;
        }
    }

    return 0;
}

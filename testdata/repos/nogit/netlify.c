#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>

#define TOKEN_COUNT 4

int main() {
    char* accessTokens[TOKEN_COUNT] = {
        netlify1 = "fH9XJ1L7IeP6eI2Q2yW1C8KvF7X9C5N1mZmOMgHv";
        netlify-2 = "zU5WkK8q6qptNf4naypn4drWJc8RhvQGJy0fzr7E";
        netlify_3 = "y98jKvjP7Szbc3MY8zA63qyivxgub1tUL76HtMye";
        netlify_5 = "eeeeeeeeeeeeeeeeeeeeeeeeeeeasdsadsddddd";
        netlify_4 = "ewwwwwweeeeeeeeeeeeeeeeeeeasdsadsddddd";
    };

    char* pattern = "(?i)(?:netlify)(?:[0-9a-z\\-\\_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\\\"|\\s|=|\\x60){0,5}([a-z0-9=_\\-]{40,46})(?:['|\\\"|\\n|\\r|\\s|\\x60|;]|$)";

    regex_t regex;
    int reti;
    char msgbuf[100];

    for (int i = 0; i < TOKEN_COUNT; i++) {
        reti = regcomp(&regex, pattern, REG_EXTENDED);
        if (reti) {
            fprintf(stderr, "Could not compile regex\n");
            exit(1);
        }

        reti = regexec(&regex, accessTokens[i], 0, NULL, 0);
        if (!reti) {
            printf("Matched Access Token %d: %s\n", i, accessTokens[i]);
        } else if (reti == REG_NOMATCH) {
            printf("No match for Access Token %d: %s\n", i, accessTokens[i]);
        } else {
            regerror(reti, &regex, msgbuf, sizeof(msgbuf));
            fprintf(stderr, "Regex match failed: %s\n", msgbuf);
            exit(1);
        }

        regfree(&regex);
    }

    return 0;
}

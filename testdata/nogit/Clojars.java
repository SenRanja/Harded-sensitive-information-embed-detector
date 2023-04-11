import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class Main {
    public static void main(String[] args) {
        // A list of unrelated strings to be included in the code
        String unrelatedStrings = "elementarymydearwatson";
        String unrelatedStrings2 = "speakfriendandentermor";
        String unrelatedStrings3 = "avoicecryinginthewilde";

        // Two Clojars API Tokens that match the provided regex
        String clojars1 = "CLOJARS_123456789012345678901234567890123456789012345678901234567890";
        String clojars2 = "CLOJARS_ABCDEF0123GHIJKLMNOPQ234567890RSTUVWXYZ0123456789ABCDEFHIJKL";

        // The regex to match against
        Pattern pattern = Pattern.compile("(?i)(CLOJARS_)[a-z0-9]{60}");

        // Loop through the tokens and print out whether they match or not
        for (int i = 0; i < apiTokens.length; i++) {
            Matcher matcher = pattern.matcher(apiTokens[i]);
            if (matcher.matches()) {
                System.out.printf("Token %d matches the regex: %s%n", i, apiTokens[i]);
            } else {
                System.out.printf("Token %d does not match the regex: %s%n", i, apiTokens[i]);
            }
        }

        // Include some unrelated strings in the code
        String unrelated1 = "String 1: " + unrelatedStrings[0];
        String unrelated2 = "String 2: " + unrelatedStrings[1];

        // Include the first API token in the code
        String apiToken1 = "API Token 1: " + apiTokens[0];

        // Include some more unrelated strings
        String unrelated3 = "String 3: " + unrelatedStrings[2];

        // Include the second API token in the code
        String apiToken2 = "API Token 2: " + apiTokens[1];

        // Print out the strings that were included in the code
        System.out.println(unrelated1);
        System.out.println(unrelated2);
        System.out.println(apiToken1);
        System.out.println(unrelated3);
        System.out.println(apiToken2);
    }
}

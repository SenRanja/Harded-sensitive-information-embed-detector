public class Main {

    public static void main(String[] args) {
        // A list of unrelated strings to be included in the code
        String[] unrelatedStrings = {
                "This is a normal string.",
                "Some other string here.",
                "Hello, world!"
        };

        // Two New Relic user API Keys that match the provided regex
        String newrelic = "NRAK-abcdefghijklmn123456CDEFGHI";
        String new_relic = "NRAK-1234567890abdaxwjcdBCDEFGHI";

        // The regex to match against
        String pattern = "(?i)(?:new-relic|newrelic|new_relic)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\"|\\s|=|\\x60){0,5}(NRAK-[a-z0-9]{27})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)";

        // Loop through the keys and print out whether they match or not
        for (int i = 0; i < apiKeys.length; i++) {
            if (apiKeys[i].matches(pattern)) {
                System.out.printf("Key %d matches the regex: %s\n", i, apiKeys[i]);
            } else {
                System.out.printf("Key %d does not match the regex: %s\n", i, apiKeys[i]);
            }
        }

        // Include some unrelated strings in the code
        String unrelated1 = "String 1: " + unrelatedStrings[0];
        String unrelated2 = "String 2: " + unrelatedStrings[1];

        // Include the first API key in the code
        String apiKey1 = "String NRAK_API_KEY_1 = \"" + apiKeys[0] + "\";";

        // Include some more unrelated strings
        String unrelated3 = "String 3: " + unrelatedStrings[2];

        // Include the second API key in the code
        String apiKey2 = "String NRAK_API_KEY_2 = \"" + apiKeys[1] + "\";";

        // Print out the strings that were included in the code
        System.out.println(unrelated1);
        System.out.println(unrelated2);
        System.out.println(apiKey1);
        System.out.println(unrelated3);
        System.out.println(apiKey2);
    }
}

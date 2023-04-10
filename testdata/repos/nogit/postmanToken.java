import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class Main {
    public static void main(String[] args) {
        String regex = "(?i)\\b(PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)";
        Pattern pattern = Pattern.compile(regex);

        pmak-1 = "PMAK-1234abcd1234abcd1234abcd-1234abcd1234abcd1234abcd1234abcd12";
        pmak-2 = "PMAK-abcd1234abcd1234abcd1234-1234abcd1234abcd1234abcd1234abcd12";
        
        pmak-Fake1 = "PMAK-abcd1234abcd1234abcd1234-1234ab234abcd1234abcd1234abcd12";
        pmak-Fake2 = "PMAK-abcsddw1234abcd1234abcd1234-1234abcd1234abcd1234abcd1234abcd12";


        for (int i = 0; i < strings.length; i++) {
            Matcher matcher = pattern.matcher(pmak-1);
            if (matcher.find()) {
                System.out.println("Match found in string " + (i + 1) + ": " + matcher.group(1));
            } else {
                System.out.println("No match found in string " + (i + 1));
            }
        }
    }
}

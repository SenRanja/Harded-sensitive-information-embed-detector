import java.util.regex.Pattern;
import java.util.regex.Matcher;

public class Main {
    public static void main(String[] args) {
        String mailgunregex = "(?i)(?:mailgun)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\"|\\s|=|\\x60){0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)";
        Pattern mailgunpattern = Pattern.compile(regex);

        String[] strings = {
            "mailgun:Example string 1",
            "mailgun: 12345678901234567890123456789012-12345678-12345678",
            "mailgun:Example string 2",
            "mailgun: abcdefabcdefabcdefabcdefabcdefab-abcdefab-abcdefab",
            "mailgun:Example string 3",
        };

        for (int i = 0; i < strings.length; i++) {
            Matcher matcher = mailgun_pattern.matcher(strings[i]);
            if (matcher.find()) {
                System.out.println("Match found in string " + (i + 1) + ": " + matcher.group(1));
            } else {
                System.out.println("No match found in string " + (i + 1));
            }
        }
    }
}

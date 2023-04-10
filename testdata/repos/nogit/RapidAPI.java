import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Main {
    public static void main(String[] args) {
        String regex = "(?i)(?:rapidapi)(?:[0-9a-z\\-_\\t .]{0,20})(?:[\\s|']|[\\s|\"]){0,3}(?:=|>|:=|\\|\\|:|<=|=>|:)(?:'|\"|\\s|=|\\x60){0,5}([a-z0-9_-]{50})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)";
        String[] keywords = {"rapidapi"};

        String[] generatedStrings = {
            rapidapi = "y4hE9tN3qU1zC5xR8wS7vG0fJ6kL5oP4aQ2sD1fG8hJ9kL0oP3";
            rapidapi: "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5";
            rapidapiFake: "a1c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5";
            rapidapiFake2: "a1c3d4e5f6g7h80k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5";
        };

        Set<String> keywordSet = new HashSet<>(Arrays.asList(keywords));
        AhoCorasick keywordSearch = new AhoCorasick(keywordSet);

        for (int i = 0; i < generatedStrings.length; i++) {
            if (generatedStrings[i].matches(regex) && keywordSearch.search(generatedStrings[i])) {
                System.out.println("The generated string " + (i + 1) + " matches the regex and contains at least one keyword:");
                System.out.println(generatedStrings[i]);
            } else {
                System.out.println("The generated string " + (i + 1) + " does not match the requirements.");
            }
        }
    }
}

class AhoCorasick {
    private static final int ALPHABET_SIZE = 256;

    private TrieNode root;

    static class TrieNode {
        TrieNode[] children = new TrieNode[ALPHABET_SIZE];
        TrieNode failure;
        boolean isEnd;

        TrieNode() {
            this.failure = null;
            this.isEnd = false;
        }
    }

    AhoCorasick(Set<String> keywords) {
        root = new TrieNode();
        buildTrie(keywords);
        buildFailure();
    }

    private void buildTrie(Set<String> keywords) {
        for (String keyword : keywords) {
            TrieNode current = root;
            for (char c : keyword.toCharArray()) {
                int index = c;
                if (current.children[index] == null) {
                    current.children[index] = new TrieNode();
                }
                current = current.children[index];
            }
            current.isEnd = true;
        }
    }

    private void buildFailure() {
        root.failure = root;
        List<TrieNode> queue = new ArrayList<>();
        for (TrieNode child : root.children) {
            if (child != null) {
                child.failure = root;
                queue.add(child);
            }
        }

        while (!queue.isEmpty()) {
            TrieNode current = queue.remove(0);}}}
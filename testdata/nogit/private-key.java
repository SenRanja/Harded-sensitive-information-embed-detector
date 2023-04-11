import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Main {
    public static void main(String[] args) {
        String regex = "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY-----[\\s\\S-]*KEY----";
        String[] keywords = {"-----begin"};

        String generatedString = "-----BEGIN RSA PRIVATE KEY-----\n" +
                "MIICXAIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n" +
                "KEY----";

        Set<String> keywordSet = new HashSet<>(Arrays.asList(keywords));
        AhoCorasick keywordSearch = new AhoCorasick(keywordSet);

        if (generatedString.matches(regex) && keywordSearch.search(generatedString)) {
            System.out.println("The generated string matches the regex and contains at least one keyword:");
            System.out.println(generatedString);
        } else {
            System.out.println("The generated string does not match the requirements.");
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
            TrieNode current = queue.remove(0);
            for (int i = 0; i < ALPHABET_SIZE; i++) {
                TrieNode child = current.children[i];
                if (child != null) {
                    TrieNode failure = current.failure;
                    while (failure.children[i] == null && failure != root) {
                        failure = failure.failure;
                    }
                    child.failure = (failure.children[i] != null) ? failure.children[i] : root;
                    queue.add(child);
                }
            }
        }
    }
}
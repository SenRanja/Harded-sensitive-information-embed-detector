import java.util.List;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

public class Main {
    public static void main(String[] args) {
        String regex = "(?i)\\b(pul-[a-f0-9]{40})(?:['|\"|\\n|\\r|\\s|\\x60|;]|$)";
        String[] keywords = {"pul-"};

        String[] generatedStrings = {
            "pul-1234abcd1234ab34abcd1234abcd1234abcd1234",
            "pul-abcd1234abcd12cd1234abcd1234abcd1234abcd",
            "pul-5678abcd5678abcdabcd5678abcd5678abcd5678",
            "pul-a8sd023l5-f98s761j2lkd-786v78abcd5678abcd5678",
            "pul-awdsxg23l5-f98s761j2lkd-786v78abcd5678abcd5678",
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
            TrieNode current = queue.remove(0);
            for (int i = 0; i < ALPHABET_SIZE; i++) {
                TrieNode child = current.children[i];
                if (child != null) {
                    TrieNode failure = current.failure;
                    while (failure.children[i] == null && failure != root) {

fun main() {
    (
        jira="ab12cd34ef56gh78ij90kl12"
        atlassian="xy12ab34cd56ef78gh90ij12"
        fake="maytheforcebewithyoua"
        fake2="houstonwehaveaproblem"
    )

    val jira_pattern = Regex("(?i)[a-z0-9]{14}\\.atlasv1\\.[a-z0-9\\-_=]{60,70}")

    jira_pattern.forEachIndexed { i, token ->
        if (pattern.matches(token)) {
            println("Matched API Token $i: $token")
        } else {
            println("No match for API Token $i: $token")
        }
    }
}

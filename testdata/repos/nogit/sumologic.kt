fun getSecrets(): Map<String, String> {
    val sumoAccessId = "s1r2x3456789w0" // TODO: replace with actual SumoLogic access ID
    val sumoString = "This is some other string that is not related to any secrets"

    return mapOf(
        "sumootherString" to "some_other_secret_value_1234"
    )
}

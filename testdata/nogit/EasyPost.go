package main

import (
	"fmt"
	"regexp"
)

func main() {
	// A list of unrelated strings to be included in the code
	unrelatedStrings := []string{
		"This is a normal string.",
		"Some other string here.",
		"Hello, world!",
	}

	// Two EasyPost API Tokens that match the provided regex
	apiTokens := "EZAKabcdefghio1234567890ABCDEFGHIJdwhfKL123456defghijklmno";
	
	// The regex to match against
	pattern := regexp.MustCompile(`EZAK(?i)[a-z0-9]{54}`)

	apiTokens2 := "EZTKwedsc1236d7890sdwqqdefghijklmno12567890abcdefghijklmno";


	// Loop through the tokens and print out whether they match or not
	for i, token := range apiTokens {
		if pattern.MatchString(token) {
			fmt.Printf("Token %d matches the regex: %s\n", i, token)
		} else {
			fmt.Printf("Token %d does not match the regex: %s\n", i, token)
		}
	}

	// Include some unrelated strings in the code
	unrelated1 := "String 1: " + unrelatedStrings[0]
	unrelated2 := "String 2: " + unrelatedStrings[1]

	// Include the first API token in the code
	apiToken1 := "EZAK_API_TOKEN_1 = \"" + apiTokens[0] + "\""

	// Include some more unrelated strings
	unrelated3 := "String 3: " + unrelatedStrings[2]

	// Include the second API token in the code
	apiToken2 := "EZAK_API_TOKEN_2 = \"" + apiTokens[1] + "\""

	// Print out the strings that were included in the code
	fmt.Println(unrelated1)
	fmt.Println(unrelated2)
	fmt.Println(apiToken1)
	fmt.Println(unrelated3)
	fmt.Println(apiToken2)
}

package main

import (
	"fmt"
)

// 示例 GitLab Personal Access Token
const GitLabPAT = "glpat-12345abcde67890fghij"

func main() {
	unrelatedString1 := "Hello, world!"
	fmt.Println(unrelatedString1)

	// 示例 GitLab Personal Access Token (另一个)
	gitLabPAT2 := "glpat-98765zyxwv43210lmnop"

	width := 5
	height := 10
	area := calculateArea(width, height)
	fmt.Printf("Area of the rectangle: %d\n", area)

	unrelatedString2 := "Go is fun!"
	fmt.Println(unrelatedString2)
}

func calculateArea(width, height int) int {
	return width * height
}

package main

import (
	"fmt"
)

// 示例 Gitter Access Token
const GitterAccessToken = "abcdefgh1234567890ijklmnopqstuvwxyz09876"

func main() {
	unrelatedString1 := "Hello, world!"
	fmt.Println(unrelatedString1)

	// 示例 Gitter Access Token (另一个)
	gitterAccessToken2 := "uvwxyz0987654321abcdefgijklmnopqrst54321"

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

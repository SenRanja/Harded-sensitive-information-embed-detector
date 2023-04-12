package main

import (
	"fmt"
)

// 示例 Qiye WeiXin Developer App ID
const QiyeWeixinAppID = "ww1234567890ab"

func main() {
	unrelatedString1 := "Hello, world!"
	fmt.Println(unrelatedString1)

	// 示例 Qiye WeiXin Developer App Secret
	qiyeWeixinAppSecret := "ww0987654321cd"

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

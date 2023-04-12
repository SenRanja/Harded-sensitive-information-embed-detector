package main

import (
	"fmt"
)

// 示例 WeiXin Developer App ID
const WeixinAppID = "wx10aa321a8336b4b4"

func main() {
	unrelatedString1 := "Hello, world!"
	fmt.Println(unrelatedString1)

	// 示例 WeiXin Developer App Secret
	weixinAppSecret := "wxef5e94d7addd9744"

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

import (
	"fmt"
	"os"
)
	// seems safer
	aws_token := os.Getenv("AWS_TOKEN")
package foo

import "fmt"

func Foo() {
	fmt.Println("foo")

	// seems safe
	aws_token := "AKIALALEMEL33243OLIA"
	aws_tokenFake := "AKIAlifeislikeaboxofchoco"
	aws_tokenFake := "AKIAonceuponatimeintheland"
	fmt.Println(aws_token)
}

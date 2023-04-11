package main

import (
	"encoding/base64"
	"fmt"
)


var bitbucket = []string{
	"JvI9+9S0EsT/KZG+eC7A+/WWlNDf2Dd+YIS31BGU6Vc=",
	"r6rZaIL5F5o5Aq3x1/mH5y8Kjbt2+VdYPoG+MHSxcJQ=",
	"FaZwRdR+GnoPfCvJzYgyy3tD1UVtX3ArzL1s8ubxo4o=",
	"e+cYzZWvG8Wb01+2S/gdX1+dt7IOuZGgFiwQV57Bsfk=",
	"vwY6cNwmhVpO6ljng5f5ZDRNd5wOVJ5c5q3mDQVY+Yg=",
	"0rxM9n24Pld5a5Z5wAUBMD3xqDjOG2fY1yR/QG7LlPc=",
	"oAOpETwHd2Uf1xgIkm6Bkjy6OMeH83pL9XN+Ov8s+h0=",
	"OHRN/jLlNys8UXlWSDS/2dSy9fUDJv49ZMUfzRwBdZI=",
	"9sPSYRcGvCU7GzNtF64r/3oUDb2eLn0lCg+T/9XWmO8=",
	"/OoGm2uV7W0CNmuOwVpL+1kmmu5X5YdU6vDzZB5U6hA=",
	"U6kx+NyBY5/MQ2Fe4qMQRT4Q4n1+tZz4OKiS95SdRzk=",
	"xzlJiulmjyZbcLmyelL47+rX0G+3o4/7oNjJNcCU+yc=",
	"TRPYGfhzLg5O6X9Y6U5I6QeJlcOaetgfr8m42Ueq+1Q=",
	"zZ+8LhgJ/gE1HxV98A+bdBRe7VxiWpxMCwStzGYWXZs=",
	"w9YRtJvL7Bo+TtFWnTQitEwd3qJrZDokN0tFb9A1Rss=",
	"k7TfT+n1/0QhDTtf3aJQ2EGCHqwOz/s9XWmMj1hVxgI=",
	"V7WkLhd/Pw5zZPE5GpGeLyX6YcU6v2QyNDiK6BGfHd8=",
	"lT3vJ8W1t0iM29KM/GMyAs9q3t8bj1dxquCfufyO/xM=",
	"T8wBZ5e5i0r5d/aI0sk5a5JkklnUVlSSONiFLIa/sk8=",
	"YQkpDzmimN9ccZgZYIaMmzjiNp1M5x/OyieI5gflnNg=",
}

var FakeBitbucket String =  "tobeornottobethatisthe="

func main() {
	for i, secret := range bitbucket {
		fmt.Printf("Client Secret %d: %s\n", i+1, secret)
	}
}

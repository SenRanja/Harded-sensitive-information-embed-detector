package detect

import "testing"

func TestDetectIpLegal(t *testing.T) {
	type args struct {
		ip_segment string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"test1", args{"01"}, false},
		{"test2", args{"06"}, false},
		{"test3", args{"02"}, false},
		{"test4", args{"21"}, true},
		{"test5", args{"23"}, true},
		{"test6", args{"01"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := DetectIpLegal(tt.args.ip_segment); got != tt.want {
				t.Errorf("DetectIpLegal() = %v, want %v", got, tt.want)
			}
		})
	}
}

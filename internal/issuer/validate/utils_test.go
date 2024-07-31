package validate

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainsString(t *testing.T) {
	type params struct {
		s     string
		slice []string
	}

	type want struct {
		result bool
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldFindStringInSlice": {
			params: params{
				s:     "example",
				slice: []string{"test", "example", "check"},
			},
			want: want{
				result: true,
			},
		},
		"ShouldNotFindStringInSlice": {
			params: params{
				s:     "missing",
				slice: []string{"test", "example", "check"},
			},
			want: want{
				result: false,
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			found := containsString(test.params.s, test.params.slice)
			assert.Equal(t, test.want.result, found)
		})
	}
}

func TestContainsInt(t *testing.T) {
	type params struct {
		d     int
		slice []int
	}

	type want struct {
		result bool
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldFindIntInSlice": {
			params: params{
				d:     42,
				slice: []int{1, 42, 3},
			},
			want: want{
				result: true,
			},
		},
		"ShouldNotFindIntInSlice": {
			params: params{
				d:     99,
				slice: []int{1, 42, 3},
			},
			want: want{
				result: false,
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			found := containsInt(test.params.d, test.params.slice)
			assert.Equal(t, test.want.result, found)
		})
	}
}

func TestHasSuffix(t *testing.T) {
	type params struct {
		s      string
		suffix string
	}

	type want struct {
		result bool
	}

	cases := map[string]struct {
		params params
		want   want
	}{
		"ShouldHaveSuffix": {
			params: params{
				s:      "example.txt",
				suffix: ".txt",
			},
			want: want{
				result: true,
			},
		},
		"ShouldNotHaveSuffix": {
			params: params{
				s:      "example.txt",
				suffix: ".jpg",
			},
			want: want{
				result: false,
			},
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			match := hasSuffix(test.params.s, test.params.suffix)
			assert.Equal(t, test.want.result, match)
		})
	}
}

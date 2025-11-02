package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestGenerateName(t *testing.T) {
	type args struct {
		name   string
		suffix string
	}
	type want struct {
		generatedName string
	}
	cases := map[string]struct {
		reason string
		args   args
		want   want
	}{
		"ResourceNameUnder63Characters": {
			reason: "a generated name under 63 characters should include the full name, hash, and suffix",
			args: args{
				name:   "composed-resource-c82ef4fa3e45",
				suffix: "fn-protection",
			},
			want: want{
				generatedName: "composed-resource-c82ef4fa3e45-bf2238-fn-protection",
			},
		},
		"ResourceNameOver63Characters": {
			reason: "a generated name over 63 characters should be truncated but still include hash and suffix",
			args: args{
				name:   "a-very-long-string-that-is-more-than-sixty-three-characters-long",
				suffix: "fn-protection",
			},
			want: want{
				generatedName: "a-very-long-string-that-is-more-than-sixty-acc595-fn-protection",
			},
		},
		"NameUnder63NoTruncation": {
			reason: "a name that results in under 63 characters should not be truncated",
			args: args{
				name:   "this-name-is-exactly-the-right-length-for",
				suffix: "suffix",
			},
			want: want{
				generatedName: "this-name-is-exactly-the-right-length-for-cbb2af-suffix",
			},
		},
		"NameRequiresTruncationEndsWithoutDash": {
			reason: "when truncated, if name doesn't end with dash, a dash should be added before suffix",
			args: args{
				name:   "this-is-a-very-long-configuration-name-that-will-be-truncated",
				suffix: "fn-protection",
			},
			want: want{
				generatedName: "this-is-a-very-long-configuration-name-tha-b33995-fn-protection",
			},
		},
		"NameRequiresTruncationEndsWithDash": {
			reason: "when truncated, if name already ends with dash, that dash should be preserved",
			args: args{
				name:   "this-is-a-very-long-configuration-name-end-",
				suffix: "fn-protection",
			},
			want: want{
				generatedName: "this-is-a-very-long-configuration-name-end-0cba3d-fn-protection",
			},
		},
		"Exactly63CharactersResult": {
			reason: "generated name should be exactly 63 characters when at the limit",
			args: args{
				name:   "long-resource-name-for-kubernetes-environment-test",
				suffix: "suffix",
			},
			want: want{
				generatedName: "long-resource-name-for-kubernetes-environment-tes-512922-suffix",
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := GenerateName(tc.args.name, tc.args.suffix)

			if diff := cmp.Diff(tc.want.generatedName, got, protocmp.Transform()); diff != "" {
				t.Errorf("%s\nGenerateName(...): -want rsp, +got rsp:\n%s", tc.reason, diff)
			}

			// Verify the generated name never exceeds 63 characters
			if len(got) > 63 {
				t.Errorf("Generated name exceeds Kubernetes limit: %d characters (max 63)", len(got))
			}
		})
	}
}

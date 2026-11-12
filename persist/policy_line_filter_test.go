// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package persist_test

import (
	"reflect"
	"testing"

	"github.com/casbin/casbin/v3/persist"
)

func TestParsePolicyLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		want    []string
		wantErr bool
	}{
		{
			name: "plain line",
			line: "p, alice, data1, read",
			want: []string{"p", "alice", "data1", "read"},
		},
		{
			// A quoted field containing commas must stay a single field.
			name: "quoted field with embedded commas",
			line: `p, alice, data1, read, "r.attrs in ('v1','v2')"`,
			want: []string{"p", "alice", "data1", "read", "r.attrs in ('v1','v2')"},
		},
		{
			// Doubled quotes inside a quoted field are unescaped to one quote,
			// and the embedded comma must not split the field.
			name: "escaped quotes and embedded comma",
			line: `p, alice, "say ""hi"", bob", read`,
			want: []string{"p", "alice", `say "hi", bob`, "read"},
		},
		{
			name: "escaped quote only",
			line: `p, alice, "say ""hi"""`,
			want: []string{"p", "alice", `say "hi"`},
		},
		{
			name: "blank line yields no tokens",
			line: "   ",
			want: nil,
		},
		{
			name: "comment line yields no tokens",
			line: "# this is a comment",
			want: nil,
		},
		{
			// An unterminated quote cannot be parsed as one CSV record.
			name:    "unterminated quote returns error",
			line:    `p, alice, "broken, read`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := persist.ParsePolicyLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for line %q, got tokens %q", tt.line, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for line %q: %v", tt.line, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ParsePolicyLine(%q) = %q, want %q", tt.line, got, tt.want)
			}
		})
	}
}

func TestMatchPolicyLine(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		filter  []string
		want    bool
		wantErr bool
	}{
		{
			name:   "plain field matches",
			line:   "p, alice, domain1, data1, read",
			filter: []string{"", "domain1"},
			want:   true,
		},
		{
			name:   "plain field does not match",
			line:   "p, alice, domain2, data2, read",
			filter: []string{"", "domain1"},
			want:   false,
		},
		{
			// The domain field sits before a quoted, comma-bearing field.
			// Splitting on commas naively would shift the comparison and
			// misroute the rule across tenants.
			name:   "quoted embedded comma keeps domain aligned",
			line:   `p, admin, domain1, "x, y, z", read`,
			filter: []string{"", "domain1"},
			want:   true,
		},
		{
			name:   "quoted embedded comma, different domain rejected",
			line:   `p, admin, domain2, "x, y, z", read`,
			filter: []string{"", "domain1"},
			want:   false,
		},
		{
			// Filtering on the very field that itself contains an escaped quote
			// and an embedded comma must compare the unescaped value.
			name:   "filter against escaped-quote field",
			line:   `p, alice, "say ""hi"", bob", read`,
			filter: []string{"", `say "hi", bob`},
			want:   true,
		},
		{
			name:   "line shorter than filter does not match",
			line:   "p, alice",
			filter: []string{"", "domain1", "data1"},
			want:   false,
		},
		{
			name:   "empty filter matches every parseable line",
			line:   `p, alice, "a, b"`,
			filter: nil,
			want:   true,
		},
		{
			name:   "blank line never matches",
			line:   "",
			filter: []string{"alice"},
			want:   false,
		},
		{
			name:    "unparseable line returns error instead of a silent verdict",
			line:    `p, alice, "broken`,
			filter:  []string{"alice"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := persist.MatchPolicyLine(tt.line, tt.filter)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error for line %q, got match=%v", tt.line, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for line %q: %v", tt.line, err)
			}
			if got != tt.want {
				t.Errorf("MatchPolicyLine(%q, %q) = %v, want %v", tt.line, tt.filter, got, tt.want)
			}
		})
	}
}

// TestParsePolicyLineMatchesCsvRoundTrip guarantees that the shared parser
// splits a line produced by PolicyLineToCsv back into exactly the original
// fields, i.e. save side, full load and filtered load all share one grammar.
func TestParsePolicyLineMatchesCsvRoundTrip(t *testing.T) {
	rule := []string{" alice", `say "hi", bob`, "read", "r.attrs in ('v1','v2')"}
	line, err := persist.PolicyLineToCsv("p", rule)
	if err != nil {
		t.Fatalf("PolicyLineToCsv: %v", err)
	}

	tokens, err := persist.ParsePolicyLine(line)
	if err != nil {
		t.Fatalf("ParsePolicyLine(%q): %v", line, err)
	}
	want := append([]string{"p"}, rule...)
	if !reflect.DeepEqual(tokens, want) {
		t.Errorf("round-trip tokens = %q, want %q (line: %q)", tokens, want, line)
	}
}

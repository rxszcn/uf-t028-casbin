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

package fileadapter_test

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
)

const rbacWithDomainsModelText = `
[request_definition]
r = sub, dom, obj, act

[policy_definition]
p = sub, dom, obj, act

[role_definition]
g = _ , _ , _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub, r.dom) && r.dom == p.dom && r.obj == p.obj && r.act == p.act
`

func newTestModel(t *testing.T) model.Model {
	t.Helper()
	m := model.NewModel()
	if err := m.LoadModelFromText(rbacWithDomainsModelText); err != nil {
		t.Fatalf("load model: %v", err)
	}
	return m
}

func writePolicyFile(t *testing.T, lines string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(path, []byte(lines), 0o600); err != nil {
		t.Fatalf("write policy file: %v", err)
	}
	return path
}

func sortedRules(rules [][]string) [][]string {
	out := make([][]string, len(rules))
	copy(out, rules)
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i], "\x00") < strings.Join(out[j], "\x00")
	})
	return out
}

// csvLine builds a line exactly like the save side would, so the test data
// reflects what SavePolicy actually writes to disk.
func csvLine(t *testing.T, ptype string, rule []string) string {
	t.Helper()
	line, err := persist.PolicyLineToCsv(ptype, rule)
	if err != nil {
		t.Fatalf("PolicyLineToCsv: %v", err)
	}
	return line
}

// joinLines terminates every line with a newline, matching an on-disk file.
func joinLines(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

// TestFilteredLoadQuotedCommasKeepsFieldsAligned reproduces the field-shift
// bug: a subject field containing a comma is quoted on save, and a filtered
// load must keep the following domain/object fields aligned so rules are not
// silently misrouted across tenants.
func TestFilteredLoadQuotedCommasKeepsFieldsAligned(t *testing.T) {
	// Subject carries an embedded comma; it is quoted on save.
	domain1Line := csvLine(t, "p", []string{"alice, bob", "domain1", "data1", "read"})
	domain2Line := csvLine(t, "p", []string{"admin", "domain2", "data2", "read"})
	path := writePolicyFile(t, domain1Line+"\n"+domain2Line+"\n")

	t.Run("domain filter keeps only the matching tenant", func(t *testing.T) {
		a := fileadapter.NewFilteredAdapter(path)
		m := newTestModel(t)
		if err := a.LoadFilteredPolicy(m, &fileadapter.Filter{
			P: []string{"", "domain1"},
		}); err != nil {
			t.Fatalf("LoadFilteredPolicy: %v", err)
		}
		if !a.IsFiltered() {
			t.Fatal("adapter should report a filtered policy")
		}
		rules, err := m.GetPolicy("p", "p")
		if err != nil {
			t.Fatalf("GetPolicy: %v", err)
		}
		want := [][]string{{"alice, bob", "domain1", "data1", "read"}}
		if !reflect.DeepEqual(sortedRules(rules), sortedRules(want)) {
			t.Errorf("filtered rules = %q, want %q", rules, want)
		}
	})

	t.Run("object filter after a quoted comma field stays aligned", func(t *testing.T) {
		a := fileadapter.NewFilteredAdapter(path)
		m := newTestModel(t)
		// Filter on the object field (index 2), which sits after the quoted
		// subject field (index 0).
		if err := a.LoadFilteredPolicy(m, &fileadapter.Filter{
			P: []string{"", "", "data1"},
		}); err != nil {
			t.Fatalf("LoadFilteredPolicy: %v", err)
		}
		rules, _ := m.GetPolicy("p", "p")
		want := [][]string{{"alice, bob", "domain1", "data1", "read"}}
		if !reflect.DeepEqual(sortedRules(rules), sortedRules(want)) {
			t.Errorf("filtered rules = %q, want %q", rules, want)
		}
	})
}

// TestFilteredLoadEscapedQuotes covers a field that contains both an escaped
// quote ("") and an embedded comma: the parsed value must be the unescaped
// string and the filter must compare against that value.
func TestFilteredLoadEscapedQuotes(t *testing.T) {
	cond := `say "hi", bob`
	line := csvLine(t, "p", []string{"alice", "domain1", cond, "read"})
	path := writePolicyFile(t, line+"\n")

	a := fileadapter.NewFilteredAdapter(path)
	m := newTestModel(t)
	if err := a.LoadFilteredPolicy(m, &fileadapter.Filter{
		P: []string{"", "", cond},
	}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	rules, _ := m.GetPolicy("p", "p")
	want := [][]string{{"alice", "domain1", cond, "read"}}
	if !reflect.DeepEqual(rules, want) {
		t.Errorf("filtered rules = %q, want %q (line: %q)", rules, want, line)
	}
}

// TestFilteredLoadMatchesFullLoad states the core invariant: for every filter,
// the filtered load must yield exactly the rules that a full load keeps. The
// two code paths share one parser, so they can never disagree.
func TestFilteredLoadMatchesFullLoad(t *testing.T) {
	lines := joinLines(
		csvLine(t, "p", []string{"alice, bob", "domain1", "data1", "read"}),
		csvLine(t, "p", []string{"admin", "domain2", "data2", "read"}),
		csvLine(t, "p", []string{"carol", "domain1", `tag "x", y`, "write"}),
	)
	path := writePolicyFile(t, lines)

	filter := &fileadapter.Filter{P: []string{"", "domain1"}}

	full := newTestModel(t)
	if err := fileadapter.NewAdapter(path).LoadPolicy(full); err != nil {
		t.Fatalf("full LoadPolicy: %v", err)
	}
	fullRules, _ := full.GetPolicy("p", "p")
	var want [][]string
	for _, r := range fullRules {
		if r[1] == "domain1" {
			want = append(want, r)
		}
	}

	filtered := newTestModel(t)
	if err := fileadapter.NewFilteredAdapter(path).LoadFilteredPolicy(filtered, filter); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	got, _ := filtered.GetPolicy("p", "p")

	if !reflect.DeepEqual(sortedRules(got), sortedRules(want)) {
		t.Errorf("filtered rules = %q, want the domain1 subset of full load %q", got, want)
	}
}

// TestFilteredLoadLegacyUnquotedFile ensures policies written by older
// versions (plain commas, no quoting) keep loading and filtering correctly.
func TestFilteredLoadLegacyUnquotedFile(t *testing.T) {
	legacy := "p, admin, domain1, data1, read\n" +
		"p, admin, domain2, data2, read\n" +
		"g, alice, admin, domain1\n"
	path := writePolicyFile(t, legacy)

	a := fileadapter.NewFilteredAdapter(path)
	m := newTestModel(t)
	if err := a.LoadFilteredPolicy(m, &fileadapter.Filter{
		P: []string{"", "domain1"},
		G: []string{"", "", "domain1"},
	}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}

	pRules, _ := m.GetPolicy("p", "p")
	if want := [][]string{{"admin", "domain1", "data1", "read"}}; !reflect.DeepEqual(pRules, want) {
		t.Errorf("p rules = %q, want %q", pRules, want)
	}
	gRules, _ := m.GetPolicy("g", "g")
	if want := [][]string{{"alice", "admin", "domain1"}}; !reflect.DeepEqual(gRules, want) {
		t.Errorf("g rules = %q, want %q", gRules, want)
	}
}

// TestFilteredLoadUnparseableLineErrors makes the failure policy explicit: a
// line that cannot be parsed aborts the load with an error instead of being
// silently dropped or loaded with shifted fields.
func TestFilteredLoadUnparseableLineErrors(t *testing.T) {
	// Unterminated quote is not a valid single CSV record.
	broken := `p, admin, domain1, "data1, read`
	path := writePolicyFile(t, broken+"\n")

	a := fileadapter.NewFilteredAdapter(path)
	m := newTestModel(t)
	err := a.LoadFilteredPolicy(m, &fileadapter.Filter{P: []string{"", "domain1"}})
	if err == nil {
		t.Fatal("expected an error for an unparseable line, got nil")
	}
}

// TestFilteredThenFullSaveRoundTrip verifies a save -> full-load -> filtered
// cycle preserves rules byte-for-byte at the field level.
func TestFilteredThenFullSaveRoundTrip(t *testing.T) {
	rule := []string{"alice, bob", "domain1", `say "hi"`, "read"}
	path := writePolicyFile(t, csvLine(t, "p", rule)+"\n")

	// Full load then save must reproduce the same fields.
	m1 := newTestModel(t)
	a1 := fileadapter.NewFilteredAdapter(path)
	if err := a1.LoadPolicy(m1); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if err := a1.SavePolicy(m1); err != nil {
		t.Fatalf("SavePolicy after full load: %v", err)
	}

	m2 := newTestModel(t)
	if err := fileadapter.NewFilteredAdapter(path).LoadFilteredPolicy(m2, &fileadapter.Filter{
		P: []string{"", "domain1"},
	}); err != nil {
		t.Fatalf("LoadFilteredPolicy after round-trip: %v", err)
	}
	rules, _ := m2.GetPolicy("p", "p")
	if !reflect.DeepEqual(rules, [][]string{rule}) {
		t.Errorf("rule after save/load/filter = %q, want %q", rules, [][]string{rule})
	}
}

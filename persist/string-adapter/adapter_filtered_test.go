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

package stringadapter_test

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
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

func sortedRules(rules [][]string) [][]string {
	out := make([][]string, len(rules))
	copy(out, rules)
	sort.Slice(out, func(i, j int) bool {
		return strings.Join(out[i], "\x00") < strings.Join(out[j], "\x00")
	})
	return out
}

func csvLine(t *testing.T, ptype string, rule []string) string {
	t.Helper()
	line, err := persist.PolicyLineToCsv(ptype, rule)
	if err != nil {
		t.Fatalf("PolicyLineToCsv: %v", err)
	}
	return line
}

// TestFilteredLoadQuotedCommasKeepsFieldsAligned reproduces the field-shift
// bug in the in-memory (string) storage format: a quoted subject field with an
// embedded comma must not shift the domain/object fields used by the filter.
func TestFilteredLoadQuotedCommasKeepsFieldsAligned(t *testing.T) {
	domain1Line := csvLine(t, "p", []string{"alice, bob", "domain1", "data1", "read"})
	domain2Line := csvLine(t, "p", []string{"admin", "domain2", "data2", "read"})
	text := domain1Line + "\n" + domain2Line

	t.Run("domain filter keeps only the matching tenant", func(t *testing.T) {
		a := stringadapter.NewFilteredAdapter(text)
		m := newTestModel(t)
		if err := a.LoadFilteredPolicy(m, &stringadapter.Filter{
			P: []string{"", "domain1"},
		}); err != nil {
			t.Fatalf("LoadFilteredPolicy: %v", err)
		}
		if !a.IsFiltered() {
			t.Fatal("adapter should report a filtered policy")
		}
		rules, _ := m.GetPolicy("p", "p")
		want := [][]string{{"alice, bob", "domain1", "data1", "read"}}
		if !reflect.DeepEqual(sortedRules(rules), sortedRules(want)) {
			t.Errorf("filtered rules = %q, want %q", rules, want)
		}
	})

	t.Run("object filter after a quoted comma field stays aligned", func(t *testing.T) {
		a := stringadapter.NewFilteredAdapter(text)
		m := newTestModel(t)
		if err := a.LoadFilteredPolicy(m, &stringadapter.Filter{
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

// TestFilteredLoadEscapedQuotes covers a field holding both an escaped quote
// ("") and an embedded comma, comparing the filter against the unescaped value.
func TestFilteredLoadEscapedQuotes(t *testing.T) {
	cond := `say "hi", bob`
	line := csvLine(t, "p", []string{"alice", "domain1", cond, "read"})

	a := stringadapter.NewFilteredAdapter(line)
	m := newTestModel(t)
	if err := a.LoadFilteredPolicy(m, &stringadapter.Filter{
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

// TestFilteredLoadMatchesFullLoad asserts the filtered view is exactly the
// subset a full load keeps, because both share the same parser.
func TestFilteredLoadMatchesFullLoad(t *testing.T) {
	text := strings.Join([]string{
		csvLine(t, "p", []string{"alice, bob", "domain1", "data1", "read"}),
		csvLine(t, "p", []string{"admin", "domain2", "data2", "read"}),
		csvLine(t, "p", []string{"carol", "domain1", `tag "x", y`, "write"}),
	}, "\n")

	full := newTestModel(t)
	if err := stringadapter.NewAdapter(text).LoadPolicy(full); err != nil {
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
	if err := stringadapter.NewFilteredAdapter(text).LoadFilteredPolicy(filtered, &stringadapter.Filter{
		P: []string{"", "domain1"},
	}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	got, _ := filtered.GetPolicy("p", "p")
	if !reflect.DeepEqual(sortedRules(got), sortedRules(want)) {
		t.Errorf("filtered rules = %q, want the domain1 subset of full load %q", got, want)
	}
}

// TestFilteredLoadLegacyUnquotedText keeps policies written by older versions
// (plain commas, no quoting) loadable and filterable.
func TestFilteredLoadLegacyUnquotedText(t *testing.T) {
	legacy := "p, admin, domain1, data1, read\n" +
		"p, admin, domain2, data2, read\n" +
		"g, alice, admin, domain1"

	a := stringadapter.NewFilteredAdapter(legacy)
	m := newTestModel(t)
	if err := a.LoadFilteredPolicy(m, &stringadapter.Filter{
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
// line that cannot be parsed aborts the load with an error rather than being
// silently dropped or loaded with shifted fields.
func TestFilteredLoadUnparseableLineErrors(t *testing.T) {
	broken := `p, admin, domain1, "data1, read`
	a := stringadapter.NewFilteredAdapter(broken)
	m := newTestModel(t)
	if err := a.LoadFilteredPolicy(m, &stringadapter.Filter{
		P: []string{"", "domain1"},
	}); err == nil {
		t.Fatal("expected an error for an unparseable line, got nil")
	}
}

// TestFilteredAdapterSaveGuardAndRoundTrip checks that a filtered adapter
// refuses to save, while a full (unfiltered) load still round-trips the
// comma/quote-bearing rules unchanged.
func TestFilteredAdapterSaveGuardAndRoundTrip(t *testing.T) {
	rule := []string{"alice, bob", "domain1", `say "hi"`, "read"}
	text := csvLine(t, "p", rule)

	filtered := stringadapter.NewFilteredAdapter(text)
	m := newTestModel(t)
	if err := filtered.LoadFilteredPolicy(m, &stringadapter.Filter{P: []string{"", "domain1"}}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	if err := filtered.SavePolicy(m); err == nil {
		t.Error("SavePolicy on a filtered adapter must be rejected")
	}

	full := stringadapter.NewFilteredAdapter(text)
	m2 := newTestModel(t)
	if err := full.LoadPolicy(m2); err != nil {
		t.Fatalf("LoadPolicy: %v", err)
	}
	if err := full.SavePolicy(m2); err != nil {
		t.Fatalf("SavePolicy after full load: %v", err)
	}

	m3 := newTestModel(t)
	if err := stringadapter.NewAdapter(full.Line).LoadPolicy(m3); err != nil {
		t.Fatalf("reload saved line: %v", err)
	}
	rules, _ := m3.GetPolicy("p", "p")
	if !reflect.DeepEqual(rules, [][]string{rule}) {
		t.Errorf("rule after round-trip = %q, want %q (saved: %q)", rules, [][]string{rule}, full.Line)
	}
}

// TestFilteredAdapterNilAndWrongFilter covers the filter contract.
func TestFilteredAdapterNilAndWrongFilter(t *testing.T) {
	text := "p, admin, domain1, data1, read"

	t.Run("nil filter falls back to a full load", func(t *testing.T) {
		a := stringadapter.NewFilteredAdapter(text)
		m := newTestModel(t)
		if err := a.LoadFilteredPolicy(m, nil); err != nil {
			t.Fatalf("LoadFilteredPolicy(nil): %v", err)
		}
		if a.IsFiltered() {
			t.Error("nil filter must leave the adapter unfiltered")
		}
		rules, _ := m.GetPolicy("p", "p")
		if len(rules) != 1 {
			t.Errorf("expected 1 rule from full load, got %d", len(rules))
		}
	})

	t.Run("wrong filter type is rejected", func(t *testing.T) {
		a := stringadapter.NewFilteredAdapter(text)
		m := newTestModel(t)
		if err := a.LoadFilteredPolicy(m, []string{"domain1"}); err == nil {
			t.Error("expected invalid filter type error, got nil")
		}
	})
}

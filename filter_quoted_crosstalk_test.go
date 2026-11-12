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

package casbin

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/casbin/casbin/v3/persist"
	fileadapter "github.com/casbin/casbin/v3/persist/file-adapter"
	stringadapter "github.com/casbin/casbin/v3/persist/string-adapter"
)

const tenantModelPath = "examples/rbac_with_domains_model.conf"

// quotedTenantLines builds two tenant rules where a subject field contains a
// comma. The lines are produced through the same CSV serializer the save side
// uses (persist.PolicyLineToCsv), so they are exactly what SavePolicy writes.
func quotedTenantLines(t *testing.T) string {
	t.Helper()
	a, err := persist.PolicyLineToCsv("p", []string{"alice, contractor", "domainA", "docA", "read"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := persist.PolicyLineToCsv("p", []string{"bob", "domainB", "docB", "read"})
	if err != nil {
		t.Fatal(err)
	}
	return a + "\n" + b
}

func testHasPolicyBool(t *testing.T, e *Enforcer, rule []string) bool {
	t.Helper()
	ok, err := e.HasPolicy(rule)
	if err != nil {
		t.Fatalf("HasPolicy(%q): %v", rule, err)
	}
	return ok
}

// assertTenantIsolation drives one filtered adapter through the Enforcer and
// asserts that, with a quoted comma in a field, the domain filter neither
// drops domainA's rule nor leaks domainB's rule — both at the policy level and
// at the enforcement decision level.
func assertTenantIsolation(t *testing.T, e *Enforcer) {
	t.Helper()

	if !testHasPolicyBool(t, e, []string{"alice, contractor", "domainA", "docA", "read"}) {
		t.Error("domainA rule with quoted comma subject was dropped by the filter")
	}
	if testHasPolicyBool(t, e, []string{"bob", "domainB", "docB", "read"}) {
		t.Error("domainB rule leaked across the tenant boundary during filtered load")
	}

	if allowed, _ := e.Enforce("alice, contractor", "domainA", "docA", "read"); !allowed {
		t.Error("legitimate domainA access denied after filtered load")
	}
	if allowed, _ := e.Enforce("bob", "domainB", "docB", "read"); allowed {
		t.Error("domainB access allowed although only domainA was filtered in (tenant crosstalk)")
	}
}

// TestFilteredLoadTenantIsolationFileAdapter covers the on-disk storage format.
func TestFilteredLoadTenantIsolationFileAdapter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.csv")
	if err := os.WriteFile(path, []byte(quotedTenantLines(t)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	e, err := NewEnforcer(tenantModelPath, fileadapter.NewFilteredAdapter(path))
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	if err := e.LoadFilteredPolicy(&fileadapter.Filter{P: []string{"", "domainA"}}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	assertTenantIsolation(t, e)
}

// TestFilteredLoadTenantIsolationStringAdapter is the in-memory counterpart
// exercising the same CSV-aware filtering through the string adapter.
func TestFilteredLoadTenantIsolationStringAdapter(t *testing.T) {
	e, err := NewEnforcer(tenantModelPath, stringadapter.NewFilteredAdapter(quotedTenantLines(t)))
	if err != nil {
		t.Fatalf("new enforcer: %v", err)
	}
	if err := e.LoadFilteredPolicy(&stringadapter.Filter{P: []string{"", "domainA"}}); err != nil {
		t.Fatalf("LoadFilteredPolicy: %v", err)
	}
	assertTenantIsolation(t, e)
}

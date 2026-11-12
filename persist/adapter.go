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

package persist

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/casbin/casbin/v3/model"
)

// LoadPolicyLine loads a text line as a policy rule to model.
func LoadPolicyLine(line string, m model.Model) error {
	tokens, err := ParsePolicyLine(line)
	if err != nil {
		return err
	}
	// A blank or comment line yields no tokens; there is nothing to load.
	if tokens == nil {
		return nil
	}

	return LoadPolicyArray(tokens, m)
}

// ParsePolicyLine splits one physical policy line into its fields using the
// same CSV semantics as the save side (PolicyLineToCsv). Quoted fields may
// therefore contain commas, and doubled quotes ("") inside a quoted field are
// unescaped to a single quote. Sharing this parser between the full load, the
// filtered load and the save side guarantees that a line is split into exactly
// the same fields in every code path.
//
// A blank line or a line whose first non-space character is '#' yields
// (nil, nil): it carries no rule and must simply be ignored. Any other line
// that cannot be parsed as a single CSV record yields an error, so that a
// corrupt policy file fails loudly instead of silently shifting fields.
func ParsePolicyLine(line string) ([]string, error) {
	if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
		return nil, nil
	}

	r := csv.NewReader(strings.NewReader(line))
	r.Comma = ','
	r.Comment = '#'
	r.TrimLeadingSpace = true

	tokens, err := r.Read()
	if err == io.EOF {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return tokens, nil
}

// MatchPolicyLine reports whether the fields of a policy line match the given
// filter words. The line is parsed with ParsePolicyLine, i.e. with the exact
// same semantics as the full load and the save side, so quoted commas and
// escaped quotes never shift the compared fields.
//
// filter holds the words to compare against the rule fields after the policy
// type: empty words are ignored, every non-empty word must equal the field at
// the same position (leading/trailing spaces are ignored on both sides, as in
// the historical filtered-adapter behaviour). A line shorter than the filter
// does not match.
//
// Blank lines and comment lines never match (they return false). A line that
// cannot be parsed returns an error, leaving the decision to abort the load to
// the caller rather than silently dropping or misrouting the rule.
func MatchPolicyLine(line string, filter []string) (bool, error) {
	tokens, err := ParsePolicyLine(line)
	if err != nil {
		return false, err
	}
	if len(tokens) == 0 {
		return false, nil
	}

	// tokens[0] is the policy type (p, g, ...); the rule fields follow.
	rule := tokens[1:]
	if len(rule) < len(filter) {
		return false, nil
	}
	for i, word := range filter {
		if word != "" && strings.TrimSpace(word) != strings.TrimSpace(rule[i]) {
			return false, nil
		}
	}
	return true, nil
}

// PolicyLineToCsv serializes a policy type and its rule fields into a CSV-safe line.
// Fields are separated by ", " to match the conventional layout of Casbin policy
// files, which LoadPolicyLine accepts because its reader trims leading spaces.
// Fields containing commas are properly quoted so the line can be round-tripped
// through LoadPolicyLine without corruption. Fields containing a line break are
// rejected, because policy lines are loaded one physical line at a time.
func PolicyLineToCsv(ptype string, rule []string) (string, error) {
	record := append([]string{ptype}, rule...)

	// Each field is written as its own single-field record so that the standard
	// library decides on quoting, then the fields are joined with ", ".
	var buf bytes.Buffer
	w := csv.NewWriter(&buf)
	fields := make([]string, 0, len(record))
	for _, field := range record {
		if strings.Contains(field, "\n") {
			return "", fmt.Errorf("invalid policy field %q: line breaks are not allowed", field)
		}

		buf.Reset()
		if err := w.Write([]string{field}); err != nil {
			return "", err
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return "", err
		}
		fields = append(fields, strings.TrimRight(buf.String(), "\r\n"))
	}

	return strings.Join(fields, ", "), nil
}

// LoadPolicyArray loads a policy rule to model.
func LoadPolicyArray(rule []string, m model.Model) error {
	if len(rule) == 0 || rule[0] == "" {
		return errors.New("invalid policy rule: missing policy type")
	}

	key := rule[0]
	sec := key[:1]
	ok, err := m.HasPolicyEx(sec, key, rule[1:])
	if err != nil {
		return err
	}
	if ok {
		return nil // skip duplicated policy
	}

	err = m.AddPolicy(sec, key, rule[1:])
	if err != nil {
		return err
	}

	return nil
}

// Adapter is the interface for Casbin adapters.
type Adapter interface {
	// LoadPolicy loads all policy rules from the storage.
	LoadPolicy(model model.Model) error
	// SavePolicy saves all policy rules to the storage.
	SavePolicy(model model.Model) error

	// AddPolicy adds a policy rule to the storage.
	// This is part of the Auto-Save feature.
	AddPolicy(sec string, ptype string, rule []string) error
	// RemovePolicy removes a policy rule from the storage.
	// This is part of the Auto-Save feature.
	RemovePolicy(sec string, ptype string, rule []string) error
	// RemoveFilteredPolicy removes policy rules that match the filter from the storage.
	// This is part of the Auto-Save feature.
	RemoveFilteredPolicy(sec string, ptype string, fieldIndex int, fieldValues ...string) error
}

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

package fileadapter

import (
	"bufio"
	"errors"
	"os"
	"strings"

	"github.com/casbin/casbin/v3/model"
	"github.com/casbin/casbin/v3/persist"
)

// FilteredAdapter is the filtered file adapter for Casbin. It can load policy
// from file or save policy to file and supports loading of filtered policies.
type FilteredAdapter struct {
	*Adapter
	filtered bool
}

// Filter defines the filtering rules for a FilteredAdapter's policy. Empty values
// are ignored, but all others must match the filter.
type Filter struct {
	P  []string
	G  []string
	G1 []string
	G2 []string
	G3 []string
	G4 []string
	G5 []string
}

// NewFilteredAdapter is the constructor for FilteredAdapter.
func NewFilteredAdapter(filePath string) *FilteredAdapter {
	a := FilteredAdapter{}
	a.filtered = true
	a.Adapter = NewAdapter(filePath)
	return &a
}

// LoadPolicy loads all policy rules from the storage.
func (a *FilteredAdapter) LoadPolicy(model model.Model) error {
	a.filtered = false
	return a.Adapter.LoadPolicy(model)
}

// LoadFilteredPolicy loads only policy rules that match the filter.
func (a *FilteredAdapter) LoadFilteredPolicy(model model.Model, filter interface{}) error {
	if filter == nil {
		return a.LoadPolicy(model)
	}
	if a.filePath == "" {
		return errors.New("invalid file path, file path cannot be empty")
	}

	filterValue, ok := filter.(*Filter)
	if !ok {
		return errors.New("invalid filter type")
	}
	err := a.loadFilteredPolicyFile(model, filterValue, persist.LoadPolicyLine)
	if err == nil {
		a.filtered = true
	}
	return err
}

func (a *FilteredAdapter) loadFilteredPolicyFile(model model.Model, filter *Filter, handler func(string, model.Model) error) error {
	f, err := os.Open(a.filePath)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		skip, err := filterLine(line, filter)
		if err != nil {
			return err
		}
		if skip {
			continue
		}

		if err = handler(line, model); err != nil {
			return err
		}
	}
	return scanner.Err()
}

// IsFiltered returns true if the loaded policy has been filtered.
func (a *FilteredAdapter) IsFiltered() bool {
	return a.filtered
}

// SavePolicy saves all policy rules to the storage.
func (a *FilteredAdapter) SavePolicy(model model.Model) error {
	if a.filtered {
		return errors.New("cannot save a filtered policy")
	}
	return a.Adapter.SavePolicy(model)
}

// filterLine reports whether the line must be skipped because it does not
// match the filter. The line is split with the same CSV parser as the full
// load and the save side (persist.ParsePolicyLine via persist.MatchPolicyLine),
// so fields quoted because they contain commas or quotes are treated as a
// single field instead of being silently split out of alignment.
//
// A line that cannot be parsed returns an error and aborts the load, mirroring
// LoadPolicyLine; it is never silently filtered or loaded with shifted fields.
func filterLine(line string, filter *Filter) (bool, error) {
	if filter == nil {
		return false, nil
	}

	tokens, err := persist.ParsePolicyLine(line)
	if err != nil {
		return false, err
	}
	if len(tokens) == 0 {
		// Blank or comment line: nothing to filter, let the handler ignore it.
		return false, nil
	}

	var filterSlice []string
	switch strings.TrimSpace(tokens[0]) {
	case "p":
		filterSlice = filter.P
	case "g":
		filterSlice = filter.G
	case "g1":
		filterSlice = filter.G1
	case "g2":
		filterSlice = filter.G2
	case "g3":
		filterSlice = filter.G3
	case "g4":
		filterSlice = filter.G4
	case "g5":
		filterSlice = filter.G5
	}

	match, err := persist.MatchPolicyLine(line, filterSlice)
	if err != nil {
		return false, err
	}
	// Skip lines that do not match; keep (return false) the matching lines.
	return !match, nil
}

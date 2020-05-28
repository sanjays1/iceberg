// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"gopkg.in/yaml.v2"
)

type CachePolicy struct {
	ID         string           `json:"id" yaml:"id"`
	Statements []CacheStatement `json:"statements" yaml:"statements"`
}

func (p CachePolicy) Clone() CachePolicy {
	statements := make([]CacheStatement, 0, len(p.Statements))
	for _, s := range p.Statements {
		statements = append(statements, s.Clone())
	}
	return CachePolicy{
		ID:         p.ID,
		Statements: statements,
	}
}

func (p CachePolicy) Validate() error {
	for i, s := range p.Statements {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("cache statement %d (%q) is invalid: %w", i, s.ID, err)
		}
	}
	return nil
}

func (p CachePolicy) Evaluate(path string) (bool, bool, Duration) {
	cache := false
	expires := false
	duration := Duration(0)
	for _, statement := range p.Statements {
		if !statement.MatchPath(path) {
			continue
		}
		if !statement.Cache {
			return false, false, Duration(0)
		}
		cache = true
		expires = statement.Expires
		duration = statement.Duration
	}
	return cache, expires, duration
}

func ParseCachePolicy(path string, format string) (*CachePolicy, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading cache policy from path %q: %w", path, err)
	}
	if format == "json" {
		p := &CachePolicy{}
		err = json.Unmarshal(b, p)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling cache policy from path %q: %w", path, err)
		}
		return p, nil
	}
	if format == "yaml" {
		p := &CachePolicy{}
		err = yaml.Unmarshal(b, p)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling cache policy from path %q: %w", path, err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("unknown cache policy format %q", format)
}

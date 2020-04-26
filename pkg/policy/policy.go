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

const (
	Allow    = "allow"
	Deny     = "deny"
	Wildcard = "*"
)

var (
	StatementDefaultAllow = Statement{
		ID:       "DefaultAllow",
		Effect:   Allow,
		Paths:    []string{Wildcard},
		Users:    []string{Wildcard},
		NotUsers: []string{},
	}
)

var (
	PolicyDefaultAllow = Policy{
		Statements: []Statement{
			StatementDefaultAllow,
		},
	}
	PolicyDefaultDeny = Policy{
		Statements: []Statement{},
	}
)

type Policy struct {
	ID         string      `json:"id" yaml:"id"`
	Statements []Statement `json:"statements" yaml:"statements"`
}

func (p Policy) Clone() Policy {
	statements := make([]Statement, 0, len(p.Statements))
	for _, s := range p.Statements {
		statements = append(statements, s.Clone())
	}
	return Policy{
		ID:         p.ID,
		Statements: statements,
	}
}

func (p Policy) Validate() error {
	for i, s := range p.Statements {
		if err := s.Validate(); err != nil {
			return fmt.Errorf("statement %d (%q) is invalid: %w", i, s.ID, err)
		}
	}
	return nil
}

func (p *Policy) Evaluate(path string, user *User) bool {
	allow := false
	for _, statement := range p.Statements {
		if !statement.MatchPath(path) {
			continue
		}
		if len(statement.Users) > 0 {
			if statement.MatchUser(user) {
				if statement.Effect == Allow {
					allow = true
				} else {
					return false
				}
			}
		} else if len(statement.NotUsers) > 0 {
			if statement.MatchNotUser(user) {
				if statement.Effect == Allow {
					allow = true
				} else {
					return false
				}
			}
		}
	}
	return allow
}

func Parse(path string, format string) (*Policy, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading policy from path %q: %w", path, err)
	}
	if format == "json" {
		p := &Policy{}
		err = json.Unmarshal(b, p)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling policy from path %q: %w", path, err)
		}
		return p, nil
	}
	if format == "yaml" {
		p := &Policy{}
		err = yaml.Unmarshal(b, p)
		if err != nil {
			return nil, fmt.Errorf("error unmarshaling policy from path %q: %w", path, err)
		}
		return p, nil
	}
	return nil, fmt.Errorf("unknown policy format %q", format)
}

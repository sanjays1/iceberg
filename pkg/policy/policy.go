package policy

import (
	"crypto/x509/pkix"
	"fmt"
	"strings"
)

func match(pattern string, value string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		if strings.HasPrefix(value, pattern[0:len(pattern)-2]) {
			return true
		}
	} else {
		if pattern == value {
			return true
		}
	}
	return false
}

type User struct {
	Subject pkix.Name
}

func (u *User) DistinguishedName() string {
	terms := make([]string, 0)
	for _, n := range u.Subject.Names {
		if n.Type.Equal([]int{2, 5, 4, 6}) {
			terms = append(terms, fmt.Sprintf("C=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 10}) {
			terms = append(terms, fmt.Sprintf("O=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 11}) {
			terms = append(terms, fmt.Sprintf("OU=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 3}) {
			terms = append(terms, fmt.Sprintf("CN=%s", n.Value))
		} else {
			terms = append(terms, fmt.Sprintf("%s=%s", n.Type, n.Value))
		}
	}
	return "/" + strings.Join(terms, "/")
}

type Policy struct {
	Statements []Statement `json:"statements"`
}

func (p *Policy) Evaluate(path string, user *User) bool {
	allow := false
	for _, statement := range p.Statements {
		if !statement.MatchPath(path) {
			continue
		}
		if len(statement.Users) > 0 {
			if statement.MatchUser(user) {
				if statement.Effect == "allow" {
					allow = true
				} else {
					return false
				}
			}
		} else if len(statement.NotUsers) > 0 {
			if statement.MatchNotUser(user) {
				if statement.Effect == "allow" {
					allow = true
				} else {
					return false
				}
			}
		}
	}
	return allow
}

type Statement struct {
	ID       string   `json:"id"`
	Effect   string   `json:"effect"`
	Paths    []string `json:"paths"`
	Users    []string `json:"users,omitempty"`
	NotUsers []string `json:"not_users,omitempty"`
}

func (s *Statement) MatchPath(path string) bool {
	for _, candidate := range s.Paths {
		if match(candidate, path) {
			return true
		}
	}
	return false
}

func (s *Statement) MatchUser(user *User) bool {
	dn := user.DistinguishedName()
	for _, candidate := range s.Users {
		if match(candidate, dn) {
			return true
		}
	}
	return false
}

func (s *Statement) MatchNotUser(user *User) bool {
	dn := user.DistinguishedName()
	for _, candidate := range s.NotUsers {
		if match(candidate, dn) {
			return false
		}
	}
	return true
}

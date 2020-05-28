// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"errors"
)

type CacheStatement struct {
	ID       string   `json:"id" yaml:"id"`
	Paths    []string `json:"paths" yaml:"paths"`
	Cache    bool     `json:"cache" yaml:"cache"`
	Expires  bool     `json:"expires" yaml:"expires"`
	Duration Duration `json:"duration" yaml:"duration"`
}

func (s CacheStatement) Clone() CacheStatement {
	return CacheStatement{
		ID:       s.ID,
		Cache:    s.Cache,
		Paths:    append([]string{}, s.Paths...),
		Duration: s.Duration,
	}
}

func (s CacheStatement) Validate() error {
	if len(s.Paths) == 0 {
		return errors.New("missing paths, expecting at least one path")
	}
	return nil
}

func (s CacheStatement) MatchPath(path string) bool {
	for _, candidate := range s.Paths {
		if Match(candidate, path) {
			return true
		}
	}
	return false
}

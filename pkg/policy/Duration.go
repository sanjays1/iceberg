// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"time"
)

type Duration time.Duration

func (c Duration) MarshalText() ([]byte, error) {
	return []byte(time.Duration(c).String()), nil
}

func (c *Duration) UnmarshalText(text []byte) error {
	d, err := time.ParseDuration(string(text))
	if err != nil {
		return err
	}
	*c = Duration(d)
	return nil
}

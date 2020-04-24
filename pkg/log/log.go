// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package log

import (
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// SimpleLogger is a simple logger that logs using JSON Lines.
type SimpleLogger struct {
	writer io.Writer
	mutex  *sync.Mutex
}

func NewSimpleLogger(w io.Writer) *SimpleLogger {
	return &SimpleLogger{
		writer: w,
		mutex:  &sync.Mutex{},
	}
}

func (s *SimpleLogger) Log(msg string, fields ...map[string]interface{}) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	obj := map[string]interface{}{
		"ts":  time.Now().Format(time.RFC3339),
		"msg": msg,
	}
	if len(fields) > 0 {
		for k, v := range fields[0] {
			obj[k] = v
		}
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return fmt.Errorf("error marshaling long entry: %w", err)
	}
	_, err = fmt.Fprintln(s.writer, string(b))
	return err
}

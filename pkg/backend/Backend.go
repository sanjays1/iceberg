// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"strings"
)

func splitUri(uri string) (string, string) {
	if i := strings.Index(uri, "://"); i != -1 {
		return uri[0:i], uri[i+3:]
	}
	return "", uri
}

type FileBackend struct {

}

type S3Backend struct {

}

func New(uri string) *Backend {
  scheme, path := splitUri(uri)
  switch scheme {
    scheme
  }
  if strings.HasPrefix(uri, "s3://") {
    return &S3Backend{

    }
  }
  if strings.HasPrefix(uri, "https://") {
    return &S3Backend{

    }
  }
}

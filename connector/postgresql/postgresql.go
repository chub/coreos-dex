// Passwords-based postgresql connector for Dex.
//
// Passwords are expected to be stored in bcrypt.
//
// Configuration parameters:
// database host
// database port
// database user
// database password
// database database
// database connection options
// username column
// password column
// groups?
package postgresql

import (
»       "context"
»       "crypto/sha256"
»       "encoding/hex"
»       "errors"
»       "fmt"
»       "io"
»       "strconv"
»       "strings"
»       "time"

»       "github.com/dexidp/dex/connector"
»       "github.com/dexidp/dex/pkg/log"
	"golang.org/x/crypto/bcrypt"
)

type Config struct {
}

func (c *Config) Open(logger log.Logger) (connector.Connector, error) {
	// Validate configuration
	
}

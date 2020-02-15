// Authenticates against user data stored in PostgreSQL.
// Passwords are assumed to be bcrypted.

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/go-pg/pg"
	"golang.org/x/crypto/bcrypt"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/pkg/log"
)

type Config struct {
	// Connection string to Postgres (including ODBC flags)
	PgDbUrl string `json:"dbURL"`

	// Table to query for username/bcrypt password
	PgAuthTableName string `json:"authTableName"`
	// Column to match username
	PgAuthIdColumnName string `json:"authIdColumnName"`
	// Column to retrieve bcrypt password
	PgAuthBcryptColumnName string `json:"authBcryptColumnName"`

	// [optional] application used in logs on the postgres side
	PgAppName string `json:"appName"` // optional

	// Connection Pool parameters
	PgPoolSize int `json:"poolSize"`
	PgMinIdleConns int `json:"minIdleConns"`
	PgMaxConnAge string `json:"maxConnAge"` // converted to time.Duration
	PgPoolTimeout string `json:"poolTimeout"` // converted to time.Duration
	PgIdleTimeout string `json:"idleTimeout"` // converted to time.Duration
	PgIdleCheckFrequency string `json:"idleCheckFrequency"` // converted to time.Duration

	// UsernamePrompt allows customers to override the label used to identify the username field.
	// Defaults to "Username"
	UsernamePrompt string `json:"usernamePrompt"`
}

type postgresConnector struct {
	Config

	// postgres connection handler
	db *pg.DB

	logger log.Logger
}

var (
	_ connector.PasswordConnector = (*postgresConnector)(nil)
)

// Open returns an authentication strategy that queries PostgreSQL tables.
func (c *Config) Open(id string, logger log.Logger) (connector.Connector, error) {
	logger.Debug("opening postgres connector now")
	conn, err := c.OpenConnector(logger)
	if err != nil {
		return nil, err
	}
	return connector.Connector(conn), nil
}

// OpenConnector is the same as Open but returns a type with all implemented connector interfaces.
func (c *Config) OpenConnector(logger log.Logger) (interface {
	connector.Connector
	connector.PasswordConnector
}, error) {
	return c.openConnector(logger)
}

func (c *Config) openConnector(logger log.Logger) (*postgresConnector, error) {
	pgOptions, err := generatePgOptions(c)
	if err != nil {
		return nil, fmt.Errorf("postgres: unable to configure options: %v", err)
	}

	// Initial database connection pool
	db := pg.Connect(pgOptions)

	// Verify connection immediately
	_, err = db.Exec("SELECT 1")
	if err != nil {
		return nil, fmt.Errorf("postgres: Unable to verify connection, %v", err)
	}

	return &postgresConnector{*c, db, logger}, nil
}

func generatePgOptions(config *Config) (*pg.Options, error) {
	var options *pg.Options
	var err error

	if config.PgDbUrl != "" {
		options, err = pg.ParseURL(config.PgDbUrl)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid value for dbUrl %q: %v", config.PgDbUrl, err)
		}
	} else {
		options = &pg.Options{}
	}

	if config.PgAppName != "" {
		options.ApplicationName = config.PgAppName
	}

	if config.PgPoolSize != 0 {
		if config.PgPoolSize < 0 {
			return nil, fmt.Errorf("postgres: invalid value for poolSize %q", config.PgPoolSize)
		}
		options.PoolSize = config.PgPoolSize
	}

	if config.PgMinIdleConns != 0 {
		options.MinIdleConns = config.PgMinIdleConns
	}

	if config.PgMaxConnAge != "" {
		options.MaxConnAge, err = time.ParseDuration(config.PgMaxConnAge)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid value for maxConnAge %q: %v", config.PgMaxConnAge, err)
		}
	}

	if config.PgPoolTimeout != "" {
		options.PoolTimeout, err = time.ParseDuration(config.PgPoolTimeout)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid value for poolTimeout %q: %v", config.PgPoolTimeout, err)
		}
	}

	if config.PgIdleTimeout != "" {
		options.IdleTimeout, err = time.ParseDuration(config.PgIdleTimeout)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid value for idleTimeout %q: %v", config.PgIdleTimeout, err)
		}
	}

	if config.PgIdleCheckFrequency != "" {
		options.IdleCheckFrequency, err = time.ParseDuration(config.PgIdleCheckFrequency)
		if err != nil {
			return nil, fmt.Errorf("postgres: invalid value for idleCheckFrequency %q: %v", config.PgIdleCheckFrequency, err)
		}
	}

	return options, nil
}

func (c *postgresConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPass bool, err error) {
	// TODO(chub): Trim the username

	// Plausible deniability: assume the username is correct and accept it as the identity.
	//
	// This is done because this function always returns Identity.
	identity.Email = username
	validPass = false

	if password == "" {
		return identity, validPass, nil
	}

	_, err = c.db.Exec("SELECT 1")
	if err != nil {
		c.logger.Warn("Failed to check user due to failed connection", username, err)
		return identity, validPass, fmt.Errorf("postgres: Unable to verify connection, %v", err)
	}


	// This pattern was least confusing for parametric column and tables names.
	var bcryptPassword string
	err = c.db.Model().
		Column(c.Config.PgAuthBcryptColumnName).
			Table(c.Config.PgAuthTableName).
				Where(c.Config.PgAuthIdColumnName + " = ?", username).Select(&bcryptPassword)
	if err != nil {
		return identity, validPass, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(bcryptPassword), []byte(password))
	validPass = (err == nil)

	return identity, validPass, nil
}

func (c *postgresConnector) Prompt() string {
	return c.UsernamePrompt
}

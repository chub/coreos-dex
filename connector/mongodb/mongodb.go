// The mongodb package authenticates against a mongodb collection.
//
// Caution: This is not a general purpose plugin as the hash used is:
// bcrypt(rounds=[10,12], sha256(plaintext password)), which, although commonly
// used in web frontends, is not a standard.  At the moment, this is not
// configurable.
package mongodb

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/chub/coreos-dex/connector"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

type Config struct {
	DbHosts []string `json:"dbHosts"`
	DbUsername string `json:"dbUsername"` // optional
	DbPassword string `json:"dbPassword"` // optional
	DbAuthSource string `json:"dbAuthSource"` // optional
	DbAuthMechanism string `json:"dbAuthMechanism"` // optional
	ConnectTimeoutMs int `json:"connectTimeoutMs"` // optional
	DbDirect bool `json:"dbDirect"` // optional
	QueryTimeoutMs int `json:"queryTimeoutMs"` // optional
	DatabaseName string `json:"databaseName"`
	CollectionName string `json:"collectionName"`
	UserIDField string `json:"userIDField"`
	UsernameField string `json:"usernameField"`
	EmailFields []string `json:"emailFields"` // optional
	PasswordField string `json:"passwordField"`
}

type mongoDocument struct {
	Extra bson.M `bson:",inline"`
}

type mongoConnector struct {
	logger     logrus.FieldLogger
	session    *mgo.Session
	collection *mgo.Collection
	config     *Config
}

var (
	ErrDatabaseIsGone = errors.New("Database is not reachable or did not respond to a ping")
)

// Returns values of nested fields from unstructured bson objects.
func getFieldAsString(root bson.M, field string) (string, bool) {
	node := root

	fields := strings.Split(field, ".")

	for i := 0; i < len(fields); i++ {
		f := fields[i]

		// Check if we're on our last leg.
		if i == len(fields)-1 {
			stringNode, ok := node[f].(string)
			if ok {
				return stringNode, true
			} else {
				return "", false
			}
		} else if list, ok := node[f].([]interface{}); !!ok {
			// Check if we may be traversing into an array
			if i >= len(fields) {
				// Nope, we're no good here.
				return "", false
			}

			// Check if the next field is actually a numerical index.
			var index int
			var err error
			if index, err = strconv.Atoi(fields[i+1]); err != nil {
				// Nope, it wasn't a numerical index.
				return "", false
			}

			if index >= len(list) {
				// Nope, the index is out of bounds in this array.
				return "", false
			}

			if node, ok = list[index].(bson.M); !ok {
				// Nope, we weren't able to deference to an expected object.
				// TODO: We may face nested arrays here, but that's for some time in the future.
				return "", false
			}

			// Advance the counter since we also consumed the array index field.
			i++
		} else if node, ok = node[f].(bson.M); !ok {
			return "", false
		}
	}

	// Did not find the element
	return "", false
}

func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	// Validate configuration
	if len(c.DbHosts) == 0 {
		return nil, errors.New("dbHosts must not be empty")
	}

	if c.DatabaseName == "" {
		return nil, errors.New("databaseName must not be empty")
	}

	if c.CollectionName == "" {
		return nil, errors.New("collectionName must not be empty")
	}

	if c.UserIDField == "" {
		return nil, errors.New("usernameIDField must not be empty")
	}

	if c.UsernameField == "" {
		return nil, errors.New("usernameField must not be empty")
	}

	if c.PasswordField == "" {
		return nil, errors.New("passwordField must not be empty")
	}

	logger.Infof("Attempting to connect to mongodb")

	// Connect to the database, 10 second timeout (mgo default)
	connectTimeout := time.Duration(10) * time.Millisecond
	if c.ConnectTimeoutMs != 0 {
		connectTimeout = time.Duration(c.ConnectTimeoutMs) * time.Millisecond
		logger.Infof("Setting mongodb connect timeout to %v", connectTimeout)
	}
	mongoDialInfo := &mgo.DialInfo {
		Addrs: c.DbHosts,
		Database: c.DbAuthSource,
		Username: c.DbUsername,
		Password: c.DbPassword,
		Timeout: connectTimeout,
		Mechanism: c.DbAuthMechanism,
		Direct: c.DbDirect,
	}
	session, err := mgo.DialWithInfo(mongoDialInfo)
	if err != nil {
		logger.Errorf("Failed to connect to mongo database. %v", err)
		return nil, err
	}

	// Set query timeout, if defined
	if c.QueryTimeoutMs != 0 {
		queryTimeout := time.Duration(c.QueryTimeoutMs) * time.Millisecond
		logger.Infof("Setting mongodb query timeout to %v", queryTimeout)
		session.SetSocketTimeout(queryTimeout)
	}

	// Set the read mode (reading from secondaries are okay)
	session.SetMode(mgo.Eventual, true)

	// Check the connection
	if err := session.Ping(); err != nil {
		logger.Errorf("Unable to completely connect to server: %v", err)
		return nil, err
	}
	logger.Infof("Successfully connected to mongodb")

	// Switch to the collection
	collection := session.DB(c.DatabaseName).C(c.CollectionName)

	// Create internal state struct
	m := mongoConnector {
		logger: logger,
		session: session,
		collection: collection,
		config: c,
	}

	return &m, nil
}

func (c *mongoConnector) fetchMongoUser(username string) (mongoDocument, error) {
	document := mongoDocument{}

	// Trim leading and trailing spaces
	username = strings.TrimSpace(username)

	// Expression to search specific fields with
	searchFilter := bson.M{"$regex": bson.RegEx{
		// TODO: Properly escape this regex. "^" + re.Escape(username) + "$"
		Pattern: "^" + username + "$",
		Options: "i",
	}}

	// Check the server is up
	if err := c.session.Ping(); err != nil {
		c.logger.Errorf("Unable to reach server: %v", err)
		return document, ErrDatabaseIsGone
	}

	// Search for the username (case-insensitive)
	err := c.collection.Find(bson.M{c.config.UsernameField: searchFilter}).One(&document)
	if err == nil {
		// Found the user by username
		return document, nil
	}

	// Search for the user using the email fields in the order they were defined (case-insensitive)
	for _, emailField := range c.config.EmailFields {
		err := c.collection.Find(bson.M{emailField: searchFilter}).One(&document)
		if err == nil {
			// Found the user by one of the email fields.
			return document, nil
		}
	}

	// We did not find the user
	return document, errors.New("User not found in database")
}

func (c *mongoConnector) findUser(input string) (connector.Identity, mongoDocument, error) {
	var err error
	var document mongoDocument

	if document, err = c.fetchMongoUser(input); err != nil {
		return connector.Identity{}, document, err
	}

	// Fill in the identity
	var email string
	var emailVerified, ok bool
	for _, emailField := range c.config.EmailFields {
		if email, ok = getFieldAsString(document.Extra, emailField); ok {
			emailVerified = true
			break;
		}
	}

	userId, _ := getFieldAsString(document.Extra, c.config.UserIDField)
	username, _ := getFieldAsString(document.Extra, c.config.UsernameField)
	identity := connector.Identity{
		UserID: userId,
		Username: username,
		Email: email,
		EmailVerified: emailVerified,
	}

	return identity, document, nil
}

func (c *mongoConnector) Login(ctx context.Context, s connector.Scopes, username, password string) (identity connector.Identity, validPass bool, err error) {
	if username == "" {
		return identity, false, nil
	}

	if password == "" {
		return identity, false, nil
	}

	identity, result, err := c.findUser(username)
	if err != nil {
		if err == ErrDatabaseIsGone {
			return identity, false, err
		} else {
			c.logger.Infof("Unable to fetch user data (%s) %v", username, err)
			return identity, false, nil
		}
	}

	bcryptPassword, ok := getFieldAsString(result.Extra, c.config.PasswordField)
	if !ok {
		c.logger.Infof("Unable to verify user (%s); unable to read bcrypt field", username)
		return identity, false, nil
	}

	if bcryptPassword == "" {
		c.logger.Infof("Unable to verify user (%s); empty/unset bcrypt field", username)
		return identity, false, errors.New(fmt.Sprintf("Bcrypt password not available for user \"%s\"", username))
	}

	hashedPassword := []byte(bcryptPassword)
	sum := sha256.New()
	io.WriteString(sum, password)
	shaPassword := sum.Sum(nil)
	if err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(hex.EncodeToString(shaPassword))); err != nil {
		c.logger.Infof("Unable to verify user (%s); password does not match hash: %v", username, err)
		return identity, false, nil
	}

	c.logger.Infof("Verified user (%s) as %v", username, identity)
	return identity, true, nil
}

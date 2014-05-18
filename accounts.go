// A simple password store that utilizes bcrypt to hash passwords with individual salts.
// The password store is backed by a leveldb and data is stored in json format. The data stored
// on a user is intentenally sparse. It should be used only to authenticate users, any additional
// information should be stored in a separate database.
package accounts

import (
	"code.google.com/p/go.crypto/bcrypt"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/syndtr/goleveldb/leveldb"
	//	"log"
	"math/big"
	"regexp"
	"time"
)

/**
TODO create tests.
TODO implement a way to limit number of previous passwords to keep.
		right now we keep only the most recent old password.
TODO implement a way to set optionally disallow password re-use
TODO allow for global fail-rate checking.
*/

// Accounts keeps global preferences and maintains a database of Users
type Accounts struct {
	// ponter to level db
	db *leveldb.DB
	// the default expiration time of passwords.
	defaultExp int64
	// the max nuber of times a user can fail to login before the account is "locked"
	maxFails int
}

// load an existing password store at path, specify the number of seconds before a password
// should expire, the number of consecutive failed logins before an account locks.
func NewAccounts(path string, exp int64, fails int) (*Accounts, error) {
	// set up access to the accounts DB
	db, err := leveldb.OpenFile(path, nil)
	if err != nil {
		return nil, err
	}
	a := new(Accounts)
	a.db = db
	a.defaultExp = exp
	a.maxFails = fails
	return a, nil
}

// This essentially logs a user in. If the passwords and the account is clean (not locked or
// expired) it returns a pointer to the User and a nil error. If the password has expired,
// the User is still returned, but the error indicates an expired password. The caller may
// safely ignore the error.
func (a *Accounts) CheckPassword(username, password string) (*Account, error) {
	account, err := a.getAccount(username)
	if err != nil {
		time.Sleep(2 * time.Second)
		return nil, err
	}

	// if a max number of fails is set, enforce it.
	if account.Fails > a.maxFails && a.maxFails > 0 {
		return nil, errors.New("Locked")
	}

	// compare hashes.
	if account.Current.check([]byte(password)) != nil {
		// passwords did not match. log a failed attempt
		account.Fails += 1
		if err = a.putAccount(account); err != nil {
			return nil, err
		}
		time.Sleep(2 * time.Second)
		return nil, errors.New("Invalid")
	}

	// expired passwords will allow login but will also return an error. It is upto the caller
	// to decide how to handle this (they can ignore it, force the user to change passwords,
	// reset the password, or forbid access).
	if (account.Current.Temporary && account.Current.Created+43200 <= time.Now().Unix()) ||
		(0 < a.defaultExp && account.Current.Created+a.defaultExp <= time.Now().Unix()) {
		// note that while it does not count as a failed login,
		// it does not reset the failed attempts.
		account.LastLogin = time.Now().Unix()
		if err = a.putAccount(account); err != nil {
			return nil, err
		}
		return account, errors.New("Expired")
	}

	// Set failed attempts back to 0
	account.Fails = 0
	account.LastLogin = time.Now().Unix()
	if err = a.putAccount(account); err != nil {
		return nil, err
	}
	return account, nil
}

// Resets the user's password. If no password is specified, one will
// be generated. The new temporary password is returned. DO NOT store this password anywhere.
func (a *Accounts) ResetPasswd(username, passwd string) (string, error) {
	account, err := a.getAccount(username)
	if err != nil {
		return "", err
	}

	account.Previous = []credentials{account.Current}

	pass := ""
	if passwd != "" {
		pass = passwd
	} else {
		pass, err = GenPassword(12)
		if err != nil {
			return "", errors.New("Could not generate temporary password")
		}
	}

	account.Current, err = newCredentials([]byte(pass), true)
	if err != nil {
		return "", err
	}
	if err = a.putAccount(account); err != nil {
		return "", err
	}

	return pass, nil
}

// a helper method to get a user from the database.
func (a *Accounts) getAccount(username string) (*Account, error) {
	data, err := a.db.Get([]byte(username), nil)
	if err != nil {
		return nil, errors.New("Could not find user")
	}
	account := new(Account)
	account.accts = a

	err = json.Unmarshal(data, account)
	if err != nil {
		return nil, err
	}
	return account, nil
}

// a helper method to pull a user out of the database.
func (a *Accounts) putAccount(account *Account) error {
	bytes, err := json.Marshal(account)
	if err != nil {
		return err
	}
	if err = a.db.Put([]byte(account.UserName), bytes, nil); err != nil {
		return errors.New("Unable to update or add user.")
	}
	return nil
}

// Creates a new user and stores them into the database. If no password is specified, one will
// be generated. The new temporary password is returned. DO NOT store this password anywhere.
func (a *Accounts) CreateAccount(username, email, passwd string, level int) (string, error) {
	if _, err := a.getAccount(username); err == nil {
		return "", errors.New("Cannot create user. User already exists")
	}

	// check that the email is an email address
	check := regexp.MustCompile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4}$")
	if !check.MatchString(email) {
		return "", errors.New("Invalid email address")
	}

	var cr credentials
	var err error
	var pass string
	if passwd != "" {
		cr, err = newCredentials([]byte(passwd), false)
		pass = ""
	} else{
		if pass, err = GenPassword(12); err != nil {
			return "", errors.New("Could not generate temporary password")
		} else {
			cr, err = newCredentials([]byte(pass), false)
		}
	}
	if err != nil {
		return "", err
	}

	// write account struct
	account := &Account{
		User: User{
			UserName:  username,
			Email:     email,
			LastLogin: 0,
			Level:     level,
		},
		accountInfo: accountInfo{
			Current: cr,
			Fails:   0,
		},
		accts: a,
	}
	if err = a.putAccount(account); err != nil {
		return "", err
	}
	return pass, nil
}

// Deletes an existing user.
func (a *Accounts) RemoveAccount(username string) error {
	if err := a.db.Delete([]byte(username), nil); err != nil {
		return errors.New("Unable to delete user.")
	}
	return nil
}

// Returns a slice of all Users. User should contain no private data, nor allow the caller
// to affect changes to the associated account.
func (a *Accounts) GetAllUsers() ([]User, error) {
	users := []User{}
	iter := a.db.NewIterator(nil, nil)
	for iter.Next() {
		value := iter.Value()
		user := User{}
		err := json.Unmarshal(value, &user)
		if err != nil {
			break
		}
		users = append(users, user)
	}
	iter.Release()
	if err := iter.Error(); err != nil {
		return users, err
	}

	return users, nil
}

// Gets a single user by username, the result contains no private data nor allows the caller
// to affect changes to the associated account
func (a *Accounts) GetUser(username string) (*User, error) {
	data, err := a.db.Get([]byte(username), nil)
	if err != nil {
		return nil, errors.New("Could not find user")
	}
	user := new(User)

	err = json.Unmarshal(data, user)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// Closes the underlying database connection.
func (a *Accounts) Close() error {
	return a.db.Close()
}

// Generate a random password that contains at least on letter of each case,
// a number and a symbol.
func GenPassword(length int) (string, error) {
	if length < 5 {
		return "", errors.New("length must be at least 5")
	}
	numbers := []byte("0123456789")
	letters := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	symbols := []byte("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")

	num, err := rand.Int(rand.Reader, big.NewInt(int64(len(numbers))))
	if err != nil {
		return "", err
	}
	lower, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
	if err != nil {
		return "", err
	}
	upper, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
	if err != nil {
		return "", err
	}
	symbol, err := rand.Int(rand.Reader, big.NewInt(int64(len(symbols))))
	if err != nil {
		return "", err
	}

	pass := make([]byte, length)
	pass[0] = numbers[num.Int64()]
	pass[1] = letters[lower.Int64()] + 32
	pass[2] = letters[upper.Int64()]
	pass[3] = symbols[symbol.Int64()]

	// fill the rset of the slice with random printable chars
	for k, _ := range pass[4:] {
		r, err := rand.Int(rand.Reader, big.NewInt(126-33))
		if err != nil {
			return "", err
		}
		pass[k+4] = byte(r.Int64() + 33)
	}
	// shuffle the characters
	for k, _ := range pass {
		r, err := rand.Int(rand.Reader, big.NewInt(int64(length)))
		if err != nil {
			return "", err
		}
		temp := pass[k]
		pass[k] = pass[r.Int64()]
		pass[r.Int64()] = temp
	}
	return string(pass), nil
}

// password hash, salt, and a little bit of metadata
type credentials struct {
	// time of password creation
	Created int64
	// is this a temp password?
	Temporary bool
	// the hashed password and the salt used.
	Secret, Salt []byte
}

// helper function to make a hash and a salt from a given password.
func newCredentials(password []byte, temp bool) (credentials, error) {
	// generate salt
	salt := make([]byte, 8)
	_, err := rand.Read(salt)
	if err != nil {
		return credentials{}, errors.New("Could not generate salt.")
	}

	// generate hash
	hash, err := bcrypt.GenerateFromPassword(append(password, salt...), bcrypt.DefaultCost)
	if err != nil {
		return credentials{}, errors.New("Could not generate hash.")
	}
	return credentials{time.Now().Unix(), temp, hash, salt}, nil
}

// helper method to check the credentials against a password.
func (c credentials) check(plain []byte) error {
	return bcrypt.CompareHashAndPassword(c.Secret, append(plain, c.Salt...))
}

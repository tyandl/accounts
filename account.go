package accounts

import (
	"errors"
)

// Account keeps some information on a user. if additional information is required,
// it is recomended that it be stored in a separate database.
type Account struct {
	// ifnormation about the user.
	User
	// some private account information
	accountInfo
	// a pointer to the accounts object that returned this user.
	accts *Accounts
}

type User struct {
	// the user's name
	UserName string
	// the user's email address
	Email string
	// the users priviledge level (for the application)
	Level int
	// the time of last successful login.
	LastLogin int64
}

type accountInfo struct {
	// the current credentials
	Current credentials
	// previous credentials (so that we can prevent password reuse)
	Previous []credentials
	// number of consecutive failed login attempts
	Fails int
}

// Changes the specified user's password, user must provide old password,
// but the expiration is not checked. It is the caller's duty to verify that the
// new password meets their business rules (i.e is a strong enough password). As far as
// this library is concerned, any printable character is valid
// (unprintable characters are untested but may work))
func (a *Account) ChangePassword(oldPwd, newPwd string) error {
	// compare hashes.
	if a.Current.check([]byte(oldPwd)) != nil {
		return errors.New("Invalid")
	}
	var err error
	a.Previous = []credentials{a.Current}
	a.Current, err = newCredentials([]byte(newPwd), true)
	if err != nil {
		return err
	}
	if err := a.accts.putAccount(a); err != nil {
		return err
	}
	return nil
}

func (a *Account) GetLevel() int {
	return a.Level
}

func (a *Account) GetEmail() string {
	return a.Email
}

func (a *Account) GetLastLogin() int64 {
	return a.LastLogin
}

func (a *Account) SetUserName(userName string) error {
	old := a.UserName
	a.UserName = userName
	if err := a.accts.putAccount(a); err != nil {
		return err
	}
	if err := a.accts.RemoveAccount(old); err != nil {
		return err
	}
	return nil
}

func (a *Account) SetEmail(email string) error {
	a.Email = email
	if err := a.accts.putAccount(a); err != nil {
		return err
	}
	return nil
}

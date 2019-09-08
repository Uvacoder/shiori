package webserver

import (
	"fmt"

	"github.com/go-shiori/shiori/internal/database"

	"github.com/go-shiori/shiori/internal/model"
	"golang.org/x/crypto/bcrypt"
)

// authUser is method for checking whether user is authorized to access web interface
func (h *handler) authUser(username, password string, ownerMode bool) (model.Account, error) {
	// If LDAP client is not exist, just use database
	if h.LDAPClient == nil {
		return h.authUserDatabase(username, password, ownerMode)
	}

	return h.authUserLDAP(username, password, ownerMode)
}

func (h *handler) authUserDatabase(username, password string, ownerMode bool) (model.Account, error) {
	// Check if user's database is empty or there are no owner.
	// If yes, and user uses default account, let him in.
	searchOptions := database.GetAccountsOptions{
		Owner: true,
	}

	accounts, err := h.DB.GetAccounts(searchOptions)
	if err != nil {
		return model.Account{}, err
	}

	if len(accounts) == 0 && username == "shiori" && password == "gopher" {
		defaultAccount := model.Account{
			ID:       -1,
			Username: "shiori",
			Owner:    true,
		}

		return defaultAccount, nil
	}

	// Get account data from database
	account, exist := h.DB.GetAccount(username)
	if !exist {
		return account, fmt.Errorf("username doesn't exist")
	}

	// Compare password with database
	err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
	if err != nil {
		return account, fmt.Errorf("username and password don't match")
	}

	// If login request is as owner, make sure this account is owner
	if ownerMode && !account.Owner {
		return account, fmt.Errorf("account level is not sufficient as owner")
	}

	return account, nil
}

func (h *handler) authUserLDAP(username, password string, ownerMode bool) (model.Account, error) {
	// Search account in LDAP
	dn, username, err := h.LDAPClient.Search(username, ownerMode)
	if err != nil {
		return model.Account{}, err
	}

	// Make sure the password is valid
	err = h.LDAPClient.VerifyDN(dn, password)
	if err != nil {
		return model.Account{}, err
	}

	return model.Account{
		Username: username,
		Owner:    ownerMode,
	}, nil
}

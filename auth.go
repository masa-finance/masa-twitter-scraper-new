package twitterscraper

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/imperatrona/twitter-scraper/auth"
)

// IsLoggedIn check if scraper logged in
func (s *Scraper) IsLoggedIn() bool {
	s.isLogged = true
	s.setBearerToken(bearerToken2)
	req, err := http.NewRequest("GET", verifyCredentialsURL, nil)
	if err != nil {
		return false
	}
	var verify verifyCredentials
	err = s.RequestAPI(req, &verify)
	if err != nil || verify.Errors != nil {
		s.isLogged = false
		s.setBearerToken(BearerToken)
	} else {
		s.isLogged = true
	}
	return s.isLogged
}

// Login to Twitter
// Use Login(username, password) for ordinary login
// or Login(username, password, email) for login if you have email confirmation
// or Login(username, password, code_for_2FA) for login if you have two-factor authentication
func (s *Scraper) Login(credentials ...string) error {
	var username, password, confirmation string
	var err error
	if len(credentials) < 2 || len(credentials) > 3 {
		return fmt.Errorf("invalid credentials")
	}

	username, password = credentials[0], credentials[1]
	if len(credentials) == 3 {
		confirmation = credentials[2]
	}
	logrus.WithFields(logrus.Fields{
		"username":     username,
		"confirmation": confirmation != "",
	}).Info("Attempting to log in")

	loginFlow := auth.NewLoginFlow(s.client, bearerToken2, username, password, confirmation)
	err = loginFlow.Start()
	if err != nil {
		return err
	}
	s.bearerToken = loginFlow.BearerToken
	s.guestToken = loginFlow.GuestToken
	s.isLogged = loginFlow.IsLogged
	s.isOpenAccount = loginFlow.IsOpenAccount
	logrus.Info("Successfully logged in")
	return nil
}

// LoginOpenAccount as Twitter app
func (s *Scraper) LoginOpenAccount() error {
	loginFlow := auth.NewLoginFlow(s.client, "", "", "", "")
	err := loginFlow.LoginOpenAccount(appConsumerKey, appConsumerSecret)
	if err != nil {
		return err
	}
	s.setBearerToken(loginFlow.BearerToken)
	s.guestToken = loginFlow.GuestToken
	s.guestCreatedAt = time.Now()
	s.isLogged = loginFlow.IsLogged
	return nil
}

// Logout is reset session
func (s *Scraper) Logout() error {
	req, err := http.NewRequest("POST", logoutURL, nil)
	if err != nil {
		return err
	}
	err = s.RequestAPI(req, nil)
	if err != nil {
		return err
	}

	s.isLogged = false
	s.isOpenAccount = false
	s.guestToken = ""
	s.oAuthToken = ""
	s.oAuthSecret = ""
	s.client.WithJar()
	s.setBearerToken(BearerToken)
	return nil
}

func (s *Scraper) GetCookies() []*http.Cookie {
	var cookies []*http.Cookie
	for _, cookie := range s.client.GetCookies(twURL) {
		if strings.Contains(cookie.Name, "guest") {
			continue
		}
		cookie.Domain = twURL.Host
		cookies = append(cookies, cookie)
	}
	return cookies
}

func (s *Scraper) SetCookies(cookies []*http.Cookie) {
	s.client.SetCookies(twURL, cookies)
}

func (s *Scraper) ClearCookies() {
	s.client.WithJar()
}

func (s *Scraper) sign(method string, ref *url.URL) string {
	return auth.Sign(method, s.oAuthToken, s.oAuthSecret, appConsumerKey, appConsumerSecret, ref)
}

// AuthToken Use auth_token cookie as Token and ct0 cookie as CSRFToken
type AuthToken struct {
	Token     string
	CSRFToken string
}

// SetAuthToken Auth using auth_token and ct0 cookies
//func (s *Scraper) SetAuthToken(token AuthToken) {
//	expires := time.Date(1, time.January, 1, 0, 0, 0, 0, time.UTC)
//	cookies := []*http.Cookie{{
//		Name:       "auth_token",
//		Value:      token.Token,
//		Path:       "",
//		Domain:     "twitter.com",
//		Expires:    expires,
//		RawExpires: "",
//		MaxAge:     0,
//		Secure:     false,
//		HttpOnly:   false,
//		SameSite:   0,
//		Raw:        "",
//		Unparsed:   nil,
//	}, {
//		Name:       "ct0",
//		Value:      token.CSRFToken,
//		Path:       "",
//		Domain:     "twitter.com",
//		Expires:    expires,
//		RawExpires: "",
//		MaxAge:     0,
//		Secure:     false,
//		HttpOnly:   false,
//		SameSite:   0,
//		Raw:        "",
//		Unparsed:   nil,
//	}}
//
//	s.SetCookies(cookies)
//}

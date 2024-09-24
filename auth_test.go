package twitterscraper_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	twitterscraper "github.com/imperatrona/twitter-scraper"
)

var (
	proxy         = os.Getenv("PROXY")
	proxyRequired = os.Getenv("PROXY_REQUIRED") != ""
	authToken     = os.Getenv("AUTH_TOKEN")
	csrfToken     = os.Getenv("CSRF_TOKEN")
	cookies       = os.Getenv("COOKIES")
	username      = os.Getenv("TWITTER_USERNAME")
	password      = os.Getenv("TWITTER_PASSWORD")
	email         = os.Getenv("TWITTER_EMAIL")
	skipAuthTest  = os.Getenv("SKIP_AUTH_TEST") != ""
	testScraper   = newTestScraper(false)
)

func init() {
	if err := godotenv.Load(); err != nil {
		logrus.WithError(err).Warn("Error loading .env file")
	}
	logrus.Infof("Loaded .env TWITTER_USER=%s", os.Getenv("TWITTER_USERNAME"))
	logrus.Infof("Skip auth test: %v", os.Getenv("SKIP_AUTH_TEST"))
	skipAuthTest = os.Getenv("SKIP_AUTH_TEST") != ""
	if skipAuthTest {
		return
	}

	if authToken != "" && csrfToken != "" {
		testScraper.SetAuthToken(twitterscraper.AuthToken{Token: authToken, CSRFToken: csrfToken})
		if !testScraper.IsLoggedIn() {
			panic("Invalid AuthToken")
		}
		return
	}

	if cookies != "" {
		var parsedCookies []*http.Cookie
		json.NewDecoder(strings.NewReader(cookies)).Decode(&parsedCookies)
		testScraper.SetCookies(parsedCookies)
		if !testScraper.IsLoggedIn() {
			panic("Invalid Cookies")
		}
		return
	}

	if username != "" && password != "" {
		err := testScraper.Login(username, password, email)
		if err != nil {
			logrus.Fatalf("Login() error = %v", err)
		}
		return
	}

	//skipAuthTest = true
	fmt.Println("None of any auth data provided, skipping all tests that requires auth")
}

func newTestScraper(skip_auth bool) *twitterscraper.Scraper {
	s := twitterscraper.New()

	if proxy != "" && proxyRequired {
		err := s.SetProxy(proxy)
		if err != nil {
			panic(fmt.Sprintf("SetProxy() error = %v", err))
		}
	}

	// Check connection by getting guest token
	if err := s.GetGuestToken(); err != nil {
		panic(fmt.Sprintf("cannot get guest token, can also be error with connection to twitter.\n %v", err))
	}

	if skip_auth == true || !skipAuthTest {
		err := s.ClearGuestToken()
		if err != nil {
			return nil
		}
		return s
	}
	return s
}

func TestLoginPassword(t *testing.T) {
	if skipAuthTest || username == "" || password == "" {
		t.Skip("Skipping test due to environment variable")
	}
	scraper := newTestScraper(true)
	if err := scraper.Login(username, password, email); err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	if !scraper.IsLoggedIn() {
		t.Fatalf("Expected IsLoggedIn() = true")
	}
	if err := scraper.Logout(); err != nil {
		t.Errorf("Logout() error = %v", err)
	}
	if scraper.IsLoggedIn() {
		t.Error("Expected IsLoggedIn() = false")
	}
}

func TestLoginToken(t *testing.T) {
	if skipAuthTest || authToken == "" || csrfToken == "" {
		t.Skip("Skipping test due to environment variable")
	}

	scraper := newTestScraper(true)

	scraper.SetAuthToken(twitterscraper.AuthToken{Token: authToken, CSRFToken: csrfToken})
	if !scraper.IsLoggedIn() {
		t.Error("Expected IsLoggedIn() = true")
	}
}

func TestLoginCookie(t *testing.T) {
	if skipAuthTest || cookies == "" {
		t.Skip("Skipping test due to environment variable")
	}

	scraper := newTestScraper(true)

	var c []*http.Cookie

	json.NewDecoder(strings.NewReader(cookies)).Decode(&c)

	scraper.SetCookies(c)
	if !scraper.IsLoggedIn() {
		t.Error("Expected IsLoggedIn() = true")
	}
}

func TestLoginOpenAccount(t *testing.T) {
	if os.Getenv("TEST_OPEN_ACCOUNT") == "" {
		t.Skip("Skipping test due to environment variable")
	}

	scraper := twitterscraper.New()
	err := scraper.LoginOpenAccount()
	if err != nil {
		t.Fatalf("LoginOpenAccount() error = %v", err)
	}
}

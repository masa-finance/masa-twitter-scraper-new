package twitterscraper_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

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
	// Set log level to Debug
	logrus.SetLevel(logrus.DebugLevel)

	// Optionally, set a custom formatter
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	if err := godotenv.Load(); err != nil {
		logrus.WithError(err).Warn("Error loading .env file")
	}

	username = os.Getenv("TWITTER_USERNAME")
	password = os.Getenv("TWITTER_PASSWORD")
	email = os.Getenv("TWITTER_EMAIL")
	skipAuthTest = os.Getenv("SKIP_AUTH_TEST") != ""

	logrus.WithFields(logrus.Fields{
		"username":     username,
		"password":     password,
		"email":        email,
		"skipAuthTest": skipAuthTest,
	}).Info("Environment variables loaded")
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

func TestBasic(t *testing.T) {
	//client := httpwrap.NewClient().WithJar() // Ensure cookies are handled

	scraper := twitterscraper.New()
	if scraper == nil {
		t.Fatalf("New() returned nil")
	}

	req, err := http.NewRequest("GET", "https://twitter.com", nil)
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	// Set a User-Agent header
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3")

	resp, err := scraper.GetHTTPClient().Do(req)
	if err != nil {
		fmt.Println("Error making request:", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("Request successful")
	} else {
		fmt.Printf("Request failed with status: %d\n", resp.StatusCode)
	}
}

func TestAuth(t *testing.T) {
	if skipAuthTest {
		t.Skip("Skipping test due to environment variable")
	}

	scraper := twitterscraper.New()

	// Add a short delay before login attempt
	time.Sleep(2 * time.Second)

	err := scraper.Login(username, password, email)
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	// Add a short delay after login attempt
	time.Sleep(2 * time.Second)

	if !scraper.IsLoggedIn() {
		t.Fatalf("Expected IsLoggedIn() = true")
	}

	// Save cookies
	cookies := scraper.GetCookies()
	err = saveCookiesToFile(cookies, "twitter_cookies.json")
	if err != nil {
		t.Fatalf("Failed to save cookies: %v", err)
	}

	// Log success
	t.Log("Successfully logged in and saved cookies")
}

//func TestLoginPassword(t *testing.T) {
//	if skipAuthTest || username == "" || password == "" {
//		t.Skip("Skipping test due to environment variable")
//	}
//	scraper := newTestScraper(true)
//	if err := scraper.Login(username, password, email); err != nil {
//		t.Fatalf("Login() error = %v", err)
//	}
//	if !scraper.IsLoggedIn() {
//		t.Fatalf("Expected IsLoggedIn() = true")
//	}
//	if err := scraper.Logout(); err != nil {
//		t.Errorf("Logout() error = %v", err)
//	}
//	if scraper.IsLoggedIn() {
//		t.Error("Expected IsLoggedIn() = false")
//	}
//}
//
//func TestLoginToken(t *testing.T) {
//	if skipAuthTest || authToken == "" || csrfToken == "" {
//		t.Skip("Skipping test due to environment variable")
//	}
//
//	scraper := newTestScraper(true)
//
//	scraper.SetAuthToken(twitterscraper.AuthToken{Token: authToken, CSRFToken: csrfToken})
//	if !scraper.IsLoggedIn() {
//		t.Error("Expected IsLoggedIn() = true")
//	}
//}
//
//func TestLoginCookie(t *testing.T) {
//	if skipAuthTest || cookies == "" {
//		t.Skip("Skipping test due to environment variable")
//	}
//
//	scraper := newTestScraper(true)
//
//	var c []*http.Cookie
//
//	json.NewDecoder(strings.NewReader(cookies)).Decode(&c)
//
//	scraper.SetCookies(c)
//	if !scraper.IsLoggedIn() {
//		t.Error("Expected IsLoggedIn() = true")
//	}
//}
//
//func TestLoginOpenAccount(t *testing.T) {
//	if os.Getenv("TEST_OPEN_ACCOUNT") == "" {
//		t.Skip("Skipping test due to environment variable")
//	}
//
//	scraper := twitterscraper.New()
//	err := scraper.LoginOpenAccount()
//	if err != nil {
//		t.Fatalf("LoginOpenAccount() error = %v", err)
//	}
//}

func saveCookiesToFile(cookies []*http.Cookie, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	return encoder.Encode(cookies)
}

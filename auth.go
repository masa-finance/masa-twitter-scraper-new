package twitterscraper

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/imperatrona/twitter-scraper/auth"
)

func (s *Scraper) getAccessToken(consumerKey, consumerSecret string) (string, error) {
	req, err := http.NewRequest("POST", oAuthURL, strings.NewReader("grant_type=client_credentials"))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	req.SetBasicAuth(consumerKey, consumerSecret)

	res, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return "", fmt.Errorf("unexpected status code: %d, body: %s", res.StatusCode, body)
	}

	var a struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&a); err != nil {
		return "", err
	}
	return a.AccessToken, nil
}

func (s *Scraper) getFlow(data map[string]interface{}) (*flow, error) {
	headers := http.Header{
		"Authorization": []string{"Bearer " + s.bearerToken},
		"Content-Type":  []string{"application/json"},
		//"User-Agent":                []string{GetRandomUserAgent()},
		"X-Guest-Token":             []string{s.guestToken},
		"X-Twitter-Auth-Type":       []string{"OAuth2Client"},
		"X-Twitter-Active-User":     []string{"yes"},
		"X-Twitter-Client-Language": []string{"en"},
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", loginURL, bytes.NewReader(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header = headers

	// Set CSRF token
	//s.setCSRFToken(req)

	resp, err := s.client.Do(req)
	if err != nil {
		logrus.WithError(err).Error("Failed to execute request")
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logrus.WithError(err).Error("Failed to read response body")
		return nil, err
	}

	logrus.WithFields(logrus.Fields{
		"status_code": resp.StatusCode,
		"body":        string(body),
	}).Debug("Received response from Twitter API")

	var info flow
	err = json.Unmarshal(body, &info)
	if err != nil {
		logrus.WithError(err).Error("Failed to unmarshal response body")
		return nil, err
	}

	return &info, nil
}

func (s *Scraper) getFlowToken(data map[string]interface{}) (string, error) {
	info, err := s.getFlow(data)
	if err != nil {
		return "", err
	}

	if len(info.Errors) > 0 {
		logrus.WithFields(logrus.Fields{
			"error_code":    info.Errors[0].Code,
			"error_message": info.Errors[0].Message,
		}).Error("Auth error returned by Twitter API")
		return "", fmt.Errorf("auth error (%d): %v", info.Errors[0].Code, info.Errors[0].Message)
	}

	if info.Subtasks != nil && len(info.Subtasks) > 0 {
		subtaskID := info.Subtasks[0].SubtaskID
		logrus.WithField("subtask_id", subtaskID).Debug("Received subtask from Twitter API")

		switch subtaskID {
		case "LoginEnterAlternateIdentifierSubtask", "LoginAcid", "LoginTwoFactorAuthChallenge", "DenyLoginSubtask":
			err = fmt.Errorf("auth error: %v", subtaskID)
			logrus.WithError(err).Error("Authentication failed")
		}
	}
	return info.FlowToken, err
}

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

// randomDelay introduces a random delay between 1 and 3 seconds
func randomDelay() {
	delay := time.Duration(3000+rand.Intn(5000)) * time.Millisecond
	time.Sleep(delay)
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
	m := make(map[string]string)
	m["oauth_consumer_key"] = appConsumerKey
	m["oauth_nonce"] = "0"
	m["oauth_signature_method"] = "HMAC-SHA1"
	m["oauth_timestamp"] = strconv.FormatInt(time.Now().Unix(), 10)
	m["oauth_token"] = s.oAuthToken

	key := []byte(appConsumerSecret + "&" + s.oAuthSecret)
	h := hmac.New(sha1.New, key)

	query := ref.Query()
	for k, v := range m {
		query.Set(k, v)
	}

	req := []string{method, ref.Scheme + "://" + ref.Host + ref.Path, query.Encode()}
	var reqBuf bytes.Buffer
	for _, value := range req {
		if reqBuf.Len() > 0 {
			reqBuf.WriteByte('&')
		}
		reqBuf.WriteString(url.QueryEscape(value))
	}
	h.Write(reqBuf.Bytes())

	m["oauth_signature"] = base64.StdEncoding.EncodeToString(h.Sum(nil))

	var b bytes.Buffer
	for k, v := range m {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(url.QueryEscape(v))
	}

	return "OAuth " + b.String()
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

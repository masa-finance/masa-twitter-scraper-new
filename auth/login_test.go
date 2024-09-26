package auth

import (
	"errors"
	"net/http"
	"os"
	"testing"

	"github.com/joho/godotenv"
	"github.com/sirupsen/logrus"

	"github.com/masa-finance/twitter-scraper/httpwrap"
	"github.com/masa-finance/twitter-scraper/types"
)

func init() {
	if err := godotenv.Load("../.env"); err != nil {
		logrus.WithError(err).Warn("Error loading .env file")
	}
	logrus.Infof("Loaded .env TWITTER_USER=%s", os.Getenv("TWITTER_USER"))
}

// MockClient is a mock implementation of the httpwrap.Client interface
type MockClient struct {
	GetFunc  func(url string, params map[string]string, headers http.Header, result interface{}) (*http.Response, error)
	PostFunc func(url string, data interface{}, headers http.Header, result interface{}) (*http.Response, error)
}

func (m *MockClient) Get(url string, params map[string]string, headers http.Header, result interface{}) (*http.Response, error) {
	if m.GetFunc != nil {
		return m.GetFunc(url, params, headers, result)
	}
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func (m *MockClient) Post(url string, data interface{}, headers http.Header, result interface{}) (*http.Response, error) {
	if m.PostFunc != nil {
		return m.PostFunc(url, data, headers, result)
	}
	return &http.Response{StatusCode: http.StatusOK}, nil
}

func TestLoginFlow_Start(t *testing.T) {
	// Mock responses for the POST requests made during the login flow
	mockFlowToken := "mock_flow_token"

	mockClient := &MockClient{
		GetFunc: func(url string, params map[string]string, headers http.Header, result interface{}) (*http.Response, error) {
			// Simulate a successful GET request to initialize cookies
			return &http.Response{StatusCode: http.StatusOK}, nil
		},
		PostFunc: func(url string, data interface{}, headers http.Header, result interface{}) (*http.Response, error) {
			if url == OAuthURL {
				// Mock response for getAccessToken
				if tokenResult, ok := result.(*types.Token); ok {
					tokenResult.AccessToken = "mock_access_token"
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			}

			if url == LoginURL {
				// Mock response for getFlow and getFlowToken
				if flowResult, ok := result.(*types.Flow); ok {
					flowResult.FlowToken = mockFlowToken
					flowResult.Errors = nil
					flowResult.Subtasks = []types.Subtask{
						{
							SubtaskID: "test_subtask",
						},
					}
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			}

			return nil, errors.New("unexpected POST request")
		},
	}

	loginFlow := NewLoginFlow(
		httpwrap.NewClient(),
		"test_bearer_token",
		"test_guest_token",
		"test_username",
		"test_password",
		"",
	)

	err := loginFlow.Start()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Assert that the FlowToken was updated
	if loginFlow.FlowToken != mockFlowToken {
		t.Errorf("Expected FlowToken to be '%s', got '%s'", mockFlowToken, loginFlow.FlowToken)
	}

	// Assert that IsLogged is true
	if !loginFlow.IsLogged {
		t.Errorf("Expected IsLogged to be true")
	}

	// Additional assertions can be added as needed
}

func TestLoginFlow_Validate(t *testing.T) {
	cases := []struct {
		username string
		password string
		valid    bool
	}{
		{"user", "pass", true},
		{"user", "", false},
		{"", "pass", false},
		{"", "", false},
	}

	for _, c := range cases {
		lf := &LoginFlow{
			Username: c.username,
			Password: c.password,
		}
		if lf.Validate() != c.valid {
			t.Errorf("Validate() with username='%s', password='%s' expected %v",
				c.username, c.password, c.valid)
		}
	}
}

func TestLoginFlow_handleConfirmation(t *testing.T) {
	mockClient := &MockClient{}
	lf := &LoginFlow{
		Client:       mockClient,
		Confirmation: "test_code",
	}

	// Mock handleSubtask to simulate successful confirmation
	lf.handleSubtask = func(subtaskID string, subtaskData map[string]interface{}) error {
		if subtaskID != "LoginTwoFactorAuthChallenge" {
			t.Errorf("Expected subtaskID to be 'LoginTwoFactorAuthChallenge', got '%s'", subtaskID)
		}
		return nil
	}

	err := lf.handleConfirmation(errors.New("auth error: LoginTwoFactorAuthChallenge"))
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestLoginFlow_handleSubtask(t *testing.T) {
	mockFlowToken := "new_mock_flow_token"

	mockClient := &MockClient{
		PostFunc: func(url string, data interface{}, headers http.Header, result interface{}) (*http.Response, error) {
			if url == LoginURL {
				if flowResult, ok := result.(*types.Flow); ok {
					flowResult.FlowToken = mockFlowToken
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			}
			return nil, errors.New("unexpected POST request")
		},
	}

	lf := &LoginFlow{
		Client:    mockClient,
		FlowToken: "current_flow_token",
	}

	err := lf.handleSubtask("TestSubtaskID", map[string]interface{}{
		"test_key": "test_value",
	})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if lf.FlowToken != mockFlowToken {
		t.Errorf("Expected FlowToken to be updated to '%s', got '%s'", mockFlowToken, lf.FlowToken)
	}
}

func TestLoginFlow_initializeCookies(t *testing.T) {
	initialized := false

	mockClient := &MockClient{
		GetFunc: func(url string, params map[string]string, headers http.Header, result interface{}) (*http.Response, error) {
			if url == "https://twitter.com" {
				initialized = true
				return &http.Response{StatusCode: http.StatusOK}, nil
			}
			return nil, errors.New("unexpected GET request")
		},
	}

	lf := &LoginFlow{
		Client: mockClient,
	}

	err := lf.initializeCookies()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if !initialized {
		t.Errorf("Expected initializeCookies to perform GET request to 'https://twitter.com'")
	}
}

func TestLoginFlow_getAccessToken(t *testing.T) {
	expectedAccessToken := "mock_access_token"

	mockClient := &MockClient{
		PostFunc: func(url string, data interface{}, headers http.Header, result interface{}) (*http.Response, error) {
			if url == OAuthURL {
				if tokenResult, ok := result.(*types.Token); ok {
					tokenResult.AccessToken = expectedAccessToken
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			}
			return nil, errors.New("unexpected POST request")
		},
	}

	lf := &LoginFlow{
		Client: mockClient,
	}

	accessToken, err := lf.getAccessToken("consumerKey", "consumerSecret")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if accessToken != expectedAccessToken {
		t.Errorf("Expected access token to be '%s', got '%s'", expectedAccessToken, accessToken)
	}
}

func TestLoginFlow_getFlowToken(t *testing.T) {
	expectedFlowToken := "mock_flow_token"

	mockClient := &MockClient{
		PostFunc: func(url string, data interface{}, headers http.Header, result interface{}) (*http.Response, error) {
			if url == LoginURL {
				if flowResult, ok := result.(*types.Flow); ok {
					flowResult.FlowToken = expectedFlowToken
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			}
			return nil, errors.New("unexpected POST request")
		},
	}

	lf := &LoginFlow{
		Client: mockClient,
	}

	flowToken, err := lf.getFlowToken(map[string]interface{}{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if flowToken != expectedFlowToken {
		t.Errorf("Expected flow token to be '%s', got '%s'", expectedFlowToken, flowToken)
	}
}

func TestLoginFlow_getFlow(t *testing.T) {
	expectedFlowToken := "mock_flow_token"

	mockClient := &MockClient{
		PostFunc: func(url string, data interface{}, headers http.Header, result interface{}) (*http.Response, error) {
			if url == LoginURL {
				if flowResult, ok := result.(*types.Flow); ok {
					flowResult.FlowToken = expectedFlowToken
					flowResult.Errors = nil
					flowResult.Subtasks = []types.Subtask{}
					return &http.Response{StatusCode: http.StatusOK}, nil
				}
			}
			return nil, errors.New("unexpected POST request")
		},
	}

	lf := &LoginFlow{
		Client:      mockClient,
		BearerToken: "test_bearer_token",
		GuestToken:  "test_guest_token",
	}

	flow, err := lf.getFlow(map[string]interface{}{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if flow.FlowToken != expectedFlowToken {
		t.Errorf("Expected flow token to be '%s', got '%s'", expectedFlowToken, flow.FlowToken)
	}
}

func TestLoginFlow_setBearerToken(t *testing.T) {
	expectedGuestToken := "mock_guest_token"

	mockClient := &MockClient{}

	// Mock GetGuestToken function
	originalGetGuestToken := GetGuestToken
	defer func() { GetGuestToken = originalGetGuestToken }()
	GetGuestToken = func(client *httpwrap.Client, bearerToken string) (string, error) {
		return expectedGuestToken, nil
	}

	lf := &LoginFlow{
		Client: mockClient,
	}

	err := lf.setBearerToken("new_bearer_token")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if lf.BearerToken != "new_bearer_token" {
		t.Errorf("Expected BearerToken to be 'new_bearer_token', got '%s'", lf.BearerToken)
	}

	if lf.GuestToken != expectedGuestToken {
		t.Errorf("Expected GuestToken to be '%s', got '%s'", expectedGuestToken, lf.GuestToken)
	}
}

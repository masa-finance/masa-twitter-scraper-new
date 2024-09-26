package auth

import (
	"encoding/base64"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/masa-finance/twitter-scraper/httpwrap"
	"github.com/masa-finance/twitter-scraper/types"
)

const (
	LoginURL  = "https://api.twitter.com/1.1/onboarding/task.json"
	LogoutURL = "https://api.twitter.com/1.1/account/logout.json"
	OAuthURL  = "https://api.twitter.com/oauth2/token"

	SubtaskLoginJsInstrumentation = "LoginJsInstrumentationSubtask"
	SubtaskEnterUserIdentifier    = "LoginEnterUserIdentifierSSO"
	SubtaskEnterPassword          = "LoginEnterPassword"
	SubtaskAccountDuplication     = "AccountDuplicationCheck"
	SubtaskOpenAccount            = "OpenAccount"
)

type LoginFlow struct {
	Client        *httpwrap.Client
	BearerToken   string
	GuestToken    string
	FlowToken     string
	CsrfToken     string
	Username      string
	Password      string
	Confirmation  string
	OAuthToken    string
	OAuthSecret   string
	IsLogged      bool
	IsOpenAccount bool
	// Add other necessary fields
}

func NewLoginFlow(client *httpwrap.Client, bearerToken, username, password, confirmation string) *LoginFlow {
	return &LoginFlow{
		Client:       client,
		BearerToken:  bearerToken,
		Username:     username,
		Password:     password,
		Confirmation: confirmation,
	}
}

func (lf *LoginFlow) Validate() bool {
	return lf.Username != "" && lf.Password != ""
}

func (lf *LoginFlow) setBearerToken(token string) (err error) {
	lf.BearerToken = token
	lf.Client.WithBearerToken(lf.BearerToken)
	lf.GuestToken = ""
	lf.GuestToken, err = GetGuestToken(lf.Client, lf.BearerToken)
	if err != nil {
		return
	}
	return
}

func (lf *LoginFlow) Log() {
	logrus.WithFields(logrus.Fields{
		"bearer_token": lf.BearerToken,
		"guest_token":  lf.GuestToken,
		"flow_token":   lf.FlowToken,
		"username":     lf.Username,
		"confirmation": lf.Confirmation,
		"oauth_token":  lf.OAuthToken,
		"oauth_secret": lf.OAuthSecret,
		"is_logged":    lf.IsLogged,
		"is_open":      lf.IsOpenAccount,
	}).Info("LoginFlow")
}

// Start performs the authentication process using the provided LoginRequest.
// It manages the multi-step flow required for logging into a service that uses
// OAuth-like authentication mechanisms. The function handles various subtasks
// such as entering user credentials, handling two-factor authentication, and
// managing flow tokens.
//
// Parameters:
//   - request: A pointer to a LoginRequest struct containing all necessary
//     attributes for the login process, including bearer and guest tokens,
//     username, password, and optional confirmation data.
//
// Returns:
// - An error if any step in the login process fails.
//
// The function executes the following steps:
//  1. Initializes the login flow by setting up the initial data structure
//     required for the authentication process.
//  2. Handles JavaScript instrumentation, which may be required by the service
//     to track client-side interactions.
//  3. Submits the username as part of the login flow, ensuring the correct
//     user identifier is provided.
//  4. Submits the password to authenticate the user.
//  5. Checks for account duplication, which may occur if the account is already
//     logged in elsewhere.
//  6. Handles additional confirmation steps, such as two-factor authentication
//     or other security challenges, if required.
//
// Note:
//   - The function updates the FlowToken within the LoginRequest as the flow
//     progresses, ensuring the correct state is maintained across requests.
//   - If the login process requires additional confirmation (e.g., 2FA), the
//     Confirmation field in the LoginRequest must be populated.
//   - Ensure that sensitive information such as passwords and tokens are handled
//     securely and not exposed in logs or error messages.
func (lf *LoginFlow) Start() error {
	lf.Log()
	if !lf.Validate() {
		return fmt.Errorf("invalid credentials")
	}
	err := lf.initializeCookies()
	if err != nil {
		return err
	}
	randomDelay()

	err = lf.setBearerToken(lf.BearerToken)
	if err != nil {
		return err
	}

	flowToken, err := lf.startLoginFlow()
	if err != nil {
		return err
	}
	lf.FlowToken = flowToken

	randomDelay()
	// Handle JavaScript instrumentation
	if err := lf.handleSubtask(SubtaskLoginJsInstrumentation, map[string]interface{}{
		"js_instrumentation": map[string]interface{}{"response": "{}", "link": "next_link"},
	}); err != nil {
		return err
	}

	randomDelay()
	// Submit username
	if err := lf.handleSubtask(SubtaskEnterUserIdentifier, map[string]interface{}{
		"settings_list": map[string]interface{}{
			"setting_responses": []map[string]interface{}{
				{
					"key":           "user_identifier",
					"response_data": map[string]interface{}{"text_data": map[string]interface{}{"result": lf.Username}},
				},
			},
			"link": "next_link",
		},
	}); err != nil {
		return err
	}

	randomDelay()
	// Submit password
	if err := lf.handleSubtask(SubtaskEnterPassword, map[string]interface{}{
		"enter_password": map[string]interface{}{"password": lf.Password, "link": "next_link"},
	}); err != nil {
		return err
	}

	randomDelay()
	// Check for account duplication
	if err := lf.handleSubtask(SubtaskAccountDuplication, map[string]interface{}{
		"check_logged_in_account": map[string]interface{}{"link": "AccountDuplicationCheck_false"},
	}); err != nil {
		return lf.handleConfirmation(err)
	}
	lf.IsLogged = true
	lf.IsOpenAccount = false

	return err
}

func (lf *LoginFlow) initializeCookies() error {
	_, err := lf.Client.Get("https://twitter.com", nil, nil, nil)
	if err != nil {
		return err
	}
	return nil
}

func (lf *LoginFlow) startLoginFlow() (string, error) {
	data := map[string]interface{}{
		"flow_name": "login",
		"input_flow_data": map[string]interface{}{
			"flow_context": map[string]interface{}{
				"debug_overrides": map[string]interface{}{},
				"start_location":  map[string]interface{}{"location": "splash_screen"},
			},
		},
	}
	return lf.getFlowToken(data)
}

func (lf *LoginFlow) handleSubtask(subtaskID string, subtaskData map[string]interface{}) error {
	data := map[string]interface{}{
		"flow_token": lf.FlowToken,
		"subtask_inputs": []map[string]interface{}{
			{
				"subtask_id": subtaskID,
			},
		},
	}
	for k, v := range subtaskData {
		data["subtask_inputs"].([]map[string]interface{})[0][k] = v
	}
	flowToken, err := lf.getFlowToken(data)
	if err != nil {
		return err
	}
	lf.FlowToken = flowToken
	return nil
}

func (lf *LoginFlow) handleConfirmation(inErr error) error {
	var confirmationSubtask string
	for _, subtask := range []string{"LoginAcid", "LoginTwoFactorAuthChallenge"} {
		if strings.Contains(inErr.Error(), subtask) {
			confirmationSubtask = subtask
			break
		}
	}
	if confirmationSubtask != "" {
		if lf.Confirmation == "" {
			return fmt.Errorf("confirmation data required for %v", confirmationSubtask)
		}
		if err := lf.handleSubtask(confirmationSubtask, map[string]interface{}{
			"enter_text": map[string]interface{}{"text": lf.Confirmation, "link": "next_link"},
		}); err != nil {
			return err
		}
	} else {
		return inErr
	}
	return nil
}

// LoginOpenAccount performs the process of opening an account using the provided OpenAccountRequest.
// It manages the multi-step flow required for opening an account, handling tasks such as
// obtaining access tokens and managing flow tokens.
//
// Parameters:
//   - request: A pointer to an OpenAccountRequest struct containing all necessary
//     attributes for the open account process, including bearer and guest tokens,
//     consumer keys, and secrets.
//
// Returns:
// - An error if any step in the open account process fails.
//
// The function executes the following steps:
//  1. Obtains an access token using the provided consumer key and secret.
//  2. Initializes the open account flow by setting up the initial data structure
//     required for the process.
//  3. Proceeds to the next task in the flow, which may involve opening a link or
//     performing additional actions.
//  4. Updates the OpenAccountRequest with the OAuth token and secret if the
//     process is successful.
//
// Note:
//   - The function updates the OpenAccountRequest with the OAuth token and secret,
//     as well as the login state, ensuring the correct state is maintained.
//   - Ensure that sensitive information such as tokens and secrets are handled
//     securely and not exposed in logs or error messages.
func (lf *LoginFlow) LoginOpenAccount(consumerKey, consumerSecret string) error {
	accessToken, err := lf.getAccessToken(consumerKey, consumerSecret)
	if err != nil {
		return err
	}
	lf.BearerToken = accessToken
	lf.GuestToken = ""
	lf.GuestToken, err = GetGuestToken(lf.Client, lf.BearerToken)
	if err != nil {
		return err
	}

	// Flow start
	data := map[string]interface{}{
		"flow_name": "welcome",
		"input_flow_data": map[string]interface{}{
			"flow_context": map[string]interface{}{
				"debug_overrides": map[string]interface{}{},
				"start_location":  map[string]interface{}{"location": "splash_screen"},
			},
		},
	}
	flowToken, err := lf.getFlowToken(data)
	if err != nil {
		return err
	}

	// Flow next link
	data = map[string]interface{}{
		"flow_token": flowToken,
		"subtask_inputs": []interface{}{
			map[string]interface{}{
				"subtask_id": "NextTaskOpenLink",
			},
		},
	}
	info, err := lf.getFlow(data)
	if err != nil {
		return err
	}

	if info.Subtasks != nil && len(info.Subtasks) > 0 {
		if info.Subtasks[0].SubtaskID == "OpenAccount" {
			lf.OAuthToken = info.Subtasks[0].OpenAccount.OAuthToken
			lf.OAuthSecret = info.Subtasks[0].OpenAccount.OAuthTokenSecret
			if lf.OAuthToken == "" || lf.OAuthSecret == "" {
				return fmt.Errorf("auth error: %v", "Token or Secret is empty")
			}
			lf.IsLogged = true
			lf.IsOpenAccount = true
			return nil
		}
	}
	return fmt.Errorf("auth error: %v", "OpenAccount")
}

// getAccessToken retrieves an access token using the provided consumer key and secret.
// It sends a POST request to the OAuth URL with the necessary headers and data.
//
// Parameters:
// - consumerKey: The consumer key provided by the service for your application.
// - consumerSecret: The secret associated with the consumer key.
//
// Returns:
// - A string representing the access token.
// - An error if the request fails or the response cannot be parsed.
func (lf *LoginFlow) getAccessToken(consumerKey, consumerSecret string) (string, error) {
	data := []byte("grant_type=client_credentials")
	header := make(http.Header)
	header.Add("Content-Type", "application/x-www-form-urlencoded")
	base64Value := base64.StdEncoding.EncodeToString([]byte(consumerKey + ":" + consumerSecret))
	header.Add("Authorization", "Basic "+base64Value)

	var token types.Token
	_, err := lf.Client.Post(OAuthURL, data, header, token)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

// getFlow sends a POST request to the Login URL to retrieve flow information.
// It constructs the necessary headers and sends the request with the provided data.
//
// Parameters:
// - data: A map containing the flow data to be sent in the request body.
// - bearerToken: The bearer token for authentication.
// - guestToken: The guest token for authentication.
//
// Returns:
// - A pointer to a Flow struct containing the flow information.
// - An error if the request fails or the response cannot be parsed.
func (lf *LoginFlow) getFlow(data map[string]interface{}) (*types.Flow, error) {
	headers := http.Header{
		"Authorization":             []string{"Bearer " + lf.BearerToken},
		"Content-Type":              []string{"application/json"},
		"User-Agent":                []string{GetRandomUserAgent()},
		"X-Guest-Token":             []string{lf.GuestToken},
		"X-Twitter-Auth-Type":       []string{"OAuth2Client"},
		"X-Twitter-Active-User":     []string{"yes"},
		"X-Twitter-Client-Language": []string{"en"},
	}
	loginUrl, err := url.Parse(LoginURL)
	if err != nil {
		logrus.Errorf("Failed to parse URL: %v", err)
	}

	for _, cookie := range lf.Client.GetCookies(loginUrl) {
		if cookie.Name == "ct0" {
			headers.Set("X-CSRF-Token", cookie.Value)
			break
		}
	}

	var info types.Flow
	// TODO: Check if the result is a pointer
	_, err = lf.Client.Post(LoginURL, data, headers, &info)
	if err != nil {
		return nil, err
	}
	return &info, nil
}

// getFlowToken retrieves a flow token by sending a request to the flow endpoint.
// It processes the response to extract the flow token and handle any errors.
//
// Parameters:
// - data: A map containing the flow data to be sent in the request body.
// - bearerToken: The bearer token for authentication.
// - guestToken: The guest token for authentication.
//
// Returns:
// - A string representing the flow token.
// - An error if the request fails, the response contains errors, or the flow token cannot be extracted.
func (lf *LoginFlow) getFlowToken(data map[string]interface{}) (string, error) {
	info, err := lf.getFlow(data)
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

// randomDelay introduces a random delay between 1 and 3 seconds
func randomDelay() {
	delay := time.Duration(3000+rand.Intn(5000)) * time.Millisecond
	time.Sleep(delay)
}

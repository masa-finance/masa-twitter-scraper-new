package api

import (
	"fmt"
	"net/http"
	"strings"
	"sync"

	twitterscraper "github.com/imperatrona/twitter-scraper"
	"github.com/imperatrona/twitter-scraper/config"
	"github.com/imperatrona/twitter-scraper/features"
	"github.com/imperatrona/twitter-scraper/types"
)

// Global cache for user IDs
var cacheIDs sync.Map

type user struct {
	Data struct {
		User struct {
			Result struct {
				RestID  string           `json:"rest_id"`
				Legacy  types.LegacyUser `json:"legacy"`
				Message string           `json:"message"`
			} `json:"result"`
		} `json:"user"`
	} `json:"data"`
	Errors []types.Error `json:"errors"`
}

// GetProfile retrieves the profile information of a Twitter user by their username.
//
// This function sends a GET request to the Twitter API to fetch user profile data
// using the provided username. It constructs the request with necessary query
// parameters and feature flags, then processes the API response to return a
// structured Profile object.
//
// Parameters:
//   - username: The Twitter handle (screen name) of the user whose profile is to be retrieved.
//
// Returns:
//   - Profile: A structured object containing the user's profile information, such as
//     avatar, banner, biography, follower count, and more.
//   - error: An error object if the request fails or the user is not found.
//
// Errors:
//   - Returns an error if the HTTP request fails, the user is suspended, or the user
//     does not exist. Specific error messages are provided for these cases.
//
// Example:
//
//	profile, err := scraper.GetProfile("jack")
//	if err != nil {
//	    log.Fatalf("Error fetching profile: %v", err)
//	}
//	fmt.Printf("User %s has %d followers\n", profile.Username, profile.FollowersCount)
//
// Note:
//   - Ensure that the Twitter API credentials are correctly configured in the Scraper
//     instance before calling this function.
//   - This function uses specific feature flags to enhance the profile data retrieved.
//     Adjust the feature flags as necessary to meet your application's requirements.
func GetProfile(scraper *twitterscraper.Scraper, username string) (types.Profile, error) {
	profile := types.Profile{}
	req, err := http.NewRequest("GET", config.UserProfileByScreenNameUrl, nil)
	if err != nil {
		return profile, err
	}

	variables := map[string]interface{}{
		"screen_name":              username,
		"withSafetyModeUserFields": true,
	}

	featureOverrides := map[string]interface{}{
		"subscriptions_verification_info_is_identity_verified_enabled": true,
		"subscriptions_verification_info_verified_since_enabled":       true,
	}
	featureMap := features.MergeFeatures(features.BaseProfileFeatures, featureOverrides)

	query := req.URL.Query()
	query.Set("variables", mapToJSONString(variables))
	query.Set("features", mapToJSONString(featureMap))
	req.URL.RawQuery = query.Encode()

	var jsn user
	err = scraper.RequestAPI(req, &jsn)
	if err != nil {
		return profile, err
	}
	return processProfileResult(jsn, username)
}

// GetProfileByID retrieves the profile information of a Twitter user by their user ID.
//
// This function sends a GET request to the Twitter API to fetch user profile data
// using the provided user ID. It constructs the request with necessary query
// parameters and feature flags, then processes the API response to return a
// structured Profile object.
//
// Parameters:
//   - userID: The unique identifier of the user whose profile is to be retrieved.
//
// Returns:
//   - Profile: A structured object containing the user's profile information, such as
//     avatar, banner, biography, follower count, and more.
//   - error: An error object if the request fails or the user is not found.
//
// Errors:
//   - Returns an error if the HTTP request fails, the user is suspended, or the user
//     does not exist. Specific error messages are provided for these cases.
//
// Example:
//
//	profile, err := scraper.GetProfileByID("123456789")
//	if err != nil {
//	    log.Fatalf("Error fetching profile: %v", err)
//	}
//	fmt.Printf("User %s has %d followers\n", profile.Username, profile.FollowersCount)
//
// Note:
//   - Ensure that the Twitter API credentials are correctly configured in the Scraper
//     instance before calling this function.
//   - This function uses specific feature flags to enhance the profile data retrieved.
//     Adjust the feature flags as necessary to meet your application's requirements.
func GetProfileByID(scraper *twitterscraper.Scraper, userID string) (types.Profile, error) {
	profile := types.Profile{}
	req, err := http.NewRequest("GET", config.UserProfileByIdUrl, nil)
	if err != nil {
		return profile, err
	}

	variables := map[string]interface{}{
		"user_id": userID,
	}

	query := req.URL.Query()
	query.Set("variables", mapToJSONString(variables))
	query.Set("features", mapToJSONString(features.BaseProfileFeatures))
	req.URL.RawQuery = query.Encode()

	var jsn user
	err = scraper.RequestAPI(req, &jsn)
	if err != nil {
		return profile, err
	}
	return processProfileResult(jsn, "")
}

// GetUserIDByScreenName retrieves the user ID of a Twitter user by their screen name.
//
// This function first checks a local cache for the user ID associated with the given screen name.
// If the user ID is not found in the cache, it calls the GetProfile function to fetch the profile
// data from the Twitter API and extracts the user ID. The user ID is then stored in the cache
// for future requests.
//
// Parameters:
//   - screenName: The Twitter handle (screen name) of the user whose user ID is to be retrieved.
//
// Returns:
//   - string: The user ID associated with the given screen name.
//   - error: An error object if the request fails or the user is not found.
//
// Errors:
//   - Returns an error if the profile cannot be fetched or if the user does not exist.
//
// Example:
//
//	userID, err := scraper.GetUserIDByScreenName("jack")
//	if err != nil {
//	    log.Fatalf("Error fetching user ID: %v", err)
//	}
//	fmt.Printf("User ID for @jack is %s\n", userID)
//
// Note:
//   - Ensure that the Twitter API credentials are correctly configured in the Scraper
//     instance before calling this function.
//   - This function utilizes a cache to improve performance by avoiding repeated API calls
//     for the same screen name.
func GetUserIDByScreenName(scraper *twitterscraper.Scraper, screenName string) (string, error) {
	id, ok := cacheIDs.Load(screenName)
	if ok {
		return id.(string), nil
	}

	profile, err := GetProfile(scraper, screenName)
	if err != nil {
		return "", err
	}

	cacheIDs.Store(screenName, profile.UserID)

	return profile.UserID, nil
}

// processProfileResult processes the API response to extract and return a structured Profile object.
//
// This function takes the JSON response from the Twitter API and parses it to construct
// a Profile object. It handles error messages and checks for user suspension or non-existence.
//
// Parameters:
//   - jsn: The JSON response from the Twitter API containing user data.
//   - username: The Twitter handle (screen name) of the user, used for error messages.
//
// Returns:
//   - Profile: A structured object containing the user's profile information, such as
//     avatar, banner, biography, follower count, and more.
//   - error: An error object if the user is suspended, does not exist, or if there are
//     issues with the response data.
//
// Errors:
//   - Returns an error if the user is suspended or does not exist. Specific error messages
//     are provided for these cases.
//
// Note:
//   - This function assumes that the JSON response has been unmarshaled into the `user` struct.
//   - Ensure that the JSON response is correctly formatted and contains the expected fields
//     before calling this function.
func processProfileResult(jsn user, username string) (types.Profile, error) {
	profile := types.Profile{}
	if len(jsn.Errors) > 0 {
		if strings.Contains(jsn.Errors[0].Message, "Missing LdapGroup(visibility-custom-suspension)") {
			return profile, fmt.Errorf("user is suspended")
		}
		return profile, fmt.Errorf("%s", jsn.Errors[0].Message)
	}

	if jsn.Data.User.Result.RestID == "" {
		if jsn.Data.User.Result.Message == "User is suspended" {
			return profile, fmt.Errorf("user is suspended")
		}
		return profile, fmt.Errorf("user not found")
	}
	jsn.Data.User.Result.Legacy.IDStr = jsn.Data.User.Result.RestID

	if jsn.Data.User.Result.Legacy.ScreenName == "" {
		return profile, fmt.Errorf("either @%s does not exist or is private", username)
	}
	profile.FromLegacy(jsn.Data.User.Result.Legacy)
	return profile, nil
}

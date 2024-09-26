package auth

import (
	"fmt"
	"net/http"

	"github.com/imperatrona/twitter-scraper/httpwrap"
)

// GetGuestToken from Twitter API
func GetGuestToken(client *httpwrap.Client, bearerToken string) (string, error) {
	result := map[string]interface{}{}
	header := http.Header{}
	header.Set("Authorization", "Bearer "+bearerToken)

	_, err := client.Post("https://api.twitter.com/1.1/guest/activate.json", nil, header, &result)
	if err != nil {
		return "", err
	}

	if result["guest_token"] == nil || result["guest_token"] == "" {
		return "", fmt.Errorf("guest_token not found")
	}
	guestToken := result["guest_token"].(string)
	//guestCreatedAt = time.Now()
	return guestToken, nil
}

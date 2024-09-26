package twitterscraper

import "testing"

func TestScraper(t *testing.T) {
	scraper := New()
	if scraper.bearerToken != BearerToken {
		t.Errorf("Expected bearerToken to be '%s', got '%s'", BearerToken, scraper.bearerToken)
	}
	scraper.Login()
}

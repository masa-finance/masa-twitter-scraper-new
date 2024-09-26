package twitterscraper

import (
	"sync"
	"time"

	"github.com/masa-finance/twitter-scraper/auth"
	"github.com/masa-finance/twitter-scraper/httpwrap"
)

// Scraper object
type Scraper struct {
	bearerToken    string
	client         *httpwrap.Client
	delay          int64
	guestToken     string
	guestCreatedAt time.Time
	includeReplies bool
	isLogged       bool
	isOpenAccount  bool
	oAuthToken     string
	oAuthSecret    string
	proxy          string
	searchMode     SearchMode
	wg             sync.WaitGroup
	userAgent      string
}

// SearchMode type
type SearchMode int

const (
	// SearchTop - default mode
	SearchTop SearchMode = iota
	// SearchLatest - live mode
	SearchLatest
	// SearchPhotos - image mode
	SearchPhotos
	// SearchVideos - video mode
	SearchVideos
	// SearchUsers - user mode
	SearchUsers
)

// DefaultClientTimeout default http client timeout
const DefaultClientTimeout = 10 * time.Second

// New creates a Scraper object
func New() *Scraper {
	scraper := &Scraper{
		bearerToken: BearerToken,
		client:      httpwrap.NewClient().WithJar(),
	}
	scraper.SetUserAgent(auth.GetRandomUserAgent())
	return scraper
}

func (s *Scraper) GetHTTPClient() *httpwrap.Client {
	return s.client
}

func (s *Scraper) setBearerToken(token string) {
	s.bearerToken = token
	s.guestToken = ""
	s.client.WithBearerToken(token)
}

// SetUserAgent sets the user agent for the scraper
func (s *Scraper) SetUserAgent(userAgent string) *Scraper {
	s.userAgent = userAgent
	return s
}

// IsGuestToken check if guest token not empty
func (s *Scraper) IsGuestToken() bool {
	return s.guestToken != ""
}

// SetSearchMode switcher
func (s *Scraper) SetSearchMode(mode SearchMode) *Scraper {
	s.searchMode = mode
	return s
}

// WithDelay add delay between API requests (in seconds)
func (s *Scraper) WithDelay(seconds int64) *Scraper {
	s.delay = seconds
	return s
}

// WithReplies enable/disable load timeline with tweet replies
func (s *Scraper) WithReplies(b bool) *Scraper {
	s.includeReplies = b
	return s
}

// client timeout
func (s *Scraper) WithClientTimeout(timeout time.Duration) *Scraper {
	s.client.SetTimeout(timeout)
	return s
}

// SetProxy
// set http proxy in the format `http://HOST:PORT`
// set socket proxy in the format `socks5://HOST:PORT`
func (s *Scraper) SetProxy(proxyAddr string) error {
	return s.client.SetProxy(proxyAddr)
}

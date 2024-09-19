package httpwrap

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

const DefaultClientTimeout = 10 * time.Second

// Client is a wrapper around http.Client that provides simplified HTTP methods.
type Client struct {
	httpClient  *http.Client
	proxy       string
	bearerToken string
}

// NewClient creates a new Client with the specified timeout.
func NewClient() *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: DefaultClientTimeout,
			Transport: &http.Transport{
				MaxIdleConnsPerHost: 10,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
	}
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.httpClient.Do(req)
}

// DoRequest executes an HTTP request and returns the response body, headers, and any error encountered.
// It ensures that the request has a default "Content-Type" and "Accept-Encoding" header if not already set.
// The method handles HTTP responses with status codes 300 or higher by reading the response body,
// logging the error, and returning an HTTPError.
//
// Parameters:
// - req: A pointer to an http.Request object that represents the HTTP request to be sent.
//
// Returns:
// - io.ReadCloser: The response body, which must be closed by the caller to free resources.
// - http.Header: The headers from the HTTP response.
// - error: An error if the request failed or the response status code is 300 or higher.
//
// The method performs the following steps:
//  1. Checks if the "Content-Type" header is set on the request; if not, sets it to "application/json".
//  2. Sets the "Accept-Encoding" header to support gzip, deflate, and br encodings.
//  3. Sends the HTTP request using the client's http.Client.
//  4. If an error occurs during the request, returns the error.
//  5. If the response status code is 300 or higher, reads the response body, logs an error using logrus,
//     and returns an HTTPError with the status, status code, and response body.
//  6. Returns the response body and headers if the request is successful.
func (c *Client) DoRequest(req *http.Request) (io.ReadCloser, http.Header, error) {
	// Default Content-Type
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode >= 300 {
		defer func(Body io.ReadCloser) {
			err := Body.Close()
			if err != nil {
				logrus.Errorf("error closing response body: %v\n", err)
			}
		}(resp.Body)
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, nil, fmt.Errorf("error reading response: %w", err)
		}
		httpErr := HTTPError{
			Status:     resp.Status,
			StatusCode: resp.StatusCode,
			Body:       respBody,
			Err:        fmt.Errorf("HTTP %d: %s ", resp.StatusCode, http.StatusText(resp.StatusCode)),
		}
		httpErr.Log()
		return nil, nil, httpErr
	}
	return resp.Body, resp.Header, nil
}

// Get sends an HTTP GET request to the specified baseURL with the provided URL parameters and headers.
// It decodes the JSON response into the provided obj parameter and returns the decoded object,
// the remaining rate limit count, and any error encountered.
//
// Parameters:
// - baseURL: The base URL to which the GET request is sent.
// - urlParams: URL parameters to be appended to the base URL.
// - header: HTTP headers to be included in the request.
// - obj: A pointer to an object where the JSON response will be decoded.
//
// Returns:
// - any: The decoded object from the JSON response.
// - int: The remaining rate limit count, or -1 if not applicable or an error occurred.
// - error: An error if the request failed or the response could not be decoded.
//
// The method performs the following steps:
// 1. Parses the baseURL and appends the encoded URL parameters to it.
// 2. Initializes the limitCount to -1, which will be updated if the "X-Rate-Limit-Remaining" header is present.
// 3. Creates a new HTTP GET request with the constructed URL.
// 4. Sets the provided headers on the request.
// 5. Calls DoRequest to execute the request and obtain the response body and headers.
// 6. Closes the response body after processing to free resources.
// 7. Checks the "X-Rate-Limit-Remaining" header to update the limitCount.
// 8. If an error occurred during the request or response processing, returns the error.
// 9. If the obj parameter is nil, initializes it as a map to hold the decoded JSON data.
// 10. Decodes the JSON response into the obj parameter.
// 11. Returns the limitCount, and any error encountered during decoding.
func (c *Client) Get(baseURL string, urlParams url.Values, header http.Header, obj any) (int, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return -1, fmt.Errorf("invalid base URL: %w", err)
	}

	// Set the query parameters
	parsedURL.RawQuery = urlParams.Encode()
	limitCount := -1

	req, err := http.NewRequest(http.MethodGet, parsedURL.String(), nil)
	if err != nil {
		return limitCount, err
	}

	req.Header = header
	respBody, respHeader, err := c.DoRequest(req)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logrus.Errorf("error closing response body: %v\n", err)
		}
	}(respBody)

	if respHeader != nil && respHeader.Get("X-Rate-Limit-Remaining") != "" {
		limitCount, err = strconv.Atoi(respHeader.Get("X-Rate-Limit-Remaining"))
		if err != nil {
			logrus.Errorf("error parsing rate limit count: %v\n", err)
			limitCount = -1
		}
	}
	if err != nil {
		return limitCount, err
	}
	if obj == nil {
		obj = make(map[string]interface{})
	}
	err = json.NewDecoder(respBody).Decode(&obj)
	if err != nil {
		return limitCount, err
	}
	return limitCount, nil
}

// Post sends an HTTP POST request to the specified URL with a JSON-encoded body and the provided headers.
// It decodes the JSON response into the provided obj parameter and returns the decoded object,
// the remaining rate limit count, and any error encountered.
//
// Parameters:
// - url: The URL to which the POST request is sent.
// - body: The data to be JSON-encoded and sent as the request body.
// - header: HTTP headers to be included in the request.
// - obj: A pointer to an object where the JSON response will be decoded.
//
// Returns:
// - any: The decoded object from the JSON response.
// - int: The remaining rate limit count, or -1 if not applicable or an error occurred.
// - error: An error if the request failed or the response could not be decoded.
//
// The method performs the following steps:
// 1. Initializes a variable bodyReader to nil, which will hold the JSON-encoded body.
// 2. If the body parameter is not nil, marshals the body into JSON and assigns it to bodyReader.
// 3. Initializes the limitCount to -1, which will be updated if the "X-Rate-Limit-Remaining" header is present.
// 4. Creates a new HTTP POST request with the specified URL and bodyReader.
// 5. Sets the provided headers on the request.
// 6. Calls DoRequest to execute the request and obtain the response body.
// 7. If an error occurred during the request, returns the error.
// 8. Closes the response body after processing to free resources.
// 9. If the obj parameter is nil, initializes it as a map to hold the decoded JSON data.
// 10. Decodes the JSON response into the obj parameter.
// 11. Returns the limitCount, and any error encountered during decoding.
func (c *Client) Post(url string, body interface{}, header http.Header, obj any) (int, error) {
	var bodyReader io.Reader
	if body != nil {
		bodyBytes, err := json.Marshal(body)
		if err != nil {
			return -1, err
		}
		bodyReader = bytes.NewBuffer(bodyBytes)
	}

	limitCount := -1

	req, err := http.NewRequest(http.MethodPost, url, bodyReader)
	if err != nil {
		return limitCount, err
	}

	req.Header = header
	respBody, _, err := c.DoRequest(req)
	if err != nil {
		return limitCount, err
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			logrus.Errorf("error closing response body: %v\n", err)
		}
	}(respBody)

	if obj == nil {
		obj = make(map[string]interface{})
	}
	err = json.NewDecoder(respBody).Decode(&obj)
	if err != nil {
		return limitCount, err
	}
	return limitCount, nil
}

// SetTimeout sets the timeout for the singleton http.Client.
func (c *Client) SetTimeout(timeout time.Duration) {
	c.httpClient.Timeout = timeout
}

// SetProxy configures the HTTP client to use a specified proxy server.
// It supports HTTP, HTTPS, and SOCKS5 proxy protocols. If no proxy address is provided,
// the method resets the transport to use direct connections.
//
// Parameters:
// - proxyAddr: A string representing the proxy server address. It can be an HTTP(S) or SOCKS5 URL.
//
// Returns:
// - error: An error if the proxy address is invalid or if setting up the proxy fails.
//
// The method performs the following steps:
//  1. If proxyAddr is an empty string, it resets the client's transport to use direct connections
//     with a default timeout.
//  2. If proxyAddr starts with "http" or "https", it parses the URL and sets up an HTTP(S) proxy
//     using the http.ProxyURL function.
//  3. If proxyAddr starts with "socks5", it parses the URL to extract the host, port, and optional
//     username and password for authentication. It then sets up a SOCKS5 proxy using the proxy.SOCKS5
//     function.
//  4. If the proxy setup is successful, it updates the client's proxy field with the proxy address.
//  5. If the proxyAddr does not match any supported protocols, it returns an error indicating that
//     only HTTP(S) and SOCKS5 protocols are supported.
func (c *Client) SetProxy(proxyAddr string) error {
	if proxyAddr == "" {
		c.httpClient.Transport = &http.Transport{
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			DialContext: (&net.Dialer{
				Timeout: c.httpClient.Timeout,
			}).DialContext,
		}
	} else if strings.HasPrefix(proxyAddr, "http") {
		urlproxy, err := url.Parse(proxyAddr)
		if err != nil {
			return err
		}
		c.httpClient.Transport = &http.Transport{
			Proxy:        http.ProxyURL(urlproxy),
			TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
			DialContext: (&net.Dialer{
				Timeout: c.httpClient.Timeout,
			}).DialContext,
		}
		c.proxy = proxyAddr
	} else if strings.HasPrefix(proxyAddr, "socks5") {
		baseDialer := &net.Dialer{
			Timeout:   c.httpClient.Timeout,
			KeepAlive: c.httpClient.Timeout,
		}
		proxyURL, err := url.Parse(proxyAddr)
		if err != nil {
			return err
		}

		// username password
		username := proxyURL.User.Username()
		password, _ := proxyURL.User.Password()

		// ip and port
		host := proxyURL.Hostname()
		port := proxyURL.Port()

		dialSocksProxy, err := proxy.SOCKS5("tcp", host+":"+port, &proxy.Auth{User: username, Password: password}, baseDialer)
		if err != nil {
			return errors.New("error creating socks5 proxy :" + err.Error())
		}
		if contextDialer, ok := dialSocksProxy.(proxy.ContextDialer); ok {
			dialContext := contextDialer.DialContext
			c.httpClient.Transport = &http.Transport{
				DialContext: dialContext,
			}
		} else {
			return errors.New("failed type assertion to DialContext")
		}
		c.proxy = proxyAddr
		return nil
	} else {
		return errors.New("only support http(s) or socks5 protocol")
	}
	return nil
}

func (c *Client) GetCookies(url *url.URL) []*http.Cookie {
	return c.httpClient.Jar.Cookies(url)
}

func (c *Client) SetCookies(url *url.URL, cookies []*http.Cookie) {
	c.httpClient.Jar.SetCookies(url, cookies)
}

func (c *Client) WithTimeout(timeout time.Duration) *Client {
	c.httpClient.Timeout = timeout
	return c
}

func (c *Client) WithJar() *Client {
	jar, err := cookiejar.New(nil)
	if err != nil {
		logrus.Errorf("error creating cookie jar: %v\n", err)
		return c
	}
	c.httpClient.Jar = jar
	return c
}

// WithBearerToken sets the Bearer Token for the client.
func (c *Client) WithBearerToken(token string) *Client {
	c.bearerToken = token
	c.httpClient.Transport = &BearerTransport{
		Transport: c.httpClient.Transport,
		Token:     token,
	}
	return c
}

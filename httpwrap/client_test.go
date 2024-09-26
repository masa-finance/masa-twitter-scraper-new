package httpwrap

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestDoRequest(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request method
		if r.Method != http.MethodGet {
			t.Errorf("Expected method GET, got %s", r.Method)
		}

		// Check the request headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Respond with a JSON body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"message": "success"}`))
		if err != nil {
			return
		}
	}))
	defer server.Close()

	client := NewClient()

	// Create a new request
	req, err := http.NewRequest(http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	// Call DoRequest
	respBody, respHeader, err := client.DoRequest(req)
	if err != nil {
		t.Fatalf("DoRequest failed: %v", err)
	}
	defer func(respBody io.ReadCloser) {
		err := respBody.Close()
		if err != nil {
			t.Fatalf("Failed to close response body: %v", err)
		}
	}(respBody)

	// Check the response headers
	if respHeader.Get("Content-Type") != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", respHeader.Get("Content-Type"))
	}

	// Check the response body
	bodyBytes, err := io.ReadAll(respBody)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	bodyString := strings.TrimSpace(string(bodyBytes))
	expectedBody := `{"message": "success"}`
	if bodyString != expectedBody {
		t.Errorf("Expected body %s, got %s", expectedBody, bodyString)
	}
}

func TestPost(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request method
		if r.Method != http.MethodPost {
			t.Errorf("Expected method POST, got %s", r.Method)
		}

		// Check the request headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Check the request body
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("Failed to read request body: %v", err)
		}
		expectedBody := `{"key":"value"}`
		if strings.TrimSpace(string(bodyBytes)) != expectedBody {
			t.Errorf("Expected body %s, got %s", expectedBody, string(bodyBytes))
		}

		// Respond with a JSON body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(`{"message": "success"}`))
		if err != nil {
			return
		}
	}))
	defer server.Close()

	client := NewClient()

	// Create a request body
	body := map[string]string{"key": "value"}

	// Call Post
	var responseObj map[string]interface{}
	limitCount, err := client.Post(server.URL, body, http.Header{"Content-Type": []string{"application/json"}}, &responseObj)
	if err != nil {
		t.Fatalf("Post failed: %v", err)
	}

	// Check the response object
	if responseObj["message"] != "success" {
		t.Errorf("Expected message 'success', got %v", responseObj["message"])
	}

	// Check the limit count
	if limitCount != -1 {
		t.Errorf("Expected limit count -1, got %d", limitCount)
	}
}

func TestGet(t *testing.T) {
	// Create a mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check the request method
		if r.Method != http.MethodGet {
			t.Errorf("Expected method GET, got %s", r.Method)
		}

		// Check the request headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type application/json, got %s", r.Header.Get("Content-Type"))
		}

		// Respond with a JSON body
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Rate-Limit-Remaining", "10")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"message": "success"}`))
		if err != nil {
			return
		}
	}))
	defer server.Close()

	client := NewClient()

	// Create URL parameters
	urlParams := url.Values{}
	urlParams.Add("param1", "value1")

	// Call Get
	var responseObj map[string]interface{}
	limitCount, err := client.Get(server.URL, urlParams, http.Header{"Content-Type": []string{"application/json"}}, &responseObj)
	if err != nil {
		t.Fatalf("Get failed: %v", err)
	}

	// Check the response object
	if responseObj["message"] != "success" {
		t.Errorf("Expected message 'success', got %v", responseObj["message"])
	}

	// Check the limit count
	if limitCount != 10 {
		t.Errorf("Expected limit count 10, got %d", limitCount)
	}
}

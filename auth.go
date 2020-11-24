package goarcher

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
)

// TokenResponse is the token response.
type TokenResponse struct {
	RequestedObject RequestedObject `json:"RequestedObject"`
}

// RequestedObject is the request object.
type RequestedObject struct {
	SessionToken string `json:"SessionToken"`
}

//------------------------------------------------------------------------------
// Functions
//------------------------------------------------------------------------------

// Authenticate to the REST API.
func (c *Client) Authenticate() (string, error) {
	// Prepare the URL
	var reqURL *url.URL
	reqURL, err := url.Parse(c.BaseURL)
	if err != nil {
		return "", fmt.Errorf("Error while parsing the URL : %s", err)
	}
	reqURL.Path += "/api/core/security/login"

	// Marshal the request body
	data, err := json.Marshal(map[string]string{
		"InstanceName": c.InstanceName,
		"Username":     c.Username,
		"UserDomain":   c.UserDomain,
		"Password":     c.Password,
	})
	if err != nil {
		return "", fmt.Errorf("Error while marshaling the request body : %s", err)
	}

	// Create the request
	req, err := http.NewRequest("POST", reqURL.String(), bytes.NewBuffer(data))
	if err != nil {
		return "", fmt.Errorf("Error while creating the request : %s", err)
	}

	// Set the headers
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json,text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	// Do the request
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("Error while doing the request : %s", err)
	}
	defer resp.Body.Close()

	// Read the respsonse
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("Error while reading the request : %s", err)
	}

	// StatusCode is 500
	if resp.StatusCode == 500 {
		return "", fmt.Errorf("Status code is 500 and body is %s", string(body))
	}

	// Check the other status codes
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("Status code is %d", resp.StatusCode)
	}

	// Prepare the response
	var tokenResponse *TokenResponse

	// Unmarshal the response
	err = json.Unmarshal([]byte(body), &tokenResponse)
	if err != nil {
		return "", fmt.Errorf("Error while unmarshalling the response : %s", err)
	}

	return tokenResponse.RequestedObject.SessionToken, nil
}

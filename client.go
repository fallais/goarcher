package goarcher

import (
	"net/http"
)

//------------------------------------------------------------------------------
// Structure
//------------------------------------------------------------------------------

// Client is a client for QRadar REST API.
type Client struct {
	httpClient *http.Client

	BaseURL      string
	InstanceName string
	Username     string
	UserDomain   string
	Password     string

	// Endpoints
	Incidents Incidents
}

//------------------------------------------------------------------------------
// Factory
//------------------------------------------------------------------------------

// NewClient returns a new QRadar API client.
func NewClient(httpClient *http.Client, baseURL, instanceName, username, userDomain, password string) *Client {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	// Create the client
	c := &Client{
		httpClient:   httpClient,
		BaseURL:      baseURL,
		InstanceName: instanceName,
		Username:     username,
		UserDomain:   userDomain,
		Password:     password,
	}

	// Add the endpoints
	c.Incidents = &Endpoint{client: c}

	return c
}

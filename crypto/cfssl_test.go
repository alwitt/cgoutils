package crypto_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/alwitt/cgoutils/crypto"
	"github.com/apex/log"
	"github.com/go-resty/resty/v2"
	"github.com/google/uuid"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestCFSSLCallCSRSigning(t *testing.T) {
	assert := assert.New(t)
	log.SetLevel(log.DebugLevel)

	utCtxt := context.Background()

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	testClient := resty.New()
	// Install with mock
	httpmock.ActivateNonDefault(testClient.GetClient())

	testURL, err := url.Parse("http://ut.testing.dev")
	assert.Nil(err)

	uut, err := crypto.NewCFSSLClient(log.Fields{}, testURL, testClient, "request-id")
	assert.Nil(err)

	// ------------------------------------------------------------------------------------
	// Case 0: server return non-success status code

	{
		expectedURL := fmt.Sprintf("%s/api/v1/cfssl/sign", testURL.String())
		// Prepare mock
		httpmock.Reset()
		httpmock.RegisterResponder(
			"POST",
			expectedURL,
			func(_ *http.Request) (*http.Response, error) {
				// return bad response
				return httpmock.NewJsonResponse(
					http.StatusBadRequest, map[string]interface{}{"success": false},
				)
			},
		)

		complete := make(chan bool, 1)

		lclCtxt, lclCancel := context.WithTimeout(utCtxt, time.Second)
		go func() {
			_, err := uut.SignCSR(lclCtxt, "some csr", "server")
			assert.NotNil(err)
			complete <- true
		}()

		select {
		case <-lclCtxt.Done():
			assert.False(true, "request timed out")
		case <-complete:
			break
		}
		lclCancel()
	}

	// ------------------------------------------------------------------------------------
	// Case 1: server failed CSR

	{
		expectedURL := fmt.Sprintf("%s/api/v1/cfssl/sign", testURL.String())
		// Prepare mock
		httpmock.Reset()
		httpmock.RegisterResponder(
			"POST",
			expectedURL,
			func(_ *http.Request) (*http.Response, error) {
				// return bad response
				return httpmock.NewJsonResponse(
					http.StatusOK, map[string]interface{}{"success": false},
				)
			},
		)

		complete := make(chan bool, 1)

		lclCtxt, lclCancel := context.WithTimeout(utCtxt, time.Second)
		go func() {
			_, err := uut.SignCSR(lclCtxt, "some csr", "server")
			assert.NotNil(err)
			complete <- true
		}()

		select {
		case <-lclCtxt.Done():
			assert.False(true, "request timed out")
		case <-complete:
			break
		}
		lclCancel()
	}

	// ------------------------------------------------------------------------------------
	// Case 2: server returned incomplete message

	{
		expectedURL := fmt.Sprintf("%s/api/v1/cfssl/sign", testURL.String())
		// Prepare mock
		httpmock.Reset()
		httpmock.RegisterResponder(
			"POST",
			expectedURL,
			func(_ *http.Request) (*http.Response, error) {
				// return bad response
				return httpmock.NewJsonResponse(
					http.StatusOK, map[string]interface{}{"success": true},
				)
			},
		)

		complete := make(chan bool, 1)

		lclCtxt, lclCancel := context.WithTimeout(utCtxt, time.Second)
		go func() {
			_, err := uut.SignCSR(lclCtxt, "some csr", "server")
			assert.NotNil(err)
			complete <- true
		}()

		select {
		case <-lclCtxt.Done():
			assert.False(true, "request timed out")
		case <-complete:
			break
		}
		lclCancel()
	}

	// ------------------------------------------------------------------------------------
	// Case 3: server signed CSR

	{
		expectedURL := fmt.Sprintf("%s/api/v1/cfssl/sign", testURL.String())
		testCSR := uuid.NewString()
		result := uuid.NewString()
		// Prepare mock
		httpmock.Reset()
		httpmock.RegisterResponder(
			"POST",
			expectedURL,
			func(r *http.Request) (*http.Response, error) {
				// Verify the request payload
				var req map[string]string
				assert.Nil(json.NewDecoder(r.Body).Decode(&req))
				assert.Equal("server", req["profile"])
				assert.Equal(testCSR, req["certificate_request"])
				return httpmock.NewJsonResponse(http.StatusOK, map[string]interface{}{
					"success": true, "result": map[string]string{"certificate": result},
				})
			},
		)

		complete := make(chan bool, 1)

		lclCtxt, lclCancel := context.WithTimeout(utCtxt, time.Second)
		go func() {
			resp, err := uut.SignCSR(lclCtxt, testCSR, "server")
			assert.Nil(err)
			assert.Equal(result, resp)
			complete <- true
		}()

		select {
		case <-lclCtxt.Done():
			assert.False(true, "request timed out")
		case <-complete:
			break
		}
		lclCancel()
	}
}

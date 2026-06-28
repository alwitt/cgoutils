package crypto

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/alwitt/goutils"
	"github.com/apex/log"
	"github.com/go-playground/validator/v10"
	"github.com/go-resty/resty/v2"
	"github.com/oklog/ulid/v2"
)

// CFSSLClient client for interacting with CFSSL
type CFSSLClient interface {
	/*
		SignCSR request CFSSL to sign a certificate signing request, and return the certificate

			@param ctxt context.Context - calling context
			@param csfPayload string - the CSR in PEM encoding
			@param certProfile string - the CFSSL cert profile to sign the cert with
			@returns the new certificate signed by CFSSL
	*/
	SignCSR(ctxt context.Context, csrPayload string, certProfile string) (string, error)
}

// cfsslClientImpl implements CFSSLClient
type cfsslClientImpl struct {
	goutils.Component
	baseURL         *url.URL
	client          *resty.Client
	requestIDHeader string
	validate        *validator.Validate
}

/*
NewCFSSLClient define a new CFSSL client

	@param logTags log.Fields - component log tags
	@param baseURL string - CFSSL API base URL
	@param httpClient *resty.Client - core HTTP client
	@param requestIDHeader string - request tracking ID header field
	@returns new CFSSL client
*/
func NewCFSSLClient(
	logTags log.Fields,
	baseURL *url.URL,
	httpClient *resty.Client,
	requestIDHeader string,
) (CFSSLClient, error) {
	instance := &cfsslClientImpl{
		Component: goutils.Component{
			LogTags: logTags,
			LogTagModifiers: []goutils.LogMetadataModifier{
				goutils.ModifyLogMetadataByRestRequestParam,
			},
		},
		baseURL:         baseURL,
		client:          httpClient,
		requestIDHeader: requestIDHeader,
		validate:        validator.New(),
	}
	return instance, nil
}

func (c *cfsslClientImpl) makeRequest(
	ctxt context.Context,
	apiURL *url.URL,
	method string,
	payload interface{},
	headers, params map[string]string,
	logTags log.Fields,
) ([]byte, error) {
	reqID := ulid.Make().String()

	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			WithField("outbound-request-id", reqID).
			Error("Unable to serialize payload")
	}

	// Make request
	request := c.client.R().
		SetContext(ctxt).
		// Set request header
		SetHeader(c.requestIDHeader, reqID).
		// Add headers
		SetHeaders(headers).
		// Add query params
		SetQueryParams(params).
		// Set request payload
		SetBody(payloadRaw).
		// Setup error parsing
		SetError(goutils.RestAPIBaseResponse{})

	var resp *resty.Response

	switch method {
	case "POST":
		resp, err = request.Post(apiURL.String())
	case "GET":
		resp, err = request.Get(apiURL.String())
	default:
		return nil, goutils.NewBadInputError("unsupported target method", nil, true)
	}

	if err != nil {
		log.
			WithError(err).
			WithFields(logTags).
			WithField("outbound-request-id", reqID).
			Error("Request failed on call")
		return nil, goutils.NewRuntimeError("request failed on call", err, true)
	}

	// Request failed
	if !resp.IsSuccess() {
		respError := resp.Error().(*goutils.RestAPIBaseResponse)
		message := "request failed"
		if respError.Error != nil {
			message = respError.Error.Detail
		}
		err := goutils.NewHTTPRequestError(resp.StatusCode(), message, nil, true)
		log.
			WithError(err).
			WithFields(logTags).
			WithField("outbound-request-id", reqID).
			Error("Request failed")
		return nil, err
	}

	return resp.Body(), nil
}

type baseCFSSLResponse struct {
	Success  bool          `json:"success"`
	Errors   []interface{} `json:"errors"`
	Messages []interface{} `json:"messages"`
}

/*
SignCSR request CFSSL to sign a certificate signing request, and return the certificate

	@param ctxt context.Context - calling context
	@param csfPayload string - the CSR in PEM encoding
	@param certProfile string - the CFSSL cert profile to sign the cert with
	@returns the new certificate signed by CFSSL
*/
func (c *cfsslClientImpl) SignCSR(
	ctxt context.Context, csrPayload string, certProfile string,
) (string, error) {
	logTags := c.GetLogTagsForContext(ctxt)

	// Generate the URL for the request
	targetURL := c.baseURL.JoinPath("/api/v1/cfssl/sign")
	logTags["target-url"] = targetURL.String()

	// Generate the request payload
	requestPayload := map[string]string{"certificate_request": csrPayload, "profile": certProfile}

	// Make request
	respRaw, err := c.makeRequest(ctxt, targetURL, "POST", &requestPayload, nil, nil, logTags)
	if err != nil {
		log.WithError(err).WithFields(logTags).Error("CSR request failed")
		return "", err
	}

	// Parse the response
	type cfsslSignedCertPayload struct {
		Certificate string `json:"certificate" validate:"required"`
	}
	type cfsslCSRResponse struct {
		baseCFSSLResponse
		Result cfsslSignedCertPayload `json:"result" validate:"required"`
	}
	var resp cfsslCSRResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to parse CSR response")
		return "", goutils.NewBadInputError("failed to parse CSR response", err, true)
	}
	if !resp.Success {
		err := goutils.NewRuntimeError("cfssl failed to sign CSR", nil, true)
		log.
			WithError(err).
			WithFields(logTags).
			WithField("resp", string(respRaw)).
			Error("Failed to sign CSR")
		return "", err
	}
	if err := c.validate.Struct(&resp); err != nil {
		log.WithError(err).WithFields(logTags).Error("Failed to validate CSR response")
		return "", goutils.NewValidationError("failed to validate CSR response", err, true)
	}

	return resp.Result.Certificate, nil
}

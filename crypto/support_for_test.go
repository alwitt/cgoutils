package crypto_test

import (
	"net/url"
	"os"
)

func runningInCICD() bool {
	return os.Getenv("UT_IN_CICD") != ""
}

func getTestCFSSLBaseURL() (*url.URL, error) {
	urlStr := os.Getenv("UT_CFSSL_BASE_URL")
	if urlStr == "" {
		urlStr = "http://127.0.0.1:8888"
	}
	return url.Parse(urlStr)
}

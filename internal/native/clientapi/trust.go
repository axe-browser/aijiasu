package clientapi

const officialLoginEndpoint = "https://login.ajs-app.com/client.php"

// Application-maintained trust anchor approved for distribution. Its official
// ownership has not been independently established; never replace it by
// automatically trusting a certificate observed on an unverified connection.
const officialLoginSPKI = "423ebbdd38f5c452762fb6e2851a404df580d3047f8bcdfec6265298464566af"

type loginTrust struct {
	endpoint string
	spki     string
}

var bundledLoginTrust = loginTrust{endpoint: officialLoginEndpoint, spki: officialLoginSPKI}

func (trust loginTrust) pin(endpoint, explicit string) string {
	if explicit != "" {
		return explicit
	}
	if endpoint == trust.endpoint {
		return trust.spki
	}
	return ""
}

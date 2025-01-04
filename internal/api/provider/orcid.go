package provider

import (
	"context"
	"strings"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
	// We'll do a direct GET to the ORCID /userinfo endpoint for user data
	// see: https://info.orcid.org/documentation/ (Search "User Info Endpoint" or "OAuth")
)

const (
	// ORCID uses "https://orcid.org" for production.
	// For the sandbox, you can override or set ext.URL to "https://sandbox.orcid.org".
	defaultOrcidAuthBase = "orcid.org"
	defaultOrcidAPIBase  = "orcid.org"
)

// orcidProvider implements OAuthProvider
type orcidProvider struct {
	*oauth2.Config
	APIHost     string
	userInfoURL string
}

// Minimal userinfo shape from ORCID's /userinfo endpoint:
// https://info.orcid.org/documentation/integration-guide/user-experience-display-guidelines/#ORCID_OAuth_sign-in_screens
// The actual JSON can contain more fields, but these are the main ones to parse.
type orcidUser struct {
	Sub        string `json:"sub"`
	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
	Email      string `json:"email,omitempty"`
	// etc. you can add more as needed from the orcid userinfo response
}

// NewORCIDProvider builds the orcidProvider object,
// implementing the same pattern as other providers like Apple or Zoom.
func NewORCIDProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	// Validate the minimal fields are set (client_id, secret, redirect_uri)
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}

	// For the default public ORCID flow:
	// https://orcid.org/oauth/authorize
	// https://orcid.org/oauth/token
	// for sandbox, you might set ext.URL to "https://sandbox.orcid.org"
	authHost := chooseHost(ext.URL, defaultOrcidAuthBase)
	apiHost := chooseHost(ext.URL, defaultOrcidAPIBase)

	// ORCID typically wants the "openid" scope; you can add more like "/read-limited" if needed:
	// e.g. "openid /read-limited" or "openid email"
	oauthScopes := []string{"openid"}
	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	// Build an oauth2.Config
	return &orcidProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			RedirectURL:  ext.RedirectURI,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authHost + "/oauth/authorize",
				TokenURL: authHost + "/oauth/token",
			},
			Scopes: oauthScopes,
		},
		APIHost: apiHost,
		// As of ORCID docs, the userinfo endpoint is:
		// https://orcid.org/oauth/userinfo (or sandbox)
		userInfoURL: chooseHost(ext.URL, defaultOrcidAuthBase) + "/oauth/userinfo",
	}, nil
}

// GetOAuthToken implements the OAuthProvider interface, exchanging an auth code
// for an ORCID access token via the configured TokenURL.
func (p orcidProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	return p.Exchange(context.Background(), code)
}

// GetUserData fetches user info from the /userinfo endpoint
// using the bearer token, then populates the standard UserProvidedData struct.
func (p orcidProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	// if there is no access token, no user info
	if tok.AccessToken == "" {
		return &UserProvidedData{}, nil
	}

	// do the typical GET request to e.g. https://orcid.org/oauth/userinfo
	// with "Authorization: Bearer <token>"
	var u orcidUser
	if err := makeRequest(ctx, tok, p.Config, p.userInfoURL, &u); err != nil {
		return nil, err
	}

	// prepare the data in the same shape as other providers
	data := &UserProvidedData{}
	if u.Email != "" {
		data.Emails = []Email{{
			Email:    u.Email,
			Verified: false, // ORCID userinfo might or might not guarantee verified email
			Primary:  true,
		}}
	}

	// fill the claims
	// We do "Name" if it is present, else maybe combine given_name + family_name
	displayName := u.Name
	if displayName == "" {
		displayName = strings.TrimSpace(u.GivenName + " " + u.FamilyName)
	}

	data.Metadata = &Claims{
		Issuer:  p.APIHost,
		Subject: u.Sub,
		Name:    displayName,
		// The ORCID iD is in "sub", e.g. "0000-0002-1825-0097"
		// we can also store it in ProviderId, or use sub
		ProviderId: u.Sub,

		// For backward-compat with the rest of the system
		FullName: displayName,
	}
	return data, nil
}

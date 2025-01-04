// file: ./internal/api/provider/orcid_test.go
package api

import (
	"github.com/stretchr/testify/require"
	"github.com/supabase/auth/internal/conf"
	"testing"
)

func TestNewORCIDProvider(t *testing.T) {
	ext := conf.OAuthProviderConfiguration{
		Enabled:     true,
		ClientID:    []string{"fake-client-id"},
		Secret:      "fake-secret",
		RedirectURI: "http://localhost:9999/callback",
	}
	p, err := NewORCIDProvider(ext, "")
	require.NoError(t, err)
	require.NotNil(t, p)
	orcid, ok := p.(*orcidProvider)
	require.True(t, ok)
	require.Equal(t, "https://orcid.org/oauth/authorize", orcid.Endpoint.AuthURL)
	require.Equal(t, "https://orcid.org/oauth/token", orcid.Endpoint.TokenURL)
}

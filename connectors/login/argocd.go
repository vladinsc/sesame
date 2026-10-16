package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/vladinsc/sesame/pkg/connector"
)

func init() { Register(argocd{}) }

// argocd logs in to ArgoCD's session API. The server sets the argocd.token cookie; some versions only return
// the token in the body, so we set the cookie ourselves in that case.
type argocd struct{}

func (argocd) Meta() connector.LoginMeta {
	return connector.LoginMeta{
		Type:      "argocd",
		LoggedOut: []string{"/login"},
		Check:     "/api/v1/session/userinfo",
		Cookies:   []string{"argocd.token"},
	}
}

func (a argocd) Login(ctx context.Context, c *http.Client, job connector.LoginJob) (connector.LoginResult, error) {
	body, _ := json.Marshal(map[string]string{"username": job.Credential.Username, "password": job.Credential.Password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, job.UserURL+"/api/v1/session", bytes.NewReader(body))
	if err != nil {
		return connector.LoginResult{}, err
	}
	setCommon(req, job)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return connector.LoginResult{}, err
	}
	defer drain(resp)
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		return connector.LoginResult{}, connector.ErrBadCredentials
	default:
		return connector.LoginResult{}, fmt.Errorf("%w: status %d", connector.ErrUnexpectedResponse, resp.StatusCode)
	}
	origin := originOf(job.UserURL)
	arts := collectCookies(origin, resp.Cookies(), a.Meta().Cookies)
	if len(arts) == 0 {
		// Fall back to the token in the body.
		var out struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err == nil && out.Token != "" {
			arts = []connector.Artifact{{
				Origin: origin, Type: "cookie", Name: "argocd.token", Value: out.Token,
				Path: "/", Secure: true, SameSite: "lax",
			}}
		}
	}
	if len(arts) == 0 {
		return connector.LoginResult{}, fmt.Errorf("%w: no token", connector.ErrUnexpectedResponse)
	}
	return connector.LoginResult{Artifacts: arts, Landing: "/applications"}, nil
}

func (argocd) Check(ctx context.Context, c *http.Client, job connector.LoginJob) error {
	return simpleCheck(ctx, c, job, "/api/v1/session/userinfo")
}

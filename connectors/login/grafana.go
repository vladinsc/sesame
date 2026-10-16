package login

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/vladinsc/sesame/pkg/connector"
)

func init() { Register(grafana{}) }

// grafana logs in to Grafana's built-in user/password endpoint. The session is the grafana_session cookie.
type grafana struct{}

func (grafana) Meta() connector.LoginMeta {
	return connector.LoginMeta{
		Type:      "grafana",
		LoggedOut: []string{"/login"},
		Check:     "/api/user",
		Cookies:   []string{"grafana_session", "grafana_session_expiry"},
	}
}

func (g grafana) Login(ctx context.Context, c *http.Client, job connector.LoginJob) (connector.LoginResult, error) {
	body, _ := json.Marshal(map[string]string{"user": job.Credential.Username, "password": job.Credential.Password})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, job.UserURL+"/login", bytes.NewReader(body))
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
	case http.StatusUnauthorized:
		return connector.LoginResult{}, connector.ErrBadCredentials
	default:
		return connector.LoginResult{}, fmt.Errorf("%w: status %d", connector.ErrUnexpectedResponse, resp.StatusCode)
	}
	origin := originOf(job.UserURL)
	arts := collectCookies(origin, resp.Cookies(), g.Meta().Cookies)
	if len(arts) == 0 {
		return connector.LoginResult{}, fmt.Errorf("%w: no session cookie", connector.ErrUnexpectedResponse)
	}
	return connector.LoginResult{Artifacts: arts, Landing: "/"}, nil
}

func (grafana) Check(ctx context.Context, c *http.Client, job connector.LoginJob) error {
	return simpleCheck(ctx, c, job, "/api/user")
}

// helpers shared by several connectors

func setCommon(req *http.Request, job connector.LoginJob) {
	if job.UserAgent != "" {
		req.Header.Set("User-Agent", job.UserAgent)
	}
	if job.AcceptLanguage != "" {
		req.Header.Set("Accept-Language", job.AcceptLanguage)
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

func originOf(u string) string {
	// u is validated as an absolute http(s) URL upstream; return scheme://host[:port].
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return u
	}
	return req.URL.Scheme + "://" + req.URL.Host
}

func simpleCheck(ctx context.Context, c *http.Client, job connector.LoginJob, path string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, job.UserURL+path, nil)
	if err != nil {
		return err
	}
	setCommon(req, job)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: check status %d", connector.ErrUnexpectedResponse, resp.StatusCode)
	}
	return nil
}

package login

import (
	"encoding/json"
	"net/http"
)

func jsonDecode(r *http.Request, v any) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

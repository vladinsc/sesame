package policy

import "testing"

func engine() *Engine {
	return New([]Rule{
		{Groups: []string{"/admins"}, Scopes: []string{"*"}},
		{GroupPattern: "/projects/{p}/{env}", Scopes: []string{"projects/{p}/{env}"}},
		{GroupPattern: "/projects/{p}", Scopes: []string{"projects/{p}/*"}},
	})
}

func TestAllows(t *testing.T) {
	e := engine()
	cases := []struct {
		name   string
		groups []string
		scopes []string
		want   bool
	}{
		{"admin sees all", []string{"/admins"}, []string{"projects/cnair/prod"}, true},
		{"exact env", []string{"/projects/cnair/prod"}, []string{"projects/cnair/prod"}, true},
		{"wrong env", []string{"/projects/cnair/staging"}, []string{"projects/cnair/prod"}, false},
		{"project root wildcard", []string{"/projects/cnair"}, []string{"projects/cnair/prod"}, true},
		{"project root other project", []string{"/projects/silex"}, []string{"projects/cnair/prod"}, false},
		{"no groups", nil, []string{"projects/cnair/prod"}, false},
		{"unrelated group", []string{"/team-box"}, []string{"projects/cnair/prod"}, false},
		{"placeholder not crossing slash", []string{"/projects/cnair"}, []string{"projects/cnair/prod/extra"}, true},
		{"multiple scopes one matches", []string{"/projects/cnair/prod"}, []string{"projects/x/y", "projects/cnair/prod"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := e.Allows(tc.groups, tc.scopes); got != tc.want {
				t.Fatalf("Allows(%v,%v)=%v want %v", tc.groups, tc.scopes, got, tc.want)
			}
		})
	}
}

// A project name must not leak across the slash into another project via a crafted scope.
func TestNoCrossProjectLeak(t *testing.T) {
	e := engine()
	if e.Allows([]string{"/projects/cnair/prod"}, []string{"projects/cnair-evil/prod"}) {
		t.Fatal("prefix of a different project should not match")
	}
}

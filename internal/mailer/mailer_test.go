package mailer

import "testing"

func TestDevelopmentMailerRejectsProduction(t *testing.T) {
	if _, err := NewDevelopment("production", "https://example.com"); err == nil {
		t.Fatal("expected development mailer to be rejected in production")
	}
}

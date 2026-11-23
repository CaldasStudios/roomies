package repository

import "testing"

func TestBuildInvitationAcceptanceURLUsesAppPath(t *testing.T) {
	got, err := BuildInvitationAcceptanceURL("https://roomies.example", "tok")
	if err != nil {
		t.Fatal(err)
	}
	if want := "https://roomies.example/app/accept-invitation?token=tok"; got != want {
		t.Fatalf("BuildInvitationAcceptanceURL() = %q, want %q", got, want)
	}
}

package msauth

import "testing"

func TestGetMSCode(t *testing.T) {
	SetClient("67e646fb-20f3-4595-9830-56773a07637d", "")
	code, err := getMSAuthCode()
	if err != nil {
		t.Error(err)
	}
	t.Log(code)
}

func TestLogin(t *testing.T) {
	profile, astk, err := Login()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(profile, astk)
}

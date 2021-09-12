package MSMCAuth

import "testing"

func TestGetMSCode(t *testing.T) {
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

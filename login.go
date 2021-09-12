package msauth

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
	"io/ioutil"
	"math/rand"
	"net/http"
	"os/exec"
	"strconv"
	"time"
)

type xblAuthReq struct {
	Properties struct {
		AuthMethod string `json:"AuthMethod"`
		SiteName   string `json:"SiteName"`
		RpsTicket  string `json:"RpsTicket"`
	} `json:"Properties"`
	RelyingParty string `json:"RelyingParty"`
	TokenType    string `json:"TokenType"`
}

type AuthResp struct {
	IssueInstant  time.Time `json:"IssueInstant"`
	NotAfter      time.Time `json:"NotAfter"`
	Token         string    `json:"Token"`
	DisplayClaims struct {
		XUI []struct {
			UHS string `json:"uhs"`
		} `json:"xui"`
	} `json:"DisplayClaims"`
}

type xstsAuthReq struct {
	Properties struct {
		SandboxId  string   `json:"SandboxId"`
		UserTokens []string `json:"UserTokens"`
	} `json:"Properties"`
	RelyingParty string `json:"RelyingParty"`
	TokenType    string `json:"TokenType"`
}

type mcAuthReq struct {
	IdentityToken string `json:"identityToken"`
}

type mcAuthResp struct {
	Username    string        `json:"username"`
	Roles       []interface{} `json:"roles"`
	AccessToken string        `json:"access_token"`
	TokenType   string        `json:"token_type"`
	ExpiresIn   int32         `json:"expires_in"`
}

type mcOwnRssp struct {
	Items []struct {
		Name      string `json:"name"`
		Signature string `json:"signature"`
	} `json:"items"`
	Signature string `json:"signature"`
	KeyId     string `json:"keyId"`
}

type Profile struct {
	Id    string `json:"id"`
	Name  string `json:"name"`
	Skins []struct {
		Id      string `json:"id"`
		State   string `json:"state"`
		URL     string `json:"url"`
		Variant string `json:"variant"`
		Alias   string `json:"alias"`
	} `json:"skins"`
	Capes interface{} `json:"capes"`
}

var msConfig = oauth2.Config{
	ClientID:    "",
	Endpoint:    microsoft.LiveConnectEndpoint,
	RedirectURL: "http://127.0.0.1",
	Scopes:      []string{"XboxLive.signin", "XboxLive.offline_access"},
}

//SetClient 来自microsoft的clientID和secret
func SetClient(id, secret string) {
	msConfig.ClientID, msConfig.ClientSecret = id, secret
}

func newXBLAuth(astk string) *xblAuthReq {
	var data xblAuthReq
	data.Properties.AuthMethod = "RPS"
	data.Properties.SiteName = "user.auth.xboxlive.com"
	data.Properties.RpsTicket = "d=" + astk
	data.RelyingParty = "http://auth.xboxlive.com"
	data.TokenType = "JWT"
	return &data
}

func newXSTSAuth(XBLToken string) *xstsAuthReq {
	var data xstsAuthReq
	data.Properties.SandboxId = "RETAIL"
	data.Properties.UserTokens = []string{XBLToken}
	data.RelyingParty = "rp://api.minecraftservices.com/"
	data.TokenType = "JWT"
	return &data
}

//get microsoft auth code
func getMSAuthCode() (string, error) {
	//get microsoft auth code

	state := strconv.Itoa(rand.Int())
	server := http.Server{
		Addr: "127.0.0.1:80",
	}
	codeChan := make(chan string)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q["state"][0] != state {
			w.Write([]byte("state错误"))
		}
		w.Write([]byte("登陆完成，你现在可以关闭这个窗口"))
		codeChan <- q["code"][0]
	})
	if err := exec.Command("powershell", "start", "\""+msConfig.AuthCodeURL(state)+"\"").Start(); err != nil {
		return "", err
	}
	go server.ListenAndServe()
	msCode := <-codeChan
	server.Shutdown(context.Background())
	return msCode, nil
}

func getMSAuthToken(authCode string) (string, error) {
	// get microsoft auth token
	token, err := msConfig.Exchange(context.Background(), authCode)
	if err != nil {
		return "", err
	}
	return token.AccessToken, nil
}

func getMCProfile(MSAuthToken string) (profile *Profile, astk string, err error) {
	//XboxLive auth
	c := http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				Renegotiation:      tls.RenegotiateOnceAsClient,
				InsecureSkipVerify: true,
			},
		}}
	encoded, err := json.Marshal(newXBLAuth(MSAuthToken))
	if err != nil {
		return
	}
	req, err := http.NewRequest("POST", "https://user.auth.xboxlive.com/user/authenticate", bytes.NewReader(encoded))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return
	}
	respEncoded, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var XBLAuthResp AuthResp
	if err = json.Unmarshal(respEncoded, &XBLAuthResp); err != nil {
		return
	}

	//xsts auth
	encoded, err = json.Marshal(newXSTSAuth(XBLAuthResp.Token))
	if err != nil {
		return
	}
	req, err = http.NewRequest("POST", "https://xsts.auth.xboxlive.com/xsts/authorize", bytes.NewReader(encoded))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err = c.Do(req)
	if err != nil {
		return
	}
	respEncoded, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var xstsAuthResp AuthResp
	err = json.Unmarshal(respEncoded, &xstsAuthResp)
	if err != nil {
		return nil, "", fmt.Errorf("接收到%s\n出现错误%v", string(encoded), err)
	}

	//minecraft auth
	encoded, err = json.Marshal(mcAuthReq{IdentityToken: fmt.Sprintf(
		"XBL3.0 x=%s;%s",
		XBLAuthResp.DisplayClaims.XUI[0].UHS,
		xstsAuthResp.Token,
	)})
	req, err = http.NewRequest("POST", "https://api.minecraftservices.com/authentication/login_with_xbox", bytes.NewReader(encoded))
	if err != nil {
		return
	}
	resp, err = c.Do(req)
	if err != nil {
		return
	}
	respEncoded, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var mcAuthResp mcAuthResp
	if err = json.Unmarshal(respEncoded, &mcAuthResp); err != nil {
		return
	}
	astk = mcAuthResp.AccessToken

	//check ownership
	req, err = http.NewRequest("GET", "https://api.minecraftservices.com/entitlements/mcstore", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+astk)
	resp, err = c.Do(req)
	if err != nil {
		return
	}
	respEncoded, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var mcOwnResp mcOwnRssp
	if err = json.Unmarshal(respEncoded, &mcOwnResp); err != nil {
		return
	}
	//todo:check signature
	if mcOwnResp.Items == nil {
		return nil, "", fmt.Errorf("该账户上没有Minecraft")
	}

	//get profile
	req, err = http.NewRequest("GET", "https://api.minecraftservices.com/minecraft/profile", nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+astk)
	resp, err = c.Do(req)
	if err != nil {
		return
	}
	respEncoded, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	var mcProfileResp Profile
	err = json.Unmarshal(respEncoded, &mcProfileResp)
	if err != nil {
		return nil, "", fmt.Errorf("接收到%s\n出现错误%v", string(respEncoded), err)
	}
	return &mcProfileResp, astk, nil

}

//todo:refresh

//Login 返回玩家档案，AccessToken
func Login() (*Profile, string, error) {
	code, err := getMSAuthCode()
	if err != nil {
		return nil, "", err
	}
	MSToken, err := getMSAuthToken(code)
	if err != nil {
		return nil, "", err
	}
	return getMCProfile(MSToken)
}

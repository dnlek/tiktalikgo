package tkhttp;

import (
	"net/http"
	"net/url"
	"io"
	"io/ioutil"
	"time"
	"encoding/base64"
	"fmt"
	"crypto/sha1"
	"crypto/hmac"
	"crypto/md5"
	"strings"
)

const (
	TIKTALIK_HOST    = "https://tiktalik.com/api/v1"
	TIKTALIK_VER     = "1"
	TIKTALIK_PORT    = 80
)

type TKAuth struct {
	AccessKey, SecretKey string;
}

func DataRequest(method string, path string, data url.Values, auth TKAuth) (body string, err error) {
	t := time.Now()
	params_str := data.Encode()

	var values io.Reader;

	if params_str != "" {
		values = strings.NewReader(params_str)
	} else {
		values = strings.NewReader("")
	}

	req, err := http.NewRequest(method, TIKTALIK_HOST + path, values)
	if err != nil {
		return "", err
	}

	if params_str != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

		params_hash := md5.New()
		io.WriteString(params_hash, data.Encode())
		req.Header.Set("Content-MD5", fmt.Sprintf("%x", params_hash.Sum(nil)))
	}


	req.Header.Set("Date", t.UTC().Format("Mon, 02 Jan 2006 15:04:05 GMT"))

	canonical_string := GetCanonicalString(method, path, req.Header)
	req.Header.Set("Authorization", fmt.Sprintf("TKAuth %s:%s", auth.AccessKey, SignString(canonical_string, auth.SecretKey)))
	c := http.Client{}
	resp, err := c.Do(req)

	if err != nil {
		return "", err;
	}

	body_str, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return "", err;
	}
	return string(body_str[:]), nil
}

func Request(method string, path string, auth TKAuth) (body string, err error) {
	return DataRequest(method, path, url.Values{}, auth)
}

func GetCanonicalString(method string, path string, head http.Header) string {
	ret := method + "\n"
	ret += fmt.Sprintf("%s\n", head.Get("Content-MD5"))
	ret += fmt.Sprintf("%s\n", head.Get("Content-Type"))
	ret += fmt.Sprintf("%s\n", head.Get("Date"))
	ret += "/api/v1" + path
	return ret
}

func SignString(s string, secret string) string {
	key, _ := base64.StdEncoding.DecodeString(secret)
	data := []byte(s)

	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	sum := mac.Sum(nil)

	return base64.StdEncoding.EncodeToString(sum)
}

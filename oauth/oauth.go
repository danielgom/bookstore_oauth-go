package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/danielgom/bookstore_utils-go/errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

var (
	client = http.Client{}
)

const (
	headerXPublic    = "X-Public"
	headerXClientId  = "X-Client-Id"
	headerXCallerId  = "X-Caller-Id"
	paramAccessToken = "accessToken"
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"userId"`
	ClientId int64  `json:"clientId"`
}

func IsPublic(req *http.Request) bool {
	if req == nil {
		return true
	}

	return req.Header.Get(headerXPublic) == "true"
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}

	callerId, err := strconv.ParseInt(req.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}

	clientId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(req *http.Request) *errors.RestErr {
	if req == nil {
		return nil
	}

	cleanRequest(req)
	at := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if at == "" {
		return nil
	}

	token, err := getAccessToken(at)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	req.Header.Add(headerXClientId, strconv.FormatInt(token.ClientId, 10))
	req.Header.Add(headerXCallerId, strconv.FormatInt(token.UserId, 10))

	return nil
}

func cleanRequest(req *http.Request) {
	req.Header.Del(headerXCallerId)
	req.Header.Del(headerXClientId)
}

func getAccessToken(atId string) (*accessToken, *errors.RestErr) {

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*100)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://localhost:8080/oauth/accessToken/%s", atId), nil)

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.NewInternalServerError("Invalid response from user API while trying to get access token")
	}

	defer func() {
		err := resp.Body.Close()
		if err != nil {
		}
	}()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode > 399 {
		restErr := new(errors.RestErr)
		if err = json.Unmarshal(respBody, restErr); err != nil {
			return nil, errors.NewInternalServerError("Invalid error interface when trying to get access token")
		}
		return nil, restErr
	}

	at := new(accessToken)
	if err = json.Unmarshal(respBody, at); err != nil {
		return nil, errors.NewInternalServerError("Error when trying to unmarshal user response")
	}

	return at, nil
}

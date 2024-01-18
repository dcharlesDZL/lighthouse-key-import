package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/pflag"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

var NotFoundError = errors.New("404 not found")

type KeyStore struct {
	Crypto struct {
		Kdf struct {
			Function string `json:"function"`
			Params   struct {
				Dklen int    `json:"dklen"`
				N     int    `json:"n"`
				R     int    `json:"r"`
				P     int    `json:"p"`
				Salt  string `json:"salt"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"kdf"`
		Checksum struct {
			Function string `json:"function"`
			Params   struct {
			} `json:"params"`
			Message string `json:"message"`
		} `json:"checksum"`
		Cipher struct {
			Function string `json:"function"`
			Params   struct {
				Iv string `json:"iv"`
			} `json:"params"`
			Message string `json:"message"`
		} `json:"cipher"`
	} `json:"crypto"`
	Description string `json:"description"`
	Pubkey      string `json:"pubkey"`
	Path        string `json:"path"`
	UUID        string `json:"uuid"`
	Version     int    `json:"version"`
}

type KeystoreImportRequest struct {
	Enable   bool     `json:"enable"`
	Password string   `json:"password"`
	Keystore KeyStore `json:"keystore"`
}

func main() {
	authToken := pflag.String("auth", "", "please input the validator client auth token.")
	feeRecipient := pflag.String("feeRecipient", "", "please input the validator fee recipient.")
	password := pflag.String("password", "", "please input the validator keystore password.")
	keyPath := pflag.String("keypath", "", "please input key path.")
	isImportKey := pflag.Bool("key", false, "import key or not.")
	isSetFeeRecipient := pflag.Bool("fee", false, "set fee recipient or not.")
	isDebug := pflag.Bool("debug", false, "set log level to debug.")
	pflag.Parse()
	files, err := os.ReadDir(*keyPath)
	if err != nil {
		logrus.Errorf("load keystore dir error: %v", err)
	}
	if *isDebug {
		logrus.SetLevel(logrus.DebugLevel)
	} else {
		logrus.SetLevel(logrus.InfoLevel)
	}
	for _, file := range files {
		fileName := file.Name()

		if strings.HasPrefix(fileName, "keystore-") && strings.HasSuffix(fileName, ".json") {
			data, err := os.ReadFile(*keyPath + "/" + fileName)
			if err != nil {
				logrus.Errorf("read file error: %s", *keyPath+"/"+fileName)
				continue
			}

			var keyStore KeyStore
			err = json.Unmarshal(data, &keyStore)
			if err != nil {
				logrus.Errorf("parse JSON in file error: %s", fileName)
				continue
			}

			if *isImportKey {
				logrus.Debugf("keystore: %s", string(data))
				importKeystore(*password, *authToken, keyStore)
				time.Sleep(500 * time.Millisecond)
			}
			if *isSetFeeRecipient {
				setFeeRecipient(*feeRecipient, "0x"+keyStore.Pubkey, *authToken)
				time.Sleep(500 * time.Millisecond)
			}
		}
	}
}

func importKeystore(password, authToken string, keystore KeyStore) {
	keyReq := &KeystoreImportRequest{
		Enable:   true,
		Password: password,
		Keystore: keystore,
	}
	body, err := json.Marshal(keyReq)
	logrus.Debugf("key request: %s", string(body))
	res, err := postWithAuthToken("http://localhost:5062/lighthouse/validators/keystore", body, authToken)
	if err != nil {
		logrus.Error(err)
	}
	logrus.Info(string(res))
}

func setFeeRecipient(feeRecipient, pubkey, authToken string) {
	feeReq := fmt.Sprintf(`{"ethaddress": "%s"}`, feeRecipient)
	logrus.Debugf("fee request: %s", feeReq)
	_, err := postWithAuthToken(fmt.Sprintf("http://localhost:5062/eth/v1/validator/%s/feerecipient", pubkey), []byte(feeReq), authToken)
	if err != nil {
		parts := strings.Split(err.Error(), ",")

		var errorResponse string

		for _, part := range parts {
			trimmedPart := strings.TrimSpace(part)
			if strings.HasPrefix(trimmedPart, "error-response:") {
				errorResponse = strings.TrimSpace(strings.TrimPrefix(trimmedPart, "error-response:"))
				break
			}
		}
		if errorResponse == "null" {
			logrus.Infof("Fee recipient set successfully.")
			return
		} else {
			logrus.Errorf("fee recipient set error: %s", err.Error())
		}
	}
}

func postWithAuthToken(url string, body []byte, authToken string) ([]byte, error) {

	payload := bytes.NewReader(body)

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", authToken))

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return nil, NotFoundError
		}
		return nil, fmt.Errorf("url: %v, status: %d, error-response: %s", url, resp.StatusCode, data)
	}
	return data, err
}

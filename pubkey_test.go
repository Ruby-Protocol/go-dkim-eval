package dkim

import (
	"fmt"
	"testing"
)

func TestGetHeader(t *testing.T) {
	selector := "20221208"
	domain := "gmail.com"
	pubKey, _type, err := NewPubKeyRespFromDNS(selector, domain, nil)

	if err != nil {
		fmt.Println(pubKey)
		fmt.Println(_type)
	} else {
		t.Log(err)
	}

}

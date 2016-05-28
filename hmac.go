package aws_hmac

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha1"
	"unicode/utf8"
	"encoding/base64"
)

func HMAC256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}


func HMAC256Sign(key, dateStamp, regionName, serviceName string) []byte {
	if utf8.ValidString(key) {
		k := HMAC256([]byte("AWS4"+key), []byte(dateStamp))
		k = HMAC256(k, []byte(regionName))
		k = HMAC256(k, []byte(serviceName))
		k = HMAC256(k, []byte("aws4_request"))
		return k
	} else {
		panic("Invalid key")
	}
}


func HMAC1(key, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func HMAC1Sign(key, data string) string {
	if utf8.ValidString(key) {
		k := HMAC1([]byte(key), []byte(data))
		return base64.StdEncoding.EncodeToString(k)
	} else {
		panic("Invalid key")
	}
}

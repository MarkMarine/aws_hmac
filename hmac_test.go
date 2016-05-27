package aws_hmac

import (
	"testing"
	"encoding/hex"
	"encoding/base64"
)

func TestHMAC256Sign(t *testing.T) {

	key := `wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY`
	dateStamp := "20120215"
	regionName := "us-east-1"
	serviceName := "iam"

	//kSecret := "41575334774a616c725855746e46454d492f4b374d44454e472b62507852666943594558414d504c454b4559"
	//kDate := "969fbb94feb542b71ede6f87fe4d5fa29c789342b0f407474670f0c2489e0a0d"
	//kRegion := "69daa0209cd9c5ff5c8ced464a696fd4252e981430b10e3d3fd8e2f197d7a70c"
	//kService := "f72cfd46f26bc4643f06a11eabb6c0ba18780c19a8da0c31ace671265e3c87fa"
	kSigning := "f4780e2d9f65fa895f9c67b32ce1baf0b0d8a43505a000a1a9e090d414db404d"

	Signing := HMAC256Sign(key, dateStamp, regionName, serviceName)

	if hex.EncodeToString(Signing) != kSigning {
		t.Errorf("Error with Signing\nExpected:\t%v\nRecieved:\t%v\n", string(kSigning), string(Signing))
	}
}

func TestHMAC1Sign(t *testing.T) {
	// PUT /quotes/nelson HTTP/1.0
	// Content-Md5: c8fdb181845a4ca6b8fec737b3581d76
	// Content-Type: text/html
	// Date: Thu, 17 Nov 2005 18:49:58 GMT
	// X-Amz-Meta-Author: foo@bar.com
	// X-Amz-Magic: abracadabra

	verb := "PUT"
	contentMD5 := "c8fdb181845a4ca6b8fec737b3581d76"
	contentType := "text/html"
	date := "Thu, 17 Nov 2005 18:49:58 GMT"
	canonicalizedAmzHeaders := "x-amz-magic:abracadabra"+"\n"+"x-amz-meta-author:foo@bar.com"
	canonicalizedResource := "/quotes/nelson"
	key := "OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV"

	// conical string to sign:
	// "PUT\nc8fdb181845a4ca6b8fec737b3581d76\ntext/html\nThu, 17 Nov 2005 18:49:58 GMT\nx-amz-magic:abracadabra\nx-amz-meta-author:foo@bar.com\n/quotes/nelson"

	// Access Key: 44CF9590006BF252F707
	// Secret Key: OtxrzxIsfpFjA7SwPzILwy8Bw21TLhquhboDYROV

	sig := HMAC1Sign(verb, contentMD5, contentType, canonicalizedAmzHeaders, canonicalizedResource, key, date)

	signed := base64.StdEncoding.EncodeToString(sig)
	expectedSignature := "jZNOcbfWmD/A/f3hSvVzXZjM2HU="

	if signed != expectedSignature {
		t.Error("expected:", string(expectedSignature), "recieved:", string(sig))
	}
	// Result:
	//PUT /quotes/nelson HTTP/1.0
	//Authorization: AWS 44CF9590006BF252F707:jZNOcbfWmD/A/f3hSvVzXZjM2HU=
	//Content-Md5: c8fdb181845a4ca6b8fec737b3581d76
	//Content-Type: text/html
	//Date: Thu, 17 Nov 2005 18:49:58 GMT
	//X-Amz-Meta-Author: foo@bar.com
	//X-Amz-Magic: abracadabra
}

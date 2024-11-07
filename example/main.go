package main

import (
	"crypto/rand"
	"fmt"
	"log"

	"github.com/AlexandrSoloviov/go-rsa-auth/example/econtroller"
	"github.com/AlexandrSoloviov/go-rsa-auth/gorest"
	"github.com/AlexandrSoloviov/go-rsa-auth/gorsaauth"
)

const testToken = "534d2d52472d303189a7007a65d8a1b9542028eec8b531b8f1f8a6ff37910eb55912927dfa90ef0b1673ebef52e6fed44a28beaa4ec828105256b3b5d108a05bc1b625343bce4d1d1d1e4163f6c78a3829d93b855784fe1d4e13ceb01953cb0b49d532288e4d3c9f21c87ecbdd5db84dc8ea9e7a00a9523ebc585693cb99a83d640beb628a34ca444adfba4526c75db6c794e1b841699e56de2c1cbcfa6206ff75f317305b2fe9eb06834db236ece6f97821605dc21067c56661a31f9c39baf025eeae9b0cd26b9060c7375d076621ffc182472f839dc37dbd52ba3c6eadae9551f0b02e2bab997dff439439b04f9de92cee320e39c1e04909edf76a95c01d4fc1389c2ce08e0bd75663a6b29775c2a35c70add04ca60709d89c8478d5ef8ad547d91e5c3024a986f4a64c746b52c953a5dcb580d8cb28ae51fa107a39daad94d99e0f7150a661597da08456191cc04e673ba03d5fabd6be09d6efa61222d72a0d1ca96754ba7159e6d874f3d645175a389b2d66f24bddfc821444910179bb8ab05cfcb8bfb80cb88cf364ed96839db1ad87c5661da0fcd54ae40462c406d406ee408100eaf474972294aa1f472c272f966c51d5b0ad01a440835d02708f36e6a09e6be686a796989e5c7d2cb9a9cb0ea45710e3ca27bc20dfe06006da44655191ac14f057e91555bd62d8b0db1edc879e660ebbecb71565709728d7cee017186cee9d3b2c5b86230020ff7b0f299d7ec9091e9533f593996ca7ffb40b0424179637127ea7d0ce599dd414ee60c85de449b512469e6e684eaf62fae023436d63c9fd350f49f23c6a8880dcc1dc3acede945abaa487671b3c06491406fd761d1bcf79c18cc716e654c2c7898dd7986fa15eac43d4bec1f620ef564c8042d153538f13f1eacf3a43e9bb3f219cda146d8b6e4dad3c2c8732a3a588c24bb56d7f5122ef0f05dec6d5f5f8206fdfc6181c32da93bc93a71530ee80f5c6e0dabe08592ad5b1d22ade1c155302c947b56aa5a83bd49cbf0f109411db98217bacf59adf9966cf53c4af3740b7678bcf66b943d10d414fe8c160b767062702ccd7bc4021ce619475f7bef7647daf2998469bcab5d1176f500b05b41d0e2a8af6fb0ac65add8152577f885d403b7044711c8a6bae503083f7d991d0ac675970c312ddec73552aa88700c636784c872e020c2a9c9d46b01e3460a3ee0ea552ef7a7f3049e00cc20cbac995857d63d142a06c93001c26bc62ccc3b993c24f41956bd20833c8a898029d54ce2dc37919acb78ccbd925c05e034ebfc453f79f5b66d4d744f9a6a10420f2c674e315c1cad10c2ffac509466bebb79082249c4ddbfa283d1dca509cbff6d2f093bfa558fd6324853c7af605d785cface625ed2a3daf640557f137368f505653004b4214d86b213fa712ee8952865c5e52a02213486a2b67faf756"

func main() {
	var private *gorsaauth.PrivateKey
	var public *gorsaauth.PublicKey
	if pem, err := gorsaauth.LoadPem("example/private.pem"); err != nil {
		log.Fatal("BAD DAY TO LOAD PEM", err)
	} else if pk, err := pem.PrivateKey(); err != nil {
		log.Fatal("CANT PARSE PRIVATE KEY", err)
	} else {
		private = pk
	}

	if pem, err := gorsaauth.LoadPem("example/public.pem"); err != nil {
		log.Fatal("BAD DAY TO LOAD PEM", err)
	} else if pk, err := pem.PublicKey(); err != nil {
		log.Fatal("CANT PARSE PRIVATE KEY", err)
	} else {
		public = pk
	}

	testData := make([]byte, 128)
	rand.Read(testData)
	sign, err := private.Sign(testData)
	if err != nil {
		log.Fatal("SIGN ERROR", err)
	}
	if err := public.Verify(testData, sign); err != nil {
		log.Fatal("SIGN VERIFY ERROR", err)
	} else {
		log.Println("SIGN VERIFY OK")
	}

	token := private.NewToken("SM-RG-01-LLLLLLLLL", 1)
	signedToken, err := token.Sign(private)
	if err != nil {
		log.Fatal("cant`t sign token", err)
	}

	// signedToken[10] = 1
	strSignedToken := fmt.Sprintf("%0+x", signedToken)
	log.Println("GENERATED TOKEN:", strSignedToken)

	if token, err := public.AuthHex(strSignedToken); err != nil {
		log.Fatal("GENERATED TOKEN AUTH FAIL", err)
	} else {
		log.Println("GENERATED TOKEN:", token.Id(), token.ExpiredAt())
	}

	if token, err := public.AuthHex(testToken); err != nil {
		log.Fatal("TEST TOKEN AUTH FAIL", err)
	} else {
		log.Println("TEST TOKEN:", token.Id(), token.ExpiredAt())
	}
	service := gorest.New(33333)

	service.SetTimeout(20)

	c := econtroller.NewController(service.Sessions)
	c.SetKey(public)
	c.SetErrorMessage("OKNOT")

	service.Handle("/auth", c.Auth)
	service.AuthHandle("/work", c.Work)
	service.Run()
	// gorsaauth.NewPrivateKey()
}

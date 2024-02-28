package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"io/ioutil"
	"os"
	"path/filepath"
)

func make_signature_of_message(private_key *rsa.PrivateKey, message string) []byte {
	hashed := sha256.Sum256([]byte(message))
	sig, err := rsa.SignPSS(rand.Reader, private_key, crypto.SHA256, hashed[:], nil)
	error_handle(err)

	encoded_signature := base64.StdEncoding.EncodeToString(sig)
	return []byte(encoded_signature)

}

func make_signature_of_file(private_key *rsa.PrivateKey, file_path string) []byte {
	// file path should be the unencrypted file

	file_contents, err := ioutil.ReadFile(file_path)
	hashed := sha256.Sum256([]byte(file_contents))

	error_handle(err)
	sig, err := rsa.SignPSS(rand.Reader, private_key, crypto.SHA256, hashed[:], nil)
	error_handle(err)

	encoded_signature := base64.StdEncoding.EncodeToString(sig)
	return []byte(encoded_signature)

}

func verify_signature_of_message(message string, signature []byte) (bool, string) {
	// check all the public keys
	hashed := sha256.Sum256([]byte(message))

	filename, _ := os.Executable()
	dir := filepath.Dir(filename)

	public_keys := list_all_public_keys_for_func(dir)

	// check each public key against the signature and if found, return the public key username

	for _, public_key := range public_keys {

		public_key_bytes, err := ioutil.ReadFile(public_key)
		error_handle(err)

		public_key_bytes, err = base64.StdEncoding.DecodeString(string(public_key_bytes))
		error_handle(err)
		parsed_public_key, err := x509.ParsePKIXPublicKey(public_key_bytes)
		error_handle(err)
		rsa_public_key := parsed_public_key.(*rsa.PublicKey)
		sig, err := base64.StdEncoding.DecodeString(string(signature))
		error_handle(err)

		err = rsa.VerifyPSS(rsa_public_key, crypto.SHA256, hashed[:], sig, nil)

		if err == nil {
			return true, public_key
		}

	}
	return false, " " // if no public key is found, return false and an empty string

}

func verify_signature_of_file(file_path string, signature []byte) (bool, string) {
	// file path should be the decrypted
	file_contents, err := ioutil.ReadFile(file_path)
	defer error_handle(err)
	hashed := sha256.Sum256([]byte(file_contents))
	filename, _ := os.Executable()
	dir := filepath.Dir(filename)

	public_keys := list_all_public_keys_for_func(dir)
	// check each public key against the signature and if found, return the public key username
	for _, public_key := range public_keys {
		public_key_bytes, err := ioutil.ReadFile(public_key)
		error_handle(err)
		public_key_bytes, err = base64.StdEncoding.DecodeString(string(public_key_bytes))
		error_handle(err)

		parsed_public_key, err := x509.ParsePKIXPublicKey(public_key_bytes)
		error_handle(err)
		rsa_public_key := parsed_public_key.(*rsa.PublicKey)
		sig, err := base64.StdEncoding.DecodeString(string(signature))
		error_handle(err)

		err = rsa.VerifyPSS(rsa_public_key, crypto.SHA256, hashed[:], sig, nil)

		if err == nil {
			return true, public_key
		}
	}
	return false, " "

}

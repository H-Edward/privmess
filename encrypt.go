package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func encrypt(dir string) {
	// encrypt a message
	var message string
	fmt.Println("What would you like to encrypt?")
	fmt.Println("Please enter the message here:")
	message = Reader()
	// message needs to be appended with a type
	// so that the receiver knows what to do with it
	// e.g. "message" or "file"

	message = "message" + message

	// receiver will need to know what to do with the message
	// hence will respond accordingly and remove the type string

	// take the public key to encrypt with
	var name string
	fmt.Println("What is the public key of the person you want to encrypt to?")
	fmt.Println("Please enter the username here:")
	name = Reader()

	public_key_path := filepath.Join(dir, name+"_public_key.pem")
	if _, err := os.Stat(public_key_path); os.IsNotExist(err) {
		fmt.Println(red + "Public key does not exist!" + white)

		return
	}

	// read the file

	public_key, err := ioutil.ReadFile(public_key_path)
	error_handle(err)

	// encrypt the message

	// decode the public key
	public_key_bytes, err := base64.StdEncoding.DecodeString(string(public_key))
	error_handle(err)

	// parse the public key
	parsed_public_key, err := x509.ParsePKIXPublicKey(public_key_bytes)
	error_handle(err)

	// break message into chucks of 440 bytes (440 for ease of use)
	// The message must be no longer than the length of the public modulus minus twice the hash length, minus a further 2. - documentation
	// encrypt each chuck
	// put the encrypted chucks together seperated by a newline

	encrypted_message_array := make([]string, (len(message)/440)+1)

	for i := 0; i < (len(message)/440)+1; i++ {

		if (i+1)*440 > len(message) {

			encrypted_message, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed_public_key.(*rsa.PublicKey), []byte(message[i*440:]), nil)
			error_handle(err)

			encrypted_message = []byte(base64.StdEncoding.EncodeToString((encrypted_message)))
			encrypted_message_array[i] = string(encrypted_message)
		} else { // last chunk code block otherwise it will be searching for parts of the message that don't exist (out of range)
			encrypted_message, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed_public_key.(*rsa.PublicKey), []byte(message[i*440:(i+1)*440]), nil)
			error_handle(err)

			encrypted_message = []byte(base64.StdEncoding.EncodeToString((encrypted_message)))
			encrypted_message_array[i] = string(encrypted_message)
		}

	}

	fmt.Println("Encrypted message:")
	var to_display string
	for i := 0; i < len(encrypted_message_array); i++ {
		to_display += encrypted_message_array[i] + " "
	}
	to_display = strings.TrimSuffix(to_display, " ")
	fmt.Println(to_display)

}

func encrypt_file(dir string) {

	var message string
	fmt.Println("Enter a path to the file relative to your current working directory (e.g. file.txt):")
	filepath_unencrypted := Reader()

	// find the file size
	file_info, err := os.Stat(filepath_unencrypted)
	error_handle(err)
	// if the file is over 1MB, use AES RSA encryption method since it is faster
	// RSA can take a long time to encrypt large files whereas AES is much faster since it is symmetric
	if file_info.Size() > 1000000 { // 1MB
		fmt.Println(yellow + "File size is over 1MB, RSA + AES in use" + white)
		encrypt_file_large(filepath_unencrypted, dir)
		return

	} else {
		fmt.Println(yellow + "File size is under 1MB, RSA in use" + white)
	}

	file_contents, err := ioutil.ReadFile(filepath_unencrypted)
	error_handle(err)

	filename := filepath_unencrypted[strings.LastIndex(filepath_unencrypted, "/")+1:] // this will get the filename from the path

	filename_safe := strings.ReplaceAll(filename, "|", "_") // replace any | with _ since | is used as the spliting character on the receiver side

	// type the message so the receiver knows what to do with it
	length_of_filename := len(filename_safe)

	message = "file" + "|" + string(length_of_filename) + "|" + filename_safe + "|" + string(file_contents)

	// take the public key to encrypt with
	var name string
	fmt.Println("What is the public key of the person you want to encrypt to?")
	fmt.Println("Please enter the username here:")
	name = Reader()
	public_key_path := filepath.Join(dir, name+"_public_key.pem")

	if _, err := os.Stat(public_key_path); os.IsNotExist(err) {
		fmt.Println(red + "Public key does not exist!" + white)

		return
	}
	// read the file

	public_key, err := ioutil.ReadFile(public_key_path)
	error_handle(err)

	public_key_bytes, err := base64.StdEncoding.DecodeString(string(public_key))
	error_handle(err)

	parsed_public_key, err := x509.ParsePKIXPublicKey(public_key_bytes)
	error_handle(err)

	encrypted_message_array := make([]string, (len(message)/440)+1)

	for i := 0; i < (len(message)/440)+1; i++ {

		if (i+1)*440 > len(message) {
			encrypted_message, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed_public_key.(*rsa.PublicKey), []byte(message[i*440:]), nil)
			error_handle(err)

			encrypted_message = []byte(base64.StdEncoding.EncodeToString((encrypted_message)))
			encrypted_message_array[i] = string(encrypted_message)
		} else {
			encrypted_message, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed_public_key.(*rsa.PublicKey), []byte(message[i*440:(i+1)*440]), nil)
			error_handle(err)

			encrypted_message = []byte(base64.StdEncoding.EncodeToString((encrypted_message)))
			encrypted_message_array[i] = string(encrypted_message)
		}

	}

	var to_display string
	for i := 0; i < len(encrypted_message_array); i++ {
		to_display += encrypted_message_array[i] + " "
	}
	to_display = strings.TrimSuffix(to_display, " ")
	path_to_sent := filepath.Join(dir, "sent", filename)

	encrypted_file, err := os.Create(path_to_sent + ".enc")
	error_handle(err)
	defer encrypted_file.Close()
	encrypted_file.Write([]byte(to_display))
	fmt.Println("Encrypted file:", path_to_sent+".enc")

}

func encrypt_file_large(filepath_unencrypted string, dir string) {
	// will use aes to encrypt the file
	// then encrypt the aes key with rsa
	// then the file will have the aes key attached to it, encrypted with rsa and then the actual file encrypted with aes
	// the receiver will decrypt the aes key with rsa and then decrypt the file with aes

	// function is not meant to be called directly, only called from encrypt_file
	var message string

	file_contents, err := ioutil.ReadFile(filepath_unencrypted)
	error_handle(err)

	filename_unencrypted := filepath_unencrypted[strings.LastIndex(filepath_unencrypted, "/")+1:] // this will get the filename from the path

	filename_safe := strings.ReplaceAll(filename_unencrypted, "|", "_") // replace any | with _

	// type the message so the receiver knows what to do with it
	length_of_filename := len(filename_safe)

	message = "largefile" + "|" + string(length_of_filename) + "|" + filename_safe + "|" + string(file_contents)
	// take the public key to encrypt with
	var name string
	fmt.Println("What is the public key of the person you want to encrypt to?")
	fmt.Println("Please enter the username here:")
	name = Reader()
	public_key_path := filepath.Join(dir, name+"_public_key.pem")

	if _, err := os.Stat(public_key_path); os.IsNotExist(err) {
		fmt.Println(red + "Public key does not exist!" + white)

		return
	}

	// do aes encryption on the message
	// generate a random key
	key := make([]byte, 32)
	_, err = rand.Read(key)
	error_handle(err)

	// create the aes block
	block, err := aes.NewCipher(key)
	error_handle(err)

	// create a gcm
	gcm, err := cipher.NewGCM(block)

	error_handle(err)

	// create a nonce
	nonce := make([]byte, gcm.NonceSize())
	_, err = rand.Read(nonce)
	error_handle(err)

	// encrypt the message
	encrypted_message := gcm.Seal(nonce, nonce, []byte(message), nil)

	// encrypt the key with rsa
	public_key, err := ioutil.ReadFile(public_key_path)
	error_handle(err)

	public_key_bytes, err := base64.StdEncoding.DecodeString(string(public_key))
	error_handle(err)

	parsed_public_key, err := x509.ParsePKIXPublicKey(public_key_bytes)
	error_handle(err)

	encrypted_key, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed_public_key.(*rsa.PublicKey), key, nil)
	error_handle(err)

	// save the encrypted key and the encrypted message to a file

	path_to_sent := filepath.Join(dir, "sent", filename_safe)
	path_to_sent_w_ext := filepath.Join(path_to_sent + ".enc")
	encrypted_file, err := os.Create(path_to_sent_w_ext)
	error_handle(err)
	defer encrypted_file.Close()

	encrypted_key_string := base64.StdEncoding.EncodeToString(encrypted_key)
	header := "largefile" + "|" + string(length_of_filename) + "|" + filename_safe
	// conv to base64
	// encrypt the header

	encrypted_header, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, parsed_public_key.(*rsa.PublicKey), []byte(header), nil)
	error_handle(err)
	encrypted_header = []byte(base64.StdEncoding.EncodeToString(encrypted_header))

	encrypted_message = []byte(base64.StdEncoding.EncodeToString(encrypted_message))
	complete_message := string(encrypted_header) + " " + encrypted_key_string + " " + string(encrypted_message)

	encrypted_file.Write([]byte(complete_message))

	fmt.Println("Encrypted file:", path_to_sent_w_ext)

	// take the public key to encrypt with

}

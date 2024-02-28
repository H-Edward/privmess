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

func decrypt(private_key string) {

	// take what is to be decrypted
	var encrypted_message string
	fmt.Println("What would you like to decrypt?")
	fmt.Println("Please enter the message here:")

	// separate the message into chucks
	// decrypt each chuck
	// put the decrypted chucks together
	encrypted_message = Reader()
	private_key_bytes, err := base64.StdEncoding.DecodeString(private_key)
	error_handle(err)
	parsed_private_key, err := x509.ParsePKCS1PrivateKey(private_key_bytes)
	error_handle(err)

	// separate the message into chucks
	encrypted_message_array := strings.Split(encrypted_message, " ")
	decrypted_message := make([]string, len(encrypted_message_array)*440)

	for i := 0; i < len(encrypted_message_array); i++ {
		encrypted_message_bytes, err := base64.StdEncoding.DecodeString(encrypted_message_array[i])
		error_handle(err)
		decrypted_message_chunk, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_message_bytes, nil)
		error_handle(err)
		decrypted_message[i] = string(decrypted_message_chunk)

	}
	// combine the chucks

	decrypted_message_string := strings.Join(decrypted_message, "")
	// check the type of the message
	// if first 4 characters are "file" then it is a file
	if decrypted_message_string[:4] == "file" {

		// message is in the form file|length_of_filename|filename|file_contents

		header := strings.SplitN(decrypted_message_string, "|", 4)
		filename := header[2]
		file_contents := header[3]

		fmt.Println("Message is a file with the name:", filename)
		fmt.Println("Do you want to save the file? (y/N)")

		choice := Reader()
		if choice == "y" {
			path_to_received := filepath.Join("received", filename)
			file, err := os.Create(path_to_received)
			error_handle(err)
			defer file.Close()
			file.Write([]byte(file_contents))
			fmt.Println("File saved at:", path_to_received)
		} else {
			fmt.Println("File not saved")
		}

	} else if decrypted_message_string[:9] == "largefile" {
		fmt.Println("Message is a large file, please use the decrypt file option")
		// probably shouldn't be happening, since the function is only on for 1MB files+ but just in case
		return

	} else {
		// if not a file then it is a message by default
		fmt.Println("Decrypted message:")
		// remove the type string and print the rest
		fmt.Println(decrypted_message_string[7:])
	}

	fmt.Println("Do you want to check a signature? (y/N)")
	choice := Reader()
	if choice == "y" {
		fmt.Println("Please enter the signature here:")
		signature := Reader()
		// conv to bytes
		sig := []byte(signature)
		// check the signature

		verified, username := verify_signature_of_message(decrypted_message_string, sig)
		if verified {
			fmt.Println("Signature verified, signed by:", username)
		} else {
			fmt.Println("Signature not verified")
		}
	}

}

func decrypt_file(private_key string, dir string) {
	// file will be given as filename.txt.enc
	// take what is to be decrypted
	var encrypted_message string
	fmt.Println("What would you like to decrypt?")
	fmt.Println("Please enter the filename here:")
	encrypted_filename := Reader()
	encrypted_message_bytes, err := ioutil.ReadFile(encrypted_filename)
	error_handle(err)
	encrypted_message = string(encrypted_message_bytes)

	private_key_bytes, err := base64.StdEncoding.DecodeString(private_key)
	error_handle(err)
	parsed_private_key, err := x509.ParsePKCS1PrivateKey(private_key_bytes)
	error_handle(err)

	// separate the message into chucks
	encrypted_message_array := strings.Split(encrypted_message, " ")
	decrypted_message := make([]string, len(encrypted_message_array)*440)

	// decrypt first chunk on its own
	encrypted_message_bytes, err = base64.StdEncoding.DecodeString(encrypted_message_array[0])
	error_handle(err)
	decrypted_message_chunk, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_message_bytes, nil)
	error_handle(err)

	decrypted_message[0] = string(decrypted_message_chunk) // check if it is a large file
	if decrypted_message[0][:9] == "largefile" {
		decrypt_file_large(dir, private_key, encrypted_filename)
		return
	}

	for i := 0; i < len(encrypted_message_array); i++ {
		encrypted_message_bytes, err := base64.StdEncoding.DecodeString(encrypted_message_array[i])
		error_handle(err)
		decrypted_message_chunk, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_message_bytes, nil)
		error_handle(err)
		decrypted_message[i] = string(decrypted_message_chunk)

	}
	// combine the chucks
	decrypted_message_string := strings.Join(decrypted_message, "")
	// check the type of the message
	// if first 4 characters are "file" then it is a file
	if decrypted_message_string[:4] == "file" {
		// message is in the form file|length_of_filename|filename|file_contents
		header := strings.Split(decrypted_message_string, "|")
		filename := header[2]
		file_contents := header[3]

		fmt.Println("Message is a file with the name:", filename)
		fmt.Println("Do you want to save the file? (y/N)")
		choice := Reader()
		var received_dir_file string
		if choice == "y" {
			received_dir_file = filepath.Join(dir, "received", filename)
			file, err := os.Create(received_dir_file)
			error_handle(err)
			defer file.Close()
			file.Write([]byte(file_contents))

			fmt.Println("File saved at:", received_dir_file)
			fmt.Println("Do you want to delete the encrypted file? (y/N)")
			choice := Reader()
			if choice == "y" {
				err := os.Remove(encrypted_filename)
				error_handle(err)
				fmt.Println("Encrypted file deleted")
			} else {
				fmt.Println("Encrypted file not deleted")
			}
			fmt.Println("Do you want to check a signature? (y/N)")
			sig_choice := Reader()
			if sig_choice == "y" {
				fmt.Println("Please enter the signature here:")
				signature := Reader()
				// conv to bytes
				sig := []byte(signature)
				// check the signature

				verified, username := verify_signature_of_file(received_dir_file, sig)
				if verified {
					fmt.Println("Signature verified, signed by:", username)
				} else {
					fmt.Println("Signature not verified")
				}
			}

		}
	}

}

func decrypt_file_large(dir string, private_key string, encrypted_filename string) {
	private_key_bytes, err := base64.StdEncoding.DecodeString(private_key)
	error_handle(err)
	parsed_private_key, err := x509.ParsePKCS1PrivateKey(private_key_bytes)
	error_handle(err)

	// take what is to be decrypted
	var encrypted_message string

	encrypted_message_bytes, err := ioutil.ReadFile(encrypted_filename)
	error_handle(err)
	encrypted_message = string(encrypted_message_bytes)

	// 0 is header 1 is aes key 2 is file
	encrypted_message_array := strings.Split(encrypted_message, " ")

	encrypted_base_64_header := encrypted_message_array[0]
	encrypted_base64_aes_key := encrypted_message_array[1]
	encrypted_base64_file := encrypted_message_array[2]

	// decrypt the aes key

	encrypted_aes_key, err := base64.StdEncoding.DecodeString(encrypted_base64_aes_key)
	error_handle(err)

	decrypted_aes_key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_aes_key, nil)
	error_handle(err)

	// decrypt the header
	encrypted_header, err := base64.StdEncoding.DecodeString(encrypted_base_64_header)
	error_handle(err)
	decrypted_header, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_header, nil)
	error_handle(err)

	header := strings.Split(string(decrypted_header), "|")
	decrypted_filename := header[2]

	// now decrypt the file using the aes key
	encrypted_file, err := base64.StdEncoding.DecodeString(encrypted_base64_file)
	error_handle(err)

	c, err := aes.NewCipher(decrypted_aes_key)
	error_handle(err)

	gcm, err := cipher.NewGCM(c)
	error_handle(err)

	nonceSize := gcm.NonceSize()
	if len(encrypted_file) < nonceSize {
		fmt.Println("Encrypted file is too short")
		return
	}
	nonce, encrypted_file := encrypted_file[:nonceSize], encrypted_file[nonceSize:]
	decrypted_file, err := gcm.Open(nil, nonce, encrypted_file, nil)
	error_handle(err)

	fmt.Println("Message is a file with the name:", decrypted_filename)
	fmt.Println("Do you want to save the file? (y/N)")
	choice := Reader()
	if choice == "y" {
		received_dir_file := filepath.Join(dir, "received", decrypted_filename)
		file, err := os.Create(received_dir_file)
		error_handle(err)
		defer file.Close()
		file.Write([]byte(decrypted_file))

		fmt.Println("File saved at:", received_dir_file)
		fmt.Println("Do you want to delete the encrypted file? (y/N)")
		choice := Reader()
		if choice == "y" {
			err := os.Remove(encrypted_filename)
			error_handle(err)
			fmt.Println("Encrypted file deleted")
		} else {
			fmt.Println("Encrypted file not deleted")
		}
		fmt.Println("Do you want to check a signature? (y/N)")
		sig_choice := Reader()
		if sig_choice == "y" {
			fmt.Println("Please enter the signature here:")
			signature := Reader()
			// conv to bytes
			sig := []byte(signature)
			// check the signature

			verified, username := verify_signature_of_file(received_dir_file, sig)
			if verified {
				fmt.Println(blue+"Signature verified, signed by:", username, white)
			} else {
				fmt.Println(red+"Signature not verified", white)

			}
		}
	}

}

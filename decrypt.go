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
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

func decrypt(private_key string, dir string) {

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
		if err != nil {
			fmt.Println("Error decrypting message, likely malformed message")
			error_handle(err)
		}
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
			path_to_received := filepath.Join(dir, "received", filename)
			file, err := os.Create(path_to_received)
			error_handle(err)
			defer file.Close()
			file.Write([]byte(file_contents))
			fmt.Println("File saved at:", path_to_received)
			// set pointer of file_contents to decrypted_message_string
			decrypted_message_string = file_contents
		} else {
			fmt.Println("File not saved")
		}

	} else if decrypted_message_string[:9] == "largefile" {
		fmt.Println("Message is a large file, please use the decrypt file option")
		// probably shouldn't be happening, since the function is only on for 1MB files+ but just in case
		// one megabyte of data would flood the terminal, so it is better to use the decrypt file option
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

	// read the first part of the file since it could be a large file

	buffer := make([]byte, 684)

	file, err := os.Open(encrypted_filename)
	error_handle(err)
	defer file.Close()

	// read the first 16kb of the file
	_, err = file.Read(buffer)
	error_handle(err)

	// get the header and the aes key through splitting using spaces

	first_chunk_split := strings.Split(string(buffer), " ")

	// decode the encoded header

	encrypted_base_64_header := first_chunk_split[0]

	encrypted_header, err := base64.StdEncoding.DecodeString(encrypted_base_64_header)
	error_handle(err)

	// decrypt the header

	private_key_bytes, err := base64.StdEncoding.DecodeString(private_key)
	error_handle(err)
	parsed_private_key, err := x509.ParsePKCS1PrivateKey(private_key_bytes)
	error_handle(err)

	decrypted_header, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_header, nil)
	error_handle(err)
	decrypted_header_string := string(decrypted_header)

	if decrypted_header_string[:9] == "largefile" {
		decrypt_file_large(dir, private_key, encrypted_filename)
		return
	}
	// if not a large file then it is a small file, so its safe to read the whole file into memory
	encrypted_message_bytes, err := ioutil.ReadFile(encrypted_filename)
	error_handle(err)
	encrypted_message = string(encrypted_message_bytes)

	// separate the message into chucks
	encrypted_message_array := strings.Split(encrypted_message, " ")
	decrypted_message := make([]string, len(encrypted_message_array)*440)

	// decrypt first chunk on its own

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

	// only first 2 chunks are encrypted using the key and the rest are encrypted using aes

	// get the first 2 chunks of the file
	// file maybe very large, too big for memory so we need to read it in chunks

	// read the first 2 chunks

	file, err := os.Open(encrypted_filename)
	error_handle(err)
	defer file.Close()

	buffer := make([]byte, 1370) // 684 is the distance between the start of the chunk and the end of the chunk

	_, err = file.Read(buffer)
	error_handle(err)

	// get the header and the aes key through splitting using spaces

	first_chunk_split := strings.Split(string(buffer), " ")

	encrypted_base_64_header := first_chunk_split[0]
	encrypted_base64_aes_key := first_chunk_split[1]

	// decode the encoded header and aes key
	encrypted_header, err := base64.StdEncoding.DecodeString(encrypted_base_64_header)
	error_handle(err)
	encrypted_aes_key, err := base64.StdEncoding.DecodeString(encrypted_base64_aes_key)
	error_handle(err)

	// decrypt the aes key

	decrypted_aes_key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_aes_key, nil)
	error_handle(err)

	// decrypt the header

	decrypted_header, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_header, nil)
	error_handle(err)

	// now we can get the length of the filename and the filename

	header := strings.Split(string(decrypted_header), "|")
	decrypted_filename := header[2]

	// see if user wants to save the file
	fmt.Println("Message is a large file with the name:", decrypted_filename)
	fmt.Println("Do you want to save the file? (y/N)")
	choice := Reader()
	if choice != "y" {
		return
	}

	// clear existing file if it exists

	if _, err := os.Stat(filepath.Join(dir, "received", decrypted_filename)); err == nil {
		fmt.Println("File already exists, do you want to overwrite it? (y/N)")
		choice := Reader()
		if choice == "y" {
			err := os.Remove(filepath.Join(dir, "received", decrypted_filename))
			error_handle(err)
			fmt.Println("File deleted")
		}
	}

	// decrypt the chunk using the aes key

	c, err := aes.NewCipher(decrypted_aes_key)
	error_handle(err)

	gcm, err := cipher.NewGCM(c)
	error_handle(err)

	nonceSize := gcm.NonceSize()

	_, _ = file.Seek(1370, 0)

	buffer_data := make([]byte, 21884) //

	// logic for reading the file
	var received_dir_file string
	for {

		// read the next chunk
		bytes_read, err := file.Read(buffer_data) /// 21868 is the size of the chunk + 1 for space
		if err != nil {
			if err == io.EOF {
				break
			}
		}

		encrypted_chunk := string(buffer_data[:bytes_read])

		// decrypt the chunk

		encrypted_chunk_bytes, err := base64.StdEncoding.DecodeString(encrypted_chunk)
		if err != nil {
			fmt.Println(encrypted_chunk)
		}
		error_handle(err)

		nonce, encrypted_chunk_bytes := encrypted_chunk_bytes[:nonceSize], encrypted_chunk_bytes[nonceSize:]
		decrypted_chunk, err := gcm.Open(nil, nonce, encrypted_chunk_bytes, nil)
		error_handle(err)

		// write the chunk to a file
		received_dir_file = filepath.Join(dir, "received", decrypted_filename)
		if _, err := os.Stat(filepath.Join(dir, "received")); os.IsNotExist(err) {
			path := filepath.Join(dir, "received")
			os.Mkdir(path, 0755)
		}
		output_file, err := os.OpenFile(received_dir_file, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		error_handle(err)
		_, err = output_file.Write(decrypted_chunk)
		error_handle(err)
		defer output_file.Close()

		// seek one forward
		_, err = file.Seek(1, 1) // 1 from the current position for the space
		error_handle(err)

	}

	// sig verification
	fmt.Println("Do you want to check a signature? (y/N)")
	sig_choice := Reader()
	if sig_choice == "y" {
		fmt.Println("Please enter the signature here:")
		signature := Reader()
		// conv to bytes
		sig := []byte(signature)
		// check the signature

		verified, username := verify_signature_of_largefile(received_dir_file, sig)
		if verified {
			fmt.Println("Signature verified, signed by:", username)
		} else {
			fmt.Println("Signature not verified")
		}
	}

}

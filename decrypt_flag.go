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

func decrypt_message_flag(private_key string, dir string, message_byte []byte, sig_requirement bool, sig_data string) {
	var encrypted_message string
	if message_byte == nil {
		fmt.Println("No message to decrypt")
		return
	}
	encrypted_message = string(message_byte)

	// message can be a file or a string, regardless of whether the user is
	// pasting a message (they could have copied the contents of a enc file)

	private_key_bytes, err := base64.StdEncoding.DecodeString(private_key)
	error_handle(err)
	parsed_private_key, err := x509.ParsePKCS1PrivateKey(private_key_bytes)
	error_handle(err)

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
	if decrypted_message_string[:4] == "file" {

		header := strings.SplitN(decrypted_message_string, "|", 4)
		filename := header[2]
		file_contents := header[3]

		path_to_received := filepath.Join(dir, "received", filename)
		file, err := os.Create(path_to_received)
		error_handle(err)
		defer file.Close()
		file.Write([]byte(file_contents))
		fmt.Println("File saved at:", path_to_received)
	} else if decrypted_message_string[:9] == "largefile" {
		fmt.Println("Large (1MB+) inputted, please use the file method (-i) to decrypt")
	} else {
		fmt.Println("Decrypted message:")
		// remove the header (message currently starts with "message"
		fmt.Println(decrypted_message_string[7:])

	}

	if sig_requirement || sig_data != "" {
		sig := []byte(sig_data)
		verified, username := verify_signature_of_message(decrypted_message_string, sig)
		if verified {
			fmt.Println("Signature verified, signed by:", username)
		} else {
			fmt.Println("Signature not verified")
		}
	}

}

func decrypt_file_flag(private_key string, dir string, encrypted_filename string, output_filename string, sig_requirement bool, sig_data string) {
	var encrypted_message string
	buffer := make([]byte, 684)

	file, err := os.Open(encrypted_filename)
	error_handle(err)
	defer file.Close()

	_, err = file.Read(buffer)
	error_handle(err)
	first_chunk_split := strings.Split(string(buffer), " ")
	encrypted_base_64_header := first_chunk_split[0]
	encrypted_header, err := base64.StdEncoding.DecodeString(encrypted_base_64_header)
	error_handle(err)
	private_key_bytes, err := base64.StdEncoding.DecodeString(private_key)
	error_handle(err)
	parsed_private_key, err := x509.ParsePKCS1PrivateKey(private_key_bytes)
	error_handle(err)

	decrypted_header, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_header, nil)
	error_handle(err)
	decrypted_header_string := string(decrypted_header)

	if decrypted_header_string[:9] == "largefile" {
		decrypt_file_large_flag(dir, private_key, encrypted_filename, output_filename, sig_requirement, sig_data)
		return
	}

	encrypted_message_bytes, err := ioutil.ReadFile(encrypted_filename)
	error_handle(err)
	encrypted_message = string(encrypted_message_bytes)

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
		///
		received_dir_file := filepath.Join(dir, "received", filename)
		if output_filename != "" {
			received_dir_file = output_filename
		}

		///
		file, err := os.Create(received_dir_file)
		error_handle(err)
		defer file.Close()
		file.Write([]byte(file_contents))

		fmt.Println("File saved at:", received_dir_file)

		if sig_requirement || sig_data != "" {
			sig := []byte(sig_data)
			verfified, usernmae := verify_signature_of_message(decrypted_message_string, sig)
			if verfified {
				fmt.Println("Signature verified, signed by:", usernmae)
			} else {
				fmt.Println("Signature not verified")
			}

		}

	}

}

func decrypt_file_large_flag(dir string, private_key string, encrypted_filename string, output_filename string, sig_requirement bool, sig_data string) {
	private_key_bytes, err := base64.StdEncoding.DecodeString(private_key)
	error_handle(err)
	parsed_private_key, err := x509.ParsePKCS1PrivateKey(private_key_bytes)
	error_handle(err)

	file, err := os.Open(encrypted_filename)
	error_handle(err)
	defer file.Close()

	buffer := make([]byte, 1370)

	_, err = file.Read(buffer)
	error_handle(err)

	first_chunk_split := strings.Split(string(buffer), " ")

	encrypted_base_64_header := first_chunk_split[0]
	encrypted_base64_aes_key := first_chunk_split[1]

	encrypted_header, err := base64.StdEncoding.DecodeString(encrypted_base_64_header)
	error_handle(err)
	encrypted_aes_key, err := base64.StdEncoding.DecodeString(encrypted_base64_aes_key)
	error_handle(err)

	decrypted_aes_key, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_aes_key, nil)
	error_handle(err)

	decrypted_header, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, parsed_private_key, encrypted_header, nil)
	error_handle(err)

	header := strings.Split(string(decrypted_header), "|")
	decrypted_filename := header[2]

	if output_filename != "" {
		decrypted_filename = output_filename
	}

	if _, err := os.Stat(decrypted_filename); err == nil {
		fmt.Println("File already exists, please specifiy a different output file")
		return
	}

	c, err := aes.NewCipher(decrypted_aes_key)
	error_handle(err)

	gcm, err := cipher.NewGCM(c)
	error_handle(err)

	nonceSize := gcm.NonceSize()

	_, _ = file.Seek(1370, 0)

	buffer_data := make([]byte, 21884)

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

	if sig_requirement || sig_data != "" {

		sig := []byte(sig_data)
		verfified, usernmae := verify_signature_of_message(received_dir_file, sig)
		if verfified {
			fmt.Println("Signature verified, signed by:", usernmae)
		} else {
			fmt.Println("Signature not verified")
		}
	}
}

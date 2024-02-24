package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

func add_public_key(dir string) {
	var username string
	var public_key string

	fmt.Println("What is the username of the person you want to add?")
	fmt.Println("Please enter the username here:")
	_, err := fmt.Scanln(&username)

	error_handle(err)
	// check if the public key already exists
	if _, err := os.Stat(dir + username + "_public_key.pem"); err == nil {
		fmt.Println(red, "Public key already exists!", white)
		return

	}

	// get the public key
	fmt.Println("What is the public key of the person you want to add?")
	fmt.Println("Please paste the public key here:")
	_, err = fmt.Scanln(&public_key)
	error_handle(err)

	// save the public key
	public_key_file, err := os.Create(dir + username + "_public_key.pem")
	error_handle(err)
	defer public_key_file.Close()
	public_key_file.Write([]byte(public_key))

}

func list_all_public_keys(dir string) {
	// list all the public keys except for my_public_key.pem and my_private_key.pem

	files, err := ioutil.ReadDir(dir)
	error_handle(err)
	for _, file := range files {
		if !file.IsDir() {
			if file.Name() != (dir+"my_public_key.pem") && file.Name() != (dir+"my_private_key.pem") {
				if file.Name()[len(file.Name())-4:] == ".pem" {
					fmt.Println(file.Name())
				}
			}
		}
	}
}

func print_my_public_key(dir string) {
	// output my_public_key.pem

	// read the file
	data, err := ioutil.ReadFile(dir + "my_public_key.pem")
	error_handle(err)
	fmt.Println(string(data))

}

func print_my_private_key(dir string) {
	// output my_private_key.pem

	// read the file
	data, err := ioutil.ReadFile(dir + "my_private_key.pem")
	error_handle(err)
	fmt.Println(string(data))
}

func make_keys(dir string) {

	private_key, err := rsa.GenerateKey(rand.Reader, 4096)
	error_handle(err)
	public_key := &private_key.PublicKey

	private_key_bytes := x509.MarshalPKCS1PrivateKey(private_key)
	private_key_bytes = []byte(base64.StdEncoding.EncodeToString(private_key_bytes))

	public_key_bytes, err := x509.MarshalPKIXPublicKey(public_key)
	error_handle(err)
	public_key_bytes = []byte(base64.StdEncoding.EncodeToString(public_key_bytes))

	// save the keys
	private_key_file, err := os.Create(dir + "my_private_key.pem")
	error_handle(err)
	defer private_key_file.Close()
	private_key_file.Write(private_key_bytes)

	public_key_file, err := os.Create(dir + "my_public_key.pem")
	error_handle(err)
	defer public_key_file.Close()
	public_key_file.Write(public_key_bytes)

}

func backup_keys(dir string) {
	// read all of the pems
	// make them into a zip file
	// make sure only to include .pem files
	files, err := ioutil.ReadDir(dir)
	error_handle(err)
	// create a zip file
	zip_file, err := os.Create(dir + "keys.zip")
	error_handle(err)
	defer zip_file.Close()
	zip_writer := zip.NewWriter(zip_file)
	defer zip_writer.Close()
	var files_to_zip []string
	for _, file := range files {
		if !file.IsDir() {
			if file.Name()[len(file.Name())-4:] == ".pem" {
				files_to_zip = append(files_to_zip, file.Name())
			}
		}
	}
	for _, file := range files_to_zip {
		// add the file to the zip
		file_to_zip, err := os.Open(dir + file)
		error_handle(err)
		defer file_to_zip.Close()
		info, err := file_to_zip.Stat()
		error_handle(err)
		header, err := zip.FileInfoHeader(info)
		error_handle(err)
		header.Name = file
		writer, err := zip_writer.CreateHeader(header)
		error_handle(err)
		_, err = io.Copy(writer, file_to_zip)
		error_handle(err)
	}
	fmt.Println("Backup complete!")
	fmt.Println("The backup is located at:"+blue, dir+"keys.zip"+white)
}

package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

// File structure of the program
// main.go - file with the main loop
// encrypt.go - file with the encryption functions
// decrypt.go - file with the decryption functions
// key_management.go - file with almost all of the other functions (adding public keys, listing public keys, printing keys, backing up keys)
// my_private_key.pem - your private key
// my_public_key.pem - your public key
// name_public_key.pem - public key of the person with the username "name" (e.g. john_public_key.pem)
// received/ - directory for decrypted files
// sent/ - directory for files to be sent

// keys.zip is the output from backing up keys and is a zip file containing the public and private keys

// most of the encrypted output is base64 encoded so that it can be printed to the console/human readable
// they also have headers to describe the message for the decryption function
// this is removed in the decryption function

// the private key is crucial to you, its the only way to decrypt messages sent to you
// the public key is what you give to others so that they can encrypt messages to you

// messages and small files are encrypted using just rsa
// larger files are encrypted using a combination of rsa and aes

// the rsa key size is 4096 bits

// signatures are made using the private key as opposed to the public key so that the signature can be verified by anyone with the public key
// however since the signature is made in part from the unencrypted data, the sender's identity is hidden, since only the recepient can 

const ( // color codes
	red    = "\033[31m"
	yellow = "\033[33m"
	white  = "\033[0m"
	blue   = "\033[34m"
)

func Reader() string { // read from the console
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}
func setup() (string, string) {
	// the init of the program

	// finds the directory of the go executable
	// checks if the keys exist
	// if not, makes the keys
	// returns the private key and the directory of the go executable

	filename, _ := os.Executable()
	directory := filepath.Dir(filename)
	path_to_private_key := filepath.Join(directory, "my_private_key.pem")
	if _, err := os.Stat(path_to_private_key); os.IsNotExist(err) {
		fmt.Println(yellow + "No keys found. Making keys" + white)
		make_keys(directory)

	}

	// read the file

	data, err := ioutil.ReadFile(path_to_private_key)
	error_handle(err)

	// make sure sent and received directories exist
	if _, err := os.Stat(filepath.Join(directory, "sent")); os.IsNotExist(err) {
		os.Mkdir(directory+"sent", 0755)
	}
	if _, err := os.Stat(filepath.Join(directory, "received")); os.IsNotExist(err) {
		os.Mkdir(directory+"received", 0755)

	}

	return string(data), directory

}
func error_handle(error_message error) {
	// simple error handling
	// if there is an error, print the error and exit
	if error_message != nil {
		log.Fatal(error_message)
	}
}
func main() {
	exit := false // condition for the loop

	fmt.Println(blue+"Welcome to the encryption program", white)
	for !exit { // main loop

		private_key, dir := setup()
		// dir is the directory of the go executable, where the keys are stored

		fmt.Println("What would you like to do?")
		fmt.Println(yellow + "1." + white + " Encrypt a message")
		fmt.Println(yellow + "2." + white + " Encrypt a file")
		fmt.Println(yellow + "3." + white + " Decrypt a message")
		fmt.Println(yellow + "4." + white + " Decrypt a file")
		fmt.Println(yellow + "5." + white + " Add a public key")
		fmt.Println(yellow + "6." + white + " List all public keys")
		fmt.Println(yellow + "7." + white + " Print my public key")
		fmt.Println(yellow + "8." + white + " Print my private key")
		fmt.Println(yellow + "9." + white + " Backup keys")
		fmt.Println(yellow + "10." + white + " Exit")

		var choice string
		_, err := fmt.Scanln(&choice)
		error_handle(err)

		switch choice {
		case "1":
			encrypt(dir, private_key)
		case "2":
			encrypt_file(dir)
		case "3":
			decrypt(private_key)
		case "4":
			decrypt_file(private_key, dir)
		case "5":
			add_public_key(dir)
		case "6":
			list_all_public_keys(dir)
		case "7":
			print_my_public_key(dir)
		case "8":
			print_my_private_key(dir)
		case "9":
			backup_keys(dir)
		case "10":
			exit = true
		default:
			fmt.Println(red + "Invalid choice!" + white)
		}
	}
}

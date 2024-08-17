package main

import (
	"bufio"
	"flag"
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

func Reader() string { // read from the command line
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
		path := filepath.Join(directory, "sent")
		os.Mkdir(path, 0755)
	}
	if _, err := os.Stat(filepath.Join(directory, "received")); os.IsNotExist(err) {
		path := filepath.Join(directory, "received")

		os.Mkdir(path, 0755)

	}

	return string(data), directory

}
func error_handle(error_message error) {
	// simple error handling
	// if there is an error, print the error and exit
	// function should be used lightly as it is a catch all when it is not sensible to carry on
	// hence why it is a fatal error
	if error_message != nil {
		log.Fatal(error_message)
	}
}

func main() {
	fi, err := os.Stdin.Stat()
	error_handle(err)

	private_key, dir := setup()

	decrypt_pointer := flag.Bool("d", false, "Decrypt a message/file")

	encrypt_pointer := flag.Bool("e", false, "Encrypt a message/file")

	recipient_pointer := flag.String("r", "", "The recipient of the message")

	string_message_pointer := flag.String("m", "", "The message which you want to encrypt/decrypt")

	output_file_pointer := flag.String("o", "", "The output file")
	input_file_pointer := flag.String("i", "", "Path to the input file")
	sig_requirement_pointer := flag.Bool("s", false, "Whether you want to require a signature")
	sig_data_pointer := flag.String("S", "", "The signature data (only for decryption)")
	flag.Parse()

	if *decrypt_pointer && *encrypt_pointer {
		fmt.Println(red + "You cannot encrypt and decrypt at the same time" + white)
		return
	}

	if *encrypt_pointer {
		if *recipient_pointer == "" {
			fmt.Println(red + "Recipient not specified" + white)
			return
		}
		if !check_key_exists(*recipient_pointer, dir) { // check if the recipient exists
			fmt.Println(red + "Recipient does not exist" + white)
			return
		}

		if fi.Mode()&os.ModeCharDevice == 0 { // check if there is data in stdin
			stdin_data, err := ioutil.ReadAll(os.Stdin)
			error_handle(err)
			if stdin_data != nil {
				// make sure -m flag is not used
				if *string_message_pointer != "" {
					fmt.Println(red + "Cannot use multiple methods at once" + white)
					return
				} else if *input_file_pointer != "" {
					fmt.Println(red + "Cannot use multiple methods at once" + white)
					return
				}
				encrypt_message_flag(dir, *recipient_pointer, stdin_data, *sig_requirement_pointer)
				return
			}
		}
		if *input_file_pointer == "" && *string_message_pointer == "" {
			fmt.Println(red + "No message or file specified" + white)
			return
		}

		// if message is not in stdin, check if message is in the flag
		if *string_message_pointer != "" {
			encrypt_message_flag(dir, *recipient_pointer, []byte(*string_message_pointer), *sig_requirement_pointer)
			return
		}

		// check if input_file exists
		if _, err := os.Stat(*input_file_pointer); os.IsNotExist(err) {
			fmt.Println(red + "Input file does not exist" + white)
			return
		}
		// all methods of input are exhausted, must be a file
		if *output_file_pointer == "" {
			// default
			*output_file_pointer = filepath.Join(dir, "sent", *input_file_pointer+".enc")
		}
		outputfile_name := filepath.Clean(*output_file_pointer)
		encrypt_file_flag(dir, *recipient_pointer, *input_file_pointer, *sig_requirement_pointer, outputfile_name)
		return

	}

	if *decrypt_pointer {
		if fi.Mode()&os.ModeCharDevice == 0 { // check if there is data in stdin
			stdin_data, err := ioutil.ReadAll(os.Stdin)
			error_handle(err)
			if stdin_data != nil {
				if *input_file_pointer != "" {
					fmt.Println(red + "Cannot use multiple methods at once" + white)
					return
				} else if *string_message_pointer != "" {
					fmt.Println(red + "Cannot use multiple methods at once" + white)
					return
				}

				decrypt_message_flag(private_key, dir, stdin_data, *sig_requirement_pointer, *sig_data_pointer)
				return
			}
		}
		if *string_message_pointer != "" {

			if *input_file_pointer != "" {
				fmt.Println(red + "Cannot use multiple methods at once" + white)
				return
			}

			decrypt_message_flag(private_key, dir, []byte(*string_message_pointer), *sig_requirement_pointer, *sig_data_pointer)
			return
		}
		if _, err := os.Stat(*input_file_pointer); os.IsNotExist(err) {
			fmt.Println(red + "Input file does not exist" + white)
			return
		}
		if *recipient_pointer != "" {
			fmt.Println(yellow + "Recipient not needed for file decryption" + white)
		}

		// can omit these, since the once decrypted, the file will receive its original name
		// so unless the user wants to change the name, it is not necessary
		//if *output_file_pointer == "" {
		//*output_file_pointer = filepath.Join(dir, "received", *input_file_pointer))
		//}

		decrypt_file_flag(private_key, dir, *input_file_pointer, *output_file_pointer, *sig_requirement_pointer, *sig_data_pointer)
		return
	}

	exit := false // condition for the loop

	fmt.Println(blue+"Welcome to the encryption program", white)
	for !exit { // main loop

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

		choice := Reader()
		switch choice {
		case "1":
			encrypt(dir)
		case "2":
			encrypt_file(dir)
		case "3":
			decrypt(private_key, dir)
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

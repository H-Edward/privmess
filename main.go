package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
)

const (
	red    = "\033[31m"
	yellow = "\033[33m"
	white  = "\033[0m"
	blue   = "\033[34m"
)

func Reader() string {
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	return scanner.Text()
}
func setup() (string, string) {
	filename, _ := os.Executable()
	directory := filepath.Dir(filename)
	directory += "/"
	if _, err := os.Stat(directory + "my_private_key.pem"); os.IsNotExist(err) {
		fmt.Println(yellow + "No keys found. Making keys" + white)
		make_keys(directory)

	}

	// read the file
	data, err := ioutil.ReadFile(directory + "my_private_key.pem")
	error_handle(err)

	// make sure sent and received directories exist
	if _, err := os.Stat(directory + "sent"); os.IsNotExist(err) {
		os.Mkdir(directory+"sent", 0755)
	}
	if _, err := os.Stat(directory + "received"); os.IsNotExist(err) {
		os.Mkdir(directory+"received", 0755)

	}

	return string(data), directory

}
func error_handle(error_message error) {
	if error_message != nil {
		log.Fatal(error_message)
	}
}
func main() {
	exit := false
	fmt.Println(blue+"Welcome to the encryption program", white)
	for !exit {

		private_key, dir := setup()
		// dir is the directory of the go executable, where the keys are stored

		fmt.Println("What would you like to do?")
		fmt.Println("1. Encrypt a message")
		fmt.Println("2. Encrypt a file")
		fmt.Println("3. Decrypt a message")
		fmt.Println("4. Decrypt a file")
		fmt.Println("5. Add a public key")
		fmt.Println("6. List all public keys")
		fmt.Println("7. Print my public key")
		fmt.Println("8. Print my private key")
		fmt.Println("9. Backup keys")
		fmt.Println("10. Exit")
		
		//fmt.Println("n. Make new keys") // can be done by deleting the old keys anyway so not needed

		var choice string
		_, err := fmt.Scanln(&choice)
		error_handle(err)

		switch choice {
		case "1":
			encrypt(dir)
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

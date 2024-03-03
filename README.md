# privmess

Provides encryption through both AES of files and text.

(RSA for messages and small files)

(AES + RSA for large files)

## Usage

While in the privmess directory

for the first time

`make build`

then (and future use)

`./privmess`

keys need to be in the root of the directory - including your private key.

AES is only used on files over 1MB

## How to update

While in the privmess directory

`git pull`

then

`make build`

to build a new binary.

## Information

This project shouldn't be used for anything serious, its just a small tool for encryption.

Some issues may arise during usage, please report them and if possible with the file/raw data inputted.

You can encrypt data for yourself, by using `my` as the username you want to encrypt for, just make sure not to lose the private key and it might be worth keeping a backup of version of privmess you are running since choosing a newer version could read the message slightly different, also be sure to decrypt the data before storing it to make sure it decrypts properly.

This program doesn't have any unofficial packages in it, all of the code is written using builtin packages.

License: MIT

_See [GnuPG](https://gnupg.org) for a more serious encryption program._

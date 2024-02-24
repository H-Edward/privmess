# privmess

Provides encryption through RSA and AES of files and text.

## usage

while in the privmess directory

for the first time

`make build` 

then (and future use)

`./privmess` 



keys need to be in the root of the directory - including your private key 

AES is only used on files over 1MB

## how to update

while in the privmess directory 

`git pull`

then 

`make build` 

to build a new binary


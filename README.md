# lighthouse validator client keystore import online

## Usage

go run main.go --help

--auth string           please input the validator client auth token.
--fee                   set fee recipient or not.
--feeRecipient string   please input the validator fee recipient.
--key                   import key or not.
--keypath string        please input key path.
--password string       please input the validator keystore password.

example:
```shell
go run main.go --auth $(cat /data/lighthousedatadir/validators/api-token.txt) --fee --feeRecipient <fee address> --key --keypath <your keystore path> --password <your password>
```

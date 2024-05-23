# JWK Tool

## 產生 kid

此 kid 必須在產 jwk 時帶入

```sh
./jwktool genkid 

# example:
# ./jwktool genkid
# output:
#
# Ukf6nVSqkpVqKda6UyVynm
```

## 產生 Base64 過後的 jwk

```sh
./jwktool genjwks <kid> <file1 pem or crt> <file2 pem or crt> ...

# example:
# ./jwktool genjwks Pjtc5nvDez3bLxQ4Lc5b4J ./dev/authorize-privatekey.pem
#
# output:
#
# Processing PEM: 1 
# kid: Pjtc5nvDez3bLxQ4Lc5b4J 
#
# ˇˇˇ Please copy the following jwk to env ˇˇˇ
#
# eyJrdHkiOiJSU0EiLCJraWQiOiJQanRjNW52RGV6M2...
#

```

## 補充：產生 RSA Key

```
# 產生 rsa private key
openssl genrsa -out authorize-privatekey.pem 4096

# 從 rsa private key 產生 public key
openssl rsa -in authorize-privatekey.pem -pubout -out authorize-publickey.crt
```

## 補充：build binary

```
go build -o jwktool main.go 
```

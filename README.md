# proj-ashah85

# CS558 - Introduction to Computer Security - Course Project

## Table of Contents

- [Introduction](#introduction)
- [Author](#author)
- [Programming Language](#programming-language)
- [Execution Instructions](#execution-instructions)
- [Code Overview](#code-overview)
- [Additional Function](#additional-function)

## Introduction

This repository contains a Java program for a Bank Server and an ATM
Client. The Server and Client communicate using Socket Programming. The
Client sends user credentials to the Server. The Server validates the
credentials and sends a message to the Client indicating whether the
credentials are valid or not. The Server has a public key certificate
and a private key. The Server first sends the public key certificate to
the Client. The Client uses the public key certificate to and sends an 
encryptedSymmetricKey to the Server. The Server uses the private key to
decrypt the encryptedSymmetricKey. The Server and Client then use the
symmetric key to encrypt and decrypt the messages sent between them.
The client then sends the encrypted userID and password to the Server.
The Server decrypts the userID and password and validates them. The
Server then sends a message to the Client indicating whether the
credentials are valid or not. The Server also has a `password` file
which contains the userID and password. The Server uses the `password`
file to validate the userID and password. The Server also has a
`balance` file which contains the userID and their savings account 
and checking account balances. The Server uses the `balance` file to
retrieve the balances of the user's savings account and checking account.
Once the Client is authenticated, the Client can perform the following
operations:

1. **Transfer Money**: The Client can transfer money either from their 
savings account to other user's savings account or from their checking
account to other user's checking account. 
2. **Check Balance**: The Client can check the balance of their savings
account and checking account.
3. **Exit**: The Client can exit the program.

## Author

- **Name**: Akshat Nileshkumar Shah
- **Email**: ashah85@binghamton.edu
- **B-Number**: B00969887

## Programming Language

- **Language**: Java
- **Tested on Remote Server**: Yes

### Code for performing encryption and decryption

The code for performing encryption and decryption is in the following
files:

1. Symmetric Encryption and Decryption: `SymmetricEncryption.java`
2. Algorithm used: AES
3. Public Key has been generated using the following command:

        openssl rsa -pubout -in src/private_key.pem -out src/public_key.pem
4. Private Key has been generated using the following command:

        openssl pkcs8 -topk8 -inform PEM -outform PEM -in private_key.pem -out private_key_pkcs8.pem -nocrypt
5. The public key is stored in the file `public_key.pem`.
6. The private key is stored in the file `private_key_pkcs8.pem`.
7. The algorithm used for Public Key Encryption and Decryption is RSA.
8. The algorithm used for Symmetric Key Encryption and Decryption is AES.
9. The algorithm used for Private Key Encryption and Decryption is RSA.

## Execution Instructions

To execute the program, follow these instructions:

### Bank-ATM

1. Open a terminal or command prompt.
2. Navigate to the directory containing the Java program.
3. Run the following command to perform compilation and execution:

        make run

   This command will compile the Java programs `Bank.java` and
    `ATM.java`.
4. Run the following command to run the Bank program:

        java Bank <port>

5. Run the following command in a separate terminal or command prompt 
    to run the ATM program:

        java ATM <host> <port>

6. Provide the user's name and password using the prompts on the ATM
   once the Bank is started.
7. The ATM will then display the following options after the user is
    authenticated successfully:

    - **Transfer Money**: The user can transfer money either from their 
      savings account to other user's savings account or from their 
      checking account to other user's checking account. 
    - **Check Balance**: The user can check the balance of their savings
      account and checking account.
    - **Exit**: The user can exit the program.
8. The Bank uses multiple threads to handle multiple ATM clients. The
    Bank can handle multiple ATM clients simultaneously.
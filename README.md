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
Bank Server validates the ATM Client using a public key certificate. The
ATM Client validates the Bank Server using a public key certificate. The

## Author

- **Name**: Akshat Nileshkumar Shah
- **Email**: ashah85@binghamton.edu
- **B-Number**: B00969887

## Programming Language

- **Language**: Java
- **Tested on Remote Server**: Yes

## Execution Instructions

To execute the program, follow these instructions:

### GenPasswd

1. Open a terminal or command prompt.
2. Navigate to the directory containing the Java program.
3. Run the following command to perform compilation and execution:

        make run

   This command will compile the Java program `GenPasswd.java` and
   execute it. The program will prompt the user to enter the userID
   and password. The program will then store the userID and password
   in the `hashpasswd` file. Then, the command will compile the Java
   programs `Serv.java` and `Cli.java`.

### Client-Server

1. Open a terminal or command prompt.
2. Navigate to the directory containing the Java program.
3. Run the following command to start the Server:

        java Serv <port>
4. Open another terminal and navigate to the directory containing the
   Java program.
5. Run the following command to start the Client:

        java Cli <host> <port>
6. Provide the user's name and password using the prompts on the Client
   once the Server is started.

## Code Overview

The Java programs `GenPasswd.java`, `Serv.java`, and `Cli.java` contain
the following features:

1. **Input Validation**: The program checks for the following error
   conditions:

    - The userID contains characters other than lowercase letters    
      (a-z).
    - The password contains at least 8 characters.
    - The userID does not exist in the hashpsswd file.

2. **SHA-256 Encoding**: The program uses the SHA-256 algorithm to
   encode the password.

3. **Password Generation**: The program generates a password using the
   encoded password and the userID.

4. **Server-Client Communication**: The program uses SSL to communicate
   between the Server and the Client. The Server validates the password
   and sends a message to the Client indicating whether the password is
   correct or not.

5. **Public Key Certificate**: The program uses a public key certificate
   to validate the Server.

6. **hashpasswd File**: The program uses the `hashpasswd` file to validate
   the userID and password.I have included a sample `hashpasswd` file in
   the repository.
7. **keystore.p12**: The program uses the `keystore.p12` file to
   validate the Server.
8. **truststore.p12**: The program uses the `truststore.p12` file to
   validate the Client.
9. **server.cer**: The program uses the `server.cer` file to validate
   the Server.

## Additional Function

The program also contains a `Makefile` which can be used to compile and
run the program. The `Makefile` contains the following commands:

- `make run`: Compiles and runs the program.
- `make clean`: Removes the class files.
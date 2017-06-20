# RSA Encryption Implementation

This project is an RSA implementation for encrypting messages using 512 bit public and private keys.  This code is just an exercise and should only be used as an example.

## Getting Started

These instructions will set you up to run this example on your local machine.

### Prerequisites

Java JDK version 1.8.0_121 or greater
Apache Maven version 3.3.9 or greater

### Installing

To install this application simply clone the code into a working directory then package the code to an executable jar using Maven.

```
git clone https://github.com/lkam88/rsa-encryption.git
cd rsa-encryption
mvn clean package
```

### Running

You can run the application by running the Java application from the commandline.  The application takes one parameter which is the message you wish to generate a signature from.  The message has to be less than 250 characters.  A private and public key called "rsa_key" and "rsa_key.pub" respectively will be created in the directory you're running the command form.  If those files already exists, the application will use those keys for encrypting.

If you're at the project root,
```
java -jar target/my-awesome-app.jar "Hello, World!"
```

## Running the tests
You can run the tests for continuous integration using maven.

```
mvn clean test
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details
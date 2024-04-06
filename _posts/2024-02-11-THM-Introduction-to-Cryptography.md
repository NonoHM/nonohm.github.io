---
layout: post
title: THM Introduction to Cryptography
tags: [THM, Security Engineer]
author: NonoHM
date: 2024-02-11 21:06:35
toc:
    sidebar: left
    toc-depth: 3
---
## Task 1 - Introduction

The purpose of this room is to introduce users to basic cryptography concepts such as:

* Symmetric encryption, such as AES
* Asymmetric encryption, such as RSA
* Diffie-Hellman Key Exchange
* Hashing
* PKI

One of the earliest cryptographic mechanism is Caesar Cipher. Its principle is to shift the letter by a fixed number of places to the left or right. Consequently the key is between 1 and 25, the number of shifts.
For example: TryHackMe -> WubKdfnPh with a key of 3.

This is a **substitution cipher** because we replace each letter by another. Another type of cipher is called **transposition cipher**, which encrypts the message by changing the order of the letters.

{% include figure.liquid path="/assets/img/images/thm_introduction_to_cryptography/B1leoiUja.png" title="Transpoition Cipher Example" class="img-fluid rounded z-depth-1 bg-white" %}

For an encryption algorithm to be considered **secure**, it should be infeasible to recover the original message in a reasonable time.

### Questions

**You have received the following encrypted message:**

*“Xjnvw lc sluxjmw jsqm wjpmcqbg jg wqcxqmnvw; xjzjmmjd lc wjpm sluxjmw jsqm bqccqm zqy.” Zlwvzjxj Zpcvcol*

**You can guess that it is a quote. Who said it?**

Using [quipquip](https://www.quipqiup.com/).

*Answer: `Miyamoto Musashi`*

## Task 2 - Symmetric Encryption

Let’s review some terminology:

* **Cryptographic Algorithm** or **Cipher**: This algorithm defines the encryption and decryption processes.
* **Key**: The cryptographic algorithm needs a key to convert the plaintext into ciphertext and vice versa.
* **Plaintext**: original message that we want to encrypt
* **Ciphertext**: message in its encrypted form

A symmetric encryption algorithm uses the same key for encryption and decryption. Consequently, the communicating parties need to agree on a secret key before being able to exchange any messages.

In 1977, the Data Encryption Standard (DES) was published by the National Institute of Standard and Technology (NIST). This is an encryption algorithm that uses a key size of 56 bits and it nowadays considered as an insecure cipher algoritm because it has demonstrated that the key could be brute-force searched.

In 2001, the same organization published the Advanced Encryption Standard (AES). Like DES it is a symmetric algorithm but it uses keys of 128, 196 or 256 bits and it is still considered as secure today.
AES iterate through these transformations multiple times:

- `SubBytes(state)`: This transformation looks up each byte in a given substitution table (S-box) and substitutes it with the respective value. The state is 16 bytes, i.e., 128 bits, saved in a 4 by 4 array.
- `ShiftRows(state)`: The second row is shifted by one place, the third row is shifted by two places, and the fourth row is shifted by three places.
- `MixColumns(state)`: Each column is multiplied by a fixed matrix (4 by 4 array).
- `AddRoundKey(state)`: A round key is added to the state using the XOR operation.

In order to encrypt, strings are converted into their hexadecimal values. Then these are encrypted using block or stream algorithms:

- **Block**: Characters are concatenated into blocks of a defined size and then encrypted.
- **Stream**: Each character is encrypted at a time.

Symmetric encyption solves the CIA Triad problem:

- **Confidentiality**: The message cannot be understood without the key
- **Integrity**: Even minor modifications lead to gibberish plaint text.
- **Authenticity**: Only the conserned parts must know the key.

These two programs are widely use for symmetric but asymmetric encryption as well:

* GNU Privacy Guard
* OpenSSL Project

### GNU Privacy Guard

- Encryption

``` sh
gpg --symmetric --armor --cipher-algo CIPHER message.txt
```

> `--armor` option makes an ascii output

- Decryption

``` sh
gpg --output original_message.txt --decrypt message.gpg
```

### OpenSSL Project

- Encrypt

``` sh
openssl aes-256-cbc -pbkdf2 -iter 10000 -e -in message.txt -out encrypted_message
```

> `-pbkdf2` and `-iter <number>` options are optional but makes the encryption more secure and resilient against brute-force attacks

- Decrypt

``` sh
openssl aes-256-cbc -pbkdf2 -iter 10000 -d -in encrypted_message -out original_message.txt
```

### Questions

**Decrypt the file quote01 encrypted (using AES256) with the key `s!kR3T55` using gpg. What is the third word in the file?**

The used command: `gpg --output quote01.txt --decrypt quote01.txt.gpg`

*Answer: `waste`*

**Decrypt the file quote02 encrypted (using AES256-CBC) with the key `s!kR3T55` using openssl. What is the third word in the file?**

The used command: `openssl aes-256-cbc -d -in quote02 -out quote02.txt`

*Answer: `science`*

**Decrypt the file quote03 encrypted (using CAMELLIA256) with the key `s!kR3T55` using gpg. What is the third word in the file?**

The used command: `gpg --output quote03.txt --decrypt quote03.txt.gpg`

*Answer: `understand`*

## Task 3 - Asymmetric Encryption

Symmetric encryption requires the users to find a secure channel to exchange keys. By secure channel, we are mainly concerned with confidentiality and integrity. In other words, we need a channel where no one can change and read the sent messages.

Asymmetric encryption makes it possible to exchange encrypted messages without a secure channel; we just need a reliable channel.
When using an asymmetric encryption algorithm, we would generate a key pair: a public key and a private key. 

- **Public key**: Shared key used to encrypt the data.
- **Private key**: Never shared to anyone, used to decrypt the data.

### Confidentiality

Confidentiality is achieved by encrypting using the public key and decrypting using the private key.

### Integrity, Authenticity, and Nonrepudiation

They are achieved by encrypting using the private key and decrypting using the public key. Because the owner is normally the only one who has the key, this proves he is really the author.

- **Integrity**: The message is not altered.
- **Authenticity**: By successfully de-signing using the public key, it proves the author of the message by comparing the encrypted and the de-signed encrypted message.
- **Nonrepudation**: Nobody can deny the origin of the message.

Asymmetric ciphers can cover more fields than the symmetrical ones but it can't encrypt large amount of data fast.

Two main asymmetric encrypting methods exists today:

- RSA
- Eliptic Curves

### RSA

RSA got its name from its inventors, Rivest, Shamir, and Adleman. It works as follows:


1. Choose two random prime numbers, p and q. Calculate N = p × q.
2. Choose two integers e and d such that e × d = 1 mod ϕ(N), where ϕ(N) = N − p − q + 1. This step will let us generate the public key (N,e) and the private key (N,d).
3. The sender can encrypt a value x by calculating y = xe mod N. (Modulus)
4. The recipient can decrypt y by calculating x = y^d mod N. Note that y^d = x^ed = x^kϕ(N) + 1 = ((x^ϕ(N))^k) × x = x. This step explains why we put a restriction on the choice of e and d.

RSA security relies on factorization being a hard problem. It is easy to multiply p by q; however, it is time-consuming to find p and q given N. Moreover, for this to be secure, p and q should be pretty large numbers. It is important to note that RSA relies on secure random number generation, as with other asymmetric encryption algorithms. If an adversary can guess p and q, the whole system would be considered insecure.

### OpenSSL

- Generate a new private key

``` sh
openssl genrsa -out private-key.pem 2048
```

- Derive that private key to a public key

```sh
openssl rsa -in private-key.pem -pubout -out public-key.pem
```

- To see RSA variables used

``` sh
openssl rsa -in private-key.pem -text -noout
```

- To encrypt

``` sh
openssl pkeyutl -encrypt -in plaintext.txt -out ciphertext -inkey public-key.pem -pubin
```

- To decrypt

``` sh
openssl pkeyutl -decrypt -in ciphertext -inkey private-key.pem -out decrypted.txt
```

### Questions

*Files located in task03*

**Bob has received the file `ciphertext_message` sent to him from Alice. You can find the key you need in the same folder. What is the first word of the original plaintext?**

We need to decrypt using the bob's private key using the following command: `openssl pkeyutl -decrypt -in ciphertext_message -inkey private-key-bob.pem -out plaintext_message.txt`.

*Answer: `Perception`*

Take a look at Bob’s private RSA key. What is the last byte of p?

The used command: `openssl rsa -in private-key-bob.pem -text -noout | more`.

*Answer: `e7`*

Take a look at Bob’s private RSA key. What is the last byte of q?

Same command used.

*Answer: `27`*

## Task 4 - Diffie-Hellman Key Exchange

Diffie-Hellman is an asymmetric encryption algorithm which allow the exchange of a secret over a public channel. This works using power and modulus:

1. Alice and Bob agrees on *q* and *g*; *q* is a prime number and *g < q*.
2. Alice and Bob picks respectively, a private number *a* and *b* smaller than q.
3. They calculate *A/B = g^(a|b) mod q*
4. These are sent to each other.
5. They calculate *k = (A|B)^(a|b) mod q*

Finally they reach the same key. In real life, chosen numbers mostly are 256 bits in length.

Here is a simplified diagram:

![Diffie-Hellman algorithm with colors. Source: ResearchGate](/assets/img/images/thm_introduction_to_cryptography/HJP74TIia.png)

### OpenSSL

- To generate Diffie-Hellman parameters

``` sh
openssl dhparam -out dhparams.pem 2048
```

> `-text -noout` options to directly see parameters instead of `-out`.

- To see the parameters

``` sh
openssl dhparam -in dhparams.pem -text -noout
```

### Questions

*Files located in task04*

*A set of Diffie-Hellman parameters can be found in the file `dhparam.pem`. What is the size of the prime number in bits?*

The used command: `openssl dhparam -in dhparams.pem -text -noout`

*Answer: `4096`*

What is the prime number’s last byte (least significant byte)?

Same command used.

*Answer: `4f`*

## Task 5 - Hashing

A cryptographic hash function is an algorithm that takes data of arbitrary size as its input and returns a fixed size value, called *message digest* or *checksum*, as its output. The returned value is always the same for the same input data and should never be the same even with the most minor modification.
An example of hashing algorithm is *SHA256*. The 256 indicates that the message digest size is 256 bits long.

This type of function is useful for:
- **Storing passwords**: Passwords are stored in their hashed format. This is useful when a data breach occus in order to protect them.
- **Detecting Modifications**: Any modifications, like said before, lead to a drastic hash value change.

Some of the hashing algorithms in use and still considered secure are:

- SHA224, SHA256, SHA384, SHA512
- RIPEMD160

To calculate hash on linux, we have tools like `sha256sum`...

### HMAC

Hash-based message authentication code (HMAC) is a message authentication code (MAC) that uses a cryptographic key in addition to a hash function.

According to RFC2104, HMAC needs:

- Secret key
- Inner pad (ipad) a constant string. (RFC2104 uses the byte 0x36 repeated B times. The value of B depends on the chosen hash function.)
- Outer pad (opad) a constant string. (RFC2104 uses the byte 0x5C repeated B times.)

The HMAC is calculated as the following:

1. Fill the key with zeroes to make  it the length of B, length which match that of the ipad.
2. *key ⊕ ipad*.
3. Append the message to it and apply the hash function.
4. *key ⊕ opad*
5. Append the result to the hash output from step 3.
6. Apply the hash function.

This represents the formula: *H(K⊕opad,H(K⊕ipad,text))*.

> Note:
> ⊕ = XOR operation

To calculate hmac on linux, we have tools like `sha256hmac`...

### Questions

*Files located in task05*

**What is the SHA256 checksum of the file `order.json`?**

Using the following command: `sha256sum order.json`

*Answer: `2c34b68669427d15f76a1c06ab941e3e6038dacdfb9209455c87519a3ef2c660`*

** Open the file `order.json` and change the amount from *1000* to *9000*. What is the new SHA256 checksum?**

Changing the amount and using the same command.

*Answer: `11faeec5edc2a2bad82ab116bbe4df0f4bc6edd96adac7150bb4e6364a238466`*

**Using SHA256 and the key `3RfDFz82`, what is the HMAC of `order.txt`?**

Using the following command: `hmac256 3RfDFz82 order.txt`

*Answer: `c7e4de386a09ef970300243a70a444ee2a4ca62413aeaeb7097d43d2c5fac89f`*

## Task 6 - PKI and SSL/TLS

Like we have seen before, the Diffie-hellman key exchange allows us to agree on a secret key without sending it on a network. However, this protocol is not immune to Man In The Middle (MITM) Attacks. The reason is that there is no way of ensuring the authenticity of the two sides.

Here is a diagram explaining this:

{% include figure.liquid path="/assets/img/images/thm_introduction_to_cryptography/ry1BfTk26.png" title="Diffie-Hellman MITM" class="img-fluid rounded z-depth-1 bg-white" %}

The machanism which allows us to confirm other party identity is Public Key Infrastructure (PKI).

PKI is a system which permits the handling of cryptographic keys to securize communications.
To do that, entities called Certification Authorities (CA) delivers certificates which link a public key to a specific entity like a webserver. These keys are used to establish secure tunnels with protocols like TLS and the certificates have a period of validity.

In order to get signed by a certificate authority, we need to:

1. **Generate Certificate Signing Request (CSR)**: A certificate containing the public key which have to be signed by CA.
2. **Send CSR to a Certificate Authority (CA)**: The purpose is for the CA to sign your certificate. The alternative and usually insecure solution would be to self-sign the certificate. 

The process of signing requires the usage of the private key; because the content is encrypted with a private key, we can ensure the author is the right one by decrypting only by using the correct public key.

A CSR can be generated using `openssl`:

``` sh
openssl req -new -nodes -newkey rsa:4096 -keyout key.pem -out cert.csr
```

We can self sign our certificate using the following command:

``` sh
openssl req -x509 -newkey -nodes rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
```

The certificate can be visualized using the command:

``` sh
openssl x509 -in cert.pem -text
```

### Questions

*Files located in task06*

**What is the size of the public key in bits?**

Using the command `openssl x509 -in cert.pem -text | more`:

``` sh
Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (4096 bit)
```

*Answer: `4096`*

**Till which year is this certificate valid?**

Using the same command:

``` sh
Validity
            Not Before: Aug 11 11:34:19 2022 GMT
            Not After : Feb 25 11:34:19 2039 GMT
```

*Answer: `2039`*

## Task 7 - Authenticating with Passwords

With PKI and SSL/TLS, we can communicate with the server and provide sensitive information securely. But the data stored on the server should be also secured.

1. The least secure method: **plaintext**

No effort is required to know the password.

| Username | Password |
|:--------:|:--------:|
|   alice  |    123   |
|    bob   |    156   |
|   paul   |    123   |

2. A better improvement but not the best: **hashed passwords**

This way, in order to recover the password, an attacker should do a bruteforce/dictionnary attack and potentially get the right hash.
The snag is that same passwords have the same hash.
This kind of table is called a **rainbow table**.

| Username |          Hash(Password)          |
|:--------:|:--------------------------------:|
|   alice  | ba1f2511fc30423bdbb183fe33f3dd0f |
|    bob   | 9f430be862c6c636d251b1dddf8f80e6 |
|   paul   | ba1f2511fc30423bdbb183fe33f3dd0f |

3. The best practice: **salted passwords**

A further addition we can make is to add a little random string to the password and hash it. The result is then stored and everytime the *Hash(Password + Salt)* is calculated. This makes the result always different.

| Username |       Hash(Password + Salt)      | Salt |
|:--------:|:--------------------------------:|------|
|   alice  | 9e612320ccc0a3485902c0acb1b9845d | 1111 |
|    bob   | 824e30ea2eeb523eeb727110344fa4b3 | 123  |
|   paul   | 0a0bcd9c7eeac360f2c31ec7633b99c3 | 1269 |

An improvement to this is to use a key derivation function such as PBKDF2. It takes the password and the salt and submit it through a certain number of iterations.

Another approach is to use a slow hashing algorithm; it takes by default, a certain amount of time to calculate the hash of the password + salt.

[Password Storage Sheet Cheat](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)

### Questions

Using the website [md5encrypt.net](https://md5decrypt.net/):

*Answer: `qwerty123`*

## Task 8 - Cryptography and Data - Example

1. **Certificate Validation:** Cryptography ensures the validity of certificates. A certificate is considered valid if it's signed. Signing involves encrypting a hash of the certificate with the private key of a trusted third party, and appending the encrypted hash to the certificate.
2. **SSL/TLS Handshake:** Once the certificate is validated, an SSL/TLS handshake begins. This handshake allows the client and server to agree on a secret key and symmetric encryption algorithm for secure communication.
3. **Symmetric Encryption:** After the handshake, all session communication is encrypted using symmetric encryption, using the agreed-upon secret key.
4. **Login Credentials:** The client sends login credentials securely over the encrypted SSL/TLS session. The server receives the credentials and verifies them.
5. **Password Storage:** Following security best practices, the server hashes the password, appending a random salt to make it difficult to recover in case of a database breach.

## Task 9 - Conclusion

Cryptography is a vast topic. In this room, we have tried to focus on the core concepts that would help you understand the commonly used terms in cryptography. This knowledge is vital for understanding the configuration options of systems that use encryption and hashing.

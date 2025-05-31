# Sobo Crypto Center

The goal of this project is to create a set of Crypto tools that are easy to use for the average user and allow both encryption and decryption of any content offline, using both CLI and GUI, at the user's choice.


## A sample use - AES-GCM

### Encryption (AES-GCM):
```
zig run main.zig -- enc "Today I saw, how the quick brown fox jumped over the lazy dog."
=========================================================================================================
                              *** Sobo Crypto Center v 0.0.3 ***                                      
  Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
  Repo location: https://github.com/krzysobo/sobo_crypto_center/
  License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
=========================================================================================================
... Starting AES-GCM encryption of text:
'Today I saw, how the quick brown fox jumped over the lazy dog.'
...
ENCRYPTED DATA:
S2E7E47E9B5AE945F5C205920D65CDCB1414A9B8F8594B79BF6BF159C6DDFF23B848B8D0A94300F274F4BB407A5D0C086F46EBBDCA7F03B9DE7CD6586C530H71157E894F497AD410297FECB13F919EH616C666120626574612067616D6D61H7DB51C659F49FAA52883CDC1D4CA6E47D30D81BF84FE55544B924FAF3B372184HA2EEA1EE8E249C62426930EFS
AES KEY:
D986BB50A5D7049ADF5162F6B5EE263EE23CB490BBA84E316A67509664427517
```

The data is being encrypted with AES-GCM. The encrypted data is a structure starting end ending with "S". Betweenn those boundaries is a set of pure hex values separated with "H", namely:
- ciphertext hex 
- AES tag hex
- AD text hex 
- salt_hex
- nonce_hex


### Decryption (AES-GCM):
To decrypt the data from the above example, we call the following:
```
    zig run main.zig -- dec "S2E7E47E9B5AE945F5C205920D65CDCB1414A9B8F8594B79BF6BF159C6DDFF23B848B8D0A94300F274F4BB407A5D0C086F46EBBDCA7F03B9DE7CD6586C530H71157E894F497AD410297FECB13F919EH616C666120626574612067616D6D61H7DB51C659F49FAA52883CDC1D4CA6E47D30D81BF84FE55544B924FAF3B372184HA2EEA1EE8E249C62426930EFS" "D986BB50A5D7049ADF5162F6B5EE263EE23CB490BBA84E316A67509664427517"
        =========================================================================================================
                                    *** Sobo Crypto Center v 0.0.3 ***                                      
        Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        Repo location: https://github.com/krzysobo/sobo_crypto_center/
        License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        =========================================================================================================
        ... Starting decryption of ciphertext:
        'S2E7E47E9B5AE945F5C205920D65CDCB1414A9B8F8594B79BF6BF159C6DDFF23B848B8D0A94300F274F4BB407A5D0C086F46EBBDCA7F03B9DE7CD6586C530H71157E894F497AD410297FECB13F919EH616C666120626574612067616D6D61H7DB51C659F49FAA52883CDC1D4CA6E47D30D81BF84FE55544B924FAF3B372184HA2EEA1EE8E249C62426930EFS'
        with hex_key:
        'D986BB50A5D7049ADF5162F6B5EE263EE23CB490BBA84E316A67509664427517'
        ...
        Decrypted text:
        Today I saw, how the quick brown fox jumped over the lazy dog.

        ========================================
```

- of course, instead of calling ```zig run main.zig``` you should compile the project: it will be many times
faster! Using ```zig run xxxx.zig``` is good only for testing, since it compiles the project each time. To use the compiled version:
- do compile it first :) with ```zig build``` in the main src directory or one up.
- go to the directory ```zig-out/bin```, which is located one level above ```src```.
- call ./sobo-crypto-center with the parameters as above, only omitting the ```--```, ie.
```
    ./sobo_crypto_center dec "S2E7E47E9B5AE945F5C205920D65CDCB1414A9B8F8594B79BF6BF159C6DDFF23B848B8D0A94300F274F4BB407A5D0C086F46EBBDCA7F03B9DE7CD6586C530H71157E894F497AD410297FECB13F919EH616C666120626574612067616D6D61H7DB51C659F49FAA52883CDC1D4CA6E47D30D81BF84FE55544B924FAF3B372184HA2EEA1EE8E249C62426930EFS" "D986BB50A5D7049ADF5162F6B5EE263EE23CB490BBA84E316A67509664427517"
        =========================================================================================================
                                    *** Sobo Crypto Center v 0.0.3 ***                                      
        Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        Repo location: https://github.com/krzysobo/sobo_crypto_center/
        License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        =========================================================================================================
        ... Starting decryption of ciphertext:
        'S2E7E47E9B5AE945F5C205920D65CDCB1414A9B8F8594B79BF6BF159C6DDFF23B848B8D0A94300F274F4BB407A5D0C086F46EBBDCA7F03B9DE7CD6586C530H71157E894F497AD410297FECB13F919EH616C666120626574612067616D6D61H7DB51C659F49FAA52883CDC1D4CA6E47D30D81BF84FE55544B924FAF3B372184HA2EEA1EE8E249C62426930EFS'
        with hex_key:
        'D986BB50A5D7049ADF5162F6B5EE263EE23CB490BBA84E316A67509664427517'
        ...
        Decrypted text:
        Today I saw, how the quick brown fox jumped over the lazy dog.

        ========================================
```


## A sample use - Diffie-Hellman's
- This algorithm:
    - makes use of X25519 to generate a key pair (32 bits each) and generate a shared secret 
(for each side: "my private key + their public key"). 
    - makes use of AES-GCM to encrypt and decrypt a message with a key derived from the shared secret.
    - For example, Bob encrypts a plaintext message to Alice, starting with generation of the shared secret with his own secret (private) X25519 key and Alice's public X25519 key. Then, Alice receives his encrypted message (ciphertext) and decrypts it using her own secret (private) key and Bob's public key (which he shared in this message). Of course, Alice had to provide her public key to him first.
    - NEVER EVER share your secret (private) key!!!
   

### BOB (me) - generation of a Diffie-Hellman's key pair (X25519):
```
    $ zig run main.zig -- dh_genkey
        There are 2 args:
        /home/krzy/.cache/zig/o/e121ea67a0b5e49a1728dee0a259e262/main
        dh_genkey
        =========================================================================================================
                                    *** Sobo Crypto Center v 0.0.1 ***                                      
        Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        Repo location: https://github.com/krzysobo/sobo_crypto_center/
        License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        =========================================================================================================
        ... Generating Diffie-Hellman's key pair...


        US - KEY PAIR:
        SECRET_KEY:
        5B8A17B256ABF1ABE4688E87E987F82F0F69F08696A62D775389EBC4E29DABC8
        PUBLIC_KEY:
        608DF86978FC24A043CD5C9F752414B9A01F1E079CAB424F68D35669DCF51B05
```
#### Bob's SECRET KEY (PRIVATE KEY): 5B8A17B256ABF1ABE4688E87E987F82F0F69F08696A62D775389EBC4E29DABC8
#### Bob's PUBLIC KEY: 608DF86978FC24A043CD5C9F752414B9A01F1E079CAB424F68D35669DCF51B05
#### **Alice DOES NOT KNOW Bob's SECRET key! Only his public key!!!**



### Alice - generation of a Diffie-Hellman's key pair (X25519):
```
    zig run main.zig -- dh_genkey
        There are 2 args:
        /home/krzy/.cache/zig/o/e121ea67a0b5e49a1728dee0a259e262/main
        dh_genkey
        =========================================================================================================
                                    *** Sobo Crypto Center v 0.0.1 ***                                      
        Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        Repo location: https://github.com/krzysobo/sobo_crypto_center/
        License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        =========================================================================================================
        ... Generating Diffie-Hellman's key pair... - TODO


        US - KEY PAIR:
        SECRET_KEY:
        328D039028C352B384DE71958218D6D1F8064543AB2640AFFF7929E32FF20ECF
        PUBLIC_KEY:
        671F1ED87D314BD278513A193A270524ED6B255B66D8A42F607AB5E7D53E854F

```

#### Alice's SECRET KEY (PRIVATE KEY): 328D039028C352B384DE71958218D6D1F8064543AB2640AFFF7929E32FF20ECF
#### Alice's PUBLIC KEY: 671F1ED87D314BD278513A193A270524ED6B255B66D8A42F607AB5E7D53E854F
#### **Bob DOES NOT KNOW Alice's SECRET key! Only her public key!!!**



### Bob (me) encrypts the message to Alice:
- Encryption command format: ```dh_enc "plaintext" "their_public_key" "my_secret_key"
    - that is: ```dh_enc "plaintext" "Alice's pub key" "Bob's secret key"

```
    zig run main.zig -- dh_enc "It works, Dear Alice!" "671F1ED87D314BD278513A193A270524ED6B255B66D8A42F607AB5E7D53E854F" "5B8A17B256ABF1ABE4688E87E987F82F0F69F08696A62D775389EBC4E29DABC8"
        =========================================================================================================
                                    *** Sobo Crypto Center v 0.0.1 ***                                      
        Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        Repo location: https://github.com/krzysobo/sobo_crypto_center/
        License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        =========================================================================================================
        ... Encrypting a plaintext 'It works, Dear Alice!' with Diffie-Hellman's public key '671F1ED87D314BD278513A193A270524ED6B255B66D8A42F607AB5E7D53E854F'...


        ==== OUR PRIV KEY:
        5B8A17B256ABF1ABE4688E87E987F82F0F69F08696A62D775389EBC4E29DABC8

        ==== OUR PUB KEY:
        608DF86978FC24A043CD5C9F752414B9A01F1E079CAB424F68D35669DCF51B05

        ==== THEIR PUB KEY:
        671F1ED87D314BD278513A193A270524ED6B255B66D8A42F607AB5E7D53E854F

        ==== ENCRYPTED DATA:
        W841F5E72A0ED78E53609A5BFA22FB59F1B1676DCD4H79AF260381F73688A25FC7C7D3347590H58436AA61CA07E16EFD6F87EB63A9F549D26B1BA4273E290DAC0EE52AADAE273H5A3B28D5ED74B1D717980E0BH608DF86978FC24A043CD5C9F752414B9A01F1E079CAB424F68D35669DCF51B05W
       
```


#### Bob's (mine) encrypted data to Alice: 
```
"W841F5E72A0ED78E53609A5BFA22FB59F1B1676DCD4H79AF260381F73688A25FC7C7D3347590H58436AA61CA07E16EFD6F87EB63A9F549D26B1BA4273E290DAC0EE52AADAE273H5A3B28D5ED74B1D717980E0BH608DF86978FC24A043CD5C9F752414B9A01F1E079CAB424F68D35669DCF51B05W"
```

### Alice gets and decrypts the message from Bob. Decryption command format:
- dh_dec "ciphertext_hex" "our_priv_key_hex"
    - that is: dh_dec "ciphertext from Bob" "Alice's secret key"

```
    zig run main.zig -- dh_dec "W841F5E72A0ED78E53609A5BFA22FB59F1B1676DCD4H79AF260381F73688A25FC7C7D3347590H58436AA61CA07E16EFD6F87EB63A9F549D26B1BA4273E290DAC0EE52AADAE273H5A3B28D5ED74B1D717980E0BH608DF86978FC24A043CD5C9F752414B9A01F1E079CAB424F68D35669DCF51B05W" "328D039028C352B384DE71958218D6D1F8064543AB2640AFFF7929E32FF20ECF"
        =========================================================================================================
                                    *** Sobo Crypto Center v 0.0.1 ***                                      
        Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        Repo location: https://github.com/krzysobo/sobo_crypto_center/
        License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        =========================================================================================================
        ... Un-hexing and decrypting a ciphertext hex:
        W841F5E72A0ED78E53609A5BFA22FB59F1B1676DCD4H79AF260381F73688A25FC7C7D3347590H58436AA61CA07E16EFD6F87EB63A9F549D26B1BA4273E290DAC0EE52AADAE273H5A3B28D5ED74B1D717980E0BH608DF86978FC24A043CD5C9F752414B9A01F1E079CAB424F68D35669DCF51B05W

        ...with Diffie-Hellman's private key
        328D039028C352B384DE71958218D6D1F8064543AB2640AFFF7929E32FF20ECF


        DECRYPTED MESSAGE:
        It works, Dear Alice!
```

### If you forgot your public key, don't fret 
- it's important that you know your private one! You may restore your public key with:
    ```dh_genpubkey "your_secret_private_key"```

```
    zig run main.zig -- dh_genpubkey "150F05E32E55DD04F0736D2F8D6E46774A3F87571D4C19E0F1F0955A4CE1A560"
        =========================================================================================================
                                    *** Sobo Crypto Center v 0.0.1 ***                                      
        Copyright (c) 2025 Krzysztof Sobolewski <krzysztof.sobolewski@gmail.com> https://github.com/krzysobo
        Repo location: https://github.com/krzysobo/sobo_crypto_center/
        License: MIT  see: https://github.com/krzysobo/sobo_crypto_center/blob/main/LICENSE
        =========================================================================================================
        ... Generating Diffie-Hellman's public key from private key '150F05E32E55DD04F0736D2F8D6E46774A3F87571D4C19E0F1F0955A4CE1A560'... - 


        PUBLIC KEY:
        48BF950E9D01743726FE6DE7AAB2362A9FF02BBF3C37D9831A7D55D9FF929B42
```


TODO:
- more encryption algorithms - RSA
- more features for CLI
- file handling - encryption and decryption of the files of any type and size.
- GUI (DVUI? Caps? LVGL? Nuklear? Something else? Decision not made yet.)
- ... many other things :-)
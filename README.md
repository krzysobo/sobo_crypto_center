# Sobo Crypto Center

The goal of this project is to create a set of Crypto tools that are easy to use for the average user and allow both encryption and decryption of any content offline, using both CLI and GUI, at the user's choice.


## A sample use

### Encryption (AES-GCM):
```
    zig run main.zig -- enc "Hello World, blah blah blah. Let's encrypt everything"

    ... Starting encryption of text:
    'Hello World, blah blah blah. Let's encrypt everything'
    ...
    ENCRYPTED TEXT:
    B8E8B2F54C6445CFC2DBD3E39E5027DA607590A2F574B9D5963B53FEA74DD59665111C6E16A4D65A1EBB840FFACB05788E8FA79175
    Portable Key Suite:
    W554E87089793F0DE07291CC3B65FC6581DFD8732B4438932A16DF81AB8636BC5QB50C501D18FE8517D5A81AF8F40F0C50Q3976684D5A0F0E1BBD8BEE3FQ446F6C6F722073697420616D65742EW
```

AES-GCM from the standard crypto library (std.crypto) of Zig 0.14.0 with both key, tag, nonce and additional verification text contained in "Portable Key Suite", separated by "Q" characters. The Portable Key Suite starts and ends  with "W". Neither of those letters (W or Q) ever appear in hex, so their use makes the structure unambigous.


### Decryption (AES-GCM):
with both key, tag, nonce and additional verification text contained in "Portable Key Suite", separated by "Q" characters. The Portable Key Suite starts and ends  with "W". Neither of those letters (W or Q) ever appear in hex, so their use makes the structure unambigous.


```
    zig run main.zig -- dec "B8E8B2F54C6445CFC2DBD3E39E5027DA607590A2F574B9D5963B53FEA74DD59665111C6E16A4D65A1EBB840FFACB05788E8FA79175" "W554E87089793F0DE07291CC3B65FC6581DFD8732B4438932A16DF81AB8636BC5QB50C501D18FE8517D5A81AF8F40F0C50Q3976684D5A0F0E1BBD8BEE3FQ446F6C6F722073697420616D65742EW"

    ... Starting decryption of ciphertext:
    'B8E8B2F54C6445CFC2DBD3E39E5027DA607590A2F574B9D5963B53FEA74DD59665111C6E16A4D65A1EBB840FFACB05788E8FA79175'
    with hex_key_suite:
    'W554E87089793F0DE07291CC3B65FC6581DFD8732B4438932A16DF81AB8636BC5QB50C501D18FE8517D5A81AF8F40F0C50Q3976684D5A0F0E1BBD8BEE3FQ446F6C6F722073697420616D65742EW'
    ...
    Decrypted text:
    Hello World, blah blah blah. Let's encrypt everything
```




## TODO
- more encryption algorithms, including hybrid and asymmetric, allowing the use of key pairs
- more features for CLI
- GUI (DVUI? Caps? LVGL? Something else? Decision not made yet.)
- SQLite integration allowing storage of encrypted content
- ... many other things :-)
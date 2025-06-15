# One-Time Pad Encrypted Messenger
### Encryption/ decryption program for converting plaintext data into ciphertext, using a key via the one-time pad-like approach. 

#### Steps:
1. Compile programs: 
    gcc -std=gnu99 -o enc_sever enc_sever.c
    gcc -std=gnu99 -o enc_client enc_client.c
    gcc -std=gnu99 -o dec_server dec_sever.c
    gcc -std=gnu99 -o dec_client dec_client.c
    gcc -std=gnu99 -o keygen keygen.c

2. Start encryption server (./enc_server <PORT1> &)

3. Start decryption server (./enc_server <PORT2> &)

#### For encryption

4. Write message for encryption in flat file

5. Execute key generator to generate random characters equal or greater in character length than message (./keygen 1024). 

6. Encrypt message via client request (./enc_client <MSG or MSG_file> <key_file> <PORT1> <std_out or Cipher_file>)

#### For decryption

7. Decrypt message via client request (./dec_client <Cipher_file> <key_file> <PORT2> <std_out or output_file>)


    
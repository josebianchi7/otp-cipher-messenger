#include <stdlib.h>         // Memory management
#include <stdio.h>          // Input/ output
#include <stdbool.h>        // Boolean values
#include <string.h>         // String functions
#include <netinet/in.h>     // Internet/ socket functions
#include <sys/socket.h>     // Socket functions
#include <arpa/inet.h>      // Internet functions
#include <sys/types.h>      // Size functions
#include <unistd.h>         // Process management/ file operations
#include <sys/wait.h>       // Process termination functions
#include <ctype.h>          // Character functions

#define CONNECT_COUNT 5

/*
Program Name: Encryption Server
Author: Jose Bianchi
Description: Program is part of encryption/ decryption prgram for converting plaintext 
    data into ciphertext, using a key via the one-time pad-like approach. This specific 
    program is the encryption server meant to run in the background as a daemon. Program 
    accepts an integer argument that will be the listening port. Program expects client 
    requests be sent in 5 parts: client ID code, key sequence size, key sequence, plaintext 
    size, and plaintext message. Ciphertext is sent to client as response. Supports up to 5 
    concurrent socket connections (5 encryptions at once).
*/

// Helper function declarations
void setup_socket(struct sockaddr_in* address, int port_num);
char* encrypt_msg(char *message, int message_len, char *key_seq);

int main(int argc, char *argv[]) {
    int client_socket;
    struct sockaddr_in server_address;
    struct sockaddr_in client_address;
    socklen_t client_info_size = sizeof(client_address);
    char permitted_code[] = "4321";

    // Validate input
    if (argc < 2) {
        fprintf(stderr,"USAGE: %s port\n", argv[0]);
        exit(1);
    }
    int port_arg = atoi(argv[1]);
    if (port_arg <= 0) {
        fprintf(stderr, "Error: invalid port number '%s'\n", argv[1]);
        exit(1);
    }
    // Establish IPv4 TCP server (listener) socket
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Error: could not create/ open socket");
        exit(1);
    }
    setup_socket(&server_address, port_arg);
    int bind_result = bind(server_socket, 
                            (struct sockaddr *)&server_address, 
                            sizeof(server_address));
    if (bind_result < 0) {
        perror("Error: could not bind server to socket address");
        exit(1);
    }
    listen(server_socket, CONNECT_COUNT);
    while (1) {
        client_socket = accept(server_socket, 
                                (struct sockaddr *)&client_address, 
                                &client_info_size);
        if (client_socket < 0) {
            perror("Error: could not accept connection from socket");
            continue; 
        }
        // Use separate process to handle specific client request
        pid_t spawn_pid = fork();
        switch (spawn_pid) {
            case -1:
                perror("Error: fork() failed");
                close(client_socket);
                continue;
            case 0:
                // Receieve request from client (5 PARTS)
                char client_code[10];
                int nbo_key_len;
                int key_len;
                int nbo_msg_len;
                int msg_len;
                int bytes_read;
                int total_read;
                int bytes_written;
                int total_written;
                char *key = NULL;
                char *msg = NULL;
                char *cipher = NULL;
                // Part 1: Client ID code (only accept message from permitted client)
                memset(client_code, '\0', sizeof(client_code));
                bytes_read = recv(client_socket, client_code, sizeof(client_code) - 1, 0);
                if (bytes_read < 0) {
                    perror("Error: could not read client code");
                    // If error, end connection and start over with next client
                    close(client_socket);
                    exit(1); 
                } 
                client_code[bytes_read] = '\0';
                // Send access status message based on client code
                if (strcmp(client_code, permitted_code) == 0) {
                    bytes_written = send(client_socket, "enc", 3, 0);
                } else {
                    bytes_written = send(client_socket, "reject", 6, 0);
                    close(client_socket);
                    exit(1);
                }
                bytes_read = 0;
                // Part 2: Key size
                bytes_read = recv(client_socket, &nbo_key_len, sizeof(nbo_key_len), 0);
                if (bytes_read < 0) {
                    perror("Error: could not read key length");
                    close(client_socket);
                    exit(1); 
                }
                // Allocate memory for key sequence
                key_len = ntohl(nbo_key_len);
                key = calloc(key_len + 1, sizeof(char));
                if (!key) {
                    perror("Error: failed to allocate memory for key");
                    close(client_socket);
                    exit(1);
                }
                // Part 3: Key string
                total_read = 0;
                bytes_read = 0;
                while (total_read < key_len) {
                    bytes_read = recv(client_socket, key + total_read, key_len - total_read, 0);
                    if (bytes_read < 0) {
                        perror("Error: could not read message from socket");
                        free(key);
                        close(client_socket);
                        exit(1);
                    } else if (bytes_read == 0) {
                        free(key);
                        close(client_socket);
                        exit(1);
                    }
                    total_read += bytes_read;
                }
                key[key_len] = '\0';
                bytes_read = 0;
                // Part 4: Message size
                bytes_read = recv(client_socket, &nbo_msg_len, sizeof(nbo_msg_len), 0);
                if (bytes_read < 0) {
                    perror("Error: could not read message length");
                    free(key);
                    close(client_socket);
                    exit(1); 
                }
                // Allocate memory for plaintext
                msg_len = ntohl(nbo_msg_len);  
                msg = calloc(msg_len + 1, sizeof(char));
                if (!msg) {
                    perror("Error: failed to allocate memory for message");
                    free(key);
                    close(client_socket);
                    exit(1); 
                }
                // Part 5: Message string
                total_read = 0;
                bytes_read = 0;
                while (total_read < msg_len) {
                    bytes_read = recv(client_socket, msg + total_read, msg_len - total_read, 0);
                    if (bytes_read < 0) {
                        perror("Error: could not read message from socket");
                        free(key);
                        free(msg);
                        close(client_socket);
                        exit(1);
                    } else if (bytes_read == 0) {
                        free(key);
                        free(msg);
                        close(client_socket);
                        exit(1);
                    }
                    total_read += bytes_read;
                }
                msg[msg_len] = '\0';               
                // Get ciphertext of message      
                cipher = encrypt_msg(msg, msg_len, key);
                if (!cipher) {
                    perror("Error: failed to encrypt message");
                    free(key);
                    free(msg);
                    close(client_socket);
                    exit(1);        
                }
                size_t cipher_len = strlen(cipher);
                // Send cipher as response to client
                bytes_written = 0;
                total_written = 0;
                while (total_written < cipher_len) {
                    bytes_written = send(client_socket, cipher + total_written, cipher_len - total_written, 0);
                    if (bytes_written < 0) {
                        perror("Error: could not write to client");
                        free(key);
                        free(msg);
                        free(cipher);
                        close(client_socket);
                        exit(1);
                    } else if (bytes_written == 0) {
                        free(key);
                        free(msg);
                        free(cipher);
                        close(client_socket);
                        exit(1);
                    }
                    total_written += bytes_written;
                }
                // Close connection with client after completing request
                free(key);
                free(msg);
                free(cipher);
                exit(0);
            default:
                close(client_socket);
                // Cleanup child process without blocking 
                while (waitpid(-1, NULL, WNOHANG) > 0);
        }
    }   
    close(server_socket);
    return 0;
}

/*
* Function: setup_socket()
*   Sets up a socket address with port_num value.
*   :param struct sockaddr_in* address: structure for socket address
*   :param int port_num: port number for socket address
*/
void setup_socket(struct sockaddr_in* address, int port_num) {
    // Clear out the address struct
    memset((char*) address, '\0', sizeof(*address));

    // The address should be network capable
    address->sin_family = AF_INET;
    // Convert and store the port number in network byte order
    address->sin_port = htons(port_num);
    // Allow a client at any address to connect to this server
    address->sin_addr.s_addr = INADDR_ANY;
}

/*
* Function: encrypt_msg()
*   Encrypts message using assigned character values and key sequence. 
*   :param char *message: plaintext message string
*   :param int message_len: length of message and cipher
*   :param char *key_seq: key sequence string
*   :return char*: pointer to cipher text string
*/
char* encrypt_msg(char *message, int message_len, char *key_seq) {
    char * cipher_msg = calloc(message_len + 1, sizeof(char));
    if (!cipher_msg) {
        perror("Error: failed to allocate memory for cipher");
        return NULL;
    }
    
    char msg_char;
    int msg_val;
    char key_char;
    int key_val;
    int cipher_val;
    char cipher_char;
    for (size_t i = 0; message[i] != '\0'; i++) { 
        // Convert message character to int
        msg_char = message[i];
        if (isspace(msg_char)) {
            msg_val = 26;
        } else {
            msg_val = msg_char - 'A';
        }
        // Convert key_seq character to int
        key_char = key_seq[i];
        if (isspace(key_char)) {
            key_val = 26;
        } else {
            key_val = key_char - 'A';
        }
        // Sum integer values and get resulting char
        cipher_val = msg_val + key_val;
        if (cipher_val > 26) {
            cipher_val -= 27;
        }
        if (cipher_val == 26) {
            cipher_char = ' ';
        } else {
            cipher_char = 'A' + cipher_val;
        }
        cipher_msg[i] = cipher_char;
    }
    cipher_msg[message_len] = '\0';
    return cipher_msg;
}
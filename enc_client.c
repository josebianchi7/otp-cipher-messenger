#include <netdb.h>          // DNS functions
#include <stdlib.h>         // Memory management
#include <stdio.h>          // Input/ output
#include <stdbool.h>        // Boolean values
#include <string.h>         // String functions
#include <netinet/in.h>     // Internet/ socket functions
#include <sys/socket.h>     // Socket functions
#include <arpa/inet.h>      // Internet functions
#include <sys/types.h>      // Size functions
#include <unistd.h>         // Process management/ file operations
#include <ctype.h>          // Character functions

/*
Program Name: Encryption Client
Author: Jose Bianchi
Description: Program is part of encryption/ decryption prgram for converting 
    plaintext data into ciphertext, using a key via the one-time pad-like approach. 
    This specific program is the client program that makes requests from the 
    encryption server to encrypt plaintext messages. Program requires 3 arguments:
    message, key sequence, and port number to perform all functions. Client
    outputs response (expected ciphertext) from server to stdout. Program terminates
    if plaintext or key sequence have any invalid characters, key sequence is shorter
    than plaintext, or there is an issue with the socket connection. Program sends 
    requests to encryption server via socket request in 5 parts: client ID code, 
    key sequence size, key sequence, plaintext size, and plaintext message. Expected
    response from server is ciphertext of message.
*/

// Helper function declarations
void setup_socket(struct sockaddr_in* address, int port_num);
char* parse_valid_file(char *filepath);

int main(int argc, char *argv[]) {
    char *key_buffer = NULL;
    char *text_buffer = NULL;
    int socket_fd;
    int bytes_written;
    int total_written;
    int bytes_read;
    int total_read;
    struct sockaddr_in server_address;
    char permitted_code[] = "4321";
    char access_response[10];

    // Verfiy inputs
    if (argc < 4) {
        fprintf(stderr,"USAGE: %s plaintext key port\n", argv[0]);
        exit(1);
    }
    // Parse and check key file
    key_buffer = parse_valid_file(argv[2]);
    if (!key_buffer) {
        exit(1);
    }
    size_t key_len = strlen(key_buffer);
    
    // Parse and check plaintext file
    text_buffer = parse_valid_file(argv[1]);
    if (!text_buffer) {
        free(key_buffer);
        exit(1);
    }
    size_t text_len = strlen(text_buffer);
    
    // Key file cannot be shorter than plaintext file
    if (key_len < text_len) {
        fprintf(stderr,"Error: key \'%s\' is too short\n", argv[2]);
        free(key_buffer);
        free(text_buffer);
        exit(1);
    }
    // Establish socket connection via port argument 
    int port_arg = atoi(argv[3]);
    if (port_arg <= 0) {
        fprintf(stderr, "Error: invalid port number '%s'\n", argv[3]);
        exit(1);
    }
    // Create IPv4 TCP socket for sending to server
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("Error: failed to create/ open socket");
        free(key_buffer);
        free(text_buffer);
        exit(2);
    }
    // Set up server socket
    setup_socket(&server_address, port_arg);

    // Connect client to server
    if (connect(socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
        perror("Error: failed to connect to server");
        free(key_buffer);
        free(text_buffer);
        close(socket_fd);
        exit(2);
    } 
    // Identify self to server
    bytes_written = send(socket_fd, permitted_code, strlen(permitted_code), 0);
    if (bytes_written < 0) {
        perror("Error: failed to send client ID");
        free(key_buffer);
        free(text_buffer);
        close(socket_fd);
        exit(2);
    }
    bytes_written = 0;
    // Determine if correct server contacted
    memset(access_response, '\0', sizeof(access_response));
    bytes_read = recv(socket_fd, access_response, sizeof(access_response) - 1, 0);
    if (bytes_read < 0) {
        perror("Error: failed to get server acceptance response");
        free(key_buffer);
        free(text_buffer);
        close(socket_fd);
        exit(2);
    }
    access_response[bytes_read] = '\0';
    // End connection if wrong server
    if (strcmp(access_response, "enc") != 0) {
        fprintf(stderr, "Error: could not contact enc_server on port %d\n", port_arg);
        free(key_buffer);
        free(text_buffer);
        close(socket_fd);
        exit(2);
    }
    // Notify server on how much key sequence data is coming
    int nbo_key_len = htonl(key_len);
    bytes_written = send(socket_fd, &nbo_key_len, sizeof(nbo_key_len), 0);
    if (bytes_written < 0) {
        perror("Error: failed to send message length");
        free(key_buffer);
        free(text_buffer);
        close(socket_fd);
        exit(2);
    }
    bytes_written = 0;
    // Loop and send message to ensure complete key sequence message sent
    total_written = 0;
    while (total_written < key_len) {
        bytes_written = send(socket_fd, key_buffer + total_written, key_len - total_written, 0);
        if (bytes_written < 0) {
            perror("Error: failed to write to server");
            free(key_buffer);
            free(text_buffer);
            close(socket_fd);
            exit(2);
        } else if (bytes_written == 0) {
            fprintf(stderr, "Error: server may have closed connection\n");
            free(key_buffer);
            free(text_buffer);
            close(socket_fd);
            exit(2);
        }
        total_written += bytes_written;
    }
    bytes_written = 0;
    // Notify server on how much plaintext data is coming
    int nbo_text_len = htonl(text_len);
    bytes_written = send(socket_fd, &nbo_text_len, sizeof(nbo_text_len), 0);
    if (bytes_written < 0) {
        perror("Error: failed to send message length");
        free(key_buffer);
        free(text_buffer);
        close(socket_fd);
        exit(2);
    } 
    bytes_written = 0;
    total_written = 0;
    // Loop and send message to ensure complete plaintext message sent
    while (total_written < text_len) {
        bytes_written = send(socket_fd, text_buffer + total_written, text_len - total_written, 0);
        if (bytes_written < 0) {
            perror("Error: failed to write to server");
            free(key_buffer);
            free(text_buffer);
            close(socket_fd);
            exit(2);
        } else if (bytes_written == 0) {
            fprintf(stderr, "Error: server may have closed connection\n");
            free(key_buffer);
            free(text_buffer);
            close(socket_fd);
            exit(2);
        }
        total_written += bytes_written;
    }
    bytes_written = 0;
    total_written = 0;
    // Clear out the buffer for response from socket
    memset(text_buffer, '\0', text_len + 1);
    // Read response from socket
    bytes_read = 0;
    total_read = 0;
    while (total_read < text_len) {
        bytes_read = recv(socket_fd, text_buffer + total_read, text_len - total_read, 0);
        if (bytes_read < 0){
            perror("Error: failed to read response from socket");
            free(key_buffer);
            free(text_buffer);
            close(socket_fd);
            exit(2);
        } else if (bytes_read == 0) {
            fprintf(stderr, "Error: server may have closed connection\n");
            free(key_buffer);
            free(text_buffer);
            close(socket_fd);
            exit(2);
        }
        total_read += bytes_read;
    }
    text_buffer[text_len] = '\0';
    printf("%s\n", text_buffer);
    free(key_buffer);
    free(text_buffer);
    close(socket_fd);
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
    address->sin_addr.s_addr = inet_addr("127.0.0.1");
}

/*
* Function: parse_valid_file()
*   Allocates memory for file text.
*   Verfiies file contains only valid characters. 
*   Valid characters includes uppercase letters and space character.
*   Function expects files terminate with a newline character. 
*   :param char *filepath: filepath for reading
*   :return char*: pointer to text string in memory or NULL if error
*/
char* parse_valid_file(char *filepath) {
    FILE *file = fopen(filepath, "r");
    if (!file) {
        perror("Error: failed to open file");
        return NULL;
    }
    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    if (file_size < 0) {
        perror("Error: failed to read file");
        fclose(file);
        return NULL;
    }
    rewind(file);
    // Allocate memory for file text
    char* buffer = malloc(file_size + 1);
    if (!buffer) {
        perror("Error: failed to allocate memory for file text");
        fclose(file);
        return NULL;
    }
    // Store file contents
    size_t file_bytes_read = fread(buffer, 1, file_size, file);
    if (file_bytes_read < 1) {
        perror("Error: failed to parse file");
        free(buffer);
        fclose(file);
        return NULL;
    }
    buffer[file_bytes_read] = '\0'; 
    fclose(file);
    // Remove the trailing \n 
    buffer[strcspn(buffer, "\n")] = '\0';
    // Validate characters (only uppercase letters and spaces)
    for (size_t i = 0; buffer[i] != '\0'; i++) {
        if (!(isupper(buffer[i]) || isspace(buffer[i]))) {
            perror("enc_client error: input contains bad characters");
            free(buffer);
            return NULL;
        }
    }
    return buffer;
}
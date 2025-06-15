#include <stdlib.h>         // Memory management 
#include <stdio.h>          // Input/ output
#include <string.h>         // String functions
#include <time.h>           // Random functions

#define CHAR_COUNT 27

/*
Program Name: One-Time Pads Key Generator
Author: Jose Bianchi
Description: Program is part of encryption/ decryption prgram for converting 
    plaintext data into ciphertext, using a key via the one-time pad-like approach. 
    This specific program creates a key sequence (key_seq) of specified length using 
    random selection/ generation from a pool of 27 characters (26 capital English 
    letters and one space character). Terminating character is newline character. 
    Program accepts one integer argument to know how many characters to generate. 
*/

const char char_pool[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "; 

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Please include an integer value for how many characters to generate.\n");
        exit(1);
    }
    // Data validation
    int char_count = atoi(argv[1]);  
    if (char_count < 1) {
        fprintf(stderr, "Integer value must be a positive non-zero value.\n");
        exit(1);
    }

    // Generate/ build key sequence
    char key_seq[char_count+1];
    srand(time(NULL));
    for (int i=0; i < char_count; i++) {
        int rand_index = rand() % CHAR_COUNT;
        key_seq[i] = char_pool[rand_index];
    }
    key_seq[char_count] = '\0';

    printf("%s\n", key_seq);
    return 0;
}
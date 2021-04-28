#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>
#include <unistd.h>
#include <time.h>

#define PATH_PRE "/etc/ssh/"

// Compile: gcc -o key_gen key_gen.c -lssl -lcrypto
// USAGE: sudo ./key_gen [your username]

int main (int argc, char *argv[]) {

    if (argc != 2) {
        printf("USAGE: ./key_gen [your username]\n");
        exit(9);
    }

    // Create file path
    char path[128];
    memset(path, '\0', 128);
    memcpy(path, PATH_PRE, strlen(PATH_PRE));
    memcpy(&(path[strlen(PATH_PRE)]), argv[1], strlen(argv[1]));
    path[strlen(PATH_PRE) + strlen(argv[1])] = '\0';

    // Check if file exits already
    if (access(path, F_OK) == 0) {
        printf("Key file already exist, STOP!\n");
        exit(1);
    } else {
        FILE * file;
        file = fopen(path, "wr");

        if (file == NULL) {
            perror("Error open file!\n");
            exit(99);
        } else {
            char key[129];

            time_t t;
            
            srand((unsigned) time(&t));

            for (int i = 0; i < 128; i++) {
                key[i] = 97 + rand() / (RAND_MAX / (122 - 97 + 1) + 1);
                fputc(key[i], file);
            }
            fputc('\0', file);
            key[128] = '\0';
            fclose(file);

            printf("New key file: %s\n", path);
            printf("New key: %s\n", key);
        }
    }
}
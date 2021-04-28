//#include "config.h"

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "base32.c"
#include "hmac.c"
#include "sha1.c"
#include "util.c"
#define VERIFICATION_CODE_MODULUS (1000*1000) // Six digits
#define SCRATCHCODES              5           // Default number of initial scratchcodes
#define MAX_SCRATCHCODES          10          // Max number of initial scratchcodes
#define SCRATCHCODE_LENGTH        8           // Eight digits per scratchcode
#define BYTES_PER_SCRATCHCODE     4           // 32bit of randomness is enough
#define BITS_PER_BASE32_CHAR      5           // Base32 expands space by 8/5


/****************************
 * Change this to your key  *
 ****************************/
#define KEY  ""


int main (int argc, char *argv[]) {
    int step_size = 30;
    unsigned long tm = time(NULL) / (step_size ? step_size : 30);
    uint8_t challenge[8];
    for (int i = 8; i--; tm >>= 8) {
        challenge[i] = tm;
    }

    int secretLen = (strlen(KEY) + 7)/8*BITS_PER_BASE32_CHAR;
    
    uint8_t secret[100];
    if ((secretLen = base32_decode((const uint8_t *)key, secret, secretLen)) < 1) {
        return -1;
    }

    uint8_t hash[SHA1_DIGEST_LENGTH];
    hmac_sha1(secret, secretLen, challenge, 8, hash, SHA1_DIGEST_LENGTH);
    const int offset = hash[SHA1_DIGEST_LENGTH - 1] & 0xF;

    // Compute the truncated hash in a byte-order independent loop.
    unsigned int truncatedHash = 0;
    for (int i = 0; i < 4; ++i) {
        truncatedHash <<= 8;
        truncatedHash  |= hash[offset + i];
    }

    // Truncate to a smaller number of digits.
    truncatedHash &= 0x7FFFFFFF;
    truncatedHash %= VERIFICATION_CODE_MODULUS;
    printf("code: %d\n", truncatedHash);

    return 1;
}

/*******************************************************************************
 * file:        ssh_totp.c
 * author:      Ruoyu Song & Hongxu Meng
 * description: PAM module to provide 2nd factor authentication
*******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <unistd.h>
#include "hmac.c"
#include "sha1.c"
#include "util.c"
#include "base32.c"
#define VERIFICATION_CODE_MODULUS (1000*1000) // Six digits
#define SCRATCHCODES              5           // Default number of initial scratchcodes
#define MAX_SCRATCHCODES          10          // Max number of initial scratchcodes
#define SCRATCHCODE_LENGTH        8           // Eight digits per scratchcode
#define BYTES_PER_SCRATCHCODE     4           // 32bit of randomness is enough
#define BITS_PER_BASE32_CHAR      5           // Base32 expands space by 8/5
#define PATH_PRE                  "/etc/ssh/" // Where keys are stored
#define KEY_LENGTH                128         // Key length is 128 byte


/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS ;
}


/* this function is ripped from pam_unix/support.c, it lets us do IO via PAM */
int converse( pam_handle_t *pamh, int nargs, struct pam_message **message, struct pam_response **response ) {
	int retval ;
	struct pam_conv *conv ;

	retval = pam_get_item( pamh, PAM_CONV, (const void **) &conv ) ;
	if( retval==PAM_SUCCESS ) {
		retval = conv->conv( nargs, (const struct pam_message **) message, response, conv->appdata_ptr ) ;
	}

	return retval ;
}


/* expected hook, this is where custom stuff happens */
PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags,int argc, const char **argv ) {
	int retval ;
	int i ;

	/* these guys will be used by converse() */
	char *input ;
	struct pam_message msg[1],*pmsg[1];
	struct pam_response *resp;


	/* getting the username that was used in the previous authentication */
	const char *username ;
		if( (retval = pam_get_user(pamh,&username,"login: "))!=PAM_SUCCESS ) {
		return retval ;
	}

	/* Create file path */
	char path[128];
	memset(path, '\0', 128);
	memcpy(path, PATH_PRE, strlen(PATH_PRE));
	memcpy(&(path[strlen(PATH_PRE)]), username, strlen(username));
	path[strlen(PATH_PRE) + strlen(username)] = '\0';

	char *userKey;
	char key[KEY_LENGTH + 1];
	if (access(path, F_OK) != 0) {  // There is no key file, bypass
		perror("NO key file already exist\n");
		return PAM_SUCCESS;
	} else {  // There is a key file, do OTP
		FILE * file;
		file = fopen(path, "r");

		if (file == NULL) {
			perror("Error open file!\n");
			exit(99);
		} else {
			// Open key file and read
			file = fopen(path, "r");
			fgets(key, KEY_LENGTH + 1, file);
			fclose(file);
		}
	}


	int step_size = 30;
	unsigned long tm = time(NULL)/(step_size ? step_size : 30);
	uint8_t challenge[8];
	for (int i = 8; i--; tm >>= 8) {
		challenge[i] = tm;
	}

	int secretLen = (KEY_LENGTH + 7)/8*BITS_PER_BASE32_CHAR;

	uint8_t secret[100];
	if ((secretLen = base32_decode((const uint8_t *)key, secret, secretLen))<1) {
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
	char code[6];
	sprintf(code,"%d", truncatedHash);


	/* setting up conversation call prompting for one-time code */
	pmsg[0] = &msg[0] ;
	msg[0].msg_style = PAM_PROMPT_ECHO_ON ;
	msg[0].msg = "1-time code: " ;
	resp = NULL ;
	if( (retval = converse(pamh, 1 , pmsg, &resp))!=PAM_SUCCESS ) {
		// if this function fails, make sure that ChallengeResponseAuthentication in sshd_config is set to yes
		return retval ;
	}

	/* retrieving user input */
	if( resp ) {
		if( (flags & PAM_DISALLOW_NULL_AUTHTOK) && resp[0].resp == NULL ) {
			free( resp );
			return PAM_AUTH_ERR;
		}
		input = resp[ 0 ].resp;
		resp[ 0 ].resp = NULL;
	} else {
		return PAM_CONV_ERR;
	}

	/* comparing user input with known code */
	if( strcmp(input, code)==0 ) {
		/* good to go! */
		free( input ) ;
		return PAM_SUCCESS ;
	} else {
		/* wrong code */
		free( input ) ;
		return PAM_AUTH_ERR ;
	}

	/* we shouldn't read this point, but if we do, we might as well return something bad */
	return PAM_AUTH_ERR ;
}

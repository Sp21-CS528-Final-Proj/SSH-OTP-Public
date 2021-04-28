# SSH-OTP

This is a final course project for CS528 Network Security. The purpose of this project is adding another authentication layer in ssh process. This code is tested on a Linux raspberrypi 4.19.66-v7+ with Raspbian GNU/Linux 9.11 (stretch) armv7l OS. 


## Build & install (Server Side)
1. First update your library.
    ``` bash
    sudo apt-get update
    sudo apt-get install build-essential libpam0g-dev libcurl4-openssl-dev
    ```

2. Compile and add into PAM security library.
    ``` bash
    gcc -fPIC -lcurl -c src/ssh_totp.c
    sudo ld -lcurl -x --shared -o /lib/arm-linux-gnueabihf/security/ssh_totp.so ssh_totp.o
    ```
    
3. Compile and add a personal key to /etc/ssh.
    ``` bash
    gcc -o key_gen key_gen.c -lssl -lcrypto
    sudo ./key_gen [username]
    ```

4. Copy the key from the output.



## One time Password Generation Using a Client
1. Make sure openssl library is installed.
2. In test_totp.c, paste the key to the defined constant KEY. 
3. Compiled the TOTP generation code.
    ``` bash
    gcc -o TOTP test_totp.c -lssl -lcrypto
    ```
4. Get the one time password for login.
    ``` bash
    ./TOTP [username]
    ```


## One time Password Generation Using Google Authenticator or Similar APPs
1. Choose add a new account with "Enter a step key".
2. Type the username and the key copied.
3. Google Authenticator will automatically generate a one time password and refreshes over time.
    


## Apply the module (Server Side)
1. Add the following line in /etc/pam.d/sshd file. 
    ``` bash
    auth    required    ssh_totp.so
    ```

2. In file edit /etc/ssh/sshd_config, Enable _ChallengeResponseAuthentication_ to _yes_.

3. Restart SSH service
    ``` bash
    /etc/init.d/ssh restart
    ```

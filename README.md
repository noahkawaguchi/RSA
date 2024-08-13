# RSA Public Key Encryption Project


This is a simple command line program that guides the user through the basic steps of RSA public key encryption via a main menu type interface. (This is for informational purposes only, and cannot actually be used to protect sensitive information.)


### Main Calculations
- Generate primes (for ASCII only or for full Unicode)
- Generate keys (public and private keys)
- Encode messages
- Decode messages
- Break Codes


### Other Features
- Use values generated in previous steps without having to type them in again (optional)
- Move from one step to the next or quit the program entirely without returning to the main menu every time in between (optional)


### Known Issue

Input validation is robust within reasonable use of the program to actually perform RSA calculations. However, if the user chooses an intermediate step of the program and enters random numbers that are valid data types, but have nothing to do with RSA, the program may make faulty calculations or simply crash.


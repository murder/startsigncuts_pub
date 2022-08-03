How to use PKCS#11 interface using the sample
=============================================

The sample contains p11refimpl.c, cryptoki_linux.h (other header files are also needed, see "Build the sample" section)
and this readme.txt.
The sample shows how to use PKCS#11 interfaces in ANSI-C and is implemented for the Linux and Windows environment.

The sample shows how to

  - initialize the PKCS#11 library
  - get the first reader attached to the system
  - open a session to execute
    - enumerate all certificates found on the token
    - login 
    - do a small sign operation with 2048 RSA key
    - logout
  - and close the session and unload the library


Build the sample
----------------

To build the sample for the windows and linux environment, follow the steps below

  1. Download the PKCS#11 interface definition from https://www.cryptsoft.com/pkcs11doc/STANDARD/include/v220/
     The files needed are pkcs11.h, pkcs11t.h, pkcs11f.h and cryptoki.h. 
     
  2. Copy those files to a folder where the p11refimpl.c is located.
  
  3. For windows environment, use Visual Studio 2015 (as it is currently tested with this compiler) 
      1. Create an empty solution and drag and drop the p11refimpl.c to the project tree.
      2. Add also all 4 header files (downloaded from cryptsoft) to the project tree.
      3. Build the binary.
      
  4. For linux environment, the cryptoki_linux.h is used. This is adapted from the downloaded version of cryptoki.h from CryptSoft. 
     Make sure that this file is also located next to the p11refimpl.c. Build the binary with the command
     
      > gcc p11refimpl.c -ldl -o p11refimpl
      

Testing the binary on Windows and linux
---------------------------------------  
1. Make sure PKCS#11 library, libaetpkss3.so for Linux is located in /usr/lib/ and for Windows aetpkss1.dll 
   is located in the Windows/System32 folder.
   This is automaticaly set right when tokenadmin or tokencontrol has been properly installed.
     
2. For Linux run, 
          
     > ./p11refimpl [pincode]
           
   for Windows,
        
     > p11refimpl [pincode]
       
   The sample will show a howto when executed without a parameter.



# PRINCESS
PRINCESS Cipher - Metamorphic encryption based on AES as a starting point

# Compile
gcc princess.c -o p

# Create keyfile (key.dat)
./p -k

# Encrypt test.dat to encrypted.dat
./p -e

# Decrypt encrypted.dat to decrypted.dat
./p -d

To get started generate a keyfile from command above then copy any file you want as test.dat which is the input file for encryption.

A video explaining most of it https://www.facebook.com/EstellaMystagic/videos/10155886606797832/ May have to skip to the point I start talking to get a better idea. 

Used block cipher mode IGE as starting point for the custom mode called MYST, this cipher uses some functions from other open source ciphers such as "blowfish, siphash" and uses SHA3 kecceh for the key expansion.

This cipher uses a number of concepts such as byte level metamorphic functions ROL,ROR,XOR,INV,NOP and 32bit level metamorphs, dynamic rounding on functions, dynamic sbox generation, dynamic cube sbox generation, dynamicly shuffled constant tables, to achieve a very great level of non linearity to harden against cryptanalysis. 

With great respect and thanks to "Magdy Saeb" http://www.magdysaeb.net/ who has been a great mentor in this field of metamorphic encryption for years. 

Wish to challenge yourself in cryptanalysis?, I have included a contest file a mere 196 charactors of english text. Encrypted with PRINCESS, be forever renowned by decrypting this encrypted.dat in the contest directory. 

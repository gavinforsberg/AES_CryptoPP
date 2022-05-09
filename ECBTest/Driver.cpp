// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

/* ------------------------------- ECB TEST DRIVER ------------------------------- */

#include "../osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <cstdlib>
using std::exit;

#include "../cryptlib.h"
using CryptoPP::Exception;

#include "../hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "../filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::StreamTransformationFilter;

#include "../aes.h"
using CryptoPP::AES;

#include "../modes.h"
using CryptoPP::ECB_Mode;

using CryptoPP::byte;

#include <random>

//#include <bits/stdc++.h>
#include <stdlib.h>

#include <bitset>
#include <string>
#include <iostream>
#include <climits>

int hammingDistance(int n1, int n2);

int main(int argc, char* argv[])
{
	AutoSeededRandomPool prng;

	byte key[AES::DEFAULT_KEYLENGTH];
	prng.GenerateBlock(key, sizeof(key));

	string plain = "I would rather try a shot to win than play safe and finish second-Phil Mickelson";
	string cipher, encoded, recovered;

    /* ---------------------- */
    
    // Pretty print key
    encoded.clear();
    // String Source                      // Hex Encoder        // String Sink
    StringSource(key, sizeof(key), true, new HexEncoder( new StringSink(encoded)) );
    cout << "key: " << encoded << endl;
   
    /* ---------------------- */

	try
	{
        cout << "\nOriginal plaintext: " << plain << endl;

		ECB_Mode< AES >::Encryption e;
		e.SetKey(key, sizeof(key));

		// The StreamTransformationFilter adds padding as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.   // StreamTransformationFilter   // StringSource
		StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher) ) );
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

    cout << "\nEncryption complete.\n";

    /* ---------------------- */

	// Pretty print
	encoded.clear();
	StringSource(cipher, true, new HexEncoder( new StringSink(encoded) ) );
    cout << "\nCorrect Cipher Text: " << encoded << endl << endl;
    
    string copied_cipher = encoded;
    /* ---------------------- */

	try
	{
		ECB_Mode< AES >::Decryption d;
		d.SetKey(key, sizeof(key));

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource s(cipher, true, 
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

//		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    string originalRecovery = recovered;

    /* --------------------------------------------------------------- */

    // Random number between 20 and 60 (modern generator from:
    // https://stackoverflow.com/questions/7560114/random_number_c_in_some_range)
    std::random_device mt;
    std::mt19937 gen(mt());
    std::uniform_int_distribution<> distr(20, 60);
    int randomIndex = distr(gen);
        
    // Result of the bit being flipped at the random index
    char result = copied_cipher[randomIndex] ^ 1;
   
    // This is actually flipping the bit within the copied cipher string
    copied_cipher[randomIndex] = copied_cipher[randomIndex] ^ 1;
    
    /* ---------------------- Decryption used from above ---------------------- */
    recovered = "";
    // The ciphertext with the changed bit
    cout << "Garbled Cipher Text: " << copied_cipher << endl;

    try
    {
        new HexEncoder( new StringSink(copied_cipher));
        ECB_Mode< AES >::Decryption d;
        d.SetKey(key, sizeof(key));

        // The StreamTransformationFilter removes padding as required.
        StringSource s(copied_cipher, true,
            new CryptoPP::HexDecoder(
                new StreamTransformationFilter(d,
                    new StringSink(recovered)
                )
            ) // StreamTransformationFilter
        ); // StringSource

        cout << "\nRecovered Text: " << originalRecovery << endl;
        cout << "\nRecovered Text: " << recovered << endl;
    }
    catch(const CryptoPP::Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
    
    // Displaying the bit that was flipped (the resulting flipped bit)
    cout << "\nBit Flipped: " << result << endl;


    /* --------------------------------------------------------------- */
    
    // Calculating Hamming Distance (adapted from
    // https://www.codespeedy.com/how-to-calculate-hamming-distance-using-cpp/)
    int count = 0; int one; int two;
    for(int i = 0; i < encoded.length(); i++)
    {
        if(originalRecovery[i] != recovered[i])
        {
            one = (int) originalRecovery[i];
            two = (int) recovered[i];
            count++;
        }
    }

    cout << "\nHamming Distance: " << count << endl;
    
    cout << "Hamming Distance (BITS): " << hammingDistance(one, two) << "\n\n\n";
    
    return 0;
}

// Adopted from Dr. Williams
int hammingDistance(int n1, int n2)
{
    int x = n1 ^ n2;
    int setBits = 0;
    
    while (x >0)
    {
        setBits += x & 1;
        x >>= 1;
    }
    return setBits;
}

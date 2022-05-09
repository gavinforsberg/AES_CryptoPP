// g++ -g3 -ggdb -O0 -DDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -I/usr/include/cryptopp Driver.cpp -o Driver.exe -lcryptopp -lpthread

/* ------------------------------- CBC TEST DRIVER ------------------------------- */

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

#include "../ccm.h"
using CryptoPP::CBC_Mode;

#include "assert.h"

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

	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

    string plain = "I would rather try a shot to win than play safe and finish second-Phil Mickelson";
    string cipher, encoded, recovered;

    /* ---------------------- */
	
    // Pretty print key
	encoded.clear();
    // String Source                      // Hex Encoder        // String Sink
	StringSource(key, sizeof(key), true, new HexEncoder( new StringSink(encoded)) );
	cout << "key: " << encoded << endl;

	// Pretty print iv
	encoded.clear();
	StringSource(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "iv: " << encoded << endl;

    /* ---------------------- */

	try
	{
		cout << "\nOriginal plaintext: " << plain << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes padding as required.
		StringSource s(plain, true, 
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter
		); // StringSource

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif
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
    // String Source                      // Hex Encoder        // String Sink
	StringSource(cipher, true, new HexEncoder( new StringSink(encoded) ) );
    
    cout << "\nCorrect Cipher Text: " << encoded << endl << endl;
    
    string copied_cipher = encoded;
    /* ---------------------- */

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, sizeof(key), iv);

		// The StreamTransformationFilter removes padding as required.
        // String Source              // StreamTransformationFilter           // StringSource
		StringSource s(cipher, true, new StreamTransformationFilter(d, new StringSink(recovered) ) );

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

//		cout << "recovered text: " << recovered << endl;
	}
	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
    
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
    string originalRecovery = recovered;
    recovered = "";
    // The ciphertext with the changed bit
    cout << "Garbled Cipher Text: " << copied_cipher << endl;
    
    try
    {
        new HexEncoder( new StringSink(copied_cipher));
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, sizeof(key), iv);

        // The StreamTransformationFilter removes padding as required.
        StringSource s(copied_cipher, true,
            new CryptoPP::HexDecoder(
                new StreamTransformationFilter(d,
                    new StringSink(recovered)
                ) // Hex Decoder
            ) // StreamTransformationFilter
        ); // StringSource

#if 0
        StreamTransformationFilter filter(d);
        filter.Put((const byte*)copied_cipher.data(), copied_cipher.size());
        filter.MessageEnd();

        const size_t ret = filter.MaxRetrievable();
        recovered.resize(ret);
        filter.Get((byte*)recovered.data(), recovered.size());
#endif
        
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
    
    // Calculating Character based Hamming Distance (adapted from
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

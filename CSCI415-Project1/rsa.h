#pragma once
// The program uses the external library mini-gmp: https://github.com/vfonov/cork/blob/master/contrib/gmp-6.1.2/mini-gmp/mini-gmpxx.h

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <time.h>
#include "mini-gmpxx.h"


using namespace std;

// Typedef for mpz_class
typedef mpz_class BigInteger;

// Definitions and global variables
#define BASE_LETTER 128
#define BASE_LETTER_MIN 0
#define MRLOOP 2
unsigned short g_BlockSize = 16;
unsigned int g_DigitSize = 100;
bool g_Print = true;

// Calculate base^exp using mini-gmp
BigInteger Pow(const BigInteger& base, const unsigned long exp);

// Calculate (base^exp) % mod using mini-gmp
BigInteger ModPow(const BigInteger& base, const BigInteger& exp, const BigInteger& mod);

// Calculate num * x % mod using mini-gmp
BigInteger ModInverse(const BigInteger& num, const BigInteger& mod);

// Generate n-digit prime
BigInteger GeneratePrime(int g_DigitSize);

// Encode a string into an integer
BigInteger EncodeText(const string& block);

// Decode an integer into a string
string Decode(const BigInteger& blockCode);

// Convert the passed number into its binary representation
string ToBinary(const BigInteger& num);

// Set string to have minimum character values, used for replacing ascii control characters with space
string SetMinString(string str, const char min);

// Pad leading number with zeroes for fixed-size block
string PadBlock(const BigInteger& number, const int length);

// Shorten the string, used to print large numbers without ruining the format, Ex. 123456789 -> 123...789
string Shorten(string str, int length = 16);

// Encrypt and output to the specified files, takes in the public key and modulus
int EncryptFile(const string& fileName, const string& outputFileName, const BigInteger& publicKey, const BigInteger& modulus);

// Decrypt and output to the specified files, takes in the private key and modulus
int DecryptFile(const string& fileName, const string& outputFileName, const BigInteger& privateKey, const BigInteger& modulus);

// Miller-Rabin primality test for if number is prime
bool IsPrime(BigInteger& n);

// Remove leading zeroes
void RemoveLeadingZeroes(string& str);

// Get elapsed time
double GetElapsedTime(clock_t timeStart, clock_t timeEnd);

#include "rsa.h"

int main(int argc, char* argv[])
{
    // Set random seed
    srand(time(0));

    // Initialize variables for time recording
    clock_t timeStart, timeEnd;
    double initializationTime, encryptTime, decryptTime;

    // If there are parameters...
    if (argc > 1)
    {
        for (int i = 0; i < argc; i++)
        {
            string str = argv[i];

            // If "noprint" is specified, disable printing
            if (str == "noprint")
                g_Print = false;

            // Split strings
            size_t splitLocation;
            if ((splitLocation = str.find("=")) == string::npos)
                continue;
            
            string value = str.substr(splitLocation+1);
            string command = str.substr(0, splitLocation);

            // Set parameter for each command
            if (command == "digit")
                g_DigitSize = stoi(value);
            else if (command == "read")
                g_BlockSize = stoi(value);
        }
    }

    // Generate primes and find privateKey
    timeStart = clock();
    BigInteger p = GeneratePrime(g_DigitSize);
    BigInteger q = GeneratePrime(g_DigitSize);
    BigInteger n(p * q);
    BigInteger phi((p - 1) * (q - 1));
    BigInteger e = GeneratePrime(g_DigitSize);
    BigInteger d = ModInverse(e, phi);
    timeEnd = clock();
    initializationTime = GetElapsedTime(timeStart, timeEnd);

    // Read from "Message.txt" and encrypt to "encryptedMessage.txt"
    timeStart = clock();
    int eTotalChar = EncryptFile("Message.txt", "encryptedMessage.txt", e, n);
    timeEnd = clock();
    encryptTime = GetElapsedTime(timeStart, timeEnd);

    // Decrypt from "encryptedMessage.txt" and decrypt to "decryptedMessage.txt"
    timeStart = clock();
    int dTotalChar = DecryptFile("encryptedMessage.txt", "decryptedMessage.txt", d, n);
    timeEnd = clock();
    decryptTime = GetElapsedTime(timeStart, timeEnd);

    // Print time for each sections
    cout    << "[Encrypt Read Block Size: " << g_BlockSize << "] # Chars Encrypted:" << eTotalChar << ", Decrypted:" << dTotalChar << endl
            << setw(21) << "Initialization time: " << initializationTime << "s" << endl
            << setw(21) << "Encrypt time: " << encryptTime << "s" << endl
            << setw(21) << "Decrypt time: " << decryptTime << "s" << endl;


    return 0;
}

double GetElapsedTime(clock_t timeStart, clock_t timeEnd)
{
    return ((double)timeEnd - timeStart) / CLOCKS_PER_SEC;
}

BigInteger Pow(const BigInteger& base, const unsigned long exp)
{
    mpz_class result;
    mpz_pow_ui(result.get_mpz_t(), base.get_mpz_t(), exp);
    return BigInteger(result);
}

BigInteger ModPow(const BigInteger& base, const BigInteger& exp, const BigInteger& mod)
{
    mpz_class result;
    mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
    return BigInteger(result);
}

BigInteger ModInverse(const BigInteger& num, const BigInteger& mod)
{
    mpz_class result;
    mpz_invert(result.get_mpz_t(), num.get_mpz_t(), mod.get_mpz_t());
    return BigInteger(result);
}

BigInteger GeneratePrime(int g_DigitSize)
{
    string G1;
    BigInteger P;

    // Generate random number
    for (int i = 0; i < g_DigitSize; i++)
    {
        if (i != 0)
            G1 += char(rand() % 10 + '0');
        else
            G1 += char(rand() % 1 + '1');
    }

    P = BigInteger(G1);

    // Running generated number through Miller-Rabin primality test
    while (true)
    {
        P = P - 1;
        if (IsPrime(P))
            break;
    }

    return P;
}

BigInteger EncodeText(const string& block)
{
    BigInteger result;

    for (int i = 0; i < g_BlockSize; i++)
    {
        // Get base
        BigInteger asciiCode(block[i] - BASE_LETTER_MIN);

        BigInteger baseMult = Pow(BASE_LETTER, g_BlockSize - i - 1);

        result += asciiCode * baseMult;
    }

    return result;
}

string Decode(const BigInteger& blockCode)
{
    string str;

    for (int i = 0; i < g_BlockSize; i++)
    {
        BigInteger baseMult = Pow(BASE_LETTER, g_BlockSize - i - 1);
        BigInteger asciiCode = ((blockCode / baseMult) % BASE_LETTER) + BASE_LETTER_MIN;

        // Convert BigInteger to signed long
        long l = asciiCode.get_si();

        // Ignore null terminator
        if (l == 0)
            continue;

        str += l;
    }

    return str;
}

string ToBinary(const BigInteger& num)
{
    // Convert number to base 2 and return string
    return num.get_str(2);
}

string SetMinString(string str, const char min)
{
    // For each character < min, set character = min
    for (auto& e : str)
        if (e < min)
            e = min;

    return str;
}

string PadBlock(const BigInteger& number, const int length)
{
    string result = number.get_str();

    // Pad any available header
    result = string(length - result.size(), '0') + result;

    return result;
}

string Shorten(string str, int length)
{
    if (length <= 3)
        return "...";

    int endLength = length / 2;

    // Combine first "endLength" strings with last "endLength" strings
    string result = str.substr(0, endLength) + "..." + str.substr(str.size() - endLength, endLength);

    return result;
}

int EncryptFile(const string& fileName, const string& outputFileName, const BigInteger& publicKey, const BigInteger& modulus)
{
    fstream file(fileName);
    ofstream outputFile(outputFileName);

    if (!file.is_open() || !outputFile.is_open())
    {
        cout << "Can not open files!" << endl;
        return false;
    }

    // Intialize stringstream and move file buffer
    stringstream ss;
    ss << file.rdbuf();
    string text(ss.str());

    // Pad message with '0' if not equal in blocks
    int padding = text.size() % g_BlockSize;
    if (padding != 0)
    {
        string pad = string(g_BlockSize - padding, 0);
        text = text + pad;
    }

    // Max output block size
    int outBlockSize = modulus.get_str().size();

    if (g_Print)
    {
        cout << "[Message to encrypt] " << endl
            << text << endl
            << "[End of message]" << endl << endl;

        cout << "[Encrypt Block Size: " << g_BlockSize << " | Output Block size: " << outBlockSize << "]" << endl;
    }

    // Iterate the text in g_BlockSize, the bigger g_BlockSize the faster
    int characterRead = 0;
    for (int i = 0, blockCounter = 0; i < text.size(); i += g_BlockSize, blockCounter++)
    {
        // Get g_BlockSize of text
        string plaintext = text.substr(i, g_BlockSize);

        // Encode number to integer
        BigInteger number = EncodeText(plaintext);

        // Encrypt integer
        BigInteger cipherCode = ModPow(number, publicKey, modulus);

        // Pad available spaces
        string paddedCipherCode = PadBlock(cipherCode, outBlockSize);

        // Write padded ciphercode to output file
        outputFile << paddedCipherCode;

        characterRead += g_BlockSize;

        if (g_Print)
            cout << "Encrypt Block #" << setw(4) << blockCounter << ": " << SetMinString(plaintext, 32) << " -> " << Shorten(paddedCipherCode, 32) << endl;
    }

    outputFile.close();
    file.close();
    return characterRead;
}

int DecryptFile(const string& fileName, const string& outputFileName, const BigInteger& privateKey, const BigInteger& modulus)
{
    fstream file(fileName);
    ofstream outputFile(outputFileName);

    if (!file.is_open() || !outputFile.is_open())
    {
        cout << "Can not open files!" << endl;
        return false;
    }

    string text;
    file >> text;

    // Read block size, same as outPutBlockSize from encryption function
    int readBlockSize = modulus.get_str().size();

    if (g_Print)
        cout << "[Decrypted Message] " << endl;

    // Iterate the text in readBlockSize
    int characterRead = 0;
    for (int i = 0; i < text.size(); i += readBlockSize)
    {
        // Get readBlockSize of text
        string strNumber = text.substr(i, readBlockSize);

        // Remove leading zeroes
        RemoveLeadingZeroes(strNumber);

        // Declare cipherCode from string number
        BigInteger cipherCode(strNumber);

        // Decrypt cipherCode
        BigInteger decryptedCode = ModPow(cipherCode, privateKey, modulus);

        // Decode integer
        string plaintext = Decode(decryptedCode);

        // Write plaintext to output file
        outputFile << plaintext;

        characterRead += readBlockSize;

        if (g_Print)
            cout << plaintext;
    }

    if (g_Print)
        cout << endl << "[End of message]" << endl;

    outputFile.close();
    file.close();
    return characterRead;
}

bool IsPrime(BigInteger& n) 
{
    string t;

    // Quick check if randomly generated number is divisible by 2, 3, or 5.
    if (n % 2 == 0)
        return false;
    if (n % 3 == 0)
        return false;
    if (n % 5 == 0)
        return false;

    // Creating BigInteger variables for Miller Rabin testing
    BigInteger d(n - 1);
    BigInteger dT(d % 2);

    while (dT != 0)
    {
        d = d / 2;
        BigInteger dT(d % 2);
    }

    // Generation of random variable for Miller Rabin testing
    for (int i = 0; i < MRLOOP; i++)
    {
        t = "";
        for (int i = 0; i < 100; i++)
        {
            if (i != 0)
                t += char(rand() % 10 + '0');
            else
                t += char(rand() % 9 + '1');
        }

        // Creation of Random Variable, Modded Variable a, and ModPow result for Miller Rabin.
        BigInteger T(t);
        BigInteger a(T % (n - 1) + 1);
        BigInteger x(ModPow(a, d, n));

        // Start of Miller Rabin loop
        if (x == 1 || x == (n - 1))
            continue;

        bool prime = false;
        for (BigInteger r = 1; r < d; r = r * 2)
        {
            x = (x * x) % n;
            if (x == n - 1)
            {
                prime = true;
                break;
            }
        }

        if (!prime)
            return false;
    }

    return true;
}

void RemoveLeadingZeroes(string& str)
{
    str.erase(0, std::min(str.find_first_not_of('0'), str.size() - 1));
}
#include <iostream>
#include <fstream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <string>
#include <vector>
#include <Windows.h>
#include <iomanip>
#include <sstream>

using namespace std;

int gcd(int a, int h) {
    while (true) {
        int temp = a % h;
        if (temp == 0)
            return h;
        a = h;
        h = temp;
    }
}

int modInverse(int e, int phi) {
    int m0 = phi, t, q;
    int x0 = 0, x1 = 1;

    if (phi == 1)
        return 0;

    while (e > 1) {
        q = e / phi;

        t = phi;
        phi = e % phi;
        e = t;

        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

bool isPrime(int n) {
    if (n < 2)
        return false;
    for (int i = 2; i <= sqrt(n); i++) {
        if (n % i == 0)
            return false;
    }
    return true;
}

long long power(long long base, long long exp, long long mod) {
    long long result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

void generateKeys(int& n, int& e, int& d) {
    int p, q;
    srand(time(0));

    do {
        p = rand() % 100 + 50;
    } while (!isPrime(p));

    do {
        q = rand() % 100 + 50;
    } while (!isPrime(q));

    n = p * q;
    int phi = (p - 1) * (q - 1);
    do {
        e = rand() % (phi - 1) + 1; 
    } while (gcd(e, phi) != 1);
    d = modInverse(e, phi);
}

void encrypt(const string& inputFile, const string& outputFile, int e, int n) {
    ifstream fin(inputFile, ios::binary);  
    ofstream fout(outputFile);

    if (!fin.is_open() || !fout.is_open()) {
        cout << "Помилка відкриття файлу!" << endl;
        return;
    }

    char ch;
    while (fin.get(ch)) {
        long long encrypted = power(static_cast<long long>(static_cast<unsigned char>(ch)), e, n);
        fout << encrypted << " "; 
    }

    fin.close();
    fout.close();
    cout << "Файл успішно зашифровано!" << endl;
}

void decrypt(const string& inputFile, const string& outputFile, int d, int n) {
    ifstream fin(inputFile);
    ofstream fout(outputFile, ios::binary);  

    if (!fin.is_open() || !fout.is_open()) {
        cout << "Помилка відкриття файлу!" << endl;
        return;
    }

    long long encrypted;
    while (fin >> encrypted) { 
        char decrypted = static_cast<char>(power(encrypted, d, n) % 256); 
        fout.put(decrypted);  
    }

    fin.close();
    fout.close();
    cout << "Файл успішно дешифровано!" << endl;
}


long long signMessage(int hM, int d, int n) {
    return power(hM, d, n);
}

bool verifySignature(long long S, int e, int n, int hM) {
    long long hM_prime = power(S, e, n);
    return hM_prime == hM;
}

class SHA1
{
public:
    SHA1() { reset(); }

    void update(const std::string& input) {
        for (char c : input)
            updateByte(static_cast<uint8_t>(c));
    }

    std::string final() {
        uint64_t totalBits = count * 8;
        updateByte(0x80);
        while (count % 64 != 56)
            updateByte(0x00);

        for (int i = 7; i >= 0; --i)
            updateByte((totalBits >> (i * 8)) & 0xFF);

        processBlock(); 

        std::stringstream ss;
        for (uint32_t word : buffer)
            ss << std::hex << std::setw(8) << std::setfill('0') << word;

        reset();
        return ss.str();
    }

private:
    static const size_t BLOCK_SIZE = 64;
    std::vector<uint32_t> buffer{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
    std::vector<uint8_t> dataBuffer;
    uint64_t count = 0;

    void reset() {
        buffer = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };
        dataBuffer.clear();
        count = 0;
    }

    void updateByte(uint8_t byte) {
        dataBuffer.push_back(byte);
        count++;
        if (dataBuffer.size() == BLOCK_SIZE)
            processBlock();
    }

    void processBlock() {
        if (dataBuffer.size() < BLOCK_SIZE)
            return;

        std::vector<uint32_t> w(80);
        for (int i = 0; i < 16; ++i)
            w[i] = (dataBuffer[i * 4] << 24) | (dataBuffer[i * 4 + 1] << 16) |
            (dataBuffer[i * 4 + 2] << 8) | dataBuffer[i * 4 + 3];

        for (int i = 16; i < 80; ++i)
            w[i] = rotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        uint32_t a = buffer[0], b = buffer[1], c = buffer[2], d = buffer[3], e = buffer[4];

        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            }
            else if (i < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            }
            else if (i < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            }
            else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }

            uint32_t temp = rotateLeft(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rotateLeft(b, 30);
            b = a;
            a = temp;
        }

        buffer[0] += a;
        buffer[1] += b;
        buffer[2] += c;
        buffer[3] += d;
        buffer[4] += e;

        dataBuffer.clear();
    }

    uint32_t rotateLeft(uint32_t x, uint32_t n) {
        return (x << n) | (x >> (32 - n));
    }
};
int main() {
    int n, e, d;
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);
    cout << "Генерація ключів..." << endl;
    generateKeys(n, e, d);
    cout << "Відкритий ключ (e, n): (" << e << ", " << n << ")" << endl;
    cout << "Закритий ключ (d, n): (" << d << ", " << n << ")" << endl;

    while (true) {
        cout << "\nВиберіть дію:" << endl;
        cout << "1. Шифрування файлу" << endl;
        cout << "2. Дешифрування файлу" << endl;
        cout << "3. Створення та перевірка цифрового підпису" << endl;
        cout << "4. Хешування за допомогою SHA-1" << endl; 
        cout << "5. Вихід" << endl;
        int choice;
        cin >> choice;
        cin.ignore();

        if (choice == 1) {
            string inputFile, outputFile;
            cout << "Введіть назву файлу для шифрування: ";
            cin >> inputFile;
            cout << "Введіть назву файлу для збереження шифрованих даних: ";
            cin >> outputFile;
            encrypt(inputFile, outputFile, e, n);
        }
        else if (choice == 2) {
            string inputFile, outputFile;
            cout << "Введіть назву шифрованого файлу: ";
            cin >> inputFile;
            cout << "Введіть назву файлу для збереження дешифрованих даних: ";
            cin >> outputFile;
            decrypt(inputFile, outputFile, d, n);
        }
        else if (choice == 3) {
            int hM;
            cout << "Введіть хеш повідомлення (h(M)): ";
            cin >> hM;

            long long S = signMessage(hM, d, n);
            cout << "Цифровий підпис: " << S << endl;

            if (verifySignature(S, e, n, hM)) {
                cout << "Підпис валідний!" << endl;
            }
            else {
                cout << "Підпис невалідний!" << endl;
            }
        }
        else if (choice == 4) {
            SHA1 sha1;
            string input;

            cout << "Введіть рядок для хешування: ";
            getline(cin, input);

            sha1.update(input);
            string hash = sha1.final();

            cout << "Хеш SHA-1: " << hash << endl;
        }
        else if (choice == 5) {
            break;
        }
        else {
            cout << "Невірний вибір. Спробуйте ще раз." << endl;
        }
    }
}

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <unordered_map>

/* Alphabetics for the cipher */

const std::string alphabet_27 = "ABCDEFGHIJKLMNÑOPQRSTUVWXYZ";
const std::string alphabet_191 = [] {
    std::string s;
    for (int i = 32; i < 223; i++) {
        s += char(i);
    }
    return s;
}();

/* Implementation */

std::unordered_map<char, int> build_index_map(const std::string& alphabet) {
    std::unordered_map<char, int> map_alphabet;
    for (int i = 0; i < (int)alphabet.size(); i++) {
        map_alphabet[alphabet[i]] = i;
    }
    return map_alphabet;
}

std::string vigenere_cipher(const std::string& text, const std::string& key, const std::string& alphabet) {
    std::unordered_map<char, int> index_map = build_index_map(alphabet);
    std::string cipher_text;
    int size_alphabet = alphabet.size();

    for (int i = 0; i < text.size(); i++) {
        char letter = text[i];
        if (index_map.find(letter) != index_map.end()) {
            char key_char = key[i % key.size()];
            int p = index_map[letter];
            int k = index_map[key_char];
            int c = (p + k) % size_alphabet;
            cipher_text += alphabet[c];
        }
    }

    return cipher_text;
}

std::string normalize_text(const std::string& text) {
    std::string result;
    for (char c : text) {
        unsigned char up = std::toupper((unsigned char)c);
        if (alphabet_27.find(up) != std::string::npos) {
            result += up;
        }
    }
    return result;
}

int main() {
    int option;
    std::string path = "../Files/";
    std::string file;
    std::string text_input;

    std::cout << "Cifrar a partir de un archivo (1) o entrada de texto (2): ";
    std::cin >> option;
    std::cin.ignore();

    if (option == 1) {
        std::cout << "Nombre del archivo (ejemplo: texto.txt): ";
        std::getline(std::cin, file);

        std::ifstream file_input(path + file);
        if (!file_input.is_open()) {
            std::cerr << "Error: no se pudo abrir el archivo.\n";
            return 1;
        }

        text_input.assign((std::istreambuf_iterator<char>(file_input)), std::istreambuf_iterator<char>());
        file_input.close();
    }
    else if (option == 2) {
        std::cout << "Ingrese el texto a cifrar: ";
        std::getline(std::cin, text_input);
    }
    else {
        std::cerr << "Opción inválida.\n";
        return 1;
    }

    std::string text_for_cipher = normalize_text(text_input);

    std::string key;
    std::cout << "Ingrese la clave: ";
    std::getline(std::cin, key);
    key = normalize_text(key);

    std::string cipher_text_27 = vigenere_cipher(text_for_cipher, key, alphabet_27);
    std::cout << "\n=== Resultado con alfabeto 27 ===\n" << cipher_text_27 << "\n";

    std::string cipher_text_191 = vigenere_cipher(text_for_cipher, key, alphabet_191);
    std::cout << "\n=== Resultado con alfabeto 191 ===\n" << cipher_text_191 << "\n";
}
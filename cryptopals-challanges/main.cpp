#include <string>
#include <sstream>
#include <map>
#include <iostream>
#include <fstream>    
#include <iomanip>
#include <vector>
using namespace std;

/* Helpers */
map<char, double> frequency_table{
								 {'A', 8.167},{'B', 1.492},{'C', 2.782},{'D', 4.253},{'E', 12.702},
								 {'F',2.228},{'G', 2.015},{'H', 6.094},{'I', 6.966},
								 {'J', 0.153},{'K',0.772},{'L',4.025},{'M',2.406},{'N',6.749},{'O',7.507},
								 {'P',1.929},{'Q',0.095},{'R',5.987},{'S',6.327},{'T',9.056},{'U',2.758},
								 {'V',0.978},{'W',2.360},{'X',0.150},{'Y',1.974},{'Z',0.074},{' ', 25.404}
};

string _hex_to_binary(char hex)
{
	switch (hex) {
	case '0':
		return "0000";
	case '1':
		return "0001";
	case '2':
		return "0010";
	case '3':
		return "0011";
	case '4':
		return "0100";
	case '5':
		return "0101";
	case '6':
		return "0110";
	case '7':
		return "0111";
	case '8':
		return "1000";
	case '9':
		return "1001";
	case 'a':
		return "1010";
	case 'b':
		return "1011";
	case 'c':
		return "1100";
	case 'd':
		return "1101";
	case 'e':
		return "1110";
	case 'f':
		return "1111";

	}
}

int _binary_to_decimal(string binary) {
	int decimal = 0.0;
	for (int i = binary.size() - 1; i >= 0; i--) {
		decimal += ((int)(binary[i] - '0')) * pow(2.0, (binary.size() - 1 - i));
	}
	return decimal;
}

string _decimal_to_hex(int decimal) {
	stringstream ss;
	ss << setfill('0') << setw(2) << hex << decimal;
	return ss.str();
}

char _decimal_to_base64(int index) {
	string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	return table[index];
}

int _base64_to_decimal(char c) {
	string table = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	return table.find(c);
}

double _caclulate_freq_score(string plaintext) {
	int size = plaintext.size();
	double score = 0;
	for (int i = 0; i < size; i++) {
		score += frequency_table[toupper(plaintext[i])];
	}
	return score;
}

string _ascii_to_binary(string str) {
	string result, temp_hex;
	for (int i = 0; i < str.size(); i++) {
		temp_hex = _decimal_to_hex((int)str[i]);
		result += _hex_to_binary(temp_hex[0]) + _hex_to_binary(temp_hex[1]);
	}
	return result;
}

int _hamming_distance(string str1, string str2)
{
	int  count = 0;
	for (int i = 0; i < str1.size(); i++) {
		if (str1[i] != str2[i])
			count++;
	}
	return count;
}

double _key_size_distance(string ciphertext, int size) {
	string prev = "", chunk;
	double  result = 0.0;
	int n = 0;
	int cipher_size = ciphertext.size();
	for (int i = 0; i < cipher_size; i += size) {
		if ((size_t)i + size >= cipher_size) {
			break;
		}
		chunk = ciphertext.substr(i, size);
		if (prev != "") {
			result += _hamming_distance(_ascii_to_binary(prev), _ascii_to_binary(chunk));
			n += 1;
		}
		prev = chunk;

	}
	return result;
}

int _find_key_size(string ciphertext) {
	int key_size = 2, key_distance, min_distance = _key_size_distance(ciphertext, 2);
	for (int i = 3; i <= 40; i++) {
		key_distance = _key_size_distance(ciphertext, i);
		if (min_distance > key_distance) {
			min_distance = key_distance;
			key_size = i;
		}
	}
	return key_size;
}

string _decimal_to_binary(int n) {
	int a[10], i;
	string binary;
	for (i = 0; n > 0; i++)
	{
		a[i] = n % 2;
		n = n / 2;
	}
	for (i = i - 1; i >= 0; i--)
	{
		binary += to_string(a[i]);
	}
	return binary;
}

string _base64_to_ascii(string base64_text) {
	//Switch to binary
	string str = "", ascii_text;
	for (int i = 0; i < base64_text.size(); i++) {
		stringstream ss;
		ss << setfill('0') << setw(6) << _decimal_to_binary(_base64_to_decimal(base64_text[i]));
		str += ss.str();
	}
	for (int i = 0; i < str.size(); i += 8) {
		if ((size_t)(i + 8) < str.size())
			ascii_text += (char)(_binary_to_decimal(str.substr(i, 8)));
	}
	return ascii_text;
}

string _hex_to_ascii(string hex) {
	string ascii_text;
	for (int i = 0; i < hex.size(); i += 2) {
		ascii_text += (char)strtol(hex.substr(i, 2).c_str(), NULL, 16);
	}
	return ascii_text;
}
/* ------- End Helpers ------ */


/* EX1 */
string hex_to_base64(string hexStr) {
	//Switch to binary
	string str = "";
	for (int i = 0; i < hexStr.size(); i++) {
		str.append(_hex_to_binary(hexStr[i]));
	}
	while (str.size() % 6 != 0)
		str.append("0");
	string base64 = "";
	//Take 6 bits and translate to ascii
	for (int i = 0; i < str.size(); i += 6) {
		base64 += _decimal_to_base64(_binary_to_decimal(str.substr(i, 6)));
	}
	return base64;
}
/* ------- End EX1 ------ */

/* EX2 */
string hex_xor(string hex1, string hex2) {
	string bin1 = "", bin2 = "";
	if (hex1.size() < hex2.size()) {
		while (hex1.size() != hex2.size())
			hex1 = "0" + hex1;
	}
	else if (hex1.size() > hex2.size()) {
		while (hex1.size() != hex2.size())
			hex2 = "0" + hex2;
	}
	for (int i = 0; i < hex1.size(); i++) {
		bin1.append(_hex_to_binary(hex1[i]));
		bin2.append(_hex_to_binary(hex2[i]));
	}
	long dec1 = 0, dec2 = 0;
	string result = "";
	for (int i = 0; i < bin1.size(); i += 8) {
		dec1 = _binary_to_decimal(bin1.substr(i, 8));
		dec2 = _binary_to_decimal(bin2.substr(i, 8));
		result += _decimal_to_hex(dec1 ^ dec2);
	}
	return result;
}
/* ------- End EX2 ------ */

/* EX3 */
string single_hex_key(string cipher) {
	int byte;
	char  c = '/0', cKey = '/0', final_key = '/0';
	string best_result = "", temp_result = "";
	double best_score = 0, temp_score = 0;
	for (int i = 0; i <= 255; i++) {
		cKey = (char)i;
		temp_result = "";
		for (int i = 0; i < cipher.size(); i += 2) {
			byte = (int)strtol(cipher.substr(i, 2).c_str(), NULL, 16);
			c = byte ^ cKey;
			temp_result += c;
		}
		temp_score = _caclulate_freq_score(temp_result);
		if (best_score < temp_score) {
			best_score = temp_score;
			best_result = temp_result;
			final_key = cKey;
		}
	}
	stringstream ss;
	ss << final_key << " ---> " << best_result;
	return ss.str();
}
/* ------- End EX3 ------ */

/* EX4 */
string single_hex_key_from_file(string file_path) {
	ifstream file(file_path);
	string str;
	string result = "", temp_result = "";
	double best_score = 0, temp_score = 0;
	while (getline(file, str))
	{
		temp_result = single_hex_key(str);
		temp_score = _caclulate_freq_score(temp_result);
		if (best_score < temp_score) {
			best_score = temp_score;
			result = temp_result;
		}
	}
	return result;
}
/* ------- End EX4 ------ */

/* EX5 */
string repeating_key_xor(string source_text, string key) {
	string text;
	int key_size = key.size();
	stringstream iss(source_text);
	for (int i = 0; i < source_text.size(); i++) {
		text += _decimal_to_hex(source_text[i] ^ key[i % key_size]);
	}
	return text;
}
/* ------- End EX5 ------ */

/* EX6 */
string breaking_repeating_key_xor(string file_path) {
	ifstream file(file_path);
	string ciphertext, line, hex_ciphertext;
	while (getline(file, line))
	{
		ciphertext += line;
	}
	string text = _base64_to_ascii(ciphertext);
	int key_size = _find_key_size(text);
	int byte_chunk_size = key_size * 2;
	string transposed_blocks;
	vector<string> blocks;

	for (int i = 0; i < text.size() - 1; i++) {
		hex_ciphertext += (_decimal_to_hex((int)text[i]));
	}

	for (int i = 0; i < hex_ciphertext.size() && blocks.size() < key_size; i += byte_chunk_size) {
		blocks.push_back(hex_ciphertext.substr(i, byte_chunk_size));
	}
	int chunks = 0;
	for (int j = 0; j < byte_chunk_size; j += 2) {
		for (int i = 0; i < blocks.size(); i++) {
			if (j < blocks[i].size())
			{
				transposed_blocks += blocks[i].substr(j, 2);
			}
		}
	}
	string key;
	for (int i = 0; i < transposed_blocks.size(); i += byte_chunk_size) {
		key += single_hex_key(transposed_blocks.substr(i, byte_chunk_size))[0];
	}
	return _hex_to_ascii(repeating_key_xor(text, key));
}
/* ------- End EX6 ------ */


int main(int argc, char* argv[]) {
	//EX1
	cout << hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d") << endl;
	//EX2
	cout << hex_xor("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965") << endl;
	//EX3
	cout << single_hex_key("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736") << endl;
	//EX4
	cout << single_hex_key_from_file("ex4.txt") << endl;
	//EX5
	cout << repeating_key_xor("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", "ICE") << endl;
	//EX6
	cout << breaking_repeating_key_xor("ex6.txt");
}

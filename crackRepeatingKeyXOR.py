import pdb
import base64
import itertools

MAX_KEYSIZE = 40


def encrypt_repeating_xor(plain_text, key):
    keylength = len(key)
    cipher_text = [0] * len(plain_text)
    key_pos = 0
    text_pos = 0

    for b in plain_text:
        cipher_text[text_pos] = ord(plain_text[text_pos]) ^ ord(key[key_pos])
        text_pos += 1
        key_pos += 1
        if key_pos >= keylength:
            key_pos = 0
    return cipher_text


def alpha_range_score_text(text):
    score = 0
    text_length = len(text)

    if text_length == 0:
        print 'textlength is zero'
        return 0
    
    for b in text:
        if ((b >= 48) and (b <= 57)) or ((b >= 65) and (b <= 90)) or ((b >= 97) and (b <= 122)) or (b == 32):
            score += 1
    return float(score) / float(text_length)


def decrypt_xorstring(input_string, key):
    result = [0] * len(input_string)
    i = 0
    for b in result:
        result[i] = ord(input_string[i]) ^ key
        i += 1
    return result


def calculate_hamming_distance(string_one, string_two):
    'hamming distance is the difference in bits of the two strings'

    hamming_dist = 0
    str_one = map(ord, string_one)
    str_two = map(ord, string_two)
    # ensure strings have the same length
    if(len(string_one) != len(string_two)):
            return -1

    # iterate through bytes, fine differing bits via xor,
    # and increment hamming distance for each one.
    for i in range(len(str_one)):
        b = str_one[i] ^ str_two[i]
        for j in range(8):
            if b & 0x01:
                hamming_dist += 1
            b = b >> 1

    return hamming_dist


def test_keysize(key_size, text):
    strings = ['', '', '', '']
    
    for i in range(key_size):
        strings[0] = strings[0] + text[i]
        strings[1] = strings[1] + text[i + key_size]
        strings[2] = strings[2] + text[i + (key_size * 2)]
        strings[3] = strings[3] + text[i + (key_size * 3)]

    pairs = itertools.combinations(strings, 2)
    hamming_distance = sum([calculate_hamming_distance(a, b) for (a, b) in pairs])

    return hamming_distance * 1.0 / key_size


def determine_block_key(block):
    max_score = max_score_key = 0
    
    for k in range(0, 256):
        text = decrypt_xorstring(block, k)
        score = alpha_range_score_text(text)
        if(max_score < score):
            max_score = score
            max_score_key = k

    return max_score_key


def convert_array_to_ascii(data):
    return ''.join(chr(i) for i in data)




# load encrypted file
print 'reading input file data.'
with open('xor-encrypted-file.txt', 'r') as f:
    ciphertext = f.read()

    
# decode base 64
print 'base64 decoding ciphertext.'
ciphertext = base64.b64decode(ciphertext)
                              

# determine probable keysize via average hamming
print 'calculating probable keysize...'
min_hamm = MAX_KEYSIZE * 8
key_size = 0

for k in range(1, MAX_KEYSIZE):
    avg_hamm = test_keysize(k, ciphertext)
    if(avg_hamm < min_hamm):
        min_hamm = avg_hamm
        key_size = k
print '\t_likely keysize: ' + str(key_size)


# create text blocks via key size
print 'determining key'
print '\t_splitting ciphertext into blocks'
j = 0
cipher_text_block = [''] * key_size
for k in ciphertext:
    cipher_text_block[j] = cipher_text_block[j] + k
    j += 1
    if j >= key_size:
        j = 0

        
# apply histograms to each to find most probably key characters
print '\t_calculating likely key for block'
block_key_value = [''] * key_size

for b in range(len(cipher_text_block)):
    block_key_value[b] = determine_block_key(cipher_text_block[b])

key = convert_array_to_ascii(block_key_value)
print '\t_likely key determined to be: \'' + key + '\''

# decrypt
plaintext = encrypt_repeating_xor(ciphertext, key)

print '\n\n\n'
print '***** begin decrypted text *****'
print '\n'
print convert_array_to_ascii(plaintext)
print '\n'
print '***** end decrypted text *****'
print '\n'

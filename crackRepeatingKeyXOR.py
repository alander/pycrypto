import sys
import pdb
import base64

MAX_KEYSIZE=40

def encryptRepeatingXOR( plainText, key ):
    keylength = len(key)
    cipherText = result = [ 0 for i in range( len(plainText)) ]
    keyPos=0
    textPos=0

    for b in plainText:
        cipherText[textPos] = ord(plainText[textPos]) ^ ord(key[keyPos])
        textPos=textPos+1
        keyPos=keyPos+1
        if keyPos >= keylength:
            keyPos=0
    return cipherText

def alphaRangeScoreText( text ):
    score = 0
    textLength = len( text )
    if ( textLength == 0 ):
         print "textlength is zero"
         return 0
    for b in text:
        if ((b >= 48) and (b <= 57)) or ((b >= 65) and (b <= 90)) or ((b >= 97) and (b <= 122)) or (b==32):
            score = score + 1
    return ( float(score) / float(textLength) )

def decryptXORString( inputString, key ):
    result = [ 0 for i in range( len(inputString)) ]
    i=0
    for b in result:
        result[i] = ord(inputString[i]) ^ key
        i=i+1
    return result

def calculateHammingDist( stringOne, stringTwo ):
    "Hamming distance is the difference in bits of the two strings"
    hammingDist = 0
    strOne = map( ord, stringOne )
    strTwo = map( ord, stringTwo )
    # Ensure strings have the same length
    if( len(stringOne) != len(stringTwo) ):
            return -1

    # Iterate through bytes, fine differing bits via XOR,
    # and increment hamming distance for each one.
    for i in range( len(strOne) ):
        b = strOne[i] ^ strTwo[i]
        for j in range(8):
            if( b & 0x01 ):
                hammingDist = hammingDist+1
            b = b >> 1
    return hammingDist

def testKeysize( keySize, text ):
    strOne = ""
    strTwo = ""
    strThree = ""
    strFour = ""
    for i in range(keySize):
        strOne = strOne + text[i]
        strTwo = strTwo + text[i+keySize]
        strThree = strThree + text[i+(keySize*2)]
        strFour = strFour + text[i+(keySize*3)]
    hammDist1 = calculateHammingDist( strOne, strTwo )
    hammDist2 = calculateHammingDist( strOne, strThree )
    hammDist3 = calculateHammingDist( strOne, strFour )
    hammDist4 = calculateHammingDist( strTwo, strThree )
    hammDist5 = calculateHammingDist( strTwo, strFour )
    hammDist6 = calculateHammingDist( strThree, strFour )

    avgHammDist = float( hammDist1 + hammDist2 + hammDist3 + hammDist4 + hammDist5 + hammDist6 ) / float(6.0)
    return float(avgHammDist) / float(keySize)

def determineBlockKey( block ):
    maxScore=0
    maxScoreKey=0
    for k in range(0,256):
        text = decryptXORString( block, k )
        score = alphaRangeScoreText( text )
        if( maxScore < score ):
            maxScore = score
            maxScoreKey = k
    return maxScoreKey

def convertArrayToAscii( data ):
    return ''.join(chr(i) for i in data )




# Load Encrypted File
print "Reading input file data."
f = open("XOR-encrypted-file.txt", "r")
ciphertext = f.read()
f.close()

# Decode Base 64
print "Base64 decoding ciphertext."
ciphertext = base64.b64decode( ciphertext )


# Determine probable keysize via average hamming
print "Calculating probable keysize..."
minHamm=MAX_KEYSIZE * 8
keySize = 0
for k in range(1,MAX_KEYSIZE):
    avgHamm = testKeysize( k, ciphertext )
    if( avgHamm < minHamm ):
        minHamm = avgHamm
        keySize = k
print "\tLikely Keysize: " + str(keySize)

# Create text blocks via key size
print "Determining Key"
print "\tSplitting ciphertext into blocks"
j=0
cipher_text_block = [ "" for i in range(keySize) ]
for k in ciphertext:
    cipher_text_block[j] = cipher_text_block[j] + k
    j=j+1
    if j >= keySize:
        j = 0

# Apply histograms to each to find most probably key characters
print "\tCalculating likely key for block"
block_key_value = ["" for i in range(keySize)]
for b in range(len(cipher_text_block)):
    block_key_value[b] = determineBlockKey( cipher_text_block[b] )

key=convertArrayToAscii(block_key_value)
print "\tLikely key determined to be: \"" + key + "\""

# Decrypt
plaintext = encryptRepeatingXOR( ciphertext, key )

print "\n\n\n"
print "***** BEGIN DECRYPTED TEXT *****"
print "\n"
print convertArrayToAscii(plaintext)
print "\n"
print "***** END DECRYPTED TEXT *****"
print "\n"

[
  {
    _id: ObjectId('680ab707172885783a544ca7'),
    id: 1,
    levelId: 1,
    title: 'Imperial Caesar Cipher',
    description: 'This message has been encrypted by Emperor Julius Caesar himself to hide his military plans. Decode it to reveal his strategy.',
    cipherType: 'Caesar Shift',
    ciphertext: 'FURVV WKH UXELFRQ DQG FRQTXHU URPH',
    solution: 'CROSS THE RUBICON AND CONQUER ROME',
    hints: [
      "The most common letter in English is 'E'. Look for patterns in letter frequency.",
      'Caesar used a specific number of positions to shift his messages. Try values between 1-25.',
      'This message is shifted by 3 positions (the classic Caesar cipher shift).'
    ],
    difficulty: 1
  },
  {
    _id: ObjectId('680ab707172885783a544ca8'),
    id: 2,
    levelId: 1,
    title: 'Digital Forum Secret',
    description: 'This message was hidden on an early internet forum to avoid spoilers. Can you decode this classic ROT13 cipher?',                                                           
    cipherType: 'ROT13',
    ciphertext: "GUR IVYYNVA VF GUR UREB'F SNGURE",
    solution: "THE VILLAIN IS THE HERO'S FATHER",
    hints: [
      'ROT13 shifts each letter 13 positions in the alphabet.',
      'Since there are 26 letters in the English alphabet, applying ROT13 twice returns to the original text.',                                                                               
      'A becomes N, B becomes O, and so on. Z wraps around to M.'
    ],
    difficulty: 1
  },
  {
    _id: ObjectId('680ab707172885783a544ca9'),
    id: 3,
    levelId: 1,
    title: 'Mirror Message',
    description: 'A message appears in your bathroom mirror, but you can only read it by looking at its reflection. What does it say?',                                                       
    cipherType: 'Simple Reversal',
    ciphertext: 'RORRIM EHT NI KOOL SYAWLA',
    solution: 'ALWAYS LOOK IN THE MIRROR',
    hints: [
      'Try reading the message differently than normal.',
      'What would you see if looking at this text in a mirror?',
      'The message is simply written backwards, letter by letter.'
    ],
    difficulty: 1
  },
  {
    _id: ObjectId('680ab707172885783a544caa'),
    id: 4,
    levelId: 2,
    title: 'Ancient Hebrew Code',
    description: 'This message uses the ancient Atbash cipher, first used in the Hebrew Bible. The alphabet is flipped so A becomes Z, B becomes Y, and so on.',                              
    cipherType: 'Atbash',
    ciphertext: 'GSRH NVHHZTV RH SVIVGXRZO',
    solution: 'THIS MESSAGE IS HERETICAL',
    hints: [
      'In this cipher, A becomes Z, B becomes Y, and so on.',
      'The mapping is symmetrical - encoding and decoding use the same process.',
      "The first letter of the plaintext is 'T'."
    ],
    difficulty: 2
  },
  {
    _id: ObjectId('680ab707172885783a544cab'),
    id: 5,
    levelId: 2,
    title: 'Machine Language',
    description: 'This binary sequence was transmitted from an AI shortly before it went offline. What final message did it leave behind?',                                                   
    cipherType: 'Binary',
    ciphertext: '01001001 00100000 01000001 01001101 00100000 01000001 01010111 01000001 01001011 01000101',                                                                                  
    solution: 'I AM AWAKE',
    hints: [
      'Each group of 8 bits represents one character in ASCII encoding.',
      'Convert each binary number to decimal, then look up the ASCII value.',
      "The first character (01001001) is 'I'."
    ],
    difficulty: 2
  },
  {
    _id: ObjectId('680ab707172885783a544cac'),
    id: 6,
    levelId: 2,
    title: 'Hidden Within',
    description: 'The true message is hidden within this text, but only certain letters form the actual secret. Find the pattern to reveal it.',                                              
    cipherType: 'Skip Cipher',
    ciphertext: 'TWHAETRENCIHSNTGSILAUBREKTSOAORLKEACBHOEUDT',
    solution: 'WHAT LIES ABOUT',
    hints: [
      'Not all letters in the ciphertext are part of the message.',
      'Try reading every nth letter, where n is a small number.',
      'Read every fourth letter to reveal the hidden message.'
    ],
    difficulty: 2
  },
  {
    _id: ObjectId('680ab707172885783a544cad'),
    id: 7,
    levelId: 3,
    title: 'Renaissance Encryption',
    description: "This 16th-century polyalphabetic cipher was once called 'le chiffre indéchiffrable' (the indecipherable cipher). Can you prove that wrong?",                                
    cipherType: 'Vigenère',
    ciphertext: 'OAASXDGTWWQGV',
    solution: 'HIDDEN TREASURE',
    hints: [
      "You need to discover the keyword. It's a common term related to pirates.",
      "The keyword is 'GOLD'. Each letter in the keyword determines the shift for the corresponding plaintext letter.",                                                                       
      'When you repeat the keyword (GOLD) for the length of the message, each letter in the ciphertext is shifted by the corresponding letter in the keyword.'                                
    ],
    difficulty: 3
  },
  {
    _id: ObjectId('680ab707172885783a544cae'),
    id: 8,
    levelId: 3,
    title: 'SOS Transmission',
    description: 'This distress signal was received from a submarine lost in the depths. Decode it to discover their fate.',                                                                  
    cipherType: 'Morse Code',
    ciphertext: '.-.. --- ... - / .- - / ... . .- / ... . -. -.. / .... . .-.. .--.',
    solution: 'LOST AT SEA SEND HELP',
    hints: [
      'Dots (.) represent short signals, dashes (-) represent long signals.',
      'Letters are separated by spaces, and words by forward slashes (/).',
      'Use the Morse code chart to decode each character.'
    ],
    difficulty: 3
  },
  {
    _id: ObjectId('680ab707172885783a544caf'),
    id: 9,
    levelId: 3,
    title: 'Digital Whisper',
    description: 'This message was embedded in the metadata of a classified digital file. What secrets does it contain?',                                                                     
    cipherType: 'Hex',
    ciphertext: '54 68 65 20 77 61 74 63 68 65 72 73 20 61 72 65 20 68 65 72 65',
    solution: 'THE WATCHERS ARE HERE',
    hints: [
      'Each pair of hexadecimal digits represents one ASCII character.',
      'Convert each hex value to decimal, then look up the ASCII value.',
      "The hex value 54 corresponds to the character 'T'."
    ],
    difficulty: 3
  },
  {
    _id: ObjectId('680ab707172885783a544cb0'),
    id: 10,
    levelId: 4,
    title: "Cryptanalyst's Challenge",
    description: 'A complete substitution cipher where each letter is replaced with another according to a fixed pattern. Use frequency analysis to crack it.',                               
    cipherType: 'Substitution',
    ciphertext: 'XYQ HKDSMQJ FCXYCE XYQ FCJNV CD XYDXKBP TFZCKBQ',
    solution: 'THE ANSWERS WITHIN THE WORKS OF TURING MACHINE',
    hints: [
      "Look for patterns in letter frequencies. 'E' and 'T' are the most common letters in English.",                                                                                         
      "Try to identify short words first, like 'THE' or 'OF'.",
      'The mapping is: A→D, B→N, C→Z, D→V, E→Q, F→G, G→H, H→Y, I→C, J→A, K→S, L→O, M→F, N→E, O→K, P→U, Q→P, R→R, S→T, T→X, U→M, V→W, W→L, X→J, Y→B, Z→I'                                      
    ],
    difficulty: 4
  },
  {
    _id: ObjectId('680ab707172885783a544cb1'),
    id: 11,
    levelId: 4,
    title: 'Layers of Secrecy',
    description: 'This message has been encoded twice - first with one cipher, then with another. Peel back the layers to discover the truth.',                                               
    cipherType: 'Multiple',
    ciphertext: 'XLIBTSWXHERKIVSYWIGVIXWEVIJMRHIVTPEMRWMKLX',
    solution: 'THE MOST DANGEROUS SECRETS ARE HIDDEN IN PLAIN SIGHT',
    hints: [
      'The message was first encoded with a Caesar cipher, then the spaces were removed.',
      'First, determine the Caesar shift that was used.',
      'After applying a Caesar shift of 4, add spaces to reveal the final message.'
    ],
    difficulty: 4
  },
  {
    _id: ObjectId('680ab707172885783a544cb2'),
    id: 12,
    levelId: 4,
    title: 'Twisted Message',
    description: 'This Civil War era transposition cipher arranges the plaintext in a zigzag pattern across multiple rails, then reads off the rails in sequence.',                           
    cipherType: 'Transposition',
    ciphertext: 'TETGESHCNSTEEHAEDDIRNRNEEVE',
    solution: 'THE GREATEST STRENGTH IS ENDURANCE',
    hints: [
      "The rail fence cipher rearranges letters in a zigzag pattern across multiple 'rails'.",
      'The key is the number of rails (rows). Try different values from 2 to 4.',
      'This message uses 3 rails. Write it out in a zigzag and read horizontally.'
    ],
    difficulty: 4
  },
  {
    _id: ObjectId('680ab707172885783a544cb3'),
    id: 13,
    levelId: 5,
    title: 'Victorian Secret Service',
    description: 'Used by British forces in the Boer War and WWI, this cipher encrypts pairs of letters using a 5x5 grid based on a keyword.',                                                
    cipherType: 'Playfair',
    ciphertext: 'UKGPFKUBMERBTWMUERFJTSKFQGZUDMWCSBX',
    solution: 'INTELLIGENCE REQUIRES PATIENCE AND WISDOM',
    hints: [
      'The Playfair cipher uses a 5x5 grid based on a keyword, with I and J sharing a position.',                                                                                             
      "The keyword for this cipher is 'SHADOW'.",
      'Rules: 1) Same row: take letters to the right. 2) Same column: take letters below. 3) Different row and column: form a rectangle and take the corners in the same row.'                
    ],
    difficulty: 5
  },
  {
    _id: ObjectId('680ab707172885783a544cb4'),
    id: 14,
    levelId: 5,
    title: "Shakespeare's Secret",
    description: "Francis Bacon devised this binary cipher in the 16th century, using two typefaces. Some believe he used it to hide messages in Shakespeare's plays.",                       
    cipherType: "Bacon's Cipher",
    ciphertext: 'AABBB AABAA ABBAA AABAA BABAA AABAB ABBAB AABAA AAAAA AABAA AABAA ABBAA ABBAA BABAA ABABA',                                                                                  
    solution: 'KNOWLEDGE IS POWER',
    hints: [
      "Each letter is encoded with a 5-letter sequence of 'A's and 'B's.",
      'The sequences represent a binary encoding where A=0 and B=1.',
      "Use Bacon's cipher table to decode: A=AAAAA, B=AAAAB, etc."
    ],
    difficulty: 5
  },
  {
    _id: ObjectId('680ab707172885783a544cb5'),
    id: 15,
    levelId: 5,
    title: 'The Ultimate Enigma',
    description: 'This message combines several encryption techniques and historical cipher methods. Only a true master cryptographer can decipher it.',                                      
    cipherType: 'Combined Analysis',
    ciphertext: 'KQVJA OMIGN BXGTF QSOAL CFXMV IHWMN ZBWVK SXBKR ZFRJT WLKPH UVDNQ EPYAO',
    solution: 'BEYOND EVERY LOCKED DOOR LIES ANOTHER MYSTERY WAITING TO BE SOLVED',
    hints: [
      'This combines a Vigenère cipher with columnar transposition.',
      "The keyword for the Vigenère component is 'MASTER'.",
      "After Vigenère decryption, apply a columnar transposition with the key 'CIPHER'."
    ],
    difficulty: 5
  },
  {
    _id: ObjectId('680ab707172885783a544cb6'),
    id: 16,
    levelId: 1,
    title: 'Numerical Alphabet',
    description: 'This intercepted message from an elite spy network converts letters to their numerical position in the alphabet.',                                                          
    cipherType: 'A1Z26',
    ciphertext: '20 8 5 19 16 25 23 8 15 11 14 15 23 19',
    solution: 'THE SPY WHO KNOWS',
    hints: [
      'A=1, B=2, C=3, and so on up to Z=26.',
      'Each number represents a single letter of the alphabet.',
      "The first number is 20, which corresponds to the letter 'T'."
    ],
    difficulty: 1
  },
  {
    _id: ObjectId('680ab707172885783a544cb7'),
    id: 17,
    levelId: 1,
    title: 'Backwards Speech',
    description: "A mysterious character speaks in an unusual way, with each word backwards. Decipher what they're trying to tell you.",                                                      
    cipherType: 'Word Reverse',
    ciphertext: 'REVEN LLET EM EHT SDDO',
    solution: 'NEVER TELL ME THE ODDS',
    hints: [
      'The word order remains the same.',
      'Look at each word individually.',
      'Try reversing the letters in each word while keeping the words in the same order.'
    ],
    difficulty: 1
  },
  {
    _id: ObjectId('680ab707172885783a544cb8'),
    id: 18,
    levelId: 2,
    title: 'Typing Error',
    description: 'Someone typed this message but their hands were positioned one key to the right on their QWERTY keyboard.',                                                                 
    cipherType: 'Keyboard Shift',
    ciphertext: 'YJODR O;; YJRDR [PDRR',
    solution: 'TRUST ALL THESE POWER',
    hints: [
      'Look at your keyboard layout.',
      'Each letter is replaced by the key immediately to its right.',
      "For example, 'T' becomes 'Y' because 'Y' is to the right of 'T' on a QWERTY keyboard."
    ],
    difficulty: 2
  },
  {
    _id: ObjectId('680ab707172885783a544cb9'),
    id: 19,
    levelId: 2,
    title: 'Masonic Secrets',
    description: "This ancient Freemason cipher uses symbols instead of letters. We've transcribed the symbols using letters for easier input.",                                              
    cipherType: 'Symbol Substitution',
    ciphertext: 'QWBTZ IYAHX MPQCW DRKAY',
    solution: 'ANCIENT WISDOM AWAITS',
    hints: [
      'The Pigpen cipher uses a specific grid pattern.',
      'Look up the Pigpen cipher grid online to decode.',
      "The first symbol corresponds to 'A'."
    ],
    difficulty: 2
  },
  {
    _id: ObjectId('680ab707172885783a544cba'),
    id: 20,
    levelId: 3,
    title: "Greek Mathematician's Puzzle",
    description: 'Invented by Polybius in ancient Greece, this cipher uses coordinates on a grid to represent letters.',                                                                      
    cipherType: 'Polybius',
    ciphertext: '4325 15 1544 43 35 21 43 23 31 34 11 21 15',
    solution: 'THEY ARE WATCHING',
    hints: [
      'The Polybius square typically has 5 rows and 5 columns.',
      'Each letter (except J, which is combined with I) is represented by two numbers: row and column.',                                                                                      
      "For example, 'T' is in row 4, column 3, so it's encoded as '43'."
    ],
    difficulty: 3
  }
]
Type "it" for more
Atlas xploitcraft> it
[
  {
    _id: ObjectId('680ab707172885783a544cbb'),
    id: 21,
    levelId: 3,
    title: 'Literary Encryption',
    description: 'This message was encoded using the first lines of a famous book as the key. Crack it to reveal the hidden meaning.',                                                        
    cipherType: 'Running Key',
    ciphertext: 'BTAFUHS AGYKRH KMCPR',
    solution: 'BETWEEN TWO WORLDS',
    hints: [
      "The key is the opening line of Moby Dick: 'CALL ME ISHMAEL SOME YEARS AGO'",
      'Each letter is shifted based on the corresponding letter in the key phrase.',
      "For example, 'B' + 'C' = 'D' (2 + 3 = 5 = 'D')"
    ],
    difficulty: 3
  },
  {
    _id: ObjectId('680ab707172885783a544cbc'),
    id: 22,
    levelId: 4,
    title: 'Double Coordinates',
    description: 'This fractionating cipher combines a Polybius square with transposition to create a highly secure encryption.',                                                             
    cipherType: 'Bifid',
    ciphertext: 'UESUOMYOSVNOOHBTEEL',
    solution: 'QUANTUM ENTANGLEMENT',
    hints: [
      "The Bifid cipher uses a 5×5 Polybius square with the keyword 'PHYSICS'.",
      'It records the row and column for each letter, then rearranges them.',
      'The process involves recording all rows, then all columns, then converting back to letters.'                                                                                           
    ],
    difficulty: 4
  },
  {
    _id: ObjectId('680ab707172885783a544cbd'),
    id: 23,
    levelId: 4,
    title: 'Self-Evolving Code',
    description: 'This cipher begins with a key, but then uses the plaintext itself to continue the encryption, making it harder to break.',                                                  
    cipherType: 'Autokey',
    ciphertext: 'LFLLSGMWMJDBZDWY',
    solution: 'KNOWLEDGE IS POWER',
    hints: [
      'The Autokey cipher uses the plaintext itself as part of the key after the initial key letter.',                                                                                        
      "The initial key letter is 'D'.",
      'After the first letter, each new key letter is the corresponding plaintext letter that was just decrypted.'                                                                            
    ],
    difficulty: 4
  },
  {
    _id: ObjectId('680ab707172885783a544cbe'),
    id: 24,
    levelId: 5,
    title: 'World War Secrets',
    description: 'This cipher was used by the German Army during World War I, combining fractionation and transposition for extra security.',                                                 
    cipherType: 'ADFGVX',
    ciphertext: 'FGGGAX DDAGFD AGGDFG XAXFDD FXGADA GVDFGX',
    solution: 'DECIPHER THE IMPOSSIBLE CODE',
    hints: [
      "The ADFGVX cipher uses a 6×6 grid with the keyword 'ENIGMA'.",
      'Letters and digits are mapped to pairs of the letters A, D, F, G, V, X.',
      "After substitution, the result undergoes columnar transposition with key 'BERLIN'."
    ],
    difficulty: 5
  },
  {
    _id: ObjectId('680ab707172885783a544cbf'),
    id: 25,
    levelId: 5,
    title: 'Quadruple Protection',
    description: 'This cipher uses four 5×5 squares to encrypt pairs of letters, making it resistant to simple frequency analysis.',                                                          
    cipherType: 'Four-Square',
    ciphertext: 'LUDYLOZMDNHMVELNISOSGMOEH',
    solution: 'VICTORY BELONGS TO THE PERSISTENT',
    hints: [
      'The Four-Square cipher uses four 5×5 matrices arranged in a square.',
      'The top-left and bottom-right squares contain the standard alphabet.',
      "The other two squares contain mixed alphabets based on the keywords 'VICTOR' and 'CIPHER'."                                                                                            
    ],
    difficulty: 5
  }
]


# backend/routes/cipher_routes.py
from flask import Blueprint, request, jsonify, g
from bson.objectid import ObjectId
import time
from datetime import datetime
import random

from mongodb.database import db
from models.test import get_user_by_id, update_user_coins, update_user_xp

# Initialize the blueprint
cipher_bp = Blueprint('cipher', __name__)

# Cipher collections
cipher_challenges_collection = db.cipherChallenges
cipher_progress_collection = db.cipherProgress

@cipher_bp.route('/challenges', methods=['GET'])
def get_cipher_challenges():
    """
    Get all cipher challenges with user progress information.
    """
    user_id = request.args.get('userId')
    
    start_db = time.time()
    challenges = list(cipher_challenges_collection.find({}, {'_id': 0}))
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # If there are no challenges in the database, generate some defaults
    if not challenges:
        challenges = generate_default_challenges()
        
        # Store these challenges in the database for future use
        if challenges:
            start_db = time.time()
            cipher_challenges_collection.insert_many(challenges)
            duration = time.time() - start_db
            if hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator += duration
    
    # If user_id is provided, get user progress
    completed_challenges = []
    max_unlocked_level = 1
    unlocked_hints = {}
    
    if user_id:
        try:
            user_oid = ObjectId(user_id)
            
            start_db = time.time()
            user_progress = cipher_progress_collection.find_one({"userId": user_oid})
            duration = time.time() - start_db
            if hasattr(g, 'db_time_accumulator'):
                g.db_time_accumulator += duration
            
            if user_progress:
                completed_challenges = user_progress.get("completedChallenges", [])
                max_unlocked_level = user_progress.get("maxUnlockedLevel", 1)
                unlocked_hints = user_progress.get("unlockedHints", {})
        except:
            pass
    
    return jsonify({
        "challenges": challenges,
        "completedChallenges": completed_challenges,
        "maxUnlockedLevel": max_unlocked_level,
        "unlockedHints": unlocked_hints
    })

@cipher_bp.route('/submit', methods=['POST'])
def submit_cipher_solution():
    """
    Submit a solution for a cipher challenge.
    """
    data = request.json
    user_id = data.get('userId')
    challenge_id = data.get('challengeId')
    level_id = data.get('levelId')
    hint_used = data.get('hintUsed', False)
    time_spent = data.get('timeSpent', 0)
    
    if not user_id or not challenge_id:
        return jsonify({"error": "userId and challengeId are required"}), 400
    
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400
    
    # Get user
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Check if the challenge exists
    start_db = time.time()
    challenge = cipher_challenges_collection.find_one({"id": challenge_id})
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not challenge:
        return jsonify({"error": "Challenge not found"}), 404
    
    # Find or create user progress document
    start_db = time.time()
    user_progress = cipher_progress_collection.find_one({"userId": user_oid})
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not user_progress:
        user_progress = {
            "userId": user_oid,
            "completedChallenges": [],
            "maxUnlockedLevel": 1,
            "unlockedHints": {}
        }
    
    # Check if this challenge is already completed
    completed_challenges = user_progress.get("completedChallenges", [])
    is_new_completion = challenge_id not in completed_challenges
    
    # Calculate rewards
    xp_reward = 0
    coin_reward = 0
    
    if is_new_completion:
        # Base rewards based on level
        base_xp = level_id * 50
        base_coins = level_id * 20
        
        # Adjust based on hint usage
        if hint_used:
            xp_reward = int(base_xp * 0.7)  # 30% reduction if hints were used
            coin_reward = int(base_coins * 0.7)
        else:
            xp_reward = base_xp
            coin_reward = base_coins
        
        # Add to completed challenges
        if challenge_id not in completed_challenges:
            completed_challenges.append(challenge_id)
        
        # Get all challenges at this level to check if level is completed
        start_db = time.time()
        level_challenges = list(cipher_challenges_collection.find({"levelId": level_id}))
        duration = time.time() - start_db
        if hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator += duration
        
        # Check if all challenges in this level are completed
        level_completed = all(c["id"] in completed_challenges for c in level_challenges)
        
        # Unlock next level if all challenges in current level are completed
        max_unlocked_level = user_progress.get("maxUnlockedLevel", 1)
        if level_completed and level_id == max_unlocked_level:
            max_unlocked_level = min(5, level_id + 1)  # Maximum level is 5
        
        # Update user progress
        start_db = time.time()
        cipher_progress_collection.update_one(
            {"userId": user_oid},
            {
                "$set": {
                    "completedChallenges": completed_challenges,
                    "maxUnlockedLevel": max_unlocked_level
                }
            },
            upsert=True
        )
        duration = time.time() - start_db
        if hasattr(g, 'db_time_accumulator'):
            g.db_time_accumulator += duration
        
        # Update user rewards
        update_user_xp(user_id, xp_reward)
        update_user_coins(user_id, coin_reward)
    
    # Fix: Use the actual isNewCompletion value
    return jsonify({
        "success": True,
        "isNewCompletion": is_new_completion,  # Fixed: was hardcoded to False before
        "xpAwarded": xp_reward,
        "coinsAwarded": coin_reward,
        "message": "Challenge completed successfully!" if is_new_completion else "Challenge already completed. No additional rewards."
    })

@cipher_bp.route('/unlock-hint', methods=['POST'])
def unlock_hint():
    """
    Unlock a hint for a cipher challenge by spending coins.
    """
    data = request.json
    user_id = data.get('userId')
    challenge_id = data.get('challengeId')
    hint_index = data.get('hintIndex')
    cost = data.get('cost', 0)
    
    if not user_id or not challenge_id or hint_index is None:
        return jsonify({"error": "userId, challengeId, and hintIndex are required"}), 400
    
    try:
        user_oid = ObjectId(user_id)
    except:
        return jsonify({"error": "Invalid user ID"}), 400
    
    # Get user
    start_db = time.time()
    user = get_user_by_id(user_id)
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not user:
        return jsonify({"error": "User not found"}), 404
    
    # Check if user has enough coins
    user_coins = user.get("coins", 0)
    if user_coins < cost:
        return jsonify({"error": "Not enough coins"}), 400
    
    # Find or create user progress document
    start_db = time.time()
    user_progress = cipher_progress_collection.find_one({"userId": user_oid})
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    if not user_progress:
        user_progress = {
            "userId": user_oid,
            "completedChallenges": [],
            "maxUnlockedLevel": 1,
            "unlockedHints": {}
        }
    
    # Get unlocked hints for this challenge
    unlocked_hints = user_progress.get("unlockedHints", {})
    challenge_hints = unlocked_hints.get(str(challenge_id), [])
    
    # Check if hint is already unlocked
    if hint_index in challenge_hints:
        return jsonify({"error": "Hint already unlocked"}), 400
    
    # Add new hint to unlocked list
    challenge_hints.append(hint_index)
    unlocked_hints[str(challenge_id)] = challenge_hints
    
    # Update user progress
    start_db = time.time()
    cipher_progress_collection.update_one(
        {"userId": user_oid},
        {
            "$set": {
                "unlockedHints": unlocked_hints
            }
        },
        upsert=True
    )
    duration = time.time() - start_db
    if hasattr(g, 'db_time_accumulator'):
        g.db_time_accumulator += duration
    
    # Deduct coins from user
    update_user_coins(user_id, -cost)
    
    return jsonify({
        "success": True,
        "challengeId": challenge_id,
        "hintIndex": hint_index,
        "newCoinsBalance": user_coins - cost
    })

def generate_default_challenges():
    """
    Generate a set of default cipher challenges if none exist in the database.
    """
    challenges = [
        # Level 1: Beginner
        {
            "id": 1,
            "levelId": 1,
            "title": "Imperial Caesar Cipher",
            "description": "This message has been encrypted by Emperor Julius Caesar himself to hide his military plans. Decode it to reveal his strategy.",
            "cipherType": "Caesar Shift",
            "ciphertext": "FURVV WKH UXELFRQ DQG FRQTXHU URPH",
            "solution": "CROSS THE RUBICON AND CONQUER ROME",
            "hints": [
                "The most common letter in English is 'E'. Look for patterns in letter frequency.",
                "Caesar used a specific number of positions to shift his messages. Try values between 1-25.",
                "This message is shifted by 3 positions (the classic Caesar cipher shift)."
            ],
            "difficulty": 1
        },
        {
            "id": 2,
            "levelId": 1,
            "title": "Digital Forum Secret",
            "description": "This message was hidden on an early internet forum to avoid spoilers. Can you decode this classic ROT13 cipher?",
            "cipherType": "ROT13",
            "ciphertext": "GUR IVYYNVA VF GUR UREB'F SNGURE",
            "solution": "THE VILLAIN IS THE HERO'S FATHER",
            "hints": [
                "ROT13 shifts each letter 13 positions in the alphabet.",
                "Since there are 26 letters in the English alphabet, applying ROT13 twice returns to the original text.",
                "A becomes N, B becomes O, and so on. Z wraps around to M."
            ],
            "difficulty": 1
        },
        {
            "id": 3,
            "levelId": 1,
            "title": "Mirror Message",
            "description": "A message appears in your bathroom mirror, but you can only read it by looking at its reflection. What does it say?",
            "cipherType": "Simple Reversal",
            "ciphertext": "RORRIM EHT NI KOOL SYAWLA",
            "solution": "ALWAYS LOOK IN THE MIRROR",
            "hints": [
                "Try reading the message differently than normal.",
                "What would you see if looking at this text in a mirror?",
                "The message is simply written backwards, letter by letter."
            ],
            "difficulty": 1
        },
        
        # Level 2: Easy
        {
            "id": 4,
            "levelId": 2,
            "title": "Ancient Hebrew Code",
            "description": "This message uses the ancient Atbash cipher, first used in the Hebrew Bible. The alphabet is flipped so A becomes Z, B becomes Y, and so on.",
            "cipherType": "Atbash",
            "ciphertext": "GSRH NVHHZTV RH SVIVGXRZO",
            "solution": "THIS MESSAGE IS HERETICAL",
            "hints": [
                "In this cipher, A becomes Z, B becomes Y, and so on.",
                "The mapping is symmetrical - encoding and decoding use the same process.",
                "The first letter of the plaintext is 'T'."
            ],
            "difficulty": 2
        },
        {
            "id": 5,
            "levelId": 2,
            "title": "Machine Language",
            "description": "This binary sequence was transmitted from an AI shortly before it went offline. What final message did it leave behind?",
            "cipherType": "Binary",
            "ciphertext": "01001001 00100000 01000001 01001101 00100000 01000001 01010111 01000001 01001011 01000101",
            "solution": "I AM AWAKE",
            "hints": [
                "Each group of 8 bits represents one character in ASCII encoding.",
                "Convert each binary number to decimal, then look up the ASCII value.",
                "The first character (01001001) is 'I'."
            ],
            "difficulty": 2
        },
        {
            "id": 6,
            "levelId": 2,
            "title": "Hidden Within",
            "description": "The true message is hidden within this text, but only certain letters form the actual secret. Find the pattern to reveal it.",
            "cipherType": "Skip Cipher",
            "ciphertext": "TWHAETRENCIHSNTGSILAUBREKTSOAORLKEACBHOEUDT",
            "solution": "WHAT LIES ABOUT",
            "hints": [
                "Not all letters in the ciphertext are part of the message.",
                "Try reading every nth letter, where n is a small number.",
                "Read every fourth letter to reveal the hidden message."
            ],
            "difficulty": 2
        },
        
        # Level 3: Intermediate
        {
            "id": 7,
            "levelId": 3,
            "title": "Renaissance Encryption",
            "description": "This 16th-century polyalphabetic cipher was once called 'le chiffre indéchiffrable' (the indecipherable cipher). Can you prove that wrong?",
            "cipherType": "Vigenère",
            "ciphertext": "OAASXDGTWWQGV",
            "solution": "HIDDEN TREASURE",
            "hints": [
                "You need to discover the keyword. It's a common term related to pirates.",
                "The keyword is 'GOLD'. Each letter in the keyword determines the shift for the corresponding plaintext letter.",
                "When you repeat the keyword (GOLD) for the length of the message, each letter in the ciphertext is shifted by the corresponding letter in the keyword."
            ],
            "difficulty": 3
        },
        {
            "id": 8,
            "levelId": 3,
            "title": "SOS Transmission",
            "description": "This distress signal was received from a submarine lost in the depths. Decode it to discover their fate.",
            "cipherType": "Morse Code",
            "ciphertext": ".-.. --- ... - / .- - / ... . .- / ... . -. -.. / .... . .-.. .--.",
            "solution": "LOST AT SEA SEND HELP",
            "hints": [
                "Dots (.) represent short signals, dashes (-) represent long signals.",
                "Letters are separated by spaces, and words by forward slashes (/).",
                "Use the Morse code chart to decode each character."
            ],
            "difficulty": 3
        },
        {
            "id": 9,
            "levelId": 3,
            "title": "Digital Whisper",
            "description": "This message was embedded in the metadata of a classified digital file. What secrets does it contain?",
            "cipherType": "Hex",
            "ciphertext": "54 68 65 20 77 61 74 63 68 65 72 73 20 61 72 65 20 68 65 72 65",
            "solution": "THE WATCHERS ARE HERE",
            "hints": [
                "Each pair of hexadecimal digits represents one ASCII character.",
                "Convert each hex value to decimal, then look up the ASCII value.",
                "The hex value 54 corresponds to the character 'T'."
            ],
            "difficulty": 3
        },
        
        # Level 4: Advanced
        {
            "id": 10,
            "levelId": 4,
            "title": "Cryptanalyst's Challenge",
            "description": "A complete substitution cipher where each letter is replaced with another according to a fixed pattern. Use frequency analysis to crack it.",
            "cipherType": "Substitution",
            "ciphertext": "XYQ HKDSMQJ FCXYCE XYQ FCJNV CD XYDXKBP TFZCKBQ",
            "solution": "THE ANSWERS WITHIN THE WORKS OF TURING MACHINE",
            "hints": [
                "Look for patterns in letter frequencies. 'E' and 'T' are the most common letters in English.",
                "Try to identify short words first, like 'THE' or 'OF'.",
                "The mapping is: A→D, B→N, C→Z, D→V, E→Q, F→G, G→H, H→Y, I→C, J→A, K→S, L→O, M→F, N→E, O→K, P→U, Q→P, R→R, S→T, T→X, U→M, V→W, W→L, X→J, Y→B, Z→I"
            ],
            "difficulty": 4
        },
        {
            "id": 11,
            "levelId": 4,
            "title": "Layers of Secrecy",
            "description": "This message has been encoded twice - first with one cipher, then with another. Peel back the layers to discover the truth.",
            "cipherType": "Multiple",
            "ciphertext": "XLIBTSWXHERKIVSYWIGVIXWEVIJMRHIVTPEMRWMKLX",
            "solution": "THE MOST DANGEROUS SECRETS ARE HIDDEN IN PLAIN SIGHT",
            "hints": [
                "The message was first encoded with a Caesar cipher, then the spaces were removed.",
                "First, determine the Caesar shift that was used.",
                "After applying a Caesar shift of 4, add spaces to reveal the final message."
            ],
            "difficulty": 4
        },
        {
            "id": 12,
            "levelId": 4,
            "title": "Twisted Message",
            "description": "This Civil War era transposition cipher arranges the plaintext in a zigzag pattern across multiple rails, then reads off the rails in sequence.",
            "cipherType": "Transposition",
            "ciphertext": "TETGESHCNSTEEHAEDDIRNRNEEVE",
            "solution": "THE GREATEST STRENGTH IS ENDURANCE",
            "hints": [
                "The rail fence cipher rearranges letters in a zigzag pattern across multiple 'rails'.",
                "The key is the number of rails (rows). Try different values from 2 to 4.",
                "This message uses 3 rails. Write it out in a zigzag and read horizontally."
            ],
            "difficulty": 4
        },
        
        # Level 5: Expert
        {
            "id": 13,
            "levelId": 5,
            "title": "Victorian Secret Service",
            "description": "Used by British forces in the Boer War and WWI, this cipher encrypts pairs of letters using a 5x5 grid based on a keyword.",
            "cipherType": "Playfair",
            "ciphertext": "UKGPFKUBMERBTWMUERFJTSKFQGZUDMWCSBX",
            "solution": "INTELLIGENCE REQUIRES PATIENCE AND WISDOM",
            "hints": [
                "The Playfair cipher uses a 5x5 grid based on a keyword, with I and J sharing a position.",
                "The keyword for this cipher is 'SHADOW'.",
                "Rules: 1) Same row: take letters to the right. 2) Same column: take letters below. 3) Different row and column: form a rectangle and take the corners in the same row."
            ],
            "difficulty": 5
        },
        {
            "id": 14,
            "levelId": 5,
            "title": "Shakespeare's Secret",
            "description": "Francis Bacon devised this binary cipher in the 16th century, using two typefaces. Some believe he used it to hide messages in Shakespeare's plays.",
            "cipherType": "Bacon's Cipher",
            "ciphertext": "AABBB AABAA ABBAA AABAA BABAA AABAB ABBAB AABAA AAAAA AABAA AABAA ABBAA ABBAA BABAA ABABA",
            "solution": "KNOWLEDGE IS POWER",
            "hints": [
                "Each letter is encoded with a 5-letter sequence of 'A's and 'B's.",
                "The sequences represent a binary encoding where A=0 and B=1.",
                "Use Bacon's cipher table to decode: A=AAAAA, B=AAAAB, etc."
            ],
            "difficulty": 5
        },
        {
            "id": 15,
            "levelId": 5,
            "title": "The Ultimate Enigma",
            "description": "This message combines several encryption techniques and historical cipher methods. Only a true master cryptographer can decipher it.",
            "cipherType": "Combined Analysis",
            "ciphertext": "KQVJA OMIGN BXGTF QSOAL CFXMV IHWMN ZBWVK SXBKR ZFRJT WLKPH UVDNQ EPYAO",
            "solution": "BEYOND EVERY LOCKED DOOR LIES ANOTHER MYSTERY WAITING TO BE SOLVED",
            "hints": [
                "This combines a Vigenère cipher with columnar transposition.",
                "The keyword for the Vigenère component is 'MASTER'.",
                "After Vigenère decryption, apply a columnar transposition with the key 'CIPHER'."
            ],
            "difficulty": 5
        },
        
        # Additional challenges (16-25)
        {
            "id": 16,
            "levelId": 1,
            "title": "Numerical Alphabet",
            "description": "This intercepted message from an elite spy network converts letters to their numerical position in the alphabet.",
            "cipherType": "A1Z26",
            "ciphertext": "20 8 5 19 16 25 23 8 15 11 14 15 23 19",
            "solution": "THE SPY WHO KNOWS",
            "hints": [
                "A=1, B=2, C=3, and so on up to Z=26.",
                "Each number represents a single letter of the alphabet.",
                "The first number is 20, which corresponds to the letter 'T'."
            ],
            "difficulty": 1
        },
        {
            "id": 17,
            "levelId": 1,
            "title": "Backwards Speech",
            "description": "A mysterious character speaks in an unusual way, with each word backwards. Decipher what they're trying to tell you.",
            "cipherType": "Word Reverse",
            "ciphertext": "REVEN LLET EM EHT SDDO",
            "solution": "NEVER TELL ME THE ODDS",
            "hints": [
                "The word order remains the same.",
                "Look at each word individually.",
                "Try reversing the letters in each word while keeping the words in the same order."
            ],
            "difficulty": 1
        },
        {
            "id": 18,
            "levelId": 2,
            "title": "Typing Error",
            "description": "Someone typed this message but their hands were positioned one key to the right on their QWERTY keyboard.",
            "cipherType": "Keyboard Shift",
            "ciphertext": "YJODR O;; YJRDR [PDRR",
            "solution": "TRUST ALL THESE POWER",
            "hints": [
                "Look at your keyboard layout.",
                "Each letter is replaced by the key immediately to its right.",
                "For example, 'T' becomes 'Y' because 'Y' is to the right of 'T' on a QWERTY keyboard."
            ],
            "difficulty": 2
        },
        {
            "id": 19,
            "levelId": 2,
            "title": "Masonic Secrets",
            "description": "This ancient Freemason cipher uses symbols instead of letters. We've transcribed the symbols using letters for easier input.",
            "cipherType": "Symbol Substitution",
            "ciphertext": "QWBTZ IYAHX MPQCW DRKAY",
            "solution": "ANCIENT WISDOM AWAITS",
            "hints": [
                "The Pigpen cipher uses a specific grid pattern.",
                "Look up the Pigpen cipher grid online to decode.",
                "The first symbol corresponds to 'A'."
            ],
            "difficulty": 2
        },
        {
            "id": 20,
            "levelId": 3,
            "title": "Greek Mathematician's Puzzle",
            "description": "Invented by Polybius in ancient Greece, this cipher uses coordinates on a grid to represent letters.",
            "cipherType": "Polybius",
            "ciphertext": "4325 15 1544 43 35 21 43 23 31 34 11 21 15",
            "solution": "THEY ARE WATCHING",
            "hints": [
                "The Polybius square typically has 5 rows and 5 columns.",
                "Each letter (except J, which is combined with I) is represented by two numbers: row and column.",
                "For example, 'T' is in row 4, column 3, so it's encoded as '43'."
            ],
            "difficulty": 3
        },
        {
            "id": 21,
            "levelId": 3,
            "title": "Literary Encryption",
            "description": "This message was encoded using the first lines of a famous book as the key. Crack it to reveal the hidden meaning.",
            "cipherType": "Running Key",
            "ciphertext": "BTAFUHS AGYKRH KMCPR",
            "solution": "BETWEEN TWO WORLDS",
            "hints": [
                "The key is the opening line of Moby Dick: 'CALL ME ISHMAEL SOME YEARS AGO'",
                "Each letter is shifted based on the corresponding letter in the key phrase.",
                "For example, 'B' + 'C' = 'D' (2 + 3 = 5 = 'D')"
            ],
            "difficulty": 3
        },
        {
            "id": 22,
            "levelId": 4,
            "title": "Double Coordinates",
            "description": "This fractionating cipher combines a Polybius square with transposition to create a highly secure encryption.",
            "cipherType": "Bifid",
            "ciphertext": "UESUOMYOSVNOOHBTEEL",
            "solution": "QUANTUM ENTANGLEMENT",
            "hints": [
                "The Bifid cipher uses a 5×5 Polybius square with the keyword 'PHYSICS'.",
                "It records the row and column for each letter, then rearranges them.",
                "The process involves recording all rows, then all columns, then converting back to letters."
            ],
            "difficulty": 4
        },
        {
            "id": 23,
            "levelId": 4,
            "title": "Self-Evolving Code",
            "description": "This cipher begins with a key, but then uses the plaintext itself to continue the encryption, making it harder to break.",
            "cipherType": "Autokey",
            "ciphertext": "LFLLSGMWMJDBZDWY",
            "solution": "KNOWLEDGE IS POWER",
            "hints": [
                "The Autokey cipher uses the plaintext itself as part of the key after the initial key letter.",
                "The initial key letter is 'D'.",
                "After the first letter, each new key letter is the corresponding plaintext letter that was just decrypted."
            ],
            "difficulty": 4
        },
        {
            "id": 24,
            "levelId": 5,
            "title": "World War Secrets",
            "description": "This cipher was used by the German Army during World War I, combining fractionation and transposition for extra security.",
            "cipherType": "ADFGVX",
            "ciphertext": "FGGGAX DDAGFD AGGDFG XAXFDD FXGADA GVDFGX",
            "solution": "DECIPHER THE IMPOSSIBLE CODE",
            "hints": [
                "The ADFGVX cipher uses a 6×6 grid with the keyword 'ENIGMA'.",
                "Letters and digits are mapped to pairs of the letters A, D, F, G, V, X.",
                "After substitution, the result undergoes columnar transposition with key 'BERLIN'."
            ],
            "difficulty": 5
        },
        {
            "id": 25,
            "levelId": 5,
            "title": "Quadruple Protection",
            "description": "This cipher uses four 5×5 squares to encrypt pairs of letters, making it resistant to simple frequency analysis.",
            "cipherType": "Four-Square",
            "ciphertext": "LUDYLOZMDNHMVELNISOSGMOEH",
            "solution": "VICTORY BELONGS TO THE PERSISTENT",
            "hints": [
                "The Four-Square cipher uses four 5×5 matrices arranged in a square.",
                "The top-left and bottom-right squares contain the standard alphabet.",
                "The other two squares contain mixed alphabets based on the keywords 'VICTOR' and 'CIPHER'."
            ],
            "difficulty": 5
        }
    ]
    
    return challenges

if __name__ == '__main__':
    pass

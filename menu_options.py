from typing import Tuple
from random import sample

from menu_helpers import old_or_new_ints, old_or_new_list, what_next
import RSA_calculations as rsacalc


def generate_primes_option() -> Tuple[int, int, str]:
    """Ask the user whether their messages will need ASCII or Unicode.
    Accordingly, print a pseudo-randomly generated pair of appropriate
    primes p and q.
    Ask the user what they want to do next.
    Return p, q, and the user's choice of next step.
    """

    # These primes are from this list of all primes: 
    # https://www.math.uchicago.edu/~luis/allprimes.html
    # (divided into appropriate lists by me).
    ascii_primes = [
        13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
        89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157,
        163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
        239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313,
        317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401,
        409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487,
        491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587,
        593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661,
        673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761,
        769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859,
        863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967,
        971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039,
        1049, 1051,
        ]
    unicode_primes = [
        1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129,
        1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229,
        1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303,
        1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427,
        1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489,
        1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579,
        1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663,
        1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753,
        1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867,
        1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951,
        1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039,
        2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131,
        2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239,
        2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333,
        2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399,
        2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521,
        2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621,
        2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699,
        2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789,
        2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879,
        2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971,
        2999, 3001,
        ]
    
    # Print a security disclaimer and an explanation of ASCII vs. Unicode.
    print()
    print("Let's generate primes!")
    print()
    print(('Please note that these numbers will not be large enough for '
           'genuinely secure RSA encryption. This is for informational '
           'purposes only.'))
    print()
    print(('Will the characters in your messages require only standard ASCII '
           '(basic US English letters, numbers, and symbols) or full Unicode '
           '(non-English characters, special mathematical symbols, emoji, '
           'etc.)?'))
    print()

    # Have the user choose ASCII or Unicode.
    while True:
        user_response = input('Enter 1 for ASCII only, 2 for full Unicode: ')
        if user_response == '1':
            full_unicode = False
            break
        elif user_response == '2':
            full_unicode = True
            break
        else:
            print('Invalid response, please select one of the options')
    print()

    # Choose, print, and return a pair of pseudo-random primes from one
    # of the lists above based on the user's response.
    if full_unicode:
        p, q = sample(unicode_primes, 2)
    else:
        p, q = sample(ascii_primes, 2)
    print(f'*** Your two primes p and q are {p} and {q}.')
    direction = what_next('2') # Generate keys is option 2 on the main menu.
    return p, q, direction

def generate_keys_option(
        old_p: int, old_q: int
        ) -> Tuple[Tuple[int, int], Tuple[int, int], str]:
    """Prompt the user to either use the previously generated primes
    p and q or input new ones.
    Print public key (n, e) and private key (n, d).
    Ask the user what they want to do next.
    Return (n, e), (n, d), and the user's choice of next step.
    """
    print()
    print("Let's generate keys!")
    print("We'll start with two prime numbers.")
    print()
    p, q = old_or_new_ints(('p', 'q'), (old_p, old_q))
    n, e = rsacalc.Find_Public_Key_e(p, q)
    d = rsacalc.Find_Private_Key_d(e, p, q)
    print()
    print(f'*** Your public key (n, e) is ({n}, {e}).')
    print(f'*** Your private key (n, d) is ({n}, {d}).')
    direction = what_next('3') # Encode is option 3 on the main menu.
    return (n, e), (n, d), direction

def encode_option(old_n: int, old_e: int) -> Tuple[list, str]:
    """Prompt the user to either use the previously generated values
    for public key (n, e) or input new ones.
    Prompt the user for a plaintext message and print the ciphertext.
    Ask the user what they want to do next.
    Return the ciphertext and the user's choice of next step.
    """
    print()
    print("Let's encode a message!")
    print()
    n, e = old_or_new_ints(('n', 'e'), (old_n, old_e))
    M = input('Enter your message to be encoded: ')
    C = rsacalc.Encode(n, e, M)
    print()
    print('*** Your encoded message is:', C)
    direction = what_next('4') # Decode is option 4 on the main menu.
    return C, direction

def decode_option(old_n: int, old_d: int, old_C: list) -> str:
    """Prompt the user to either use the previously generated values for
    private key (n, d) and the ciphertext or input new ones.
    Print the plaintext.
    Ask the user what they want to do next.
    Return the user's choice of next step.
    """
    print()
    print("Let's decode a message!")
    print()
    n, d = old_or_new_ints(('n', 'd'), (old_n, old_d))
    print()
    print('Now for the ciphertext!')
    C = old_or_new_list('the ciphertext', old_C)
    M = rsacalc.Decode(n, d, C)
    print()
    print('*** Your decoded message is:', M)
    direction = what_next('5') # Break codes is option 5 on the main menu.
    return direction

def break_codes_option(old_n: int, old_e: int, old_C: list) -> str:
    """Prompt the user to either use the previously generated values for
    public key (n, e) and the ciphertext or input new ones.
    Break the code and print the plaintext.
    Ask the user what they want to do next.
    Return the user's choice of next step.
    """
    print()
    print("Let's break codes!")
    print(('Please note that this is only for relatively small n values '
           '(maximum 17 digits).'))
    print()

    # Collect the n and e values, but make sure the n value does not
    # exceed 17 digits so the code breaking can stay relatively fast.
    while True:
        n, e = old_or_new_ints(('n', 'e'), (old_n, old_e))
        if n < 100000000000000000:
            break
        else:
            print('Invalid input, please enter a smaller n')

    print()
    print('Now for the ciphertext!')
    C = old_or_new_list('the ciphertext', old_C)
    print()
    print('Breaking code... ')
    print()
    M = rsacalc.break_code(n, e, C)
    print('*** Your decoded message is:', M)
    direction = what_next('no more') # There are no more steps/menu options.
    return direction

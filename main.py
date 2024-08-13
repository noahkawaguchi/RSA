from typing import Tuple
from ast import literal_eval
from random import sample

# fundamental RSA calculation functions 

def FME(b: int, n: int, m: int) -> int:
    """quickly compute b^n mod m for b, n, and m in the domain of positive integers"""  

    assert type(b) == int and b > 0, 'b must be a positive integer'
    assert type(n) == int and n > 0, 'n must be a positive integer'
    assert type(m) == int and m > 0, 'm must be a positive integer'

    r = 1 # initialize the accumulator variable to 1 because we will be multiplying it by b

    while n > 0: # we know we will be done when we have processed all the bits of n
        k = n % 2 # determine whether the binary bit is 0 or 1
        if k == 1: # only take the binary bits that are 1
            r = (r * b) % m # accumulate the result using the current bit significance via b, take mod m because of corollary 2 p. 242
        b = (b * b) % m # increase the bit significance and do mod m, like going down one row in the Square and Mod table
        n = n // 2 # advance to the next binary bit--this is crucial to avoid an infinite loop

    return r # after exiting the while loop, we have fully accumulated the value of b^n mod m

def Euclidean_Alg(a: int, b: int) -> int:
    """calculate the greatest common divisor of a and b"""
    
    assert type(a) == int and a > 0, 'a must be a positive integer'
    assert type(b) == int and b > 0, 'b must be a positive integer'
    
    # make sure we do not try to perform the calculation with b greater than a 
    if b > a:
        a, b = b, a
    
    # as per Euclid's algorithm, GCD(a, b) = GCD(a mod b, b) 
    while b > 0:
        k = a % b
        a = b
        b = k
    
    # when one of our mod operations results in a 0, the other number (a) is the GCD 
    x = a
    return x

def EEA(a: int, b: int) -> Tuple[int, Tuple[int, int]]:
    """compute the GCD and Bézout coefficients"""
        
    assert type(a) == int and a > 0, 'a must be a positive integer'
    assert type(b) == int and b > 0, 'b must be a positive integer'

    # save the original values of a and b, then switch them if necessary to assure that we do not calculate with b greater than a 
    a0, b0 = a, b
    if b0 > a0:
        a, b = b, a
    
    s1, t1 = 1, 0 # initialize s1 and t1 so that s1(a0) + t1(b0) = a for our initial value of a 
    s2, t2 = 0, 1 # initialize s2 and t2 so that s2(a0) + t2(b0) = b for our initial value of b 
    
    while b > 0: # when one of our mod operations results in a 0, the other number (a) is the GCD 

        # calculate the integer quotient q and the remainder k when dividing a by b 
        k = a % b
        q = a // b
        
        # as per Euclid's algorithm, GCD(a, b) = GCD(a mod b, b) 
        a = b
        b = k
        
        # update the Bézout coefficients to maintain the loop invariants a = s1(a0) + t1(b0) and b = s2(a0) + t2(b0) for our new values of a and b 
        # use temporary "hat" variables because we need to use the previous values of s1, t1 when calculating the new values of s2, t2 AND vice versa 
        s1hat, t1hat = s2, t2 
        s2hat, t2hat = s1 - q * s2, t1 - q * t2
        
        s1, t1, s2, t2 = s1hat, t1hat, s2hat, t2hat  # we can now assign the values of the temp variables to our non-temp variables 

    # if we calculated with a and b flipped, flip the Bézout coefficients so they will be returned in the correct order with respect to the originally provided arguments 
    if b0 > a0:
        s1, t1 = t1, s1
    
    return a, (s1, t1) # return the GCD and Bézout coefficients 

def Find_Public_Key_e(p: int, q: int) -> Tuple[int, int]:
    """generate public key (n, e) from primes p and q"""
    
    n = p * q
    pm1qm1 = (p - 1) * (q - 1)
    
    # iterate through all potential e values until we find one that is relatively prime to (p-1)(q-1) and not equal to p or q 
    for i in range(2, pm1qm1):
        if i != p and i != q and Euclidean_Alg(pm1qm1, i) == 1:
            e = i
            break
            
    return n, e

def Find_Private_Key_d(e: int, p: int, q: int) -> int:
    """generate private key d from public key e and primes p and q"""
    
    pm1qm1 = (p - 1) * (q - 1)
    
    # it follows from Bézout's Theorem that if sa + tb = 1, then s is an inverse of a (mod b) 
    gcd, (s, t) = EEA(e, pm1qm1)
    d = s
    
    # ensure d is positive because we will be using it as an exponent in FME  
    # we can add or subtract the modulus any number of times and still maintain congruency 
    while d <= 0:
        d += pm1qm1
    
    return d

def Convert_Text(_string: str) -> list:
    """convert a string of text into a list of ASCII integers corresponding to each character"""
    integer_list = []
    for ch in _string:
        integer_list.append(ord(ch))
    return integer_list

def Convert_Num(_list: list) -> str:
    """convert a list of ASCII values into a string of their corresponding characters"""
    _string = ''
    for i in _list:
        _string += chr(i)
    return _string

def Encode(n: int, e: int, message: str) -> list:
    """encode a message into numeric cipher text"""
    
    msg_nums = Convert_Text(message)
    cipher_text = []
    
    # due to Fermat's Little Theorem and the Chinese Remainder Theorem, we get the cipher from the message using C = M^e mod n 
    for M in msg_nums:
        cipher_text.append(FME(M, e, n))
        
    return cipher_text

def Decode(n: int, d: int, cipher_text: list) -> str:
    """decode a message from its numeric cipher text"""

    # due to Fermat's Little Theorem and the Chinese Remainder Theorem, we get the message from the cipher using M = C^d mod n 
    msg_nums = []
    for C in cipher_text:
        msg_nums.append(FME(C, d, n))
    
    message = ''
    message = Convert_Num(msg_nums)
    
    return message

def factorize(n: int):
    """find the smallest factor ≥2 of a number n or return False if n is not composite"""
    for i in range(2, n):
        if n % i == 0:
            return i
    return False

def break_code(n: int, e: int, C: list):
    """break an RSA encrypted cipher C using only the public key (n, e)"""
    
    # since we know n is the product of two primes, find the smaller one through brute force 
    p = factorize(n) 
    if p == False:
        return 'Error: n is supposed to be composite'
    
    # the other of the two prime factors must be the quotient 
    q = n // p 
    
    # now that we know not only n and e, but also p and q, we can proceed with standard RSA procedures as described above 
    d = Find_Private_Key_d(e, p, q)
    M = Decode(n, d, C)
    
    return M

# user input validation functions 

def validate_pos_int(prompt: str) -> int:
    """
    Prompt the user until they enter a positive integer.
    Return the integer.
    """
    while True:
        try:
            myint = int(input(prompt))
            if myint > 0:
                return myint
            else:
                print('Invalid input, please enter a positive number')
        except ValueError:
            print('Invalid input, please enter an integer')

def validate_list(prompt: str) -> list:
    """
    Prompt the user until they enter a list.
    Return the list.
    """
    while True:
        user_input = input(prompt)
        try:
            mylist = literal_eval(user_input)
            if isinstance(mylist, list):
                return mylist
            else:
                print('Invalid input, please enter a list')
        except (ValueError, SyntaxError):
            print('Invalid input, please enter a list')

# menu option helper functions 

def old_or_new_ints(val_names: Tuple[str, str], old_values: Tuple[int, int]) -> Tuple[int, int]:
    """
    Arguments for val_names (strings) and old_values (integers) must be tuples of the same length and order. 
    Prompt the user to use the preexisting values or input new ones. 
    Return the appropriate values as a tuple. 
    """

    # only need to ask the user if they want to use the previous values if there are previous values available
    valid_values = True
    for val in old_values:
        if val <= 0:
            valid_values = False
            break
    
    # if the user just generated values in previous steps, ask if they want to use them or not
    if valid_values:
        val_names_str = ''.join(''.join(str(val_names).split("'")).split('"'))
        print(f'You previously generated the values {old_values} for {val_names_str}. Would you like to use these values or enter new ones?')
        # print(f'You previously generated the values {old_values} for {str(val_names).replace("'", '')}. Would you like to use these values or enter new ones?')
        while True:
            user_response = input('Enter 1 to use the old values, 2 to enter new ones: ')
            if user_response == '1':
                return old_values
            elif user_response == '2':
                need_new = True
                break
            else:
                print('Invalid response, please select one of the options')
    else:
        need_new = True

    # if the user rejects the previous values or there are not any, collect and return new ones
    if need_new:
        new_val_list = []
        for val_name in val_names:
            new_val = validate_pos_int(f'Enter your value for {val_name}: ')
            new_val_list.append(new_val)
        new_val_tuple = tuple(new_val_list)
        return new_val_tuple

def old_or_new_list(list_name: str, old_list: list) -> list:
    """
    Prompt the user to use the preexisting list or input a new one. 
    Return the appropriate list accordingly. 
    """

    # only need to ask the user if they want to use the previous list if there is a previous list available
    if len(old_list) > 0:
        valid_values = True
    else:
        valid_values = False

    # if the user just generated a list in previous steps, ask if they want to use it or not
    if valid_values:
        print()
        print(f'You previously generated the list {old_list} for {list_name}. Would you like to use this list or enter a new one?')
        print()
        while True:
            user_response = input('Enter 1 to use the old list, 2 to enter a new one: ')
            if user_response == '1':
                return old_list
            elif user_response == '2':
                need_new = True
                break
            else:
                print('Invalid response, please select one of the options')
    else:
        need_new = True

    # if the user rejects the previous list or there are is not one, collect and return a new one
    if need_new:
        print('Enter a list of integers separated with commas and surrounded by brackets. Example: [321, 654, 987]')
        new_list = validate_list(f'Enter your list for {list_name}: ')
        return new_list

def what_next(next_step: str) -> str:
    """
    Argument should be a numeral as a one-character string corresponding to the next step (the next menu option). 
    For example: '3'.
    If this is the last step, pass the string 'no more'. 
    Prompt the user to return to the main menu, continue to the next step, or quit the program.
    Return a string corresponding to the user's choice.
    """

    # check whether there are more steps to go to after this
    if next_step == 'no more':
        more_steps = False
    else:
        more_steps = True

    # get and return the user's choice of main menu, next step, or quit
    print()
    print('What would you like to do next?')
    while True:
        print()
        print('1 - Return to the main menu')
        if more_steps: # this option is not available when there are no more steps
            print('2 - Continue to the next step')
        print('0 - Quit')
        user_choice = input('Enter the number of your choice: ')
        if user_choice == '1':
            direction = 'menu'
            break
        elif user_choice == '2' and more_steps: # this option is not available when there are no more steps
            direction = next_step
            break
        elif user_choice == '0':
            direction = '0'
            break
        else:
            print('Invalid response, please select one of the options')
    return direction

# primary input-output functions (menu options) 

def generate_primes_option() -> Tuple[int, int, str]:
    """
    Ask the user whether their messages will need ASCII or Unicode.
    Accordingly, print a pseudo-randomly generated pair of appropriate primes p and q.
    Ask the user what they want to do next. 
    Return p, q, and the user's choice of next step.
    """

    # these primes are from this list of all primes: https://www.math.uchicago.edu/~luis/allprimes.html
    # divided into appropriate lists by me 

    ascii_primes = [13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049, 1051]

    unicode_primes = [1061, 1063, 1069, 1087, 1091, 1093, 1097, 1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693, 2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001]
    
    # security disclaimer and explanation of ASCII vs. Unicode
    print()
    print("Let's generate primes!")
    print()
    print('Please note that these numbers will not be large enough for genuinely secure RSA encryption. This is for informational purposes only.')
    print()
    print('Will the characters in your messages require only standard ASCII (basic US English letters, numbers, and symbols) or full Unicode (non-English characters, special mathematical symbols, emojis, etc.)?')
    print()

    # have the user choose ASCII or Unicode
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

    # choose, print, and return a pair of pseudo-random primes from one of the lists above based on the user's response
    if full_unicode:
        p, q = sample(unicode_primes, 2)
    else:
        p, q = sample(ascii_primes, 2)

    print(f'*** Your two primes p and q are {p} and {q}.')
    direction = what_next('2') # generate keys is option 2 on the main menu
    return p, q, direction

def generate_keys_option(old_p: int, old_q: int) -> Tuple[Tuple[int, int], Tuple[int, int], str]:
    """
    Prompt the user to either use the previously generated primes p and q or input new ones.
    Print public key (n, e) and private key (n, d).
    Ask the user what they want to do next. 
    Return (n, e), (n, d), and the user's choice of next step.
    """
    print()
    print("Let's generate keys!")
    print("We'll start with two prime numbers.")
    print()
    p, q = old_or_new_ints(('p', 'q'), (old_p, old_q))
    n, e = Find_Public_Key_e(p, q)
    d = Find_Private_Key_d(e, p, q)
    print()
    print(f'*** Your public key (n, e) is ({n}, {e}).')
    print(f'*** Your private key (n, d) is ({n}, {d}).')
    direction = what_next('3') # encode is option 3 on the main menu 
    return (n, e), (n, d), direction

def encode_option(old_n: int, old_e: int) -> Tuple[list, str]:
    """
    Prompt the user to either use the previously generated values for public key (n, e) or input new ones. 
    Prompt the user for a plaintext message and print ciphertext.
    Ask the user what they want to do next. 
    Return ciphertext and the user's choice of next step.
    """
    print()
    print("Let's encode a message!")
    print()
    n, e = old_or_new_ints(('n', 'e'), (old_n, old_e))
    M = input('Enter your message to be encoded: ')
    C = Encode(n, e, M)
    print()
    print('*** Your encoded message is:', C)
    direction = what_next('4') # decode is option 4 on the main menu
    return C, direction

def decode_option(old_n: int, old_d: int, old_C: list) -> str:
    """
    Prompt the user to either use the previously generated values for private key (n, d) and ciphertext or input new ones.
    Print plaintext.
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
    M = Decode(n, d, C)
    print()
    print('*** Your decoded message is:', M)
    direction = what_next('5') # break codes is option 5 on the main menu
    return direction

def break_codes_option(old_n: int, old_e: int, old_C: list) -> str:
    """
    Prompt the user to either use the previously generated values for public key (n, e) and ciphertext or input new ones.
    Break the code and print plaintext.
    Ask the user what they want to do next. 
    Return the user's choice of next step.
    """

    print()
    print("Let's break codes!")
    print('Please note that this is only for relatively small n values (maximum 17 digits).')
    print()

    # collect the n and e values, but make sure the n value does not exceed 17 digits so the code breaking can stay relatively fast
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
    M = break_code(n, e, C)
    print('*** Your decoded message is:', M)
    direction = what_next('no more') # there are no more steps/menu options
    return direction

# print-only functions 

def welcome(welcome_width: int) -> None:
    """print the welcome message and introduce the program using the provided width"""
    print()
    print('*' * welcome_width)
    print('WELCOME TO'.center(welcome_width))
    print("NOAH KAWAGUCHI'S".center(welcome_width))
    print('RSA PROGRAM'.center(welcome_width))
    print('(summer 2024)'.center(welcome_width))
    print('*' * welcome_width)
    print()
    print('This is a simple program that guides the user through the steps of RSA public key encryption as listed in the main menu below. To best experience the full program, it is recommended to go through the menu options in order. You can move directly from one to the next without having to return to the main menu, and you can use the values generated in previous steps without having to type them in manually! However, you can also use each menu option independently if you already have elements of RSA generated previously and/or through other means. Happy encrypting!')

def main_menu(main_menu_width: int) -> None:
    """print the main menu using the provided width"""
    print()
    print('-' * main_menu_width)
    print('Main Menu'.center(main_menu_width))
    print('-' * main_menu_width)
    print('1 - Generate Primes')
    print('2 - Generate Keys')
    print('3 - Encode')
    print('4 - Decode')
    print('5 - Break Codes')
    print('0 - Quit')
    print()

# below this is the main function and the if __name__ == "__main__" conditional

def main():
    width = 25
    welcome(width) 
    p, q, n, e, d = 0, 0, 0, 0, 0 # initialize all integer menu option arguments to 0 in case the user does not use the program in order 
    C = [] # initialize the list menu option argument to [] in case the user does not use the program in order 
    direction = 'menu' # initialize to the default value so the menu will display before there is any user input
    while True:
        # if the user chooses to move directly from one step to the next, they will be taken there directly without unnecessarily being presented with the main menu in between
        if direction == 'menu':
            main_menu(width)
            menu_choice = input('Enter the number of your choice: ')
        else:
            menu_choice = direction

        # pass and return the RSA variables so the user does not have to manually type them in if they do the steps in order
        # use the direction variable to allow the user to navigate from within menu options without having to return to the main menu every time
        if menu_choice == '1':
            p, q, direction = generate_primes_option()
        elif menu_choice == '2':
            (n, e), (n, d), direction = generate_keys_option(p, q)
        elif menu_choice == '3':
            C, direction = encode_option(n, e)
        elif menu_choice == '4':
            direction = decode_option(n, d, C)
        elif menu_choice == '5':
            direction = break_codes_option(n, e, C)
        elif menu_choice == '0':
            print()
            print('Goodbye for now!')
            print()
            break
        else:
            print('Invalid response, please select one of the options')

if __name__ == "__main__":
    main()

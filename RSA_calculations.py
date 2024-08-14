from typing import Tuple

def FME(b: int, n: int, m: int) -> int:
    """Quickly compute b^n mod m for b, n, and m in the domain of 
    positive integers.
    """  
    assert type(b) == int and b > 0, 'b must be a positive integer'
    assert type(n) == int and n > 0, 'n must be a positive integer'
    assert type(m) == int and m > 0, 'm must be a positive integer'

    # Simultaneously get each binary bit for the exponent and accumulate
    # the values corresponing to those that are 1, performing mod m at 
    # each step to keep the numbers manageable and the calculations 
    # efficient.
    r = 1
    while n > 0:
        k = n % 2
        if k == 1:
            r = (r * b) % m
        b = (b * b) % m
        n = n // 2
    return r

def Euclidean_Alg(a: int, b: int) -> int:
    """Calculate the greatest common divisor of a and b."""
    assert type(a) == int and a > 0, 'a must be a positive integer'
    assert type(b) == int and b > 0, 'b must be a positive integer'
    
    # Make sure we do not try to perform the calculation with b greater
    # than a.
    if b > a:
        a, b = b, a
    
    # As per Euclid's algorithm, GCD(a, b) = GCD(a mod b, b).
    while b > 0:
        k = a % b
        a = b
        b = k
    
    # When one of our mod operations results in a 0, the other number
    # (a) is the GCD. 
    x = a
    return x

def EEA(a: int, b: int) -> Tuple[int, Tuple[int, int]]:
    """Compute the GCD and Bézout coefficients."""
    assert type(a) == int and a > 0, 'a must be a positive integer'
    assert type(b) == int and b > 0, 'b must be a positive integer'

    # Save the original values of a and b, then switch them if necessary
    # to assure that we do not calculate with b greater than a.
    a0, b0 = a, b
    if b0 > a0:
        a, b = b, a
    
    # Initialize the coefficients so that s1(a0) + t1(b0) = a and
    # s2(a0) + t2(b0) = b for our initial values of a and b.
    s1, t1 = 1, 0
    s2, t2 = 0, 1
    
    while b > 0:
        # Calculate the integer quotient q and the remainder k when 
        # dividing a by b.
        k = a % b
        q = a // b
        
        # As per Euclid's algorithm, GCD(a, b) = GCD(a mod b, b).
        a = b
        b = k
        
        # Update the Bézout coefficients to maintain the loop invariants
        # a = s1(a0) + t1(b0) and b = s2(a0) + t2(b0) for our new values
        # of a and b.
        # Use temporary "hat" variables because we need to use the
        # previous values of s1, t1 when calculating the new values of
        # s2, t2 AND vice versa.
        s1hat, t1hat = s2, t2 
        s2hat, t2hat = s1 - q * s2, t1 - q * t2
        
        # Assign the values of the temp variables to our non-temp 
        # variables.
        s1, t1, s2, t2 = s1hat, t1hat, s2hat, t2hat

    # If we calculated with a and b flipped, flip the Bézout 
    # coefficients so they will be returned in the correct order with 
    # respect to the originally provided arguments.
    if b0 > a0:
        s1, t1 = t1, s1
    
    return a, (s1, t1) 

def Find_Public_Key_e(p: int, q: int) -> Tuple[int, int]:
    """Generate public key (n, e) from primes p and q."""
    n = p * q
    pm1qm1 = (p - 1) * (q - 1)
    
    # Iterate through all potential e values until we find one that is
    # relatively prime to (p-1)(q-1) and not equal to p or q.
    for i in range(2, pm1qm1):
        if i != p and i != q and Euclidean_Alg(pm1qm1, i) == 1:
            e = i
            break 
    return n, e

def Find_Private_Key_d(e: int, p: int, q: int) -> int:
    """Generate private key d from public key e and primes p and q."""
    pm1qm1 = (p - 1) * (q - 1)
    
    # It follows from Bézout's Theorem that if sa + tb = 1, then s is an
    # inverse of a (mod b).
    gcd, (s, t) = EEA(e, pm1qm1)
    d = s
    
    # Ensure d is positive because we will be using it as an exponent in
    # FME. (We can add or subtract the modulus any number of times and 
    # still maintain congruency).
    while d <= 0:
        d += pm1qm1
    return d

def Convert_Text(_string: str) -> list:
    """Convert a string of text into a list of the ASCII integers 
    corresponding to each character.
    """
    integer_list = []
    for ch in _string:
        integer_list.append(ord(ch))
    return integer_list

def Convert_Num(_list: list) -> str:
    """Convert a list of ASCII values into a string of their 
    corresponding characters.
    """
    _string = ''
    for i in _list:
        _string += chr(i)
    return _string

def Encode(n: int, e: int, message: str) -> list:
    """Encode a message into numeric cipher text."""
    msg_nums = Convert_Text(message)
    cipher_text = []
    
    # Due to Fermat's Little Theorem and the Chinese Remainder Theorem,
    # we get the cipher from the message using C = M^e mod n.
    for M in msg_nums:
        cipher_text.append(FME(M, e, n))
    return cipher_text

def Decode(n: int, d: int, cipher_text: list) -> str:
    """Decode a message from its numeric cipher text."""

    # Due to Fermat's Little Theorem and the Chinese Remainder Theorem,
    # we get the message from the cipher using M = C^d mod n.
    msg_nums = []
    for C in cipher_text:
        msg_nums.append(FME(C, d, n))
    message = ''
    message = Convert_Num(msg_nums)
    return message

def factorize(n: int):
    """Find the smallest factor ≥2 of a number n or return False if n is
    not composite.
    """
    for i in range(2, n):
        if n % i == 0:
            return i
    return False

def break_code(n: int, e: int, C: list):
    """Break an RSA encrypted cipher C using only the public key (n, e).
    """
    
    # Since we know n is the product of two primes, find the smaller one
    # through brute force.
    p = factorize(n) 
    if p == False:
        return 'Error: n is supposed to be composite'
    
    # The other of the two prime factors must be the quotient.
    q = n // p 
    
    # Now that we know not only n and e, but also p and q, we can
    # proceed with standard RSA procedures as described above.
    d = Find_Private_Key_d(e, p, q)
    M = Decode(n, d, C)
    return M

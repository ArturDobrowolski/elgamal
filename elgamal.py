import gmpy2 as gmpy
import math
import Crypto.Util.number
import Crypto.Random.random
from random import seed
from random import randint

def Square_rem(a, p):
    e = int((p-1) // 2)
    return Binary_exp(a, e, p)
    
def Square_root(a, p):
    e = int((p+1) // 4)
    return Binary_exp(a, e, p)

def Binary_exp(a, e, p):
    r = 1
    if 1 & e:
        r = a
    while e:
        e >>= 1
        a = (a * a) % p
        if e & 1:
            r = (r * a) % p
    return r

def Reverse_element(a, p):
    return gmpy.invert(a, p)

def Reverse_point(x, y, p):
    return x, (-y % p)

def Add_points_PP(Px, Py, A, B, p):
    x1 = Px
    y1 = Py
    lam = ((3 * (x1 ** 2) + A) * Reverse_element((2 * y1), p)) % p
    x3 = ((lam ** 2) - (2 * x1)) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return x3, y3

def Add_points_PQ(Px, Py, Qx, Qy, p):
    x1 = Px
    y1 = Py
    x2 = Qx
    y2 = Qy

    lam = ((y2 - y1) * Reverse_element((x2 - x1), p)) % p
    x3 = ((lam ** 2) - x1 - x2) % p
    y3 = (lam * (x1 - x3) - y1) % p

    return x3, y3

def Add_points(Px, Py, Qx, Qy, A, B, p):
    if Px == Qx and Py == Qy:
        return Add_points_PP(Px, Py, A, B, p)
    else:
        if (Px != Qx) or (Px == Qx) and Qy != (-Py % p):
            return Add_points_PQ(Px, Py, Qx, Qy, p)
        else:
            return 0, 0

def NP(Px, Py, A, B, p, n):
    
    isFirst = True
    Qx = Px
    Qy = Py
    while n > 0:
        if n % 2 == 1:
            if isFirst:
                Rx = Qx
                Ry = Qy
                n = n - 1
                isFirst = False
            else:
                Rx, Ry = Add_points(Rx, Ry, Qx, Qy, A, B, p)
                n = n - 1
        Qx, Qy = Add_points(Qx, Qy, Qx, Qy, A, B, p)
        n = n // 2

    return Rx, Ry

def Validate_elliptic_curve(A, B, p):
    if Compute_delta(A, B, p) != 0:
        return True
    else:
        return False

def Compute_delta(A, B, p):
    return ((4 * (A ** 3) + 27 * (B ** 2)) % p)

def Generate_random_prime(n):
    return Crypto.Util.number.getPrime(n, randfunc=Crypto.Random.get_random_bytes)

def Generate_random_number(n, m):
    return Crypto.Random.random.randint(n, m)

def Calculate_left_right(x, y, A, B, p):
    L = (y ** 2) % p
    R = ((x ** 3) + (A * x) + B) % p
    return L, R, If_point_belongs(L, R)

def If_point_belongs(L, R):
    if L == R:
        return True
    else:
        return False

def Generate_elliptic_curve(p):
    while True:
        A = Generate_random_number(0, p-1)
        B = Generate_random_number(0, p-1)
        if Validate_elliptic_curve(A, B, p):
            break
    return A, B

def Generate_random_point(A, B, p):

    while True:
        x = Generate_random_number(0, p-1)
        fx = ((x ** 3) + (A * x) + B) % p

        if Square_rem(fx, p):
            break
    y = Square_root(fx, p)

    return x, y

def Generate_hash(p):
    max = math.floor(p + 1 - 2 * math.sqrt(p))
    return Generate_random_number(2, max) 

def Generate_keypair(Px, Py, A, B, p):
    x = Generate_hash(p)
    Qx, Qy = NP(Px, Py, A, B, p, x)
    return Qx, Qy, x

def Encode(M, N, u, A, B, p):
    j = 1
    while j <= u:
        x = ((M * u) + j) % p
        fx = ((x ** 3) + (A * x) + B) % p
        if(Square_rem(fx, p)):
                y = Square_root(fx, p)
        j = j + 1
    return x, y

def Decode(x, y, u):
    return ((x-1) // u), y

def Encrypt(Px, Py, Qx, Qy, PMx, PMy, A, B, p):
    y = Generate_hash(p)
    C1x, C1y = NP(Px, Py, A, B, p, y)
    yQx, yQy = NP(Qx, Qy, A, B, p, y)
    C2x, C2y = Add_points(PMx, PMy, yQx, yQy, A, B, p)

    return C1x, C1y, C2x, C2y

def Decrypt(C1x, C1y, C2x, C2y, A, B, p, x):
    xC1x, xC1y = NP(C1x, C1y, A, B, p, x)
    rxC1x, rxC1y = Reverse_point(xC1x, xC1y, p)
    PMx, PMy = Add_points(C2x, C2y, rxC1x, rxC1y, A, B, p)
    return PMx, PMy

M=12345687830759287537983407028730982034912830917489250923743249876643687391111111111122233
u=30
N=0

p = Generate_random_prime(300)
A, B = Generate_elliptic_curve(p)

while True:
    u = Generate_random_number(30, 50)-1
    Px, Py = Generate_random_point(A, B, p)
    if Py == 1:
        p = Generate_random_prime(300)
        A, B = Generate_elliptic_curve(p)
        continue
    L, R, P_belongs = Calculate_left_right(Px, Py, A, B, p)
    if not P_belongs:
        continue
    PMx, PMy = Encode(M, N, u, A, B, p)
    L, R, M_belongs = Calculate_left_right(PMx, PMy, A, B, p)
    if P_belongs and M_belongs:
        break

Qx, Qy, x = Generate_keypair(Px, Py, A, B, p)

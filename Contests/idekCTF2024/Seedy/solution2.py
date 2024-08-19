import random
from math import ceil
from time import time
from mersenne import *
import os
from Crypto.Util.number import long_to_bytes
from random import Random
from hashlib import sha512

def urandbits(n):
    """
    get os true random bits
    """
    return int.from_bytes(os.urandom(n//8),'big')


def test_seed_mt():
    """
    test seed recovery using 3 outputs in standard MT (also used in numpy)
    takes around 200s
    """
    rand_seed = urandbits(32)
    r = MT19937(rand_seed)
    outputs = [(i,r.extract_number()) for i in range(3)]
    b = Breaker()
    recovered_seed = b.get_seed_mt(outputs)
    assert recovered_seed == rand_seed 
    print("success",recovered_seed)

def test_seed_mt_64():
    """
    test seed recovery using 3 outputs in MT19937-64
    also takes around 200s
    """
    rand_seed = urandbits(64)
    r = MT19937(rand_seed,bit_64=True)
    outputs = [(i,r.extract_number()) for i in range(3)]
    b = Breaker(bit_64=True)
    recovered_seed = b.get_seed_mt(outputs)
    assert recovered_seed == rand_seed 
    print("success",recovered_seed)


def twist(mt_orig):
    """
    helper - mersenne state twist operation
    """
    mt = [i for i in mt_orig]
    um = 0x80000000
    lm = 0x7fffffff
    a = 0x9908B0DF
    n = 624
    m = 397
    for i in range(n):
        x = (mt[i]&um) + (mt[(i+1)%n]&lm)
        xA = x>>1
        if x&1:
            xA=xA^a
        mt[i] = mt[(i+m)%n]^xA
    return mt

def tamper(num):
    """
    tamper operation for 32 bit MT
    """
    u,s,t,b,c,d,l,w,n,m = 11,7,15,0x9D2C5680,0xEFC60000,0xFFFFFFFF,18,32,624,397
    y = num
    y = y^((y>>u)&d)
    y = y^((y<<s)&b)
    y = y^((y<<t)&c)
    y = y^(y>>l)
    return y


def check_ut():
    """
    Check untwist operation to find the state before twist
    recovers all states except the first ( only 1 bit information)
    """
    rand_seed = urandbits(32)
    r = MT19937()
    r.seed_mt(rand_seed)
    untwisted_orig = [i for i in r.MT]
    outputs = [r.extract_number() for i in range(624)]
    b = Breaker()
    untampered = list(map(b.ut,outputs))
    assert list(map(tamper,untampered))==outputs
    assert twist(untwisted_orig)==untampered
    untwisted = b.untwist(untampered)
    assert twist(untwisted)==untampered
    #assert untwisted == untwisted_orig 
    #wont work we only know a single from the first element
    assert untwisted_orig[1:]==untwisted[1:]
    print("success")

def test_recover_32bit():
    rand_seed = urandbits(32)
    r = MTpython(rand_seed)
    b = BreakerPy()
    outputs = [r.extract_number() for i in range(624)]
    recovered_seed = b.get_32_bit_seed_python(outputs)
    print(rand_seed,recovered_seed)
    assert recovered_seed == rand_seed
    print("success")

def test_recover_init_by_array(x, seed=None, init_array=None, outputs=None):
    if init_array is not None:
        #init_array = [urandbits(32) for i in range(x)]
        r = MTpython(0)
        r.init_by_array(init_array)
        outputs = [r.extract_number() for i in range(624)]
    elif seed is not None:
        random.seed(seed)
        outputs = [random.getrandbits(32) for i in range(624)]
    elif outputs is None:
        raise Exception('must provide outputs')
    b = BreakerPy()
    recovered_seeds = b.get_seeds_python(outputs,x)
    #print(rand_seeds)
    #print(recovered_seeds)
    return recovered_seeds
    if rand_seeds is not None:
        assert rand_seeds==recovered_seeds
    print("success")

def int_to_array(k):
    k_byte = int.to_bytes(k,(k.bit_length()+7)//8,'little')
    k_arr = [k_byte[i:i+4] for i in range(0,len(k_byte),4)]
    return [int.from_bytes(i,'little') for i in k_arr ]

def array_to_int(arr):
    return int.from_bytes( b"".join([int.to_bytes(i,4,'little') for i in arr]) ,'little')

def test_python_int_seeds():
    """
    checking init_by_array works as intended with random.seed(integer)
    """
    r = MTpython(0)
    for i in range(1,1000):
        int_seed = urandbits(8*i)
        array_seed = int_to_array(int_seed)
        assert array_to_int(array_seed)==int_seed
        r.init_by_array(array_seed)
        random.seed(int_seed)
        assert r.get_state()==random.getstate()

def test_python_int_seeds2():
    """
    checking random.seed(integer) works as intended
    """
    r = MTpython(0)
    for i in range(1,1000):
        int_seed = urandbits(8*i)
        r.seed(int_seed)
        random.seed(int_seed)
        assert r.get_state()==random.getstate()

def test_python_seed_recovery_fast():
    """
    testing the integer seed recovery in python
    should take anywhere from 200 - 800 s
    """
    seed_len = random.randint(1,624)*32
    rand_seed = urandbits(seed_len)
    rand_seed_arr = int_to_array(rand_seed)
    random.seed(rand_seed)
    outputs = [random.getrandbits(32) for i in range(624)]
    b = BreakerPy()
    seed_arr = b.get_seeds_python_fast(outputs)
    assert seed_arr==rand_seed_arr
    print("success")

def state_recovery_rand():
    """
    state recovery using 
    """
    rand_seed = urandbits(1234)
    random.seed(rand_seed)
    state_orig = list(random.getstate()[1][:-1])
    outputs = [random.random() for i in range(624)]
    b = BreakerPy()
    recovered_state = b.state_recovery_rand(outputs)
    print(sum(i==j for i,j in zip(recovered_state,state_orig)))
    assert recovered_state == state_orig
    print("success")

def compare_ut_sat_ut(num_outs=10000):
    """
    Comparing the performance of Breaker.untamper_sat and
    Breaker.ut i.e. speed comparison of sat and direct
    algorighm
    """
    outputs = [random.getrandbits(32) for i in range(num_outs)]
    b = BreakerPy()
    start_time = time()
    ut1 = list(map(b.ut,outputs))
    time_ut = time()-start_time
    start_time = time()
    ut2 = list(map(b.untamper_sat,outputs))
    time_ut_sat = time()-start_time
    print(f'time taken by ut: {time_ut}, time taken by sat: {time_ut_sat}')
    return time_ut_sat/time_ut




#test_recover_init_by_array(5)

def solve(x):
    #rand_seeds = [urandbits(32) for i in range(x)]
    #r = MTpython(0)
    #r.init_by_array(rand_seeds)
    b = BreakerPy()
    outputs = [int(i.strip()) for i in open('test.txt').read().split('\n') if i.strip()]
    recovered_seeds = b.get_seeds_python(outputs,x)
    #print(rand_seeds)
    print(recovered_seeds)
    #assert rand_seeds==recovered_seeds
    print("success")





w, n, m, r = 32, 624, 397, 31
a = 0x9908B0DF
u, d = 11, 0xFFFFFFFF
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18
f = 1812433253

def seed_mt(seed, MT):
    MT[0] = seed
    index = n
    for i in range(1, n):
        temp = f * (MT[i - 1] ^ (MT[i - 1] >> (w - 2))) + i
        MT[i] = temp & ((1 << w) - 1)


def init_by_array(init_key):
    MT = [0] * 624
    seed_mt(19650218, MT)
    i, j = 1, 0
    for k in range(max(n, len(init_key))):
        MT[i] = (MT[i] ^ (
            (MT[i - 1] ^ (MT[i - 1] >> 30)) * 1664525)) + init_key[j] + j
        MT[i] &= 0xffffffff
        i += 1
        j = (j+1)%len(init_key)
        if i >= n:
            MT[0],i = MT[n - 1],1
    for k in range(n - 1):
        MT[i] = (MT[i] ^ (
            (MT[i - 1] ^ (MT[i - 1] >> 30)) * 1566083941)) - i
        MT[i] &= 0xffffffff
        i += 1
        if i >= n:
            MT[0],i = MT[n - 1],1
    MT[0] = 0x80000000
    return MT


wtf = b'abcdefghi'
# set x = 19 for this test case
obj_hash = int.from_bytes(wtf + sha512(wtf).digest(), byteorder='big')


arrs = []
oo = obj_hash
while oo != 0:
    arrs.append(oo & 0xffffffff)
    oo = oo >> 32
print('len of arr to be passed to init_array', len(arrs))


####### test by passing in the init_array for it to generate the required 624 outputs
# recovered_seeds = test_recover_init_by_array(19, init_array=arrs)
# test_flag = b''
# for i in recovered_seeds:
#     test_flag = long_to_bytes(i) + test_flag
# print('test_flag', test_flag)

# ####### test by passing in seed directly to let it generate the required 624 outputs
# recovered_seeds = test_recover_init_by_array(19, seed=wtf)
# test_flag = b''
# for i in recovered_seeds:
#     test_flag = long_to_bytes(i) + test_flag
# print('test_flag', test_flag)


# recovered_seeds = test_recover_init_by_array(ceil((1226+64)*8/32), seed=b'abcdefghijklmnopqrstuvwxyz'+b'A'*1200)
# test_flag = b''
# for i in recovered_seeds:
#     test_flag = long_to_bytes(i) + test_flag
# print('test_flag', test_flag)



################## REAL SOLVE ##########################################################

# now we just pass our outputs to it......why not working???
outputs = []

###### these states stuff are purely optional, we only need the outputs
state = (3, (2147483648, 2980082499, 2783981764, 3961306090, 2717514318, 2469969357, 4076833896, 1879098621, 1508007984, 1809243470, 1767091472, 2134789420, 2427028676, 1581777860, 525523944, 752538384, 2142159275, 861784629, 1574690472, 1983535713, 3006857935, 2851508090, 2084278739, 1601639983, 1855741519, 740018076, 3814322795, 227653141, 2235952244, 2066727044, 3496241705, 134309826, 1717659116, 2047585885, 1783232417, 2950752139, 3272267627, 1844012732, 261934900, 3751031698, 4183484319, 663011639, 742441946, 3482588614, 871342339, 2951785870, 1345191772, 1217546531, 2856947294, 2116877232, 1483171004, 3406970212, 3126817414, 3421345934, 694826064, 1147794606, 1022707133, 795509522, 3785115320, 4021562601, 3410037676, 2309521533, 3551080264, 1038806187, 3217034096, 2990109801, 352304034, 1077414360, 237180878, 3443735555, 2496971090, 2843084760, 3497087375, 2438851815, 606149404, 1770331712, 1903923836, 4098633880, 3229186043, 1245745195, 2163119911, 536048981, 3861042956, 1493718406, 2537483808, 1450728067, 2451082726, 2541915635, 1253406275, 3304390544, 2654457049, 83340324, 3117883092, 448529645, 3186456693, 1529614109, 3387703949, 2166444559, 3933000506, 855228964, 2623381821, 4154285518, 1052426841, 3489338961, 2610225042, 991235194, 4180510471, 4027858213, 2883351994, 3283622006, 683727219, 1818044453, 2622444793, 311350295, 3094745989, 1852865076, 2999344937, 4087716198, 3329472614, 1290861984, 2711093514, 332408047, 245145117, 601940354, 2538456812, 2170479433, 1447136375, 2799480922, 2703608568, 368948833, 2869375923, 2236668273, 3793329477, 3584997187, 2416996726, 3434807455, 1099997871, 2578369856, 596059112, 2072549020, 3839005023, 2650558326, 2844786311, 922755358, 2039577321, 343043440, 4169769362, 3643757975, 917475681, 2780852300, 3188342021, 651394637, 4066915622, 2287425219, 3439052759, 2190975869, 2430344366, 3870127233, 1486406625, 2536964508, 161694893, 4030709679, 1609214975, 2922498031, 3727334665, 2219658876, 2622494215, 3459695653, 3107928126, 2195453127, 2574489037, 1687043270, 3671214744, 3897743684, 3784153119, 817368387, 2968150237, 2426691409, 3135845696, 902413978, 2181125081, 1478877218, 2470500025, 3494215788, 2374848259, 3790365549, 3424468113, 1829846151, 3285314613, 1165158573, 1031035640, 2938233846, 948511448, 1591666631, 1948696073, 3339682422, 2103132469, 2700723753, 2978167339, 255757838, 3533894361, 3904404204, 379222179, 3584184268, 783192744, 1155490761, 2753287794, 70903329, 2772578076, 1326643330, 1394308487, 342467981, 439507899, 4052971562, 709726089, 1192435781, 2909764749, 1186867325, 144925924, 1772069651, 2735187480, 1698389058, 1663798192, 3680663961, 516066988, 3972220408, 1884998997, 3203798406, 1332339042, 3067338585, 282983489, 2557215009, 1595172076, 1122331858, 374127804, 2255675778, 1014676118, 2285340553, 3137784685, 1438389782, 3289235184, 627125239, 213827249, 2532627539, 3695210599, 3143239360, 1171614440, 2276121172, 2661552226, 734639904, 1407574546, 1434980770, 1356346727, 3121959617, 1867849056, 2351573794, 693697013, 789938016, 2045733820, 2251406975, 1461326574, 1298490761, 2331652320, 2397722925, 535458781, 1413735090, 813355734, 3345739698, 4255234286, 1924182613, 3798103212, 3684892822, 1016926220, 3558562718, 2954138494, 1921160053, 3425274233, 3254419266, 4002887628, 94038416, 1960692556, 1078500688, 2706076577, 2188544229, 2471427441, 2301478002, 487944158, 478155699, 1082015815, 1330980733, 3700387449, 2152095671, 922332250, 3221133071, 893191175, 545725798, 161252134, 3817825835, 3376103873, 942973866, 1176575851, 684998352, 1391842573, 2218835078, 4223586659, 222032513, 1258108705, 1135094818, 585515, 3855400281, 3657767871, 2046199845, 3121658453, 2879536589, 252809465, 1523427597, 2055730801, 2158673831, 3327500188, 3670174857, 3938679413, 1714344919, 4083245583, 2630353250, 1073137531, 1311099930, 417782646, 2341471218, 4065445312, 3383405942, 2106143667, 3203318577, 2406409501, 3443052583, 1503139941, 3902227548, 1599849130, 1947190385, 1231717360, 3831236604, 1169201325, 74841197, 1520386053, 1073229184, 2148357543, 2505027843, 2387773519, 2618976752, 3749967478, 2846784703, 2607013704, 3070758790, 2136472139, 1683715804, 2395088763, 222152956, 4058011847, 1620832056, 33062112, 1181112480, 2494421181, 1188403428, 1760407216, 123420953, 2482035420, 1392643755, 2769120267, 1699557597, 1797114145, 3558480449, 253900022, 3291402505, 3951882160, 1402292740, 4027551149, 599065859, 2311396680, 1271158560, 574118488, 2732869537, 2054281469, 90886942, 1471716488, 322737584, 4197207078, 954886209, 4139306335, 543369601, 3837461555, 486644114, 2851644728, 3610270897, 3237810272, 727055086, 2097323158, 1507184917, 2245114695, 2654500138, 2789308998, 221424795, 3221715031, 2246288005, 3397372579, 3088458404, 375059167, 357357431, 1413288867, 3050893940, 2641050678, 4135754825, 3092041212, 280872912, 1746970949, 2853318812, 2520364003, 4183504033, 2084040209, 2203192883, 822874743, 2969549382, 3214399491, 3382289838, 2948583187, 2236216387, 699205573, 2884835730, 1371860016, 2891850692, 2140184695, 2294931267, 1101788855, 4098661709, 1611117481, 710868960, 729401051, 3691447052, 3361318048, 2263569884, 3384618396, 2617994832, 2362652198, 1134142201, 1666798832, 1591001802, 1491400486, 501451660, 2172472504, 592945510, 3874135502, 3190977409, 1811309101, 1101743472, 343303296, 283509358, 3189762559, 961225809, 2817337342, 1465950053, 602157387, 1878857285, 292232307, 2322975871, 3175665114, 1450785937, 608062064, 3025925011, 28013109, 1049960875, 1483203631, 1478951299, 486876706, 329350634, 2082696378, 1357755675, 1813508859, 941897120, 3933388951, 3057636208, 2894563269, 4141828842, 2353008809, 3674223082, 3700164560, 1197002676, 2413400795, 1006332469, 3363789409, 1051046350, 2595868716, 1549051102, 94802779, 1479052741, 4195764327, 2318433823, 3081697604, 2908420127, 3333696831, 1612962447, 2065522179, 2155588924, 2573193817, 1112065580, 1753555115, 4112431915, 1205776391, 3177114581, 1641348916, 3420393406, 2190196953, 1018479303, 3989368651, 4145830965, 3250521893, 3528490253, 1380741374, 730833982, 3597892323, 2254079165, 1509805388, 2095220852, 2162420536, 4159980985, 1800913524, 2994494689, 2746903934, 1949364356, 1345896340, 1323660802, 1536398139, 174434523, 3763455422, 175516793, 3742750952, 3073953555, 3687109449, 3991712835, 3870104611, 226371161, 42841575, 946255381, 2483925487, 2998177690, 3212092608, 3926959475, 2295901337, 287575096, 4127460814, 4194443592, 2246035378, 1313621275, 1877147166, 2115081124, 1354138177, 3651812243, 1814987211, 3250698361, 939906410, 107854025, 1111817755, 806379694, 1128488691, 206969567, 3490771360, 2299367946, 4218552386, 729170452, 1839138670, 3931104003, 1544919082, 2400296532, 4241202988, 1518070707, 532654915, 403039728, 3218325572, 3405581796, 2813205965, 1002322724, 3912960148, 170742726, 1478405832, 2352358774, 4214574163, 1298988853, 2833694335, 309099446, 1909980628, 2693837098, 3368102560, 3997329240, 765716693, 2001707812, 3519069031, 287391838, 4183753825, 1336036541, 3956343525, 3111293186, 912682723, 2712564780, 4113763771, 2368097275, 807481095, 2414126690, 3774766616, 1041972203, 1764568077, 2354532272, 4242849088, 1689052212, 3697643322, 1823625327, 1989396246, 2423554201, 4200164012, 1076416720, 793986600, 3013744368, 610989575, 267651367, 505987659, 3341383373, 30559234, 186324706, 624), None)
rflag = Random()
rflag.setstate(state)
for i in range(624):
    outputs.append(rflag.getrandbits(32))


#test_recover_init_by_array(19, rand_seeds=arrs)

for k in range(ceil((1787+64) * 8 / 32), 64, -1):
    print('k', k)
    try:
        recovered_seeds = test_recover_init_by_array(k, outputs=outputs)

        if recovered_seeds is not None:
            flags = b''
            for i in recovered_seeds:
                flags += long_to_bytes(i)
            print(flags)
            print('k', k)
            print('------------')
            if b'idek{' in flags:
                break
    except KeyboardInterrupt:
        raise
    # except:
    #     continue
#solve(19)

#rand_seed = urandbits(96)
#random.seed(rand_seed)
#outputs = [random.getrandbits(32) for i in range(624)]
#b = BreakerPy()

#r = MTpython(0)
#r.init_by_array([0x44434241,0x48474645,0x49])
#random.seed(0x494847464544434241)
#print(r.get_state()==random.getstate())
#r.init_by_array([0x44434241])
#init_state = r.MT.copy()
#r.init_32bit_seed(0x44434241)
#random.seed(0x44434241)
#print(r.get_state()==random.getstate())
#outputs = [r.extract_number() for i in range(3000)]
#untampered = list(map(b.ut,outputs))

#r2 = random.Random()
#r2.setstate(r.get_state())
#initial = r.get_state()
#assert r.get_state() == r2.getstate()
#o1 = [r.extract_number() for i in range(1000)]
#o2 = [r2.getrandbits(32) for i in range(1000)]
#common = list(set(o1)&set(o2))
#test()
#test_64()
#outputs = [random.getrandbits(32) for i in range(3)]
#b = Breaker()
#print(b.get_seed(outputs))

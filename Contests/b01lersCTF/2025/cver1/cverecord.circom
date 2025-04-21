pragma circom 2.1.9;

// SEE BELOW FOR PUBLIC INPUTS
template CVERecord() {
	signal input year;
	signal input id;
	signal input name[32];

	signal i1;
	signal i2;

	signal output existing;

	i1 <-- year;
	component yr_leq = LessEqThan(16);
	yr_leq.in[0] <-- i1;
	yr_leq.in[1] <== 2025;
	1 === yr_leq.out;

	i2 <-- id;
	component id_leq = LessEqThan(16);
	id_leq.in[0] <== i2;
	id_leq.in[1] <== 20035;
	1 === id_leq.out;

	name[0] === 68;
	name[1] === 79;
	name[2] === 71;
	name[3] === 69;

	component and = AND();
	and.a <== yr_leq.out;
	and.b <== id_leq.out;

	existing <== and.out;
}

// Source: circomlib (pretend like the below are includes)

template AND() {
    signal input a;
    signal input b;
    signal output out;

    out <== a*b;
}

template LessEqThan(n) {
    signal input in[2];
    signal output out;

    component lt = LessThan(n);

    lt.in[0] <== in[0];
    lt.in[1] <== in[1]+1;
    lt.out ==> out;
}


// Source: circomlib (pretend like this is an include)
template LessThan(n) {
    assert(n <= 252);
    signal input in[2];
    signal output out;

    component n2b = Num2Bits(n+1);

    n2b.in <== in[0]+ (1<<n) - in[1];

    out <== 1-n2b.out[n];
}

// Source: circomlib (pretend like this is an include)
template Num2Bits(n) {
    signal input in;
    signal output out[n];
    var lc1=0;

    var e2=1;
    for (var i = 0; i<n; i++) {
        out[i] <-- (in >> i) & 1;
        out[i] * (out[i] -1 ) === 0;
        lc1 += out[i] * e2;
        e2 = e2+e2;
    }

    lc1 === in;
}

component main{
	public [year, id]
} = CVERecord();


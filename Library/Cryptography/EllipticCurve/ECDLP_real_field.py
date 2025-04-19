# def ECDLP_real_field(a, b, P, Q, precision: int = 200):
# 	from mpmath import mp, polyroots, sqrt, ellipk
# 	mp.dps = 200
# 	a, b = mp.mpf(a), mp.mpf(b)
# 	def elliptic_log(x):
# 		return mp.quad(lambda z: 1 / mp.sqrt(z**3 + a * z + b), [-mp.inf, x])
# 	g2, g3 = -4 * a, -16 * b
# 	r1, r2, r3 = sorted(polyroots([4, 0, -g2, -g3]), key = lambda z: z.real, reverse = True)
# 	w = ellipk((r1 - r2) / (r1 - r3)) / sqrt(r1 - r3)
# 	print(f"{r1 = }, {r2 = }, {r3 = }")
# 	print(f"{w = }")
# 	print(f"{elliptic_log(P[0]) = }")
# 	print(f"{elliptic_log(Q[0]) = }")
# if __name__ == "__main__":
# 	from mpmath import mp
# 	mp.dps = 200
# 	ECDLP_real_field(-1, 0,
# 		(mp.mpf("1.15939524880832589559531697886995971202850341796875"), 0),
# 		(mp.mpf("1052.1869486109503324827555468817188804055933729601321435932864694301534931492427433020783168479195188024409373571681097603398390379320742186401833284576176214641603772370675124838606986281131453644941"), 0),
# 		200
# 	)
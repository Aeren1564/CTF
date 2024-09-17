obj = 10103

for ca in range(10):
	for a in range(0, 17 if ca else 1):
		for cb in range(10):
			for b in range(0, 10 if cb else 1):
				for cc in range(10):
					for c in range(0, 7 if cc else 1):
						for cd in range(2):
							for d in range(0, 7 if cd else 1):
								for ce in range(2):
									for e in range(0, 6 if ce else 1):
										for cf in range(2):
											for f in range(0, 5 if cf else 0):
												value = ca * 2**a + cb * 3**b + cc * 5**c + cd * 6**d + ce * 7**e + cf * 10**f
												if (ca == 0) + (cb == 0) + (cc == 0) + (cd == 0) + (ce == 0) + (cf == 0) >= 4 and abs(obj - value) <= 10:
													if ca:
														print(f"{ca = }, {a = }")
													if cb:
														print(f"{cb = }, {b = }")
													if cc:
														print(f"{cc = }, {c = }")
													if cd:
														print(f"{cd = }, {d = }")
													if ce:
														print(f"{ce = }, {e = }")
													if cf:
														print(f"{cf = }, {f = }")
													print(f"{obj - value = }")
													print()

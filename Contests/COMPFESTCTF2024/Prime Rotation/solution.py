from CTF_Library import *

ct = 112069250204847858434951864919494772437772309551100894283802890969294921153695033680308824238138045767163824928036225288640262479846659348456350274690146950091938837191909645393428229485475109811982995836390466223992421552045075462248484268261988513215970281479307051354279950516448154191270415379751945199844597328599643336925042296451667124633421375106611252124455800238151031224064949216810203270294287136489525063218922502754179790238733845401863560349247348618842377798382953621069669066126553437295321747661018783680078904246779293823424410074601480963728455972270367310938167374435974788290895
n = 338157083965246057571026756360795557480615383698977322739773119119768631064965448629444858368455612367321181172346297206715981930133542614118983474663804909611201532833645460572467511167118907653891577684641980804552415671777685960512779105153093618092748148197835625397758340520102160357258334250293520469968267915267730466529829639830017519012622973967936476883318368260247264026111745427467952456821708517718723537977525795647439220142795157435101213559895031087961640507169858237537062387315301224943694997736792045576174622866155698202883578606065005204942324227724078229357430907077534468953279

for shift_ac in range(0, 5):
	for shift_ab_bc in range(0, 5):
		try:
			ac = (int(str(n)[ : -500]) - shift_ac) * 10**100 + int(str(n)[-100 : ])
			print(f"{ac = }")
			print()
			assert 0 <= ac < 10**200

			n_exc_ac = n - (1 + 10**400) * ac
			assert n_exc_ac % 10**100 == 0
			n_exc_ac //= 10**100
			print(f"{n_exc_ac = }")
			print()

			ab_bc = (int(str(n_exc_ac)[ : -300]) - shift_ab_bc) * 10**100 + int(str(n_exc_ac)[-100 : ])
			print(f"{ab_bc = }")
			print(f"{len(str(ab_bc)) = }")
			print()
			assert 0 <= ab_bc < 2 * 10**200

			aa_bb_cc = n_exc_ac - (1 + 10**200) * ab_bc
			assert aa_bb_cc % 10**100 == 0
			aa_bb_cc //= 10**100
			print(f"{aa_bb_cc = }")
			print()
			assert 0 <= aa_bb_cc < 3 * 10**200

			print(f"{factor(ac) = }")
			exit(0)
		except Exception as e:
			print(e)
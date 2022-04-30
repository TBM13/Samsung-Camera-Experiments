#### Enable Raw & other features (Set Available Capabilities value to 31):
	Address		Old Value	New Value
	000ABA08:	78		1F
	000ABA09:	21		23
	000ABA0C:	48		38
	000ABA0D:	16		36

#### Set Hardware Level to 1 (FULL):
	Address		Old Value	New Value
	000AB965:	86		66

#### Set Black Level Pattern to [64, 64, 64, 64] (fixes pink tint on RAW photos):
	Address		Old Value	New Value
	000AB859:	F4		F0
	000AB85A:	7A		40
	000AB85B:	70		00

#### Don't override Available Capabilities value on camera configs:
	Address		Old Value	New Value
	000AE3A6:	C0		00
	000AE3A7:	F8		00
	000AE3A8:	38		00
	000AE3A9:	56		00

	000B15C2:	C4		00
	000B15C3:	F8		00
	000B15C4:	38		00
	000B15C5:	06		00

	000B45A8:	C4		00
	000B45A9:	F8		00
	000B45AA:	38		00
	000B45AB:	06		00

#### Don't override Hardware Level value on camera configs:
	Address		Old Value	New Value
	000AE3B0:	80		00
	000AE3B1:	F8		00
	000AE3B2:	30		00
	000AE3B3:	86		00

	000B15AA:	84		00
	000B15AB:	F8		00
	000B15AC:	30		00
	000B15AD:	56		00

	000B4590:	84		00
	000B4591:	F8		00
	000B4592:	30		00
	000B4593:	56		00

#### Don't override Black Level Pattern value on camera configs:
	Address		Old Value	New Value
	000AE5E8:	41		00
	000AE5E9:	F9		00
	000AE5EA:	CF		00
	000AE5EB:	0A		00

	000B17FD:	F9		00
	000B17FE:	CF		00
	000B17FF:	8A		00

	000B47E1:	F9		00
	000B47E2:	CF		00
	000B47E3:	8A		00
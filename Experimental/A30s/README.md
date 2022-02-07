#### Similar issues to the A12 Nacho (A12s). GCam Freezes

#### Enable Raw & other features (Set Available Capabilities value to 63):
	Address		Old Value	New Value
	000BE898:	C4			3F
	000BE899:	F8			22
	000BE89A:	04			00
	000BE89B:	58			00
	000BE89E:	00			38
	000BE89F:	58			26

#### Set Hardware Level to 1 (FULL):
	Address		Old Value	New Value
	000BE7DD:	86			66

#### Set Black Level Pattern to [64, 64, 64, 64] (fixes pink tint on RAW photos):
	Address		Old Value	New Value
	000BE6D1:	F4			F0
	000BE6D2:	7A			40
	000BE6D3:	70			00

#### Don't override Available Capabilities value on camera configs:
	Address		Old Value	New Value
	000A96FE:	01			3F
	
	000C33A8:	C0			00
	000C33A9:	F8			00
	000C33AA:	38			00
	000C33AB:	66			00

	000C7528:	C4			00
	000C7529:	F8			00
	000C752A:	38			00
	000C752B:	06			00

	000C8D16:	C4			00
	000C8D17:	F8			00
	000C8D18:	38			00
	000C8D19:	06			00

	000C92B6:	C4			00
	000C92B7:	F8			00
	000C92B8:	38			00
	000C92B9:	06			00

#### Don't override Hardware Level value on camera configs:
	Address		Old Value	New Value
	000C3420:	80			00
	000C3421:	F8			00
	000C3422:	30			00
	000C3423:	26			00

	000C7510:	84			00
	000C7511:	F8			00
	000C7512:	30			00
	000C7513:	56			00

	000C8CFE:	84			00
	000C8CFF:	F8			00
	000C8D00:	30			00
	000C8D01:	66			00

	000C929E:	84			00
	000C929F:	F8			00
	000C92A0:	30			00
	000C92A1:	56			00

#### Don't override Black Level Pattern value on camera configs:
	Address		Old Value	New Value
	000C35EC:	43			00
	000C35ED:	F9			00
	000C35EE:	CF			00
	000C35EF:	6A			00

	000C7761:	F9			00
	000C7762:	CF			00
	000C7763:	8A			00

	000C8F47:	F9			00
	000C8F48:	CF			00
	000C8F49:	8A			00

	000C94F1:	F9			00
	000C94F2:	CF			00
	000C94F3:	8A			00
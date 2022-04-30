## October 15 Library
#### Enable Raw & other features (Set Available Capabilities value to 31):
	Address		Old Value	New Value
	000B1AE4:	78			1F
	000B1AE8:	48			38

#### Set Hardware Level to 1 (FULL):
	Address		Old Value	New Value
	000B1A45:	86			66

#### Set Black Level Pattern to [64, 64, 64, 64] (fixes pink tint on RAW photos):
	Address		Old Value	New Value
	000B1939:	F4			F0
	000B193A:	7A			40
	000B193B:	70			00

#### Don't override Available Capabilities value on camera configs:
	Address		Old Value	New Value
	000B223E:	C0			00
	000B223F:	F8			00
	000B2240:	38			00
	000B2241:	46			00

	000BB336:	C4			00
	000BB337:	F8			00
	000BB338:	38			00
	000BB339:	06			00
	
	000BB912:	C4			00
	000BB913:	F8			00
	000BB914:	38			00
	000BB915:	86			00

#### Don't override Hardware Level value on camera configs:
	Address		Old Value	New Value
	000B2226:	80			00
	000B2227:	F8			00
	000B2228:	30			00
	000B2229:	86			00

	000BB31E:	84			00
	000BB31F:	F8			00
	000BB320:	30			00
	000BB321:	56			00

	000BB91A:	84			00
	000BB91B:	F8			00
	000BB91C:	30			00
	000BB91D:	66			00

#### Don't override Black Level Pattern value on camera configs:
	Address		Old Value	New Value
	000B246A:	41			00
	000B246B:	F9			00
	000B246C:	CF			00
	000B246D:	0A			00

	000BB57F:	F9			00
	000BB580:	CF			00
	000BB581:	8A			00

	000BBB65:	F9			00
	000BBB66:	CF			00
	000BBB67:	8A			00

## April 17 Library
#### Enable Raw & other features (Set Available Capabilities value to 31):
	Address		Old Value	New Value
	000B15C4:	C4		1F
	000B15C5:	F8		22
	000B15C6:	00		00
	000B15C7:	58		00
	000B15DA:	2C		38
	000B15DB:	56		26

#### Set Hardware Level to 1 (FULL):
	Address		Old Value	New Value
	000B1505:	86		66

#### Set Black Level Pattern to [64, 64, 64, 64] (fixes pink tint on RAW photos):
	Address		Old Value	New Value
	000B13F9:	F4		F0
	000B13FA:	7A		40
	000B13FB:	70		00

#### Don't override Available Capabilities value on camera configs:
	Address		Old Value	New Value
	000B1CFE:	C0		00
	000B1CFF:	F8		00
	000B1D00:	38		00
	000B1D01:	46		00

	000BADF6:	C4		00
	000BADF7:	F8		00
	000BADF8:	38		00
	000BADF9:	06		00

	000BB3D2:	C4		00
	000BB3D3:	F8		00
	000BB3D4:	38		00
	000BB3D5:	86		00

#### Don't override Hardware Level value on camera configs:
	Address		Old Value	New Value
	000B1CE6:	80		00
	000B1CE7:	F8		00
	000B1CE8:	30		00
	000B1CE9:	86		00

	000BADDE:	84		00
	000BADDF:	F8		00
	000BADE0:	30		00
	000BADE1:	56		00

	000BB3DA:	84		00
	000BB3DB:	F8		00
	000BB3DC:	30		00
	000BB3DD:	66		00

#### Don't override Black Level Pattern value on camera configs:
	Address		Old Value	New Value
	000B1F2A:	41		00
	000B1F2B:	F9		00
	000B1F2C:	CF		00
	000B1F2D:	0A		00

	000BB03F:	F9		00
	000BB040:	CF		00
	000BB041:	8A		00

	000BB625:	F9		00
	000BB626:	CF		00
	000BB627:	8A		00
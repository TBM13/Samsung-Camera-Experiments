Main Back Camera: IMX258/S5K3L6 13MP<br>
Super Wide Camera: SR556 5MP<br>
Front Camera: S5K4HA 8MP<br>

#### Enable Raw & other features (Set Available Capabilities value to 31):
	Address		Old Value	New Value
	000AB4F0:	04		1F
	000AB4F1:	F5		23
	000AB4F2:	F5		C4
	000AB4F3:	61		F8
	000AB4F4:	01		38
	000AB4F5:	F9		36
	000AB4F6:	CF		00
	000AB4F7:	8A		00

#### Set Hardware Level to 1 (FULL):
	Address		Old Value	New Value
	000AB47D:	86		66

#### Set Black Level Pattern to [64, 64, 64, 64] (fixes pink tint on RAW photos):
	Address		Old Value	New Value
	000AB371:	F4		F0
	000AB372:	7A		40
	000AB373:	70		00

#### Don't override Available Capabilities value on camera configs:
	Address		Old Value	New Value
	000AF452:	C0		00
	000AF453:	F8		00
	000AF454:	38		00
	000AF455:	56		00

	000B10DA:	C4		00
	000B10DB:	F8		00
	000B10DC:	38		00
	000B10DD:	06		00

	000B40C0:	C4		00
	000B40C1:	F8		00
	000B40C2:	38		00
	000B40C3:	06		00

#### Don't override Hardware Level value on camera configs:
	Address		Old Value	New Value
	000AF45C:	80		00
	000AF45D:	F8		00
	000AF45E:	30		00
	000AF45F:	16		00

	000B10C2:	84		00
	000B10C3:	F8		00
	000B10C4:	30		00
	000B10C5:	56		00

	000B40A8:	84		00
	000B40A9:	F8		00
	000B40AA:	30		00
	000B40AB:	56		00

#### Don't override Black Level Pattern value on camera configs:
	Address		Old Value	New Value
	000AE100:	41		00
	000AE101:	F9		00
	000AE102:	CF		00
	000AE103:	0A		00

	000AF68C:	42		00
	000AF68D:	F9		00
	000AF68E:	CF		00
	000AF68F:	0A		00

	000B1315:	F9		00
	000B1316:	CF		00
	000B1317:	8A		00
	
	000B42F9:	F9		00
	000B42FA:	CF		00
	000B42FB:	8A		00

---------------------------------------------------------------

### Available Capabilities - Function of each bit:
0x80 Depth Output (for depth camera sensors)<br>
0x40 Yuv Reprocessing<br>
0x20 Zero Shutter Lag & Private Reprocessing<br>
0x10 Scaler Stream Output Format & Raw<br>
0x8    Burst Capture<br>
0x4    Manual Post Processing<br>
0x2    Manual Sensor & Read Sensor settings<br>

0x100 Constrained High Speed Video<br>
0x200 Motion Tracking<br>
0x400 Logical Multi Camera<br>
0x800 Secure Image Data<br>
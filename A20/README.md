Main Back Camera: IMX258 13MP<br>
Super Wide Camera: SR556 5MP<br>
Front Camera: S5K4HA 8MP<br>

### New patch (set value in ExynosCameraSensorInfoBase and don't override it in camera configs):
	Enable Raw & other features (Set Available Capabilities value to 63):
		000AB4F0: 04 3F
		000AB4F1: F5 23
		000AB4F2: F5 C4
		000AB4F3: 61 F8
		000AB4F4: 01 38
		000AB4F5: F9 36
		000AB4F6: CF 00
		000AB4F7: 8A 00
	
	Set Hardware Level to 1 (FULL):
		000AB47D: 86 66
	
	Don't override Available Capabilities value on camera configs:
		000AF452: C0 00
		000AF453: F8 00
		000AF454: 38 00
		000AF455: 56 00
		000B10DA: C4 00
		000B10DB: F8 00
		000B10DC: 38 00
		000B10DD: 06 00
		000B40C0: C4 00
		000B40C1: F8 00
		000B40C2: 38 00
		000B40C3: 06 00
	
	Don't override Hardware Level value on camera configs:
		000AF45C: 80 00
		000AF45D: F8 00
		000AF45E: 30 00
		000AF45F: 16 00
		000B10C2: 84 00
		000B10C3: F8 00
		000B10C4: 30 00
		000B10C5: 56 00
		000B40A8: 84 00
		000B40A9: F8 00
		000B40AA: 30 00
		000B40AB: 56 00

### Old Patch (modify each camera config):
	Back Camera:
		Enable Raw & other features (Set Available Capabilities value to 63):
			000AF45F: 16 36
			000AF708: 43 3F
			000AF709: F2 22
			000AF70A: 33 C0
			000AF70B: 32 F8
			000AF70C: C4 38
			000AF70D: F2 26
			000AF70E: 3B 00
			000AF70F: 22 00
			000AF710: C0 00
			000AF711: F8 00
			000AF712: 84 00
			000AF713: 22 00

		Set Hardware Level to 1 (FULL):
			000AF45F: 16 36

---------------------------------------------------------------

### Available Capabilities - Function of each bit:
0 0 0 0 -4 -3 -2 -1   &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;   1 2 3 4 5 6 7 0

1: 0x80 Depth Output (for depth camera sensors)<br>
2: 0x40 Yuv Reprocessing<br>
3: 0x20 Scaler Stream Input Format & Private Reprocessing<br>
4: 0x10 Scaler Stream Output Format & Raw<br>
5: 8    Burst Capture<br>
6: 4    Manual Post Processing<br>
7: 2    Manual Sensor & Read Sensor settings<br>

-1: 0x100 Constrained High Speed Video<br>
-2: 0x200 Motion Tracking<br>
-3: 0x400 Logical Multi Camera<br>
-4: 0x800 Secure Image Data<br>

00000001 (1) (base)<br>
00001001 (9) (A20 stock value of all cameras)<br>
00001111 (15)<br>
00111111 (63) (Value applied by this patch)<br>
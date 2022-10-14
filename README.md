# IFaultrepElevatedDataCollectionUAC

PoC for UAC bypass using arbitrary file delete in auto-elevated IFaultrepElevatedDataCollection COM object.
Arbitrary file delete is abused to get SYSTEM shell using method described here https://www.thezdi.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks

This PoC will just execute cmd.exe as system so in order to performe other actions such as executing different binary new RBS file should be created (using wix or other  tools).

If you want to test this PoC it is the best to do it on system with minimum of 4 processor cores.


https://user-images.githubusercontent.com/44291883/195949020-06764265-3e9a-4bfd-9d27-636da16d5570.mp4



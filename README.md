
# PS4 wifi/bluetooth firmware ~~reversing~~ h4x
v1.0
xorloser
march 2018


<br>

## Overview

The PS4 uses a hardware module codenamed torus for its wifi and bluetooth. Currently there are two different versions of this; the older torus1 and the newer torus2.

The torus firmwares are stored in plaintext on the PS4's flash. The PS4 loads them into the hardware module.

This is not going to lead to some magical hack of the PS4, its just fun to poke around inside it to see what it does.


<br>

## Torus1
The older torus1 is based around the **Marvell Avastar 88W8797** SoC. It supports up to wifi n. This SoC has a Marvell Feroceon® CPU (ARMv5TE-compliant) inside it. [Check this pdf for more specs](http://www.marvell.com.cn/wireless/assets/marvell_avastar_88w8797.pdf).

![http://www.psdevwiki.com/ps4/images/d/d6/Marvell_88W8797.jpg](http://www.psdevwiki.com/ps4/images/d/d6/Marvell_88W8797.jpg)


<br>

## Torus2
The newer torus2 is based around the **Marvell Avastar 88W8897** SoC. This updated SoC adds wifi ac. It is used in PS4 Pro consoles and probably PS4 slim since I see that PS4 Slim supports wifi ac. [Check this pdf for more specs](http://www.marvell.com/documents/sewwqoviqtewupxpevcs/)

Apparently this SoC also inside the XboxOne :)

<br>

## Firmware files

The torus firmware files are stored in plaintext in the PS4 flash. You can parse the flash partitions and filesystems to find it stored as the filename "C0020001". Or if you have a flashdump just search for the string "C0020001" in it. The size of the firmware is a 32bit value stored 0xC bytes before the "C0020001" filename. The firmware data will be stored 0x1D0 bytes after the "C0020001" filename. 

The following bytes that show the start of the torus1 firmware:
```01 00 00 00 00 00 00 00 00 04 00 00 ```
The following bytes that show the start of the torus2 firmware:
```50 4B 03 04 14 00 08 00 08 00 ```

The firmware can also be found inside the PS4UPDATE.PUP update files. The PS4UPDATE.PUP files internally contain multiple PS4UPDATEx.PUP entries. The torus firmwares are inside PS4UPDATE1.PUP and can found from their pkg ids:
	0x003 == torus1_fw.bin
	0x022 == torus2_fw.zip

Note that newer firmwares will include both the torus1 and torus2 fws, so there will be two "C0020001" files.


<br>

## Reversing the torus FW files

The first step is to convert the firmware file into an elf file by running fw_to_elf.py. This makes it easier to access the firmware contents with various tools that support the common elf file format.

	fw_to_elf.py torus1_fw.bin torus1.elf
or
	
	fw_to_elf.py torus2_fw.zip torus2a.elf torus2b.elf

Note that torus2 firmwares internally have 2 sets of data. I am not sure why at this point. So converting torus2 firmwares will resulting in 2 elf files, whereas converting torus1 firmwares will result in 1 elf file.

The next step is to disassemble the elf files using whatever tools you normally use to reverse arm/thumb binaries. If you use IDA v7 then you can use the "ida_fw_setup.py" script I made to perform the data init routines that unpack, copy and clears data in various ram locations. This is quite important for torus1 fws to unpack packed data, however for torus2 fws it seems to just zero out certain ram areas, probably bss areas.

Load the elf into IDA. It should detect as ARM little endian. 
On the initial load screen you might want to do:
```Processor options -> Edit ARM architecture options -> tick ARMv5TEJ```
and then
```Kernel options 1 -> untick Create function tails```

Now you can run the script by doing:
```File -> Script file...```
and then selecting "ida_fw_setup.py".

Wait a few seconds for it to complete and then you are ready to explore :)

<br>

## Links

- [Torus 1 info on psdevwiki](http://www.psdevwiki.com/ps4/88W8797)
- [Torus 1 Product Brief](http://www.marvell.com.cn/wireless/assets/marvell_avastar_88w8797.pdf)
- [Torus 2 Product Brief](http://www.marvell.com/documents/sewwqoviqtewupxpevcs/)
- [Torus 2 FCC info](https://fccid.io/document.php?id=3029896)

<br>

## History

v1.0
- Initial version


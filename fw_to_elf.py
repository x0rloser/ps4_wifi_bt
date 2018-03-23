# 
# convert ps4 wifi/bt fw file to elf file
# supports torus1 and torus2 fw types
# note:

import sys
import struct
import zipfile


def write_sections_to_elf_file(elfFilename, sections):
	print "writing %d sections to %s" % (len(sections), elfFilename)
	for section in sections:
		print "%08X  %08X" % (section[0], len(section[1]))
	print ""
	
	with open(elfFilename, "w+b") as elf_fd:
		# create and write elf header
		# (32bit elf, arm little endian executable, entrypoint at 0)
		elf_hdr = struct.pack("<16BHHIIIIIHHHHHH", \
			0x7F, ord('E'), ord('L'), ord('F'), 1, 1, 1, 0, 0, 0,0,0,0,0,0,0, \
			2, 40, 1, 0, 0x34, 0, 0, 0x34, 0x20, len(sections), 0x28, 0, 0)
		elf_fd.write(elf_hdr)
		
		# create and write elf program segments
		ph_offset = 0x34 + 0x20*len(sections)
		for section in sections:
			addr = section[0]
			size = len(section[1])
			addr_type = (addr>>24)&0xFF
			perms = 7
			if   addr_type == 0x00:
				perms = 7
			elif addr_type == 0x03:
				perms = 5
			elif addr_type == 0x04:
				perms = 6
			elif addr_type == 0x80:
				perms = 6
			elif addr_type == 0x90:
				perms = 6
			elif addr_type == 0xA0:
				perms = 6
			elif addr_type == 0xA4:
				perms = 6
			elif addr_type == 0xA9:
				perms = 6
			elif addr_type == 0xB0:
				perms = 6
			elif addr_type == 0xC0:
				perms = 7
			elif addr_type == 0xFF:
				perms = 7
			elf_seg = struct.pack("<IIIIIIII", \
				1, ph_offset, addr, addr, size, size, perms, 1)
			elf_fd.write(elf_seg)
			ph_offset += size
		
		# now write out data for program segments
		for section in sections:
			elf_fd.write("" + section[1])


def title():
	print "FW to ELF file convertor for ps4 torus fws"
	
def usage():
	print "Usage:   fw_to_elf.py <fw filename> <elf filename> [elf filename 2]"
	print ""
	print "Example: fw_to_elf.py C0020001 torus1_fw.elf"
	print "         fw_to_elf.py C0020001 torus2a_fw.elf torus2b_fw.elf"
	print ""
	print "Note:    torus2 fws require 2 output elf filenames, torus1 fws only require 1"


def main(argv):
	title()
	if len(argv) < 3 or len(argv) > 4:
		usage()
		return
	
	fw_filename = argv[1]
	elf_filename = argv[2]
	elf2_filename = ""
	if len(argv)>=4:
		elf2_filename = argv[3]
	
	# load fw data
	fw_data = None
	with open(fw_filename, "rb") as fd:
		fw_data = fd.read()
	
	# if fw data is zipped, then unzip it
	# torus2 fw is zipped, torus1 fw is not
	magic = struct.unpack("<I", fw_data[0x00:0x04])[0]
	if magic == 0x04034B50:
		# torus2 fw requires 2 elf filenames
		if len(argv) < 4:
			usage()
			return
		fw_name_len = struct.unpack("<H", fw_data[0x1A:0x1C])[0]
		fw_name = fw_data[0x1E:0x1E+fw_name_len]
		with zipfile.ZipFile(fw_filename, "r") as myzip:
			fw_data = myzip.read(fw_name)
	
	# generate a list of entries where each entry has load address and data
	sections = []
	last_load_addr = 0
	last_load_size = 0
	fw_off = 0
	type6_idx = -1
	while fw_off < len(fw_data):
		(type, load_addr, load_size, checksum) = struct.unpack("<IIII", fw_data[fw_off:fw_off+0x10])
		if type==4:
			# end of file
			break
		elif type==1:
			# normal entry
#			print type, load_addr, load_size, checksum
			if load_addr != last_load_addr+last_load_size-4:
#				print "new section: %08X" % (load_addr)
				sections.append( [load_addr, ""] )
			sections[len(sections)-1][1] += fw_data[fw_off+0x10:fw_off+0x10+load_size-4]
			last_load_addr = load_addr
			last_load_size = load_size
			fw_off += 0x10 + last_load_size
		elif type==6:
			# entry that is just a header - has size and address of 0
			# this seems to "split" the fw into 2 parts (but why?)
			print "split at idx %d offset 0x%X" % (len(sections), fw_off)
			print "(%X %X %X %X)" % (type, load_addr, load_size, checksum)
			print ""
			type6_idx = len(sections)
			fw_off += 0x10
		else:
			print "unknown type at idx %d offset 0x%X" % (len(sections), fw_off)
			print "%x %X %X %X" % (type, load_addr, load_size, checksum)
			fw_off += 0x10
			print "STOPPING"
			break
	
	# if fw had a "split" signified by a type6
	sections2 = []
	if type6_idx >= 0:
		sections2 = sections[type6_idx:]
		sections = sections[0:type6_idx]
	
	# edit torus2 fw addresses thta have 0xAXXXXXXX where it would usually be 0x0XXXXXXX
	for idx in range(0, len(sections)):
		if sections[idx][0]&0xF0000000==0xA0000000:
			sections[idx][0] &= ~0xF0000000
	
	# write out elf files
	write_sections_to_elf_file(elf_filename, sections)
	if len(sections2) > 0:
		write_sections_to_elf_file(elf2_filename, sections2)
	
	print "done"


if __name__ == "__main__":
	main(sys.argv)


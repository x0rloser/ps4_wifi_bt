

import binascii

def set_name_forced(ea, name, flags=ida_name.SN_CHECK):
	if set_name(ea, name, SN_NOWARN)==0:
		cnt = 0
		while set_name(ea, name+"_%d" % cnt, SN_NOWARN)==0:
			cnt += 1


# finds data with a mask
# can be used to find functions while masking out immediate addresses etc
def find_masked_data(dataStr, maskStr, name):
	# convert them to binary
	data_bin = binascii.unhexlify(dataStr.replace(" ", ""))
	mask_bin = binascii.unhexlify(maskStr.replace(" ", ""))
	
	ea = get_inf_attr(INF_MIN_EA)
	while ea != BADADDR:
		matched = True
		for i in range(0, len(data_bin)):
			if (ord(data_bin[i]) & ord(mask_bin[i])) != (get_wide_byte(ea+i) & ord(mask_bin[i])):
				matched = False
				break;
		if matched:
			if name and len(name)>0:
				set_name(ea, name)
			return ea
		ea = NextAddr(ea)
	
	# not found
	return BADADDR

# find init_data_func()
def find_init_data_func():
	data_str = \
	"28 00 8F E2 00 0C 90 E8 00 A0 8A E0 00 B0 8B E0 " \
	"01 70 4A E2 0B 00 5A E1 69 00 00 0A 0F 00 BA E8 " \
	"14 E0 4F E2 01 00 13 E3 03 F0 47 10 13 FF 2F E1 "
	# this is the mask for init_ram_data() to handle addres relocation
	mask_str = \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF 00 00 00 00 FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
	# find it
	return find_masked_data(data_str, mask_str, "init_data_func")

# find init_memset()
def find_init_memset():
	data_str = \
	"00 30 A0 E3 00 40 A0 E3 00 50 A0 E3 00 60 A0 E3" \
	"10 20 52 E2 78 00 A1 28 FC FF FF 8A 82 2E B0 E1" \
	"30 00 A1 28 00 30 81 45 1E FF 2F E1"
	mask_str = \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF 00 00 00 00 FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF"
	# find it
	return find_masked_data(data_str, mask_str, "init_memset")

# find init_memcpy()
def find_init_memcpy():
	data_str = \
	"10 20 52 E2 78 00 B0 28 78 00 A1 28 FB FF FF 8A" \
	"82 2E B0 E1 30 00 B0 28 30 00 A1 28 00 40 90 45" \
	"00 40 81 45 1E FF 2F E1"
	mask_str = \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF 00 00 00 00 FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF"
	# find it
	return find_masked_data(data_str, mask_str, "init_memcpy")

# find init_unpack()
def find_init_unpack():
	data_str = \
	"01 C0 8F E2 1C FF 2F E1 8A 18 03 78 01 30 9C 07" \
	"A4 0F 01 D1 04 78 01 30 1D 11 01 D1 05 78 01 30" \
	"01 3C 05 D0 06 78 01 30 0E 70 01 31 01 3C F9 D1" \
	"00 2D 11 D0 04 78 1B 07 01 30 9B 0F 0C 1B 03 2B" \
	"01 D1 03 78 01 30 1B 02 E4 1A 6B 1C 26 78 01 34" \
	"0E 70 01 31 01 3B F9 D5 91 42 D6 D3 70 47"
	mask_str = \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF" \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
	# find it
	return find_masked_data(data_str, mask_str, "init_unpack")

# find svc_123456()
def find_svc_123456():
	data_str = \
	"0C 10 9F E5 18 00 A0 E3 56 34 12 EF 1E FF 2F E1"
	mask_str = \
	"FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF"
	# find it
	ea = find_masked_data(data_str, mask_str, "svc_123456")
	if get_wide_dword(ea-4) == 0xE1A00000:
		set_name(ea, "")
		set_name(ea-4, "svc_123456")
		return ea-4
	return ea


# looks for multiple jump funcs in a row
def find_jump_func_table(ea):
	min_funcs = 8
	start_ea = ea
	cnt=0
	while get_wide_dword(ea) == 0xE51FF004:
		cnt += 1
		ea += 8
	if cnt < min_funcs:
		return None
	return (start_ea, cnt)
	

def get_jump_func_target(ea):
	if get_wide_dword(ea) == 0xE51FF004:
		return get_wide_dword(ea+4)
	else:
		return BADADDR

def get_jump_func_min_max(ea, mask):
	min = BADADDR
	max = BADADDR
	while True:
		target_ea = get_jump_func_target(ea)
		ea += 8
		if target_ea==BADADDR:
			break
		if target_ea&0xFFF00000 != mask:
			continue
		if min==BADADDR or target_ea < min:
			min = target_ea
		if max==BADADDR or target_ea > max:
			max = target_ea
	print "jump target range for %08X is %08X - %08X" % (mask, min, max)
	

def setup_jump_func(ea):
	del_items(ea, DELIT_SIMPLE, 8)
	split_sreg_range(ea+0, "T", 0)
	split_sreg_range(ea+1, "T", 0)
	split_sreg_range(ea+2, "T", 0)
	split_sreg_range(ea+3, "T", 0)
	create_insn(ea)
	create_data(ea+4, FF_DWORD, 4, ida_idaapi.BADADDR)
	op_plain_offset(ea+4, 0, 0)
	add_func(ea, ea+8)
	target_ea = get_wide_dword(ea+4)
	if target_ea >= 0x03F00000 and target_ea < 0x04000000:
		set_name(ea, "")
		set_name_forced(ea, "romfunc_%08X" % target_ea)
	if target_ea >= 0xC0000000 and target_ea < 0xD0000000:
		set_name(ea, "")
		set_name_forced(ea, "extfunc_%08X" % target_ea)
	if target_ea >= 0x00000000 and target_ea < 0x00080000:
		set_name(ea, "")
		set_name_forced(ea, "mainfunc_%08X" % target_ea)

def setup_jump_funcs(ea):
	start_ea = ea
	while get_wide_dword(ea) == 0xE51FF004:
		setup_jump_func(ea)
		ea += 8
	print "setup jumps from %08X - %08X (%d jumps)" % (start_ea, ea, (ea-start_ea)/8)
	

def find_potential_section_hdrs(start_ea, end_ea):
	ea = start_ea
	crc = 0
	crc2 = 0
	while ea < end_ea:
		if get_wide_dword(ea)== 0x00000001 and get_wide_dword(ea+8)== 0x00000400:
			print "potential section hdr at %08X (next section hdr at %08X)" % (ea, ea+0x10+get_wide_dword(ea+ 8))
			print "  %08X" % (get_wide_dword(ea+ 0)) # always 1
			print "  %08X" % (get_wide_dword(ea+ 4)) # load address?
			print "  %08X" % (get_wide_dword(ea+ 8)) # size
			print "  %08X" % (get_wide_dword(ea+12)) # checksum?
#			print "crc = %08X or %08X" % (crc & 0xFFFFFFFF, crc2)
			if get_wide_dword(ea+ 0)!=1:
				print "!!!!!!!!!!!!!!!!"
			crc = 0
			crc2 = 0
		else:
			crc += get_wide_dword(ea)
			crc2 ^= get_wide_dword(ea)
		ea += 4


def create_func(startEa, endEa=BADADDR, name=""):
	add_func(startEa, endEa)
	if name != "":
		set_name(startEa, name)

	
def setup_vector(ea, name):
	# setup vector function
	set_name(ea, "vector_"+name)
	del_items(ea, DELIT_SIMPLE, 4)
	create_insn(ea)
	add_func(ea, ea+4)
	# setup handler function
	ea_of_handler_ptr = get_operand_value(ea, 1)
	ea_of_handler_func = get_wide_dword(ea_of_handler_ptr)
	set_name(ea_of_handler_func & ~1, "handler_"+name)
	add_func(ea_of_handler_func & ~1)
	


# do init data setup
# this can only be called once because the init values are zeroed after initing
def setup_init_data(initDataTableEa, initDataTableCnt):
	init_memcpy = find_init_memcpy()
	init_memset = find_init_memset()
	init_unpack = find_init_unpack()
	
	for idx in range(0, initDataTableCnt):
		init_entry_ea = initDataTableEa + idx*0x10
		src  = get_wide_dword(init_entry_ea+0)
		dest = get_wide_dword(init_entry_ea+4)
		size = get_wide_dword(init_entry_ea+8)
		func = get_wide_dword(init_entry_ea+12)
		
		print_unpack_vals = 0
		
		# memcpy
		if func == init_memcpy:
			print "init memcpy(%08X, %08X, %04X)" % (dest, src, size)
			for off in range(0, size, 4):
				patch_dword(dest+off, get_wide_dword(src+off))
			del_items(dest, DELIT_SIMPLE, size)
		# memset
		elif func == init_memset:
			print "init memset(%08X, 0, %04X)" % (dest, size)
			for off in range(0, size, 4):
				patch_dword(dest+off, 0)
			del_items(dest, DELIT_SIMPLE, size)
		# unpack
		elif func == init_unpack:
			print "init unpack(%08X, %08X, %04X)" % (dest, src, size)
			dest_start = dest
			dest_end = dest + size
			while dest < dest_end:
				flag1 = get_wide_byte(src)
				src += 1
				cnt1 = (flag1>>0) & 0x3
				off_hi = (flag1>>2) & 0x3
				cnt2 = (flag1>>4) & 0xF
				if print_unpack_vals:
					print "flag1=%X   cnt1=%X,off_hi=%X,cnt2=%X" % (flag1, cnt1, off_hi, cnt2)
				if cnt1==0:
					cnt1 = get_wide_byte(src)
					src += 1
				if cnt2==0:
					cnt2 = get_wide_byte(src)
					src += 1
				if print_unpack_vals:
					print "  cnt1=%X,cnt2=%X" % (cnt1, cnt2)
				
				# memcpy using src data as src
				for i in range(0, cnt1-1):
					patch_byte(dest, get_wide_byte(src))
					dest += 1
					src += 1
				
				# memcpy using dest data as src
				if cnt2!=0:
					off_lo = get_wide_byte(src)
					src += 1
					if off_hi==3:
						off_hi = get_wide_byte(src)
						src += 1
					src2 = dest - ((off_hi<<8) + off_lo)
					if print_unpack_vals:
						print "  off=%X, off_hi=%X, off_lo=%X   src2=%X, dest=%X" % ((off_hi<<8) + off_lo, off_hi, off_lo, src2, dest)
					for i in range(0, cnt2+2):
						patch_byte(dest, get_wide_byte(src2))
						dest += 1
						src2 += 1
			del_items(dest_start, DELIT_SIMPLE, size)


# returns: 1=torus1 fw,  2=torus2a fw,  3=torus2b fw,  0=unknown
def get_torus_version():
	ea = get_first_seg()
	while ea != BADADDR:
		if ea&0xFFF00000==0x90000000:
			# torus 1
			return 1
		if ea&0xFFF00000==0xB0000000:
			# torus 2a
			return 2
		if ea&0xFFF00000==0xFFD00000:
			# torus 2b
			return 3
		ea = get_next_seg(ea)
	# unknown
	return 0
	



# these are just guessed/based on code i have come across so far
# they will probably need updating.
# 
# memmap (each range is what i have seen so far - they may be bigger)
# 00000000 - 0005636C  RWX (main ram with code in it ???)
# 03F0AC01 - 03F5DD4D  R?X (boot rom with code in it ???)
# 04000000 - 04012A94  RW? (data)
# 8000200C - 8000A510  RW? (hw regs maybe ???)
# 90000270 - 9003F018  RW? (hw regs maybe ???)
# C0000000 - C0001100  RW?
# C0001100 - C0002F78  R??
# C0007C00 - C005FC40  RWX (code ???)
# 
#    start_addr, end_addr,   name,        class,   perms, create flag, test_addr
torus1_segment_info = ( \
	(0x00000000, 0x00080000, "ram_main",  "DATA",  7, 0, 0x00000000), \
	(0x03F00000, 0x03F80000, "rom",       "CODE",  5, 1, 0x03F00000), \
	(0x04000000, 0x04020000, "data_04",   "DATA",  6, 0, 0x04000000), \
	(0x80000000, 0x80010000, "data_80",   "DATA",  6, 1, 0x80000000), \
	(0x90000000, 0x90040000, "data_90",   "DATA",  6, 0, 0x90020000), \
	(0xC0000000, 0xC0080000, "ram_ext",   "DATA",  7, 1, 0xC0000000), \
)


# these are just guessed/based on code i have come across so far
# they will probably need updating.
# 
# ?!?!?!?!?! is it at 0x09000000 or 0xA9000000
# it appears to be the same as 0x90000000 from torus1
# 
# double check the perms and classes for torus2
# 00000000 - 00018100  RWX
# 03F01718 - 03F44941  R?X (boot rom with code in it ???)
# 04000000 - 0400BBB4  RW?
# 09020000 - 09030464  RWX	!!! is this address correct?
# B0000600 - B0006CB0  RW?
# C0001300 - C0001B40  RW?
# 
#    start_addr, end_addr,   name,        class,   perms, create flag, test_addr
torus2a_segment_info = ( \
	(0x00000000, 0x00020000, "ram_main",  "DATA",  7, 0, 0x00000000), \
	(0x03F00000, 0x03F80000, "rom",       "CODE",  5, 1, 0x03F00000), \
	(0x04000000, 0x04010000, "data_04",   "DATA",  6, 1, 0x04000000), \
	(0x09000000, 0x09040000, "ram_A9",    "DATA",  7, 0, 0x09020000), \
	(0xB0000000, 0xB0010000, "ram_B0",    "DATA",  7, 0, 0xB0000600), \
	(0xC0000000, 0xC0080000, "ram_ext",   "DATA",  7, 1, 0xC0000000), \
)


# these are just guessed/based on code i have come across so far
# they will probably need updating.
# 
# double check the perms and classes for torus2
# 00000000 - 0000D380  RWX
# 04000000 - 04006F60  RW?
# 80000000 - 80002100  RW?
# C0000000 - C009E300  RW?
# FFD00000 - FFD56AF8  RWX
# FFFD172A - FFFF0004  R?X	? rom ?
# 
#    start_addr, end_addr,   name,        class,   perms, create flag, test_addr
torus2b_segment_info = ( \
	(0x00000000, 0x00010000, "ram_main",  "DATA",  7, 0, 0x00000000), \
	(0x04000000, 0x04010000, "data_04",   "DATA",  6, 0, 0x04000000), \
	(0x80000000, 0x80010000, "data_80",   "DATA",  6, 1, 0x80000000), \
	(0xC0000000, 0xC00A0000, "ram_ext",   "DATA",  7, 1, 0xC0000000), \
	(0xFFD00000, 0xFFD80000, "ram_FF",    "DATA",  7, 0, 0xFFD00000), \
	(0xFFFF0000, 0xFFFF1000, "rom_FF",    "DATA",  7, 1, 0xFFFF0000), \
)




def main():
	# get the firmware version this is for
	torus_ver = get_torus_version()
	if torus_ver == 1:
		print "torus1 fw"
	elif torus_ver == 2:
		print "torus2a fw"
	elif torus_ver == 3:
		print "torus2b fw"
	else:
		print "unknown fw?!"
		return
	
	# set compiler to gnu
	set_inf_attr(INF_COMPILER, COMP_GNU)
	
	# setup segments
	segment_info = None
	if torus_ver == 1:
		segment_info_list = torus1_segment_info
	elif torus_ver == 2:
		segment_info_list = torus2a_segment_info
	elif torus_ver == 3:
		segment_info_list = torus2b_segment_info
	for seg_info in segment_info_list:
		# create missing segments
		if seg_info[5]==1:
			add_segm_ex(seg_info[0], seg_info[1], 0, 1, 1, scPub, ADDSEG_NOTRUNC)
		# enlarge segments to encompass full size
		set_segment_bounds(seg_info[6], seg_info[0], seg_info[1], SEGMOD_KEEP);
		# set segment names (these are just guessed for now)
		set_segm_name(seg_info[0], seg_info[2])
		# set segment classes
		set_segm_class(seg_info[0], seg_info[3])
		# set segment perms
		set_segm_attr(seg_info[0], SEGATTR_PERM, seg_info[4])
	
	# do init data setup
	# this can only be called once because the init values are zeroed after initing
	init_data_func = find_init_data_func()
	if init_data_func == BADADDR:
		print "Error finding init_data_func()"
		return
	init_data_base = get_operand_value(init_data_func, 1)
	init_data_start = get_wide_dword(init_data_func+0x30) + init_data_base
	init_data_end   = get_wide_dword(init_data_func+0x34) + init_data_base
	init_data_cnt   = (init_data_end-init_data_start) / 0x10

	print "init_data_func = %X" % init_data_func
	print "init_data_base = %X" % init_data_base
	print "init_data_start = %X" % init_data_start
	print "init_data_end = %X" % init_data_end
	print "init_data_cnt = %X" % init_data_cnt
	
	init_data_struct = add_struc(-1, "init_data_entry_t", 0)
	if init_data_struct == 0xFFFFFFFF:
		init_data_struct = get_struc_id("init_data_entry_t")
	print "init_data_struct = %d" % init_data_struct
	add_struc_member(init_data_struct, "src",  0x00, FF_DATA|FF_DWORD|FF_0OFF, 0, 4)
	add_struc_member(init_data_struct, "dest", 0x04, FF_DATA|FF_DWORD|FF_0OFF, 0, 4)
	add_struc_member(init_data_struct, "size", 0x08, FF_DATA|FF_DWORD, 0, 4)
	add_struc_member(init_data_struct, "func", 0x0C, FF_DATA|FF_DWORD|FF_0OFF, 0, 4)
	for i in range(0, init_data_cnt):
		create_struct(init_data_start+i*0x10, -1, "init_data_entry_t")
	
	setup_init_data(init_data_start, init_data_cnt)
	auto_wait()
	plan_and_wait(0, 0xFFFF1000)
	
	# setup exception vectors and their handlers
	# (these are the same for all fws)
	setup_vector(0x00, "reset")
	setup_vector(0x04, "undefined_instruction")
	setup_vector(0x08, "swi")
	setup_vector(0x0C, "abort_prefetch")
	setup_vector(0x10, "abort_data")
	setup_vector(0x14, "reserved")
	setup_vector(0x18, "irq")
	setup_vector(0x1c, "fiq")
	create_data(0x20, FF_DWORD, 4, ida_idaapi.BADADDR)
	
	# find possible jump tables and set them up
	ea = get_inf_attr(INF_MIN_EA)
	while ea != BADADDR:
		table_info = find_jump_func_table(ea)
		if table_info != None:
			(table_ea, table_cnt) = table_info
			print "table found at %X with %d funcs" % (table_ea, table_cnt)
			setup_jump_funcs(table_ea)
			ea += 8*table_cnt
		ea = NextAddr(ea)
	
	# setup a few more funcs
	init_data_func
	handler_reset = get_name_ea_simple("handler_reset")
	if handler_reset!=BADADDR:
		ea = get_func_attr(handler_reset, FUNCATTR_END) - 4
		ea = get_operand_value(ea, 1)
		start1 = get_wide_dword(ea)
		set_name(start1, "j_init_data_start");
	
	start3 = get_operand_value(init_data_func+0x18, 0)
	if start3!=BADADDR:
		set_name(start3, "start3");
		start3_end = start3
		bx_cnt = 0
		while bx_cnt < 2:
			if get_wide_dword(start3_end) == 0xE12FFF1C:
				bx_cnt += 1
			start3_end += 4
		add_func(start3, start3_end)
		add_func(start3_end, start3_end+4)
	svc_123456 = find_svc_123456()
	if svc_123456 != BADADDR:
		add_func(svc_123456, BADADDR) #svc_123456+0x10)
	
	print "done"


if __name__ == "__main__":
	main()



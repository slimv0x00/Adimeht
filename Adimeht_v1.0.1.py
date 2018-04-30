# < NOTE >
# Every path must use the English
# Author : slimV
# May 16 2017

import pykd
import types
import re
import time
import socket
import sys
import capstone
import struct

class WinDbgBridge():
	
	logPath = "C:\Users\slimv0x00\Desktop\dbiLog.txt"
	imageName = ""
	
	procImageBase = 0
	procImageSize = 0
	procImageEnd = 0
	
	lSection = [] # list of sections' information [0: virtual address, 1: va end, 2: rva, 3: virtual size, 4: guard]
	
	def __init__(self, md = None):
		if md == None:
			self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
		else: self.md = md
		self.md.detail = True
		
	def initLog(self):
		f = open(self.logPath, "w")
		f.close()

	def dbiprintf(self, str):
		f = open(self.logPath, "a")
		f.write(str + "\n")
		f.close()
		pykd.dprintln(str)
		
	def getRegVal(self, regName):
		cmdReg = "r %s" % regName
		iParseBegin = "%s=" % regName
		cmdr = pykd.dbgCommand(cmdReg)
		strReg = cmdr[cmdr.find(iParseBegin) + len(iParseBegin):]
		regVal = int(strReg, 16)
		return regVal
		
	def writeDword(self, addr, val):
		cmd = "ed %x %x" % (addr, val)
		guard = pykd.getVaProtect(addr)
		self.vprotect(addr, 4, 0x40)
		cmdr = pykd.dbgCommand(cmd)
		self.vprotect(addr, 4, guard)
		return 0
		
	def writeMemory(self, addr, data):
		cmdDw = "ed %x %x"
		cmdB = "eb %x %x"
		guard = pykd.getVaProtect(addr)
		self.vprotect(addr, len(data), 0x40)
		
		lenData = len(data)
		scope = (lenData / 4) * 4
		for dst in range(0, scope, 4):
			cmdr = pykd.dbgCommand(cmdDw % (addr + dst, struct.unpack("<L", data[dst:dst+4])[0]))
		for dst in range(scope, lenData):
			cmdr = pykd.dbgCommand(cmdB % (addr + dst, struct.unpack("<B", data[dst])[0]))
		
		self.vprotect(addr, len(data), guard)
		return 0
		
	def readDword(self, addr):
		cmd = "dd %x L1" % addr
		cmdr = pykd.dbgCommand(cmd)
		try:
			strVal = cmdr.split()
			writeVal = int(strVal[1], 16)
			return writeVal
		except:
			self.dbiprintf("[E] Cannot read memory")
			self.dbiprintf(cmdr)
			return 0
			
	def readByte(self, addr):
		cmd = "db %x L1" % addr
		cmdr = pykd.dbgCommand(cmd)
		try:
			strVal = cmdr.split()
			writeVal = int(strVal[1], 16)
			return writeVal
		except:
			self.dbiprintf("[E] Cannot read memory")
			self.dbiprintf(cmdr)
			return 0
			
	def readMemory(self, addr, len):
		data = ""
		scope = (len / 4) * 4
		pin = addr + scope
		end = addr + len
		for dst in range(addr, pin, 4):
			dw = self.readDword(dst)
			#self.dbiprintf("0x%08x = 0x%08x" % (dst, dw))
			data = data + struct.pack("<L", dw)
		for dst in range(pin, end):
			bb = self.readByte(dst)
			#self.dbiprintf("0x%08x = 0x%02x" % (dst, bb))
			data = data + struct.pack("<B", bb)
		return data
			
	def parseInstructionLine(self):
		regModule = "[0-9a-fA-F]+ +[0-9a-fA-F]+ +.+"
		cmdr = pykd.dbgCommand("r")
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Cannot load module list")
			return -1
		blist = re.findall(regModule, cmdr)
		if blist == types.NoneType:
			self.dbiprintf(" - [E] Cannot find %s" % (targetName))
		bl = blist[0]
		return bl

	def parseInstructionBytes(self):
		instLine = self.parseInstructionLine()
		blist = instLine.split()
		if len(blist) == 0:
			self.dbiprintf("[E] Invalid instruction line : %s" % instLine)
			return ""
		strBytes = blist[1]
		bytes = strBytes.decode("hex")
		return bytes
		
	def getImageInfo(self):
		iPImageBaseBegin = "ImageBaseAddress:"
		iPImageBaseEnd = "Ldr"
		iPImageNameBegin = "ImageFile:"
		iPImageNameEnd = "CommandLine"
		
		self.dbiprintf("[!] Get image information")
		cmdr = pykd.dbgCommand("!peb")
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Error on get PEB")
			return 1
		# get image base from PEB
		if cmdr.find(iPImageBaseBegin) == -1:
			self.dbiprintf(" - [E] Error on get image base address")
			self.dbiprintf(cmdr)
			return 2
		strBase = cmdr[cmdr.find(iPImageBaseBegin) + len(iPImageBaseBegin):cmdr.find(iPImageBaseEnd)]
		base = int(strBase, 16)
		self.procImageBase = base
		# get image name from PEB
		if cmdr.find(iPImageNameBegin) == -1:
			self.dbiprintf(" - [E] Error on get image name")
			self.dbiprintf(cmdr)
			return 3
		path = cmdr[cmdr.find(iPImageNameBegin) + len(iPImageNameBegin):cmdr.find(iPImageNameEnd)]
		name = path[path.rfind("\\") + 1:path.rfind("'")]
		self.imageName = name
		
		# get image end from module list
		cmdr = pykd.dbgCommand("lm")
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Error on get module list")
			return 4
		if cmdr.find("%08x" % base) == -1:
			self.dbiprintf(" - [E] Error to find image base address from module list")
			self.dbiprintf(cmdr)
			return 5
		strImage = cmdr[cmdr.find("%08x" % base):]
		lImage = strImage.split()
		try:
			if base != int(lImage[0], 16):
				self.dbiprintf(" - [E] Error to find image base address from module list")
				self.dbiprintf(cmdr)
				return 6
			self.procImageEnd = int(lImage[1], 16)
			self.procImageSize = self.procImageEnd - self.procImageBase
		except:
			self.dbiprintf(" - [E] Error to find image base address from module list")
			self.dbiprintf(cmdr)
			return 7
		
		self.dbiprintf(" -> Image name : %s ( 0x%08x ~ 0x%08x ( 0x%08x ) )" % (name, self.procImageBase, self.procImageEnd, self.procImageSize))
		return 0

	def getSectionInfo(self):
		cmdDh = "!dh -s "
		iParseSection = "SECTION HEADER"
		iParseName = "name"
		iParseVs = "virtual size"
		iParseVa = "virtual address"
		
		self.dbiprintf("[!] Get section information")
		cmd = cmdDh + "%x" % self.procImageBase
		cmdr = pykd.dbgCommand(cmd)
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Error on dump section header : 0x%08x" % self.procImageBase)
			return 1
		# add PE header's page
		guard = pykd.getVaProtect(self.procImageBase)
		self.lSection.append([self.procImageBase, self.procImageBase + 0x1000, 0, 0x1000, guard])
		# add sections' page
		tc = cmdr
		while True:
			if tc.find(iParseSection) == -1:
				break
			tc = tc[tc.find(iParseName) + len(iParseName):]
			strVs = tc[:tc.find(iParseVs)]
			vs = int(strVs, 16)
			tc = tc[tc.find(iParseVs) + len(iParseVs):]
			strVa = tc[:tc.find(iParseVa)]
			rva = int(strVa, 16)
			va = self.procImageBase + rva
			vaEnd = va + vs
			guard = pykd.getVaProtect(va)
			self.dbiprintf(" -> Section #%d : 0x%08x ( 0x%08x ) : 0x%x" % (len(self.lSection), va, vs, guard))
			self.lSection.append([va, vaEnd, rva, vs, guard])
		return 0
		
	def getSymbolFromAddr(self, addr):
		iParseBegin = "Exact matches:"
		cmdr = pykd.dbgCommand("ln %x" % addr)
		if type(cmdr) == types.NoneType:
			self.dbiprintf("[E] Cannot find symbol : 0x%08x" % addr)
			return ""
		if cmdr.find(iParseBegin) == -1:
			self.dbiprintf("[E] Cannot find exact symbol : 0x%08x" % addr)
			#self.dbiprintf(cmdr)
			return ""
		syms = cmdr[cmdr.find(iParseBegin) + len(iParseBegin):]
		lSym = syms.split()
		return lSym[0]
		
	def getSectionNum(self, addr):
		for i in range(len(self.lSection)):
			if addr >= self.lSection[i][0] and addr < self.lSection[i][1]: # [0: vaBase, 1: vaEnd]
				return i
		return -1

	def getOperands(self, inst):
		operands = [] # list of operands [0: type, 1: value]
		if len(inst.operands) > 0:
			#self.dbiprintf(" - Operands : %d" % len(inst.operands))
			for op in inst.operands:
				opInfo = []
				if op.type == capstone.x86.X86_OP_REG:
					#self.dbiprintf(" - REG: %s" % (inst.reg_name(op.value.reg)))
					opInfo.append("reg")
					opInfo.append("%s" % inst.reg_name(op.value.reg))
				elif op.type == capstone.x86.X86_OP_IMM:
					#self.dbiprintf(" - IMM: 0x%x" % (op.value.imm))
					opInfo.append("imm")
					opInfo.append(op.value.imm)
				elif op.type == capstone.x86.X86_OP_MEM: # [0: type, 1: mem addr string, 2: mem element list, 3: mem formula list, 4: mem address]
					strSegReg = ""
					strBaseReg = ""
					strIndexReg = ""
					strScale = ""
					strDisp = ""
					segReg = 0
					baseReg = 0
					indexReg = 0
					scale = 0
					disp = 0
					baseVal = 0
					indexVal = 0
					memList = []
					memList.append("[")
					if op.value.mem.segment != 0:
						segReg = op.value.mem.segment
						strSegReg = "%s:" % inst.reg_name(segReg)
						memList.append("%s" % inst.reg_name(segReg))
						memList.append(":")
					if op.value.mem.base != 0:
						baseReg = op.value.mem.base
						strBaseReg = inst.reg_name(baseReg)
						baseVal = self.getRegVal("%s" % inst.reg_name(baseReg))
						memList.append("%s" % inst.reg_name(baseReg))
					if op.value.mem.index != 0:
						indexReg = op.value.mem.index
						strIndexReg = "+%s" % inst.reg_name(indexReg)
						indexVal = self.getRegVal("%s" % inst.reg_name(indexReg))
						memList.append("+")
						memList.append("%s" % inst.reg_name(indexReg))
					if op.value.mem.scale != 0:
						scale = op.value.mem.scale
						if scale != 1:
							strScale = "*0x%x" % scale
							memList.append("*")
							memList.append(scale)
					if op.value.mem.disp != 0:
						disp = op.value.mem.disp
						if disp > 0:
							strDisp = "+0x%x" % disp
							memList.append("+")
							memList.append(disp)
						else:
							strDisp = "-0x%x" % (-disp)
							memList.append("-")
							memList.append(-disp)
					memList.append("]")
					memAddr = baseVal + (indexVal * scale) + disp
					#self.dbiprintf(" - MEM: [%s%s%s%s%s] = 0x%08x" % (strSegReg, strBaseReg, strIndexReg, strScale, strDisp, memAddr))
					opInfo.append("mem")
					opInfo.append("[%08x]" % memAddr)
					opInfo.append([strSegReg, strBaseReg, strIndexReg, strScale, strDisp])
					opInfo.append(memList)
					opInfo.append(memAddr)
				elif op.type == capstone.x86.X86_OP_FP:
					#self.dbiprintf(" - FP: %s" % (op.value.fp))
					opInfo.append("fp")
					opInfo.append("%s" % op.value.fp)
				elif op.type == capstone.x86.X86_OP_INVALID:
					#self.dbiprintf(" - UNINIT:")
					opInfo.append("Uninit")
					opInfo.append("Uninit")
				else:
					#self.dbiprintf(" - INVALID:")
					opInfo.append("Invalid")
					opInfo.append("Invalid")
				operands.append(opInfo)
					
		return operands
		
	def vprotect(self, addr, size, guard):
		cmdVprotect = "!sdbgext.vprotect %x %x %x"
		cmdr = pykd.dbgCommand(cmdVprotect % (addr, size, guard))
		#self.dbiprintf(cmdr)

class WinBpHandler(pykd.eventHandler):

	def __init__(self, br = None):
		if br == None: self.br = WinDbgBridge()
		else: self.br = br

	def unsetBp(self, addr):
		cmdBl = "bl"
		regBl = "\d +[e|d] +[0-9a-fA-F]+ "
		
		cmdr = pykd.dbgCommand(cmdBl)
		if type(cmdr) == types.NoneType:
			self.br.dbiprintf(" - [E] Has any breaks")
			return -1
		#self.br.dbiprintf(cmdr)
		bl = re.findall(regBl, cmdr)
		
		for i in bl:
			rel = i.split()
			bNum = int(rel[0])
			bAddr = int(rel[2], 16)
			if bAddr == addr:
				pykd.removeBp(bNum)
				self.bp_end = None
				#self.br.dbiprintf(" - [-] Unset break : 0x%08x" % bAddr)
				
	def unsetBpOnEip(self):
		eip = self.br.getRegVal("eip")
		self.unsetBp(eip)

	def setBpOnNextInst(self, handler):
		eip = self.br.getRegVal("eip")
		instBytes = self.br.parseInstructionBytes()
		return pykd.setBp(eip + len(instBytes), handler)
		
		
class MemBpHandler(WinBpHandler):
	
	hitMemory = None
	hitAddress = 0
	hitProtection = 0
	lMemGuards = [] # list of memory guards info [N][0: base, 1: size, 2: end, 3: guard]
	
	pIatBase = 0
	pIatEnd = 0
	sizeIat = 0
	
	pCodeBase = 0
	sizeCode = 0
	pCodeEnd = 0
	
	lOriginApi = {} # dictionary of original API info at address {address : [0: API address, 1: API name]}
	lIatCodePatch = {} # dictionary of relation infos between code patch and IAT {IAT address : [patch addresses]}
	currIat = 0
	lCurrPatches = []
	
	oep = 0
	
	def __init__(self, lObfusMem, br = None):
		self.lObfusMem = lObfusMem
		pykd.eventHandler.__init__(self)
		if br == None: self.br = WinDbgBridge()
		else: self.br = br
		self.bp_end = None
		
	def forceSetIat(self, pIatBase, sizeIat):
		self.pIatBase = pIatBase
		self.sizeIat = sizeIat
		self.pIatEnd = self.pIatBase + self.sizeIat
		self.br.dbiprintf("[+] Force set IAT : 0x%08x ( 0x%x )" % (self.pIatBase, self.sizeIat))
		#self.setBpMemoryOnWrite(self.pIatBase, self.sizeIat)
		
	def setMemBpOnWriteOnIat(self):
		guard = pykd.getVaProtect(self.pIatBase)
		if guard != 0x2:
			self.setBpMemoryOnWrite(self.pIatBase, self.sizeIat)
		
	def forceSetCode(self, pCodeBase, sizeCode):
		self.pCodeBase = pCodeBase
		self.sizeCode = sizeCode
		self.pCodeEnd = self.pCodeBase + self.sizeCode
		self.br.dbiprintf("[+] Force set CODE section : 0x%08x ( 0x%x )" % (self.pCodeBase, self.sizeCode))
		
	def setInitialProtection(self):
		for i in range(len(self.br.lSection)):
			s = self.br.lSection[i]
			self.br.dbiprintf("[!] Set initial protection at Section #%d : 0x%08x ( 0x%08x ) : 0x%x" % (i, s[0], s[3], s[4]))
			self.br.vprotect(s[0], s[3], s[4])
		
	def restoreAllProtections(self):
		for mem in self.lMemGuards:
			self.br.vprotect(mem[0], mem[1], mem[3])
		del self.lMemGuards[:]
		self.setInitialProtection()
	
	def setBpMemoryOnAccess(self, addr, size):
		guard = pykd.getVaProtect(addr)
		end = addr + size
		self.lMemGuards.append([addr, size, end, guard])
		self.br.dbiprintf("[!] Set BP Memory on Access at 0x%08x (0x%x) : Old protection 0x%x" % (addr, size, guard))
		self.br.vprotect(addr, size, guard | 0x100)
	
	def setBpMemoryOnWrite(self, addr, size):
		guard = pykd.getVaProtect(addr)
		end = addr + size
		self.lMemGuards.append([addr, size, end, guard])
		self.br.dbiprintf("[!] Set BP Memory on Write at 0x%08x (0x%x) : Old protection 0x%x" % (addr, size, guard))
		self.br.vprotect(addr, size, 0x2)
				
	def unsetBpMemoryOnWrite(self, addr, size):
		mem = self.isRegisteredMemory(addr)
		if mem != None:
			self.br.vprotect(mem[0], mem[1], mem[3])
			self.lMemGuards.remove(mem)
		else:
			self.br.dbiprintf("[E] Unregistered memory boundary : 0x%08x (0x%x)" % (addr, size))
	
	def setTemporaryProtection(self):
		if self.hitMemory != None:
			guard = pykd.getVaProtect(self.hitMemory[0])
			self.hitProtection = guard
			self.br.vprotect(self.hitMemory[0], self.hitMemory[1], self.hitMemory[3])
		else:
			self.br.dbiprintf("[E] Has any memory violations yet")
			
	def restoreTemporaryProtection(self):
		if self.hitMemory != None:
			self.br.vprotect(self.hitMemory[0], self.hitMemory[1], self.hitProtection)
			self.hitMemory = None
			self.hitAddress = 0
			self.hitProtection = 0
		else:
			self.br.dbiprintf("[E] Has any memory violations yet")
		
	def isRegisteredMemory(self, addr):
		for mem in self.lMemGuards:
			if mem[0] <= addr and mem[2] > addr:
				return mem
		return None
		
	def isInIat(self, addr):
		if self.pIatBase <= addr and self.pIatEnd > addr:
			return True
		return False
		
	def isInCode(self, addr):
		if self.pCodeBase <= addr and self.pCodeEnd > addr:
			return True
		return False

	# WinDbg -> Debug -> Event Filters -> Disable the Access violation
	def onException(self, exceptInfo):
		#self.br.dbiprintf("[!] Exception occured")
		if exceptInfo.exceptionCode == 0x80000001: # GUARD_PAGE_VIOLATION # Memory breakpoint with PAGE_GUARD
			#self.br.dbiprintf("GUARD_PAGE")
			#cmdr = pykd.dbgCommand("r")
			#self.br.dbiprintf(cmdr)
			
			eip = self.br.getRegVal("eip")
			if self.isInCode(eip): # Probably reached to OEP
				self.br.dbiprintf("[+] Probably OEP : 0x%08x" % eip)
				self.oep = eip
				cmdr = pykd.dbgCommand("r")
				self.br.dbiprintf(cmdr)
				self.restoreAllProtections()
				return pykd.eventResult.Break
			
			self.bp_end = self.setBpOnNextInst(self.handler_onAccessMemory)
			return pykd.eventResult.Proceed
			
		elif exceptInfo.exceptionCode == 0xc0000005: # ACCESS_VIOLATION # Memory breakpoint with PAGE_READONLY
			#cmdr = pykd.dbgCommand("r")
			#self.br.dbiprintf(cmdr)
			
			instBytes = self.br.parseInstructionBytes()
			if instBytes == "":
				self.br.dbiprintf(self.br.parseInstructionLine())
				return pykd.eventResult.Break
			eip = self.br.getRegVal("eip")
			for inst in self.br.md.disasm(instBytes, eip):
				#self.br.dbiprintf("0x%08x\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
				ops = self.br.getOperands(inst)
				
				if ops[0][0] == "mem":
					#cmdr = pykd.dbgCommand("r")
					#self.br.dbiprintf(cmdr)
					addr = ops[0][4]
					self.hitMemory = self.isRegisteredMemory(addr)
					#self.br.dbiprintf("Write on memory at 0x%08x" % addr)
					if self.hitMemory != None: # Registered memory area
						#self.br.dbiprintf("[!] MemBp on write at 0x%08x" % addr)
						self.hitAddress = addr
						self.setTemporaryProtection()
						if self.isInIat(addr): # on IAT
							self.bp_end = self.setBpOnNextInst(self.handler_onWriteIat)
						elif self.isInCode(addr): # on CODE section
							self.br.dbiprintf(" - 0x%08x" % addr)
							self.lCurrPatches.append(addr)
							self.bp_end = self.setBpOnNextInst(self.handler_onWriteMemory)
						else:
							#cmdr = pykd.dbgCommand("r")
							#self.br.dbiprintf(cmdr)
							if addr in self.lOriginApi:
								del self.lOriginApi[addr]
							if len(ops) > 1:
								src = ops[1]
								if src[0] == "mem":
									if src[4] in self.lOriginApi:
										apiInfo = self.lOriginApi[src[4]]
										self.br.dbiprintf("[+] 0x%08x <= 0x%08x ( %s )" % (addr, src[4], apiInfo[1]))
										self.lOriginApi[addr] = apiInfo
									if src[4] >= 0x10000000: # library address boundary
										sym = self.br.getSymbolFromAddr(src[4])
										if sym != "":
											self.br.dbiprintf("[+] 0x%08x <= 0x%08x ( %s )" % (addr, src[4], sym))
											self.lOriginApi[addr] = [src[4], sym]
										else:
											self.br.dbiprintf("[?] 0x%08x <= 0x%08x" % (addr, src[4]))
									else:
										self.br.dbiprintf("[?] 0x%08x <= 0x%08x" % (addr, src[4]))
										
							self.bp_end = self.setBpOnNextInst(self.handler_onWriteMemory)
							#return pykd.eventResult.Break
						return pykd.eventResult.Proceed
				else:
					self.br.dbiprintf("[E] Unknown ACCESS_VIOLATION occured")
					cmdr = pykd.dbgCommand("r")
					self.br.dbiprintf(cmdr)
					return pykd.eventResult.Break
				
		return pykd.eventResult.NoChange
			
	def handler_onAccessMemory(self):
		self.unsetBpOnEip()
		if self.hitMemory == None:
			self.br.dbiprintf("[E] Memory on write handler at unknown ACCESS_VIOLATION")
			cmdr = pykd.dbgCommand("r")
			self.br.dbiprintf(cmdr)
			return pykd.eventResult.Break
		self.setBpMemoryOnAccess(self.pCodeBase, self.sizeCode)
		return pykd.eventResult.Proceed
			
	def handler_onWriteMemory(self):
		self.unsetBpOnEip()
		if self.hitMemory == None:
			self.br.dbiprintf("[E] Memory on write handler at unknown ACCESS_VIOLATION")
			cmdr = pykd.dbgCommand("r")
			self.br.dbiprintf(cmdr)
			return pykd.eventResult.Break
		addr = self.hitAddress
		self.restoreTemporaryProtection()
		
		#cmdr = pykd.dbgCommand("r")
		#self.br.dbiprintf(cmdr)
		
		return pykd.eventResult.Proceed
		
	def handler_onWriteIat(self):
		self.unsetBpOnEip()
		if self.hitMemory == None:
			self.br.dbiprintf("[E] IAT on write handler at unknown ACCESS_VIOLATION")
			cmdr = pykd.dbgCommand("r")
			self.br.dbiprintf(cmdr)
			return pykd.eventResult.Break
		addr = self.hitAddress
		self.restoreTemporaryProtection()
		val = self.br.readDword(addr)
		if val != 0:
			if val in self.lOriginApi:
				apiInfo = self.lOriginApi[val]
				apiAddr = apiInfo[0]
				sym = apiInfo[1]
			else:
				sym = self.br.getSymbolFromAddr(val)
				apiAddr = val
			self.setBpMemoryOnWrite(self.pCodeBase, self.sizeCode)
			
			# save relation infos between code patch and IAT
			if self.currIat != 0:
				if self.currIat in self.lIatCodePatch:
					self.br.dbiprintf("[E] Already has value at 0x%08x in IAT : Cannot save 0x%08x ( %s )" % (addr, val, sym))
				else:
					self.lIatCodePatch[self.currIat] = self.lCurrPatches
			self.currIat = addr
			self.lCurrPatches = []
			
			# resolve original API of address in IAT
			if sym != "":
				self.br.dbiprintf("[IAT] 0x%08x <= 0x%08x ( 0x%08x : %s )" % (addr, val, apiAddr, sym))
				self.br.writeDword(addr, apiAddr)
			else: # Invalid obfuscated area
				instBytes = self.br.readMemory(val, 0x10)
				for inst in self.br.md.disasm(instBytes, val):
					if len(inst.groups) > 0:
						for g in inst.groups:
							if g == capstone.x86.X86_GRP_JUMP:
								#self.br.dbiprintf(" - Jump")
								#self.br.dbiprintf("0x%08x\t%s\t%s" % (inst.address, inst.mnemonic, inst.op_str))
								ops = self.br.getOperands(inst)
								if len(ops) > 0:
									if ops[0][0] == "imm":
										dst = ops[0][1]
										#self.br.dbiprintf(" - Jump to 0x%08x" % dst)
										if dst in self.lOriginApi:
											sym = self.lOriginApi[dst]
										else:
											sym = self.br.getSymbolFromAddr(dst)
										if sym != "":
											self.br.dbiprintf("[IAT] 0x%08x <= 0x%08x ( 0x%08x : %s )" % (addr, val, dst, sym))
											self.br.writeDword(addr, dst)
											self.bp_end = None
											return pykd.eventResult.Proceed
								break
				
				self.br.dbiprintf("[E][IAT] 0x%08x <= 0x%08x ( Invalid )" % (addr, val))
		self.bp_end = None
		return pykd.eventResult.Proceed

		
class Handler_AllocateVirtualMemory(WinBpHandler):

	symNtdll = r"ntdll"
	symAllocateVirtualMemory = r"NtAllocateVirtualMemory"
	
	hNtdll = 0
	pAllocateVirtualMemory = 0
	
	iVmPAllocAddr = 0
	iVmPAllocSize = 0
	iVmProtection = 0
	
	iVmAllocAddr = 0
	iVmAllocSize = 0
	
	pRet = 0
	
	def __init__(self, lObfusMem, br = None, memh = None):
		self.lObfusMem = lObfusMem
		if br == None: self.br = WinDbgBridge()
		else: self.br = br
		if memh == None: self.memh = MemBpHandler()
		else: self.memh = memh
		self.hNtdll = pykd.module(self.symNtdll)
		self.pAllocateVirtualMemory = self.hNtdll.offset(self.symAllocateVirtualMemory)
		self.br.dbiprintf("[!] %s!%s = 0x%08x" % (self.symNtdll, self.symAllocateVirtualMemory, self.pAllocateVirtualMemory))
		
		self.bp_init = pykd.setBp(self.pAllocateVirtualMemory, self.handler_onCall)
		self.bp_end = None
	
	def __del__(self):
		self.unsetBp(self.pAllocateVirtualMemory)
		if self.bp_end != None:
			self.unsetBp(self.pRet)
		self.bp_init = None
		self.bp_end = None
	
	def handler_onCall(self):
		cmdr = pykd.dbgCommand("dd esp+8 L1")
		if cmdr == None:
			self.br.dbiprintf("[E] Before %s : Cannot dump stack" % self.symAllocateVirtualMemory)
			return pykd.eventResult.Break
		strPAllocAddr = cmdr[cmdr.find(" "):]
		iPAllocAddr = int(strPAllocAddr, 16)
		cmdr = pykd.dbgCommand("dd esp+10 L1")
		if cmdr == None:
			self.br.dbiprintf("[E] Before %s : Cannot dump stack" % self.symAllocateVirtualMemory)
			return pykd.eventResult.Break
		strPAllocSize = cmdr[cmdr.find(" "):]
		iPAllocSize = int(strPAllocSize, 16)
		cmdr = pykd.dbgCommand("dd esp+18 L1")
		if cmdr == None:
			self.br.dbiprintf("[E] Before %s : Cannot dump stack" % self.symAllocateVirtualMemory)
			return pykd.eventResult.Break
		strProtection = cmdr[cmdr.find(" "):]
		iProtection = int(strProtection, 16)
		
		if iProtection == 0x40:
			#self.br.dbiprintf("[*] Allocating memory for obfuscation has detected")
			#self.br.dbiprintf(" -> pAlloc : 0x%08x" % iPAllocAddr)
			self.iVmPAllocAddr = iPAllocAddr
			self.iVmPAllocSize = iPAllocSize
			self.iVmProtection = iProtection
			cmdr = pykd.dbgCommand("dd esp L1")
			strRet = cmdr[cmdr.find(" "):]
			self.pRet = int(strRet, 16)
			#self.br.dbiprintf(" -> Set break on RET : 0x%08x" % self.pRet)
			self.bp_end = pykd.setBp(self.pRet, self.handler_onRet)
		
		return pykd.eventResult.Proceed
	
	def handler_onRet(self):
		self.unsetBpOnEip()
		
		#self.br.dbiprintf(" -> after pAlloc : 0x%08x" % self.iVmPAllocAddr)
		cmdr = pykd.dbgCommand("dd %x L1" % self.iVmPAllocAddr)
		if cmdr == None:
			self.br.dbiprintf("[E] After %s : Cannot dump memory" % self.symAllocateVirtualMemory)
			return pykd.eventResult.Break
		strAllocAddr = cmdr[cmdr.find(" "):]
		iAllocAddr = int(strAllocAddr, 16)
		self.iVmAllocAddr = iAllocAddr
		#self.br.dbiprintf(" -> after pSize : 0x%08x" % self.iVmPAllocSize)
		cmdr = pykd.dbgCommand("dd %x L1" % self.iVmPAllocSize)
		if cmdr == None:
			self.br.dbiprintf("[E] After %s : Cannot dump memory" % self.symAllocateVirtualMemory)
			return pykd.eventResult.Break
		strAllocSize = cmdr[cmdr.find(" "):]
		iAllocSize = int(strAllocSize, 16)
		self.iVmAllocSize = iAllocSize
		self.lObfusMem[iAllocAddr] = iAllocSize
		self.memh.setBpMemoryOnWrite(iAllocAddr, iAllocSize)
		self.br.dbiprintf("[+] Allocating obfuscation memory(0x%08x) = 0x%08x" % (iAllocSize, iAllocAddr))
		self.memh.setMemBpOnWriteOnIat()
		
		self.pRet = 0
		self.bp_end = None
		return pykd.eventResult.Proceed

		
class Handler_FreeVirtualMemory(WinBpHandler):

	symNtdll = r"ntdll"
	symFreeVirtualMemory = r"NtFreeVirtualMemory"
	
	hNtdll = 0
	pFreeVirtualMemory = 0
	
	def __init__(self, lObfusMem, br = None, memh = None):
		self.lObfusMem = lObfusMem
		if br == None: self.br = WinDbgBridge()
		else: self.br = br
		if memh == None: self.memh = MemBpHandler()
		else: self.memh = memh
		self.hNtdll = pykd.module(self.symNtdll)
		self.pFreeVirtualMemory = self.hNtdll.offset(self.symFreeVirtualMemory)
		self.br.dbiprintf("[!] %s!%s = 0x%08x" % (self.symNtdll, self.symFreeVirtualMemory, self.pFreeVirtualMemory))
		
		self.bp_init = pykd.setBp(self.pFreeVirtualMemory, self.handler_onCall)
		self.bp_end = None
	
	def __del__(self):
		self.unsetBp(self.pFreeVirtualMemory)
		self.bp_init = None
		self.bp_end = None
		
	def handler_onCall(self):
		cmdr = pykd.dbgCommand("dd esp+8 L1")
		if cmdr == None:
			self.br.dbiprintf("[E] Before %s!%s : Cannot dump stack" % (self.symNtdll, self.symFreeVirtualMemory))
			return pykd.eventResult.Break
		strPFreeAddr = cmdr[cmdr.find(" "):]
		iPFreeAddr = int(strPFreeAddr, 16)
		cmdr = pykd.dbgCommand("dd %x L1" % iPFreeAddr)
		if cmdr == None:
			self.br.dbiprintf("[E] Before %s!%s : Cannot dump memory" % (self.symNtdll, self.symFreeVirtualMemory))
			return pykd.eventResult.Break
		strFreeAddr = cmdr[cmdr.find(" "):]
		iFreeAddr = int(strFreeAddr, 16)
		
		if iFreeAddr in self.lObfusMem:
			del self.lObfusMem[iFreeAddr]
			mem = self.memh.isRegisteredMemory(iFreeAddr)
			if mem != None:
				self.memh.unsetBpMemoryOnWrite(mem[0], mem[1])
			self.br.dbiprintf("[-] Free obfuscation memory(0x%08x)" % iFreeAddr)
			if iFreeAddr in self.memh.lOriginApi:
				self.br.dbiprintf("[!] API obfuscation is over")
				if self.memh.currIat != 0:
					#self.br.dbiprintf("[+] Saving last code patching info : 0x%08x" % (self.memh.currIat))
					if self.memh.currIat in self.memh.lIatCodePatch:
						self.br.dbiprintf("[E] Already has value at 0x%08x in IAT : Cannot save last code patching info" % (self.memh.currIat))
					else:
						self.memh.lIatCodePatch[self.memh.currIat] = self.memh.lCurrPatches
				self.memh.restoreAllProtections()
				self.memh.setBpMemoryOnAccess(self.memh.pCodeBase, self.memh.sizeCode)
		
		return pykd.eventResult.Proceed
		
		
class WindbgDbi():
	winBr = None
	lObfusMem = {} # memories for obfuscated API [Addr] = Size
	
	symPath = "SRV*c:\\code\\symbols*http://msdl.microsoft.com/download/symbols;SRV*c:\\code\\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com"
	
	dumpPath = "c:\\Users\\slimv0x00\\Desktop\\"
	maxDumpSectionNum = 3
	
	lDumpNames = []
	
	def __init__(self):
		self.winBr = WinDbgBridge()
		
	def patchCall(self, patchInfos):
		self.winBr.dbiprintf("[!] Code patching")
		lastPatch = 0
		mBase = self.winBr.procImageBase
		for pIat in patchInfos.keys():
			self.winBr.dbiprintf("[IAT] 0x%08x" % pIat)
			patchList = patchInfos[pIat]
			for j in range(len(patchList)):
				pOvw = patchList[j]
				self.winBr.dbiprintf(" - 0x%08x" % pOvw)
				if pOvw > lastPatch:
					patchGap = pOvw - lastPatch
				else:
					patchGap = lastPatch - pOvw
				if patchGap > 5:
					destBuf = self.winBr.readMemory(pOvw, 2)
					if destBuf.find("\xe8") != -1: # call
						patch = "\xff\x15" + struct.pack("<L", pIat)
						self.winBr.writeMemory(pOvw, patch)
						lastPatch = pOvw
					elif destBuf.find("\xe9") != -1: #jmp
						patch = "\xff\x25" + struct.pack("<L", pIat)
						self.winBr.writeMemory(pOvw, patch)
						lastPatch = pOvw
					else:
						vDest = struct.unpack("<H", destBuf)[0]
						if vDest != 0x15ff and vDest != 0x25ff:
							self.winBr.dbiprintf(hex(pOvw) + " = Unknown patch syntax")
							self.winBr.dbiprintf(hex(struct.unpack("<H", destBuf)[0]))
		self.winBr.dbiprintf("[!] Function number : " + str(len(patchInfos)))
		
	def dumpMemory(self, dumpPath, addr, size):
		lineNumber = 0x40
		mapSize = 0x1000
		cmdDd = "dd %x L%x"
		regDd = "[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+"
		
		if size <= 0:
			self.winBr.dbiprintf("[E] Invalid dump size : 0x%08x" % size)
			return
		pykd.dprint("[+] Dump 0x%08x ( 0x%08x )" % (addr, size))
		dSize = size / mapSize
		if size % mapSize != 0:
			dSize = dSize + 1
		dSize = dSize * mapSize
		fileName = "dump_0x%x (0x%x).bin" % (addr, dSize)
		self.lDumpNames.append(fileName)
		fullPath = dumpPath + fileName
		f = open(fullPath, "wb")
		fullLoop = dSize / (lineNumber * 4)
		ta = addr
		for l in range(fullLoop):
			#self.winBr.dbiprintf(" -> 0x%08x" % ta)
			pykd.dprint(".")
			cmd = cmdDd % (ta, lineNumber)
			cmdr = pykd.dbgCommand(cmd)
			#self.winBr.dbiprintf(cmdr)
			ta = ta + (lineNumber * 4)
			
			bl = re.findall(regDd, cmdr)
			for i in bl:
				#self.winBr.dbiprintf(i)
				rel = i.split()
				f.write(struct.pack("<L", int(rel[1], 16)))
				f.write(struct.pack("<L", int(rel[2], 16)))
				f.write(struct.pack("<L", int(rel[3], 16)))
				f.write(struct.pack("<L", int(rel[4], 16)))	
		self.winBr.dbiprintf("")
		f.close()
		self.winBr.dbiprintf(" -> %s" % fullPath)

	def rebuild(self, path):
		lAddr = []

		iat_ptr = 0x0
		iat_size = 0x0

		self.winBr.dbiprintf("\n[!] Rebuild PE")
		buildPath = path + "rebuilt.exe"
		hRebuild = open(buildPath, "wb")
		
		lSectionNames = ["DOS", "CODE", "DATA", "SFX00", "SFX01", "SFX02", "SFX03"]
		section_headers = []
		self.winBr.dbiprintf(" -> Constructing Headers")
		cntLine = 0
		for line in self.lDumpNames:
			tBase = int(line[line.find("_") + 1:line.find(" (")], 16)
			tSize = int(line[line.find("(") + 1:line.find(")")], 16)
			if cntLine == 0:
				dumpPath = path + line
				hDump = open(dumpPath, "rb")
				mBase = tBase
				dos_header = hDump.read(0x40)
				hDump.seek(struct.unpack("<L", dos_header[-4:])[0])
				nt_header = hDump.read(4)
				file_header = hDump.read(0x14)
				opt_header = hDump.read(0x60)
				nDataDir = struct.unpack("<L", opt_header[-4:])[0]

				lDataDir = []
				for i in range(nDataDir):
					lDataDir.append(hDump.read(0x8))

				dos_header = dos_header[:0x3c] + struct.pack("<L", len(dos_header))
				hRebuild.write(dos_header)
				hRebuild.write(nt_header)
				hDump.close()

			else:
				section = lSectionNames[cntLine]
				for i in range(8 - len(lSectionNames[cntLine])):
					section += struct.pack("<B", 0x0)
				section += struct.pack("<L", tSize) # virtual size
				section += struct.pack("<L", tBase - mBase) # rva
				section += struct.pack("<L", tSize) # size of raw
				section += struct.pack("<L", tBase - mBase) # ptr to raw
				section += struct.pack("<L", 0x0) # ptr to rel
				section += struct.pack("<L", 0x0) # ptr to line
				section += struct.pack("<H", 0x0) # num of rel
				section += struct.pack("<H", 0x0) # num of line
				section += struct.pack("<L", 0xe0000020) # characteristics
				section_headers.append(section)

			cntLine = cntLine + 1

		self.winBr.dbiprintf(" -> Rebuilding : %d sections" % len(section_headers))
		file_header = file_header[:2] + struct.pack("<H", len(section_headers)) + file_header[4:]
		hRebuild.write(file_header)
		opt_header = opt_header[:4] + section_headers[0][0x8:0xc]\
					 + section_headers[1][0x8:0xc] + struct.pack("<L", 0x0) + struct.pack("<L", 0xd878)\
					 + section_headers[0][0xc:0x10] + section_headers[1][0xc:0x10]\
					 + opt_header[0x1c:]
		lDataDir[1] = struct.pack("<L", iat_ptr) + struct.pack("<L", iat_size)
		for i in lDataDir:
			opt_header += i
		hRebuild.write(opt_header)

		for i in range(len(section_headers)):
			hRebuild.write(section_headers[i])
		fp = hRebuild.tell()
		sectionEnd = (((fp + (len(section) * len(section_headers))) / 0x1000) + 1) * 0x1000
		paddingSize = sectionEnd - fp
		hRebuild.write("\x00" * paddingSize)

		for i in range(len(section_headers)):
			self.winBr.dbiprintf(path + self.lDumpNames[i + 1])
			hBin = open(path + self.lDumpNames[i + 1], "rb")
			while True:
				stream = hBin.read(0x1000)
				if not stream:
					break
				hRebuild.write(stream)
			hBin.close()

		self.winBr.dbiprintf("\n[!] Rebuilt PE : %s" % (buildPath))
		hRebuild.close()
		
	def run(self):
		self.winBr.initLog()
		self.winBr.dbiprintf("< WinDbg DBI >")
		if self.winBr.getImageInfo() != 0:
			self.winBr.dbiprintf("[!] Check the symbol path ( Recommended : %s )" % self.symPath)
			return 1
		if self.winBr.getSectionInfo() != 0:
			return 2
		if self.winBr.procImageBase != -1 and self.winBr.procImageEnd != -1 and self.winBr.procImageSize != 0:
			memBpHandler = MemBpHandler(self.lObfusMem, self.winBr)
			memBpHandler.forceSetIat(self.winBr.procImageBase + 0x2000, 0xa00) # IAT
			memBpHandler.forceSetCode(self.winBr.lSection[1][0], self.winBr.lSection[1][3])
			handler_AllocateVirtualMemory = Handler_AllocateVirtualMemory(self.lObfusMem, self.winBr, memBpHandler)
			handler_FreeVirtualMemory = Handler_FreeVirtualMemory(self.lObfusMem, self.winBr, memBpHandler)
		
			pykd.go()
			self.winBr.dbiprintf("[!] PYKD retake the control")
			
			self.patchCall(memBpHandler.lIatCodePatch)
			self.winBr.dbiprintf("[+] Dump %d sections" % self.maxDumpSectionNum)
			for i in range(self.maxDumpSectionNum):
				s = self.winBr.lSection[i]
				self.dumpMemory(self.dumpPath, s[0], s[3])
			self.rebuild(self.dumpPath)
			
			self.winBr.dbiprintf("[!] PE info")
			self.winBr.dbiprintf(" -> OEP : 0x%08x ( 0x%08x + 0x%08x )" % (memBpHandler.oep, self.winBr.procImageBase, memBpHandler.oep - self.winBr.procImageBase))
			self.winBr.dbiprintf(" -> IAT : 0x%08x ( 0x%08x + 0x%08x )" % (memBpHandler.pIatBase, self.winBr.procImageBase, memBpHandler.pIatBase - self.winBr.procImageBase))
			self.winBr.dbiprintf(" -> IAT size : 0x%08x" % (memBpHandler.sizeIat))
			
		return 0


windbi = WindbgDbi()
windbi.run()

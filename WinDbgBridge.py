import pykd
import types
import re
import capstone
import struct

class WinDbgBridge():

	bSilent = False

	def __init__(self, md = None, logPath = "C:\Users\USER\Desktop\dbiLog.txt"):
		if md == None:
			self.md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
		else: self.md = md
		self.md.detail = True
		self.logPath = logPath


	def initLog(self, bSilent = False):
		self.bSilent = bSilent
		f = open(self.logPath, "w")
		f.close()


	def dbiprintf(self, str):
		f = open(self.logPath, "a")
		f.write(str + "\n")
		f.close()
		if self.bSilent == False:
			pykd.dprintln(str)


	# returns types.NoneType on failed
	def getRegVal(self, regName):
		cmdReg = "r %s" % regName
		iParseBegin = "%s=" % regName
		cmdr = pykd.dbgCommand(cmdReg)
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Cannot read register %s" % regName, False)
			return types.NoneType
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


	# returns types.NoneType on failed
	def readDword(self, addr):
		cmd = "dd %x L1" % addr
		cmdr = pykd.dbgCommand(cmd)
		try:
			strVal = cmdr.split()
			readVal = int(strVal[1], 16)
			return readVal
		except:
			self.dbiprintf("[E] Cannot read dword at 0x%x" % addr, False)
			self.dbiprintf(cmdr)
			return types.NoneType


	# returns types.NoneType on failed
	def readByte(self, addr):
		cmd = "db %x L1" % addr
		cmdr = pykd.dbgCommand(cmd)
		try:
			strVal = cmdr.split()
			readVal = int(strVal[1], 16)
			return readVal
		except:
			self.dbiprintf("[E] Cannot read byte at 0x%x" % addr, False)
			self.dbiprintf(cmdr)
			return types.NoneType


	# returns types.NoneType on failed
	def readMemory(self, addr, lenMem):
		data = ""
		scope = (lenMem / 4) * 4
		pin = addr + scope
		end = addr + lenMem
		for dst in range(addr, pin, 4): # read memory in dword
			dw = self.readDword(dst)
			if dw == types.NoneType:
				self.dbiprintf(" - [E] Cannot read memory 0x%x ( 0x%x )" % (addr, lenMem), False)
				return types.NoneType
			data = data + struct.pack("<L", dw)
		for dst in range(pin, end):
			bb = self.readByte(dst)
			if dw == types.NoneType: # read memory in byte
				self.dbiprintf(" - [E] Cannot read memory 0x%x ( 0x%x )" % (addr, lenMem), False)
				return types.NoneType
			data = data + struct.pack("<B", bb)
		return data


	# returns types.NoneType on failed
	def parseInstructionLine(self):
		regModule = "[0-9a-fA-F]+ +[0-9a-fA-F]+ +.+"
		cmdr = pykd.dbgCommand("r")
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Cannot read instruction", False)
			return types.NoneType
		blist = re.findall(regModule, cmdr)
		if blist == types.NoneType:
			self.dbiprintf(" - [E] Cannot find instruction : %s" % cmdr, False)
			return types.NoneType
		bl = blist[0]
		return bl


	# returns types.NoneType on failed
	def parseInstructionBytes(self):
		instLine = self.parseInstructionLine()
		blist = instLine.split()
		if len(blist) == 0:
			self.dbiprintf("[E] Invalid instruction line : %s" % instLine, False)
			return types.NoneType
		strBytes = blist[1]
		bytes = strBytes.decode("hex")
		return bytes


	# returns [0: Image name, 1: Image base, 2: Image end, 3: Image size], types.NoneType on failed
	def getImageInfo(self):
		iPImageBaseBegin = "ImageBaseAddress:"
		iPImageBaseEnd = "Ldr"
		iPImageNameBegin = "ImageFile:"
		iPImageNameEnd = "CommandLine"
		
		self.dbiprintf("[+] Get image information", False)
		cmdr = pykd.dbgCommand("!peb")
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Cannot get PEB", False)
			return types.NoneType
		# get image name from PEB
		if cmdr.find(iPImageNameBegin) == -1:
			self.dbiprintf(" - [E] Cannot find image name : %s" % (cmdr), False)
			self.dbiprintf(cmdr)
			return types.NoneType
		path = cmdr[cmdr.find(iPImageNameBegin) + len(iPImageNameBegin):cmdr.find(iPImageNameEnd)]
		imageName = path[path.rfind("\\") + 1:path.rfind("'")]
		
		return getImageInfo(self, imageName)


	# returns [0: Image name, 1: Image base, 2: Image end, 3: Image size], types.NoneType on failed
	def getImageInfo(self, nameModule):
		cmd = "lm"
		cmdr = pykd.dbgCommand(cmd)
		extRmNameModule = nameModule
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Cannot get list of modules", False)
			return types.NoneType
		if nameModule.find(".") != -1:
			extRmNameModule = nameModule[:nameModule.rfind('.')]

		self.dbiprintf("[+] Get module information : %s" % nameModule, False)
		lines = cmdr.split('\n')
		lines = lines[1:]
		imageInfo = [nameModule]
		for line in lines:
			if not line:
				break
			info = line.split()
			if info[2] == nameModule or info[2] == extRmNameModule:
				try:
					imageBase = int(info[0], 16)
					imageEnd = int(info[1], 16)
					imageSize = imageEnd - imageBase
					imageInfo.append(imageBase)
					imageInfo.append(imageEnd)
					imageInfo.append(imageSize)
				except:
					self.dbiprintf("[E] Cannot read module address : %s" % (info), False)
					self.dbiprintf(cmdr)
					return types.NoneType
				break
		
		if len(imageInfo) == 4:
			self.dbiprintf(" -> module name : %s ( 0x%08x ~ 0x%08x ( 0x%08x ) )" % (nameModule, imageBase, imageEnd, imageSize))
			return imageInfo

		self.dbiprintf("[E] Cannot find module %s" % (nameModule), False)
		self.dbiprintf("%s" % (cmdr), False)
		return types.NoneType


	# returns [Section number][0: VA, 1: VA end, 2: RVA, 3: Virtual size, 4: Protection], types.NoneType on failed
	def getSectionInfo(self, addr):
		cmdDh = "!dh -s "
		iParseSection = "SECTION HEADER"
		iParseName = "name"
		iParseVs = "virtual size"
		iParseVa = "virtual address"

		lSection = []
		
		self.dbiprintf("[+] Get section information", False)
		cmd = cmdDh + "%x" % addr
		cmdr = pykd.dbgCommand(cmd)
		if type(cmdr) == types.NoneType:
			self.dbiprintf(" - [E] Cannot dump section header at 0x%08x" % addr, False)
			return types.NoneType
		# add PE header's page
		guard = pykd.getVaProtect(addr)
		lSection.append([addr, addr + 0x1000, 0, 0x1000, guard])
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
			va = addr + rva
			vaEnd = va + vs
			guard = pykd.getVaProtect(va)
			self.dbiprintf(" -> Section #%d : 0x%08x ( 0x%08x ) : 0x%x" % (len(lSection), va, vs, guard))
			lSection.append([va, vaEnd, rva, vs, guard])

		if len(lSection) == 0:
			self.dbiprintf(" - [E] Cannot find section at 0x%08x" % addr, False)
			self.dbiprintf("%s" % (cmdr), False)
			return types.NoneType
		return lSection


	# returns types.NoneType on failed
	def getSymbolFromAddr(self, addr, bSilent = False):
		iParseBegin = "Exact matches:"
		cmdr = pykd.dbgCommand("ln %x" % addr)
		if type(cmdr) == types.NoneType:
			if bSilent == False:
				self.dbiprintf("[E] Cannot find symbol at 0x%08x" % addr)
			return types.NoneType
		if cmdr.find(iParseBegin) == -1:
			if bSilent == False:
				self.dbiprintf("[E] Cannot find exact symbol at 0x%08x" % addr)
			return types.NoneType
		syms = cmdr[cmdr.find(iParseBegin) + len(iParseBegin):]
		lSym = syms.split()
		if len(lSym) == 0:
			if bSilent == False:
				self.dbiprintf("[E] Cannot read exact symbol at 0x%08x" % addr)
				self.dbiprintf("%s" % (cmdr), bSilent)
			return types.NoneType
		return lSym[0]


	def getSectionNum(self, lSection, addr):
		for i in range(len(lSection)):
			if addr >= lSection[i][0] and addr < lSection[i][1]: # [0: VA, 1: VA end]
				return i
		return -1


	# returns [0: type, 1: value] (type == mem: [0: type, 1: mem addr string, 2: mem element list, 3: mem formula list, 4: mem address])
	def getOperands(self, inst):
		operands = [] # list of operands [0: type, 1: value]
		if len(inst.operands) > 0:
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


	# returns [0: addr, 1: api count], types.NoneType on failed
	def searchIatCandidate(self, addr, size):
		lineNumber = 0x40
		mapSize = 0x1000
		cmdDd = "dd %x L%x"
		regDd = "[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+"

		dictCandIat = {}
		baseAddr = 0
		nullCnt = 0
		
		if size <= 0:
			self.dbiprintf("[E] Invalid dump size : 0x%08x" % size, False)
			return types.NoneType
		self.dbiprintf("[+] Searching IAT candidates in 0x%08x ( 0x%08x )" % (addr, size))
		dSize = size / mapSize
		if size % mapSize != 0:
			dSize = dSize + 1
			dSize = dSize * mapSize
		
		fullLoop = dSize / (lineNumber * 4)
		ta = addr
		for l in range(fullLoop):
			pykd.dprint(".")
			cmd = cmdDd % (ta, lineNumber)
			cmdr = pykd.dbgCommand(cmd)
			ta = ta + (lineNumber * 4)
			
			bl = re.findall(regDd, cmdr)
			for i in bl:
				rel = i.split()
				for j in range(1, len(rel)):
					valIn = int(rel[j], 16)
					if valIn == 0:
						if baseAddr != 0:
							if nullCnt > 0:
								nullCnt = 0
								baseAddr = 0
							else:
								nullCnt = nullCnt + 1
								dictCandIat[baseAddr] = dictCandIat[baseAddr] + 1
						continue
					
					nullCnt = 0
					sym = self.getSymbolFromAddr(valIn, True)
					if sym != "":
						if baseAddr == 0:
							baseAddr = int(rel[0], 16) + ((j - 1) * 4)
							dictCandIat[baseAddr] = 1
						else:
							dictCandIat[baseAddr] = dictCandIat[baseAddr] + 1
                                
                self.dbiprintf("")
                maxCnt = -1
                maxAddr = 0
                if len(dictCandIat) == 0:
                        return types.NoneType
                self.dbiprintf("[+] Candidates of IAT")
                for i in dictCandIat.keys():
                    self.dbiprintf(" - 0x%08x : %d" % (i, dictCandIat[i]))
                    if maxCnt < dictCandIat[i]:
                        maxCnt = dictCandIat[i]
                        maxAddr = i
                self.dbiprintf(" -> Longest hit : 0x%08x" % maxAddr)
		self.dbiprintf("")
		return [maxAddr, maxCnt]


	# returns [0: IAT addr, 1: IAT size], types.NoneType on failed
	def searchIatInSections(self, lSection):
		self.dbiprintf("[+] Searching IAT in sections")
		if len(lSection) == 0:
			self.dbiprintf("[E] Invalid section", False)
			return types.NoneType
		cntIat = 0
		for i in range(1, len(lSection)):
			s = lSection[i]
			candIat = self.searchIat(s[0], s[3]) # [0: VA, 3: Virtual size]
			if cntIat < candIat[1]:
				cntIat = candIat[1]
				iatBase = candIat[0]
				iatSize = (cntIat * 4) + 8
		if cntIat == 0:
			self.dbiprintf("[E] Cannot find IAT", False)
			return types.NoneType
		self.dbiprintf(" -> Probably IAT : 0x%08x ( 0x%08x ) " % (iatBase, iatSize))
		return [iatBase, iatSize]


	# returns file name, types.NoneType on failed
	def dumpMemory(self, dumpPath, addr, size):
		lineNumber = 0x40
		mapSize = 0x1000
		cmdDd = "dd %x L%x"
		regDd = "[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+"
		
		if size <= 0:
			self.dbiprintf("[E] Invalid dump size : 0x%08x" % size, False)
			return types.NoneType
		self.dbiprintf("[+] Dump 0x%08x ( 0x%08x )" % (addr, size), False)
		dSize = size / mapSize
		if size % mapSize != 0:
			dSize = dSize + 1
		dSize = dSize * mapSize
		fileName = "dump_0x%x (0x%x).bin" % (addr, dSize)
		fullPath = dumpPath + fileName
		f = open(fullPath, "wb")
		fullLoop = dSize / (lineNumber * 4)
		ta = addr
		for l in range(fullLoop):
			pykd.dprint(".")
			cmd = cmdDd % (ta, lineNumber)
			cmdr = pykd.dbgCommand(cmd)
			ta = ta + (lineNumber * 4)
			
			bl = re.findall(regDd, cmdr)
			for i in bl:
				rel = i.split()
				f.write(struct.pack("<L", int(rel[1], 16)))
				f.write(struct.pack("<L", int(rel[2], 16)))
				f.write(struct.pack("<L", int(rel[3], 16)))
				f.write(struct.pack("<L", int(rel[4], 16)))	
		self.dbiprintf("")
		f.close()
		self.dbiprintf(" -> %s" % fullPath, False)
		return fileName


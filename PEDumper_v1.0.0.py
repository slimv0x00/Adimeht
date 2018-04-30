import pykd
import types
import re
import time
import socket
import sys
import capstone
import struct

class WinDbgBridge():
	
	logPath = "C:\Users\USER\Desktop\dbiLog.txt"
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


	def getImageInfo(self, nameModule):
                cmd = "lm"
		cmdr = pykd.dbgCommand(cmd)
		extRmNameModule = nameModule
		if type(cmdr) == types.NoneType:
		    self.dbiprintf(" - [E] Error on get list of modules")
                    return 1
		if nameModule.find(".") != -1:
                    extRmNameModule = nameModule[:nameModule.rfind('.')]
                    print extRmNameModule

		self.dbiprintf("[!] Get module information : %s" % nameModule)
                lines = cmdr.split('\n')
                lines = lines[1:]
                for line in lines:
                    if not line:
                        break
                    info = line.split()
                    if info[2] == nameModule or info[2] == extRmNameModule:
                        self.procImageBase = int(info[0], 16)
                        self.procImageEnd = int(info[1], 16)
                        self.imageName = info[2]
                        self.procImageSize = self.procImageEnd - self.procImageBase
                        break
                    
                self.dbiprintf(" -> Image name : %s ( 0x%08x ~ 0x%08x ( 0x%08x ) )" % (self.imageName, self.procImageBase, self.procImageEnd, self.procImageSize))
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
		if len(lSym) == 0:
                        self.dbiprintf("[E] Cannot find exact symbol : 0x%08x" % addr)
                        return ""
		return lSym[0]


	def getSymbolFromAddrSilent(self, addr):
		iParseBegin = "Exact matches:"
		cmdr = pykd.dbgCommand("ln %x" % addr)
		if type(cmdr) == types.NoneType:
			return ""
		if cmdr.find(iParseBegin) == -1:
			return ""
		syms = cmdr[cmdr.find(iParseBegin) + len(iParseBegin):]
		lSym = syms.split()
		if len(lSym) == 0:
                        return ""
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


class WindbgDumper():
	winBr = None
	
	symPath = "SRV*c:\\code\\symbols*http://msdl.microsoft.com/download/symbols;SRV*c:\\code\\symbols*https://chromium-browser-symsrv.commondatastorage.googleapis.com"
	
	dumpPath = "c:\\Users\\USER\\Desktop\\"
	
	lDumpNames = []

        oep = 0
        
        iatBase = 0
        iatSize = 0
	
	def __init__(self):
		self.winBr = WinDbgBridge()


	def searchIat(self, addr, size):
		lineNumber = 0x40
		mapSize = 0x1000
		cmdDd = "dd %x L%x"
		regDd = "[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+ +[0-9a-fA-F]+"

		dictCandIat = {}
		baseAddr = 0
		nullCnt = 0
		
		if size <= 0:
			self.winBr.dbiprintf("[E] Invalid dump size : 0x%08x" % size)
			return
		pykd.dprint("[+] Searching IAT in 0x%08x ( 0x%08x )" % (addr, size))
		dSize = size / mapSize
		if size % mapSize != 0:
			dSize = dSize + 1
		dSize = dSize * mapSize
		
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
                            sym = self.winBr.getSymbolFromAddrSilent(valIn)
                            if sym != "":
                                if baseAddr == 0:
                                    baseAddr = int(rel[0], 16) + ((j - 1) * 4)
                                    dictCandIat[baseAddr] = 1
                                else:
                                    dictCandIat[baseAddr] = dictCandIat[baseAddr] + 1
                                
                self.winBr.dbiprintf("")
                maxCnt = -1
                maxAddr = 0
                if len(dictCandIat) == 0:
                        return [maxAddr, maxCnt]
                self.winBr.dbiprintf("[+] Candidates of IAT")
                for i in dictCandIat.keys():
                    self.winBr.dbiprintf(" - 0x%08x : %d" % (i, dictCandIat[i]))
                    if maxCnt < dictCandIat[i]:
                        maxCnt = dictCandIat[i]
                        maxAddr = i
                self.winBr.dbiprintf(" -> Probably IAT : 0x%08x" % maxAddr)
		self.winBr.dbiprintf("")
		return [maxAddr, maxCnt]
		

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
		
		lSectionNames = ["DOS", "CODE", "DATA"]#, "SFX00", "SFX01", "SFX02", "SFX03"]
                if len(self.winBr.lSection) > 3:
                        for i in range(len(self.winBr.lSection) - 3):
                                lSectionNames.append("SFX%02d" % i)
		
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
		
                # size of code
                # size of initialized data
                # size of uninitialized data
                # address of entry point (dummy)
                # base of code
                # base of data
                # image base		 
		opt_header = opt_header[:4] + section_headers[0][0x8:0xc]\
                                        + section_headers[1][0x8:0xc]\
                                        + struct.pack("<L", 0x0)\
                                        + struct.pack("<L", 0xd878)\
                                        + section_headers[0][0xc:0x10]\
                                        + section_headers[1][0xc:0x10]\
                                        + struct.pack("<L", self.winBr.procImageBase)\
                                        + opt_header[0x20:]
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
		

        def run(self, imageName = ""):
		self.winBr.initLog()
		self.winBr.dbiprintf("< Dumper >")

		self.oep = self.winBr.getRegVal("eip")

		if imageName == "":
                    rGetImageInfo = self.winBr.getImageInfo()
                else:
                    rGetImageInfo = self.winBr.getImageInfo(imageName)

                if rGetImageInfo != 0:
			self.winBr.dbiprintf("[!] Check the symbol path ( Recommended : %s )" % self.symPath)
			return 1
		if self.winBr.getSectionInfo() != 0:
			return 2
		if self.winBr.procImageBase != -1 and self.winBr.procImageEnd != -1 and self.winBr.procImageSize != 0:
                        cntIat = 0
                        for i in range(1, len(self.winBr.lSection)):
                            s = self.winBr.lSection[i]
                            candIat = self.searchIat(s[0], s[3])
                            if cntIat < candIat[1]:
                                cntIat = candIat[1]
                                self.iatBase = candIat[0]
                                self.iatSize = (cntIat * 4) + 8
                            
                        self.winBr.dbiprintf("[+] Dump %d sections" % len(self.winBr.lSection[i]))
			for i in range(len(self.winBr.lSection)):
			    s = self.winBr.lSection[i]
                            self.dumpMemory(self.dumpPath, s[0], s[3])
    
                        self.rebuild(self.dumpPath)
                        
                        self.winBr.dbiprintf("[!] PE info")
			self.winBr.dbiprintf(" -> OEP : 0x%08x ( 0x%08x + 0x%08x )" % (self.oep, self.winBr.procImageBase, self.oep - self.winBr.procImageBase))
			self.winBr.dbiprintf(" -> IAT : 0x%08x ( 0x%08x + 0x%08x )" % (self.iatBase, self.winBr.procImageBase, self.iatBase - self.winBr.procImageBase))
			self.winBr.dbiprintf(" -> IAT size : 0x%08x" % (self.iatSize))


windbgDumper = WindbgDumper()
windbgDumper.run("moduleName")

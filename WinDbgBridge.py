import pykd
import types
import re

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


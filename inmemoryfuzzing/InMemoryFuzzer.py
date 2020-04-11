#!/usr/bin/python
""" ___         __  __
|_ _|_ __   |  \/  | ___ _ __ ___   ___  _ __ _   _
 | || '_ \  | |\/| |/ _ \ '_ ` _ \ / _ \| '__| | | |
 | || | | | | |  | |  __/ | | | | | (_) | |  | |_| |
|___|_| |_| |_|  |_|\___|_| |_| |_|\___/|_|   \__, |
                                              |___/
 _____
|  ___|   _ ___________ _ __
| |_ | | | |_  /_  / _ \ '__|
|  _|| |_| |/ / / /  __/ |         Written by sinn3r
|_|   \__,_/___/___\___|_|       twitter.com/_sinn3r
"""

## sinn3r's in-memory fuzzer
## twitter.com/_sinn3r
## Corelan Security
## Offensive Security Exploit Database

import sys
try:
	from pydbg import *
	from pydbg.defines import *
	from ctypes import *
except:
	print "[ERROR] Your system does not support PYDBG and/or ctypes. Cannot continue."
	print "Download the following items to get it started:"
	print "[-] Python 2.5 (installed from Immunity Debugger)"
	print "[-] pydasm: http://therning.org/magnus/archives/278"
	print "[-] Paimei: http://www.openrce.org/downloads/details/208/PaiMei"
	sys.exit(-1)
import random
import re
import os
import time
import binascii

################################# User Settings: ###################################
global maxFuzzCount; maxFuzzCount = 6	#How many times to fuzz each routine?
global badchars; badchars = ""		#Specify badchars here. Example: "\x00\x0a"
global crashbin; crashbin = "crashbin/"	#Where to save the crash results

class FuzzLib:
	"""
	This is a class that generates random data for fuzzing. It requires a globally defined "maxFuzzCount"
	variable (integer) in order to run.
	"""
	def __init__(self):
		self._maxlibSize = 30000		#Max of 30000 bytes of fuzzing data
		self._commonDelimiters = ["\x0a", "\x0d", ",", ".", ":", ";",
					"&", "%", "$", "\x20", "\x00", "#",
					"(", ")", "{", "}", "<", ">", "\"",
					"'", "\\", "|", "@", "*", "-"]

		self._commonStrings = [ "\x41"*500,  "\x41"*1000, "\x41"*2000,
					"\x41"*3000, "\x41"*4000, "\x41"*5000,
					"\x41"*6000, "\x41"*7000, "\x41"*8000,
					"\x41"*10000,"\x41"*11000,"\x41"*12000,
					"~!@#$^&"*1000,	"~!@#$^&"*2000,
					"~!@#$^&"*3000,	"~!@#$^&"*4000,
					"~!@#$^&"*5000,	"%n%n%n%n%n", "%p%p%p%p",
					"%s"*500, "%x"*1000, "../"*1000,
					"../"*5000, "%%20x", "%2e%2e/"*1000,
					"16777215", "0x99999999", "0xffffffff",
					"%u000", "AAAA"+"../"+"A"*300, "%"+"A"*3000]

	def __rndSize(self):
		"""
		Return a random size
		"""
		return random.randint(1, self._maxlibSize)

	def rndBinary(self):
		"""
		Return a random set of bytes
		"""
		raw = ""
		max = self.__rndSize()
		for i in range(1, max):
			raw += chr(random.randint(1, 127))
		return raw

	def rndAscii(self):
		"""
		Return a random set of ASCII printable characters
		"""
		raw = ""
		for i in range(1, self.__rndSize()):
			raw += chr(random.randint(65, 90))
		return raw

	def rndDelimiter(self):
		"""
		Return a random string where there's a randomly selected delimiter in between
		"""
		buffer1 = self.common()
		buffer2 = self.common()
		d = random.choice(self._commonDelimiters)
		return buffer1 + d + buffer2

	def common(self):
		"""
		Return a string that's commonly used to crash an application
		"""
		return random.choice(self._commonStrings)

	def rndFunc(self):
		"""
		Randomly select a function for fuzzing
		"""
		func = random.choice([self.common, self.rndDelimiter, self.rndAscii, self.rndBinary])
		return func()


class Report:
	def __init__(self):
		"""
		Constructor
		"""
		self.exceptions = []	#Array that contains a list of our exceptions (dictionaries)
	
	def save(self, exception):
		"""
		Save a dictionary that contains our exception to an array, each should contain the following keys:
		hookset		- string. info about hooksets, argument
		violation	- string. write/read violation at where
		registers	- string. registers dump
		assembly	- string. disassembled instructions
		seh		- string. SEH table including offsets
		bugtype		- string. bug type (stack overflow)
		input		- binary. the input that crashed the software
		
		@param exception - dictionary about the exception
		"""
		self.exceptions.append(exception)

	def createJS(self):
		"""
		Create the JavaScript file
		"""
		self.js = """
		function highlight(code) {
			var newcode = code;
			var configs = new Array();
			//Registers
			configs["#81BEF7"] = [/([ |,](eax|ax|ah|al))/g,
					      /([ |,](ebx|bx|bh|bl))/g,
					      /([ |,](ecx|cx|ch|cl))/g,
					      /([ |,](edx|dx|dh|dl))/g,
					      /([ |,](esi|si))/g,
					      /([ |,](edi|di))/g,
					      /([ |,](ebp|bp))/g,
					      /([ |,](esp|sp))/g,
					      /([ |,](cs|es|ss|fs|ds|gs))/g, /([ |,](eip))/g];
			//x86 asm instructions
			configs["#FE2E2E"] = [/([ ](aaa|aad|aam|aas))/g, /([ ](adc|add|and))/g,
					      /([ ](call))/g, /([ ](cbw))/g, /([ ](clc|cld|cli))/g,
					      /([ ](cmc|cmp|cmpsb|cmpsw|cmpsd))/g, /([ ](cwd))/g, /([ ](daa|das|daa))/g,
					      /([ ](dec|div|esc|hlt))/g,
					      /([ ](idiv|imul|in|inc))/g,
					      /([ ](int|into|iret))/g,
					      /([ ](ja|jae|jb|jbe|jc|jcxz|je|jg|jge|jl|jle|jna|jnae|jnb|jnp|jns|jnz|jo|jp|jpe|jpo|js|jz|jmp))/g,
					      /([ ](lahf|lds|lea|les|lock))/g,
					      /([ ](lodsb|lodsw|loop|loope|loopd|loopne|loopnz|loopz|loopw|loopzw|loopnew|loopzd|loopend|loopzd))/g,
					      /([ ](mov|movsb|movsw|movsx|movzx|movsd))/g,
					      /([ ](mul|neg|nop))/g,
					      /([ ](not|or|out))/g, /([ ](pop|popf|popad|popfd|popa))/g,
					      /([ ](push|pushf|pushad|pushfd|pusha))/g,
					      /([ ](rcl|rcr))/g,
					      /([ ](rep|repe|repne|repnz|repz))/g,
					      /([ ](ret|retn|retf))/g, /([ ](rol|ror))/g, /([ ](sahf|sal|sar|sbb))/g,
					      /([ ](scasb|scasw))/g, /([ ](shl|shr))/g, /([ ](stc|std|sti|stosb|stosw))/g,
					      /([ ](sub|test|wait|xchg|xlat|xor|enter|ins|leave|outs))/g,
					      /([ ](bsf|bsr|bt|btc|btr|bts))/g,
					      /([ ](cdq))/g, /([ ](lfs|lgs|lss|lodsd))/g,
					      /([ ](scasd|seta|shld|shrd|stosx|xadd|invd|syscall|sysret))/g];
			//address
			configs["#F2F2F2"] = [/(0x([a-z0-9]{8}))/g];
			//symbols
			configs["#d7df01"] = [/(\[)/g, /(\])/g, /(\+)/g, /(\*)/g];

			for (var color in configs) {
				for (var item in configs[color]) {
					var replacement = "<font color='"+ color  +"'>$1</font>";
					newcode = newcode.replace(configs[color][item], replacement);
				}
			}
			return newcode;
		}

		function main() {
			//This is where onLoad calls
		        var asm = document.getElementById("asmcode").innerHTML;
		        var code = highlight(asm);
		        document.getElementById("asmcode").innerHTML = code;
		}
		"""
		f = open("%sjavascript.js" %crashbin, "w")
		f.write(self.js)
		f.close()

	def unique(self):
		"""
		Make sure no exceptions are repeated. This is done by checking the assembly data.
		"""
		tmpList = []	#This array will become our new exception list
		print "[*] Exceptions collected: %s" %len(self.exceptions),
		for exception in self.exceptions:
			isFound = False
			for item in tmpList:
				if exception["assembly"] == item["assembly"]:
					isFound = True
					break
			if not isFound:
				tmpList.append(exception)
		print ": %s unique results" %len(tmpList)
		self.exceptions = tmpList


	def dump(self):
		"""
		Dump every exception we saved to disk
		
		@param exception - a dictionary that contains our exception information
		"""
		template = """
		<html>
		<head>
		<script src="javascript.js"></script>
		<title>Crash Dump %s</title>
		</head>
		<body onload="main();" style="background-color:black; color:#4CC417;">
		<center>
		<table border="1" frame="border" rules="all" cellspacing="3" cellpadding="3">
		<tr>
		<td width="800" colspan="2" valign="top">
		<!--This part stores basic info-->
		<b><pre>%s</pre></b>
		</td>
		</tr>
		<tr>
		<td width="450" valign="top"><!-- Assembly -->
		<b><div id="asmcode"><pre>%s</pre></div></b>
		</td>
		<td width="350" valign="top">
		<!-- Registers and SEH -->
		<font size="2" color="red"><b>Registers:</b></font>
		<pre>%s</pre>
		<font size="2" color="red"><b>SEH:</b></font>
		<pre>%s</pre>
		<font size="2" color="red"><b>Input Dump (%s bytes):</b>
		<center>
		<pre><textarea rows="9" cols="38" style="border-width:1px;border-style:solid;border-color:lightgray;background-color:black;color:white;">%s</textarea></pre>
		</td>
		</tr>
		<tr>
		<td width="800" colspan="2" valign="top">
		<!-- WRITE/READ exception message, bug type (note), crash input -->
		<font size="2" color="red"><b>Exception:</b></font><font size="2"> %s</font><br>
		<font size="2" color="red"><b>Note:</b></font><font size="2"> %s</font><br>
		</td>
		</tr>
		</table>
		</center>
		</body>
		</html>
		"""
		self.unique()	#This will filter out all the repeated exceptions in self.exceptions
		if not os.path.exists(crashbin):
			#Create the crashbin folder if not found
			print "[*] Crash bin not found. Created one for you."
			os.mkdir(crashbin)
			self.createJS()
		counter = 0
		for exception in self.exceptions:
			counter += 1
			hexdata = ""
			for byte in exception["input"]:
				hexdata += "\\x%s" %binascii.b2a_hex(byte)
			hookset	= str(exception["hookset"])
			asm	= str(exception["assembly"])
			reg	= str(exception["registers"])
			seh	= str(exception["seh"])
			vio	= str(exception["violation"])
			bugtype	= str(exception["bugtype"])
			report = template %(str(counter), hookset, asm, reg, seh, len(exception["input"]), hexdata, vio, bugtype)
			filename = "%sexception_#%s" %(crashbin, str(counter))
			f = open("%s.html" %filename, "wb")
			f.write(report)
			f.close()


class InMemoryFuzzer:
	"""
	This class prepares, fuzzes functions, and analyzes crash dumps. It requires the FuzzLib class; a
	pre-defined breakpoints.txt (which can be generated by Tracer.py); a globally defined "crashbin"
	variable (string); globally defined "badchars" (string) in order to run.
	"""
	def __init__(self, hookSet, pid):
		"""
		InMemoryFuzzer constructor

		Parameters:
		hookSet - an array of hookpoints. hookSet[i][0]=entry addr; hookSet[i][1]=restore addr; hookSet[i][2]=argument
		pid     - process ID
		"""
		self.PID       = pid
		self.hooks     = hookSet	#hooks[i][0]=entry hook; hooks[i][1]=restore hook; hooks[i][2]=argument
		self.hooksSize = len(hookSet)	#Size of hookset
		self.hookIndex = 0		#Hookset index
		self.counter   = 0		#Counter
		self.snapshotTaken = False	#Is snapshot available
		self.lastChunkAddr = 0x00000000	#Track last heap block address
		self.lastChunkSize = 0		#Track last heap block size
		self.lastChunkData = 0x00	#Track last heap block data
		self.freshState = False		#Make sure we have a fresh state
		self.FuzzVars = FuzzLib()	#FuzzLib Class
		self.reporter = Report()	#Report Class


	def modifyArgument(self, pydbg):
		"""
		Modify the function argument (pointer) that's pushed on the stack

		Parameter:
		pydbg - pydbg object that's attached to an app
		"""
		argString = self.hooks[self.hookIndex][2].replace("ESP+", "")
		argInt = int(argString, 16)
		pydbg.write_process_memory(pydbg.context.Esp + argInt, pydbg.flip_endian(self.lastChunkAddr))


	def createMutant(self, pydbg, data):
		"""
		Create a memory chunk for the fuzzing data

		Parameters:
		pydbg - pydbg object that's attached to an app
		data  - Data that is to be inserted into the memory block
		"""
		address = pydbg.virtual_alloc(None, len(data), MEM_COMMIT, PAGE_READWRITE)
		pydbg.write_process_memory(address, data)	#Put our evil data in the buffer
		print "[*] New heap block @ 0x%08x (%s bytes)\n" %(address, len(data))
		self.lastChunkAddr = address
		self.lastChunkData = data
		self.lastChunkSize = len(data)

		
	def freeLastChunk(self, pydbg):
		"""
		Free the last fuzzing data from memory

		Parameter:
		pydbg - pydbg object that's attached to something
		"""
		print "[*] Freeing Last chunk @ 0x%08x (%s bytes)" %(self.lastChunkAddr, self.lastChunkSize)
		pydbg.virtual_free(self.lastChunkAddr, self.lastChunkSize, MEM_DECOMMIT)


	def patternOffset(self, pattern):
		"""
		Determine the pattern offset (similar to MSF's pattern_offset)

		Parameters:
		pattern - the pattern to find from the fuzzing variable.

		Return:
		The index position. If no index is found, then return "n/a"
		"""
		offset = self.lastChunkData.find(pattern)
		if offset == -1:
			return "n/a"
		return offset


	def filterBadchars(self, data):
		"""
		Filter out all the badchars to increase fuzzer's accuracy

		Parameters:
		data - fuzzing variable in a string

		Return:
		string. the filtered version of the fuzzing variable.
		"""
		if badchars != "":
			for badchar in badchars:
				data = data.replace(badchar, "\x41")
		return data


	def createSnapshot(self, pydbg):
		"""
		Create a snapshot of the function we want to fuzz

		Return:
		pydbg - pydbg object that's attached to a process
		"""
		startTime = time.time()
		pydbg.suspend_all_threads()
		print "[*] Taking a snapshot... ",
		pydbg.process_snapshot()
		pydbg.resume_all_threads()
		self.snapshotTaken = True
		endTime = time.time() - startTime
		print "took %.03f seconds." %endTime


	def restoreSnapshot(self, pydbg):
		"""
		Restore the function state

		Return:
		pydbg - pydbg object that's attached to a process
		"""
		startTime = time.time()
		pydbg.suspend_all_threads()
		print "[*] Restoring snapshot...", 
		pydbg.process_restore()
		pydbg.resume_all_threads()
		self.freshState = True
		pydbg.bp_set(self.hooks[self.hookIndex][1])	#Reset the breakpoint again
		endTime = time.time() - startTime
		print "took %.03f seconds." %endTime


	def currentHookset(self):
		"""
		Show what we're currently trying to fuzz

		Return:
		String.
		"""
		content  = "[*] Routine #%s\r\n" %str(self.hookIndex+1)
		content += "[*] Snapshot hook point = %s\r\n" %hex(self.hooks[self.hookIndex][0])
		content += "[*] Restore hook point  = %s\r\n" %hex(self.hooks[self.hookIndex][1])
		content += "[*] Argument            = %s\r\n" %self.hooks[self.hookIndex][2]
		return content


	def dbgMonitor(self, pydbg):
		"""
		Responsible for moving on to the next function, or terminate if all routines are fuzzed

		Parameter:
		pydbg - pydbg object that's attached to a process
		"""
		if self.counter >= maxFuzzCount:
			#Reset everything for the next hooks
			if self.lastChunkAddr != 0x00000000:
				#If the last chunk hasn't been freed before the new one, free now!
				self.freeLastChunk(pydbg)
			pydbg.suspend_all_threads()
			pydbg.bp_del(self.hooks[self.hookIndex][0])	#Delete the entry hoook
			pydbg.bp_del(self.hooks[self.hookIndex][1])	#Delete the restore hook
			self.snapshotTaken = False
			self.hookIndex += 1				#Next set of hook points
			if self.hookIndex >= self.hooksSize:
				#It appears we're done fuzzing all the routines, closing app
				print "[*] We're done fuzzing."
				self.reporter.dump()			#Save results to disk before exiting
				pydbg.detach()
				pydbg.terminate_process()
				print "[*] Process terminated\r\n"
				self.analyze()
				sys.exit(0)
			print "[*] Moving on to the next routine..."
			pydbg.bp_set(self.hooks[self.hookIndex][0])	#Set a new snapshot point
			pydbg.bp_set(self.hooks[self.hookIndex][1])	#Set a new restore point
			self.counter = 0
			pydbg.process_restore()
			pydbg.resume_all_threads()


	## Handling breakpoints (snapshot entry & restore)
	def bpHandler(self, pydbg):
		"""
		Handle breakpoints (snapshot entry and restore).

		Parameter:
		pydbg - pydbg object that's attached to a process

		Return:
		DBG_CONTINUE
		"""
		#hooks[index][0] = Hook entry (snapshot) point
		#hooks[index][1] = Snapshot restore point
		#hooks[index][2] = Argument (Not used in this function)
		exception = pydbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress
		if exception == self.hooks[self.hookIndex][0]:
			##### We've reached the restore hook point #####
			print "[*] Hook entry hit!"
			if not self.snapshotTaken:
				#If no snapshot taken, take it now.
				self.createSnapshot(pydbg)
			if not self.freshState:
				#Make sure we have a fresh state
				self.restoreSnapshot(pydbg)
			if self.lastChunkAddr != 0x00000000:
				#If the last chunk hasn't been freed before the new one, free now!
				self.freeLastChunk(pydbg)
			#At this point we're ready to fuzz
			variable = self.FuzzVars.rndFunc()		#Obtain a new random fuzzing variable
			variable = self.filterBadchars(variable)	#Filter out bad characters
			print "="*55
			self.createMutant(pydbg, variable)		#Cretae a heap block for the variable
			self.modifyArgument(pydbg)			#Finally modify the argument on the stack
			self.freshState = False				#Memory has been modified and no longer in a healthy state
			self.counter += 1				#Add the fuzzing couter by 1
		elif exception == self.hooks[self.hookIndex][1]:
			##### We've reached the restore hook point #####
			print "[*] Restore point hit!"
			self.restoreSnapshot(pydbg)
		return DBG_CONTINUE


	def dumpRegister(self, pydbg, address):
		"""
		Dump the memory if the register points to a valid + accessiable address

		Parameters:
		pydbg   - pydbg object that's attached to a process
		address - integer. The memory address to read

		Return:
		The first 8 bytes of the data in the memory
		"""
		try:
			dump = "-> %s" %pydbg.read_process_memory(address, 8)
			if dump == "FAILED":
				dump = ""
		except:
			dump = ""
		return dump


	def analyze(self):
		"""
		Search for log haning fruits in the crashbin, and print out the results
		"""
		root = os.listdir(crashbin)
		for case in root:
			#Move on to the next case if this one isn't an exception file
			if not "exception_" in case: continue
			path = crashbin + case
			f = open(path, "r")
			buffer = f.read()
			if "This appears to be a stack overflow" in buffer:
				print "[*] Stack overflow found: %s" %path


	def avHandler(self, pydbg):
		"""
		Handling access violations.  Print out the exception info, and save it

		Parameter:
		pydbg - pydbg object that's attached to a process
		"""
		if pydbg.dbg.u.Exception.dwFirstChance:
			exceptionRecord = pydbg.dbg.u.Exception.ExceptionRecord
			write_violation = exceptionRecord.ExceptionInformation[0]
			violationAddr   = "%08x" %exceptionRecord.ExceptionInformation[1]
			bug_type        = ""
			currentHook     = self.currentHookset()

			#Violation type
			if write_violation:
				violation = "WRITE violation on %s" %violationAddr
			else:
				violation = "READ violation on %s" %violationAddr

			#Register dump
			reg  = "EAX=0x%08x %s\r\n" %(pydbg.context.Eax, self.dumpRegister(pydbg, pydbg.context.Eax))
			reg += "ECX=0x%08x %s\r\n" %(pydbg.context.Ecx, self.dumpRegister(pydbg, pydbg.context.Ecx))
			reg += "EDX=0x%08x %s\r\n" %(pydbg.context.Edx, self.dumpRegister(pydbg, pydbg.context.Edx))
			reg += "EBX=0x%08x %s\r\n" %(pydbg.context.Ebx, self.dumpRegister(pydbg, pydbg.context.Ebx))
			reg += "ESP=0x%08x %s\r\n" %(pydbg.context.Esp, self.dumpRegister(pydbg, pydbg.context.Esp))
			reg += "EBP=0x%08x %s\r\n" %(pydbg.context.Ebp, self.dumpRegister(pydbg, pydbg.context.Ebp))
			reg += "ESI=0x%08x %s\r\n" %(pydbg.context.Esi, self.dumpRegister(pydbg, pydbg.context.Esi))
			reg += "EDI=0x%08x %s\r\n" %(pydbg.context.Edi, self.dumpRegister(pydbg, pydbg.context.Edi))
			reg += "EIP=0x%08x\r\n\r\n" %pydbg.context.Eip

			#Disassembled dump
			disam = pydbg.disasm_around(pydbg.context.Eip, 15)
			instruction_dump = ""
			for (addr, instruction) in disam:
				#Dump the assembly instructions
				if addr == pydbg.context.Eip:
					instruction_dump += "0x%08x  %s  <--- Crash\r\n" %(addr, instruction)
				else:
					instruction_dump += "0x%08x  %s\r\n" %(addr, instruction)

			#SEH dump
			sehs = pydbg.seh_unwind()
			sehdump = "Next SEH Record    SE Handler    Offset\r\n"
			for (nseh, seh) in sehs:
				#Dump all the SEH chains
				sehdump += "0x%08x" %nseh
				sehdump += "\x20"*9
				sehdump += "0x%08x" %seh
				sehdump += "\x20"*4
				pattern = binascii.unhexlify("%08x" %nseh)[::-1] #Convert to hex string and reverse order
				pattern_offset = self.patternOffset(pattern)
				sehdump += str(pattern_offset)
				sehdump += "\r\n"
				if bug_type == "":
					if (nseh == seh and seh != 0xffffffff) or pattern_offset != "n/a":
						#If nSEH and SEH are the same and aren't 0xFFFFFFFF, or
						#we find the same data in our input, we assume it's a stack overflow
						bug_type = "This appears to be a stack overflow: SEH overwrite"

			if bug_type == "":
				#If we haven't determined a bug type, do it
				unhex_eip = binascii.unhexlify("%08x" %pydbg.context.Eip)[::-1]
				pattern_offset = self.patternOffset(unhex_eip)
				if pattern_offset != "n/a":
					#If EIP is found in our input, we assume it's a stack overflow
					bug_type = "This appears to be a stack overflow: EIP overwrite"

			if bug_type == "":
				#If up to this point bug_type isn't set, then bug_type = "N/A"
				bug_type = "n/a"

			output = (currentHook+
				  "\r\n"+
				  "[*] " + violation +
				  "\r\n"+
				  "[*] " + bug_type
				  )
			print output

			exception = {"hookset":currentHook,
				     "violation":violation,
				     "registers":reg,
				     "assembly":instruction_dump,
				     "seh":sehdump,
				     "bugtype":bug_type,
				     "input":self.lastChunkData
				    }
			self.reporter.save(exception)	#Save this access violation report to the array

		pydbg.process_restore()			#Access violation reported. Go back to the healthy state
		return DBG_EXCEPTION_HANDLED


	def debugger(self):
		"""
		Main debug function
		"""
		dbg = pydbg()
		dbg.set_callback(EXCEPTION_BREAKPOINT, self.bpHandler)		#Set Breakpoint Handler
		dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, self.avHandler)	#Set Access Violation Handler
		dbg.set_callback(USER_CALLBACK_DEBUG_EVENT, self.dbgMonitor)	#Set User Call Back Handler
		#try:
		dbg.attach(self.PID)					#Attach to process
		dbg.bp_set(self.hooks[self.hookIndex][0])		#Set the very first entry hook point
		dbg.bp_set(self.hooks[self.hookIndex][1])		#Set the very first restore hook point
		print "[*] Ok! Trigger the hook point for me will ya?\n"
		dbg.debug_event_loop()					#Enter the debug loop
		#except Exception, err:
		#	print "[*] Error: %s" %err

			
def isHexAddr(a):
	"""
	Match a dexdecimal format string

	Parameter:
	a - User supplied pointer address

	Return:
	True if format is valid, otherwise False.
	"""
	m = re.match("0x[0-9A-Za-z]{8}", a)
	if m == None:
		return False
	return True

def isArgMatch(a):
	"""
	Match an argument

	Parameter:
	a - User supplied address

	Return:
	True if format is valid, otherwise False.
	"""
	m = re.match("ESP\+[0-9A-Za-z]", a)
	if m == None:
		return False
	return True
			
def getHookpointsFromFile():
	"""
	Get all the hooks from a pre-defined file

	Return:
	An array of hooks in this format: <snapshot hook> <restore hook> <argument>
	"""
	hooks = []
	try:
		f = open("breakpoints.txt", "r")
	except:
		return hooks
	while 1:
		line = f.readline()
		if line == "": break
		arguments = line.split()
		if len(arguments) == 3:
			#Only enumerate whatever matches
			if isHexAddr(arguments[0]) and isHexAddr(arguments[1]) and isArgMatch(arguments[2]):
				hooks.append([int(arguments[0][0:10], 16), int(arguments[1][0:10], 16), arguments[2]])
	f.close()
	return hooks
	
def selectProcessID():
	"""
	The interface for selecting the process to attach

	Return:
	The process ID chosen by the user
	"""
	processes = []
	dbg = pydbg()
	#First we generate an array of active processes
	for (pid, pname) in dbg.enumerate_processes():
		processes.append([pid, pname])
	print "=== Please pick a process to attach ===\n"
	print "Choice    Process Name"
	pcounter  = 0
	#And then we generate the choice list for the user
	for item in processes:
		print  "[%3d]     %s" %(pcounter, item[1])
		pcounter += 1
	while 1:
		try:
			index = int(raw_input("\nChoice [n]:"))		#If the input isn't a #, throw an exception
			if index < 0 or index >= pcounter: raise	#If the # is out of range, throw an exception
			break						#If input looks good, break loop and move on
		except KeyboardInterrupt:
			sys.exit(-1)
		except:
			print "That is not a choice."
	dbg = None
	return processes[index][0]

def usage():
	"""
	Print the usage, then exit
	"""
	u  = "\nIn-Memory Fuzzer Usage:\n"
	u += "%s <hook point> <restore point> <argument>\n"
	u += "hook point     = where the snapshot will be created\r\n"
	u += "restore point  = where the snapshot will be restored\r\n"
	u += "argument       = the function argument you want to fuzz\r\n"
	u += "Example: %s 0x01224301 0x0122440F ESP+4\r\n\r\n"
	u += "Use a pre-defined hookpoints list:\n"
	u += "1) Put the hookpoints in breakpoints.txt in this format:\n"
	u += "   <snapshot point> <restore point> <argument>\n"
	u += "2) Fire up the fuzzer.\n"
	u += "Note: Crash results are saved under crashbin/"
	print u %(sys.argv[0], sys.argv[0])
	sys.exit(0)

def main():
	"""
	The main function prepares and validates all arguments needed to start the InMemoryFuzzer class
	"""
	args_length = len(sys.argv)
	my_hooks = []
	#### Stage 1: Prepare hook points and arguments
	if args_length == 1:
		#[Mode 1] Assuming user wants to fuzz multiple routines
		my_hooks = getHookpointsFromFile()
		if len(my_hooks) == 0:
			usage()
	elif args_length == 4:
		#[Mode 2] Assuming user wants to fuzz just one routine
		snapshot_point = sys.argv[1]
		restore_point  = sys.argv[2]
		argument       = sys.argv[3]
		if isHexAddr(snapshot_point) and isHexAddr(restore_point) and isArgMatch(argument):
			my_hooks.append([int(snapshot_point, 16), int(restore_point, 16), argument])
		else:
			print "[*] Incorrect format for one or more arguments"
			usage()
	else:
		#No idea what the user is trying to do, help!
		usage()
	#### Stage 2: Specify process ID
	pid = selectProcessID()
	#### Stage 3: Run the fuzzer
	fuzzer = InMemoryFuzzer(my_hooks, pid)
	fuzzer.debugger()

if __name__ == "__main__":
	print __doc__
	main()

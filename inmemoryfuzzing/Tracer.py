#!/usr/bin/python

"""  _____
|_   _| __ __ _  ___ ___ _ __
  | || '__/ _` |/ __/ _ \ '__|
  | || | | (_| | (_|  __/ |		by sinn3r
  |_||_|  \__,_|\___\___|_|   twitter.com/_sinn3r
"""

import sys
try:
	from pydbg import *
	from pydbg.defines import *
except:
	print "[ERROR] Your system does not support PYDBG. Cannot continue."
	print "Download the following items to get it started:"
	print "[-] Python 2.5 (installed from Immunity Debugger)"
	print "[-] pydasm: http://therning.org/magnus/archives/278"
	print "[-] Paimei: http://www.openrce.org/downloads/details/208/PaiMei"
	sys.exit(-1)
import utils
import os
import re

## User setting:
global function_list_path; function_list_path = "functions.txt"	#Function list name


class Tracer:
	def __init__(self, funcsPath, input):
		"""
		Tracer constructor

		Parameters:
		funcsPath - path to the functin list filename (obtained either from IDA, or pvefindaddr)
		input     - The user input to look for (eg. "AAAA")
		"""
		_flow_log   = "flow_log.txt"		#Default log path
		self.funcsList = funcsPath		#Path to the function list copied from IDA Pro
		self.userInput = input			#The user input to look for
		self.user_input_hex = self.userInput.encode("hex")
		self.logger = open(_flow_log, "w")
		self.lastNoiseFound = None

	def __correctIDAProRETNs(self, dbg, functions):
 		"""
		This function is a fix for correcting the RETN address based on IDA Pro's function "length"
		This is done by rewinding 3 bytes from the current retnAddress to find 0xC2, 0xC3, 0xEB, 0xE9.
		It's no way near pefect, but most addresses are corrected.
		A new copy of the addresses will be saved, and returns a new function list (same type)
		This function should be called from self.run()

		Parameters:
		dbg       - pydbg object
		functions - an array of the function list in format: f[i][0]=prologue; f[i][1]=epilogue

		Return:
		An array of the newly modified function list in the same format
		"""
		content = "Function Address    RETN Address\n"
		counter = 0
		for ptrFunction in functions:
			#functions[i][0] = function address (prologue)
			#functions[i][1] = function RETN (epilogue)
			content += "0x%08x" %ptrFunction[0]
			content += " "*10
			newPtrRETN = dbg.read_process_memory(ptrFunction[1]-3, 3)	#Rewind 3 bytes from
			if newPtrRETN[0] == "\xC2":
				#We're 3 bytes off from where RETN is, do some correction
				functions[counter][1] = ptrFunction[1]-3
			elif newPtrRETN[0] != "\xC2" and newPtrRETN[-1] == "\xC3":
				#We're 1 byte off from where RETN is
				functions[counter][1] = ptrFunction[1]-1
			elif newPtrRETN[0] != "\xC2" and newPtrRETN[1] == "\xEB":
				#We're 2 bytes off from where RETN is
				functions[counter][1] = ptrFunction[1]-2
			content += "0x%08x\n" %functions[counter][1]
			counter += 1
		f = open("new_functions_addrs.txt", "w")
		f.write(content)
		f.close()
		print "[*] new_functions_addrs.txt created. Use it to create breakpoints for breakpoints.txt"
		return functions

	def enumerateFunctions(self):
		"""
		Enumerates all function addresses (including RETNs) from a file
		IDA Pro's block length appears to be incorrect. Instead of pointing at the RETN, it
		points at the next prologue. This is 1 or 3 bytes off.

		Returns:
		A list of functions
		"""
		functions = list()
		try:
			f = open(self.funcsList, "r")
		except:
			return functions
		while 1:
			line = f.readline()
			if line == "": break	#Out of lines to read
			if re.match("^sub_", line):
				#Only enumerate the function names and eliminate non-important or unrelated information
				lsplit = line.split()
				funcAddress = lsplit[0]	#Function prolog address
				funcLength  = lsplit[3] #Function block length
				funcAddress = int(funcAddress.replace("sub_", ""), 16)	#Convert function addr to int
				retnAddress = funcAddress + int(funcLength, 16)		#Convert the RETN addr to int
				functions.append([funcAddress, retnAddress])		#And then add it to the list
		f.close()
		return functions


	def log(self, dbg, args):
		"""
		Output the important functions that are caught, also save it to a file. If an unnecessary
		function is picked up (as in that function does not process your input), then it is
		considered as "noise".

		Parameters:
		dbg  - pydbg object that's attached to a process
		args - function arguments we want to check

		Return:
		DBG_CONTINUE
		"""
		argsData     = ""	#Arguments found with data
		arg_counter  = 4	#First argument should be [ESP+4], start from there
		for item in args:
			data = dbg.smart_dereference(item, False)
			item_hex = hex(item)
			if item_hex[2:] == self.user_input_hex:
				argsData += "           [ESP+%s] %s  <--- You own this\n" %(arg_counter ,item_hex)
			#if re.match("^%s" %self.userInput, data):
			if self.userInput in data:
				argsData += "           [ESP+%s] %s  \"%s\"  <--- You own this\n" %(arg_counter ,item_hex, data)
			arg_counter += 4
		if argsData != "":
			## If we own some arguments, we log it
			function_address = hex(dbg.dbg.u.Exception.ExceptionRecord.ExceptionAddress)
			_log  = "     Log: function_%s(\n" %function_address
			_log += argsData
			_log += "\n     );\n"
			self.lastNoiseFound = False
			print _log
			tmpLog = self.logger
			tmpLog.write(_log)
		else:
			##If we don't own anything, only log it when we haven't seen any "noise"
			if not self.lastNoiseFound:
				_log = "\n... Noise ...\n"
				print _log
				tmpLog = self.logger
				tmpLog.write(_log)
				self.lastNoiseFound = True
		return DBG_CONTINUE

	def createBreakpoints(self):
		"""
		This function will create breakpoints.txt for InMemoryFuzzer.py
		"""
			
		

	def run(self, pid, functions):
		"""
		Main function for class Tracer

		pid       - process ID (for pydbg.attach())
		functions - an array of modified/corrected function list
		"""
		raw_input("[*] When you're ready, press [ENTER] to continue...")
		dbg = pydbg()
		dbg.attach(pid)
		try:
			functions = self.__correctIDAProRETNs(dbg, functions)	#Correct RETN addresses - IDA specific problem
		except:
			print "[*] Error: Either you don't have the right function list, or the component is not loaded at the moment"
			sys.exit(-1)
		print "[*] Enumerating functions...",
		counter = 0
		hooks = utils.hook_container()
		for addr in functions:
			counter += 1
			hooks.add(dbg, addr[0], 10, self.log, None)	#Only look at the first 10 arguments
		print " %s hooks added" %counter
		print "[*] Press [CTRL]+[C] to stop..."
		dbg.run()
		print "[*] And we're done with tracing"


def selectProcessID():
	"""
	The interface for selecting the process to monitor

	Return:
	The process ID to attach
	"""
	processes = []
	dbg = pydbg()
	#Gather an array of active processes
	for (pid, pname) in dbg.enumerate_processes():
		processes.append([pid, pname])
	print "\n=== Please pick a process to monitor ===\n"
	print "Choice    Process Name"
	counter = 0
	#Prepare a choice list for the user
	for item in processes:
		print  "[%3d]     %s" %(counter, item[1])
		counter += 1
	while 1:
		try:
			index = int(raw_input("\nChoice [n]:"))
			if index < 0 or index >= counter: raise
			break
		except KeyboardInterrupt:
			sys.exit(-1)
		except:
			print "That is not a choice."
	dbg = None
	return processes[index][0]	#Return the process ID of the user's choosing


def main():
	"""
	main function, duh!
	"""
	if not os.path.exists(function_list_path):
		#Function list not found therefore cannot continue
		print "[*] %s not found. Use IDA or !pvefindaddr functions to generate one" %function_list_path
		sys.exit(-1)
	else:
		print "[*] Function list found"
	try:
		while 1:
			dword = raw_input("[*] Enter a DWORD to track (eg: AAAA): ")
			dword_length = len(dword)
			if dword_length <= 0 or dword_length > 4:
				print "Incorrect. I'll give you an example: AAAA"
			else:
				break
	except KeyboardInterrupt:
		print ""
		sys.exit(-1)
	tracker = Tracer(function_list_path, dword)		#Function list copied from IDA Pro
	functions = tracker.enumerateFunctions()		#Grep all matching functions including RETNs
	if len(functions) == 0:
		print "[*] No matching function(s) found. Cannot continue."
		sys.exit(-1)
	pid = selectProcessID()					#Get process ID
	tracker.run(pid, functions)				#Start tracking the flow
	print "[*] OK. Now create your breakpoints.txt based on this format"
	print "    [Entry point] [Restore Point] [Argument]"
	print "    Example:"
	print "    0x10001000 0x1000230f ESP+4"
	print "[*] Use new_functions_addrs.txt as a reference to find your restore points."
	print ""
	os.system("new_functions_addrs.txt")
	print "[*] Once you've created breakpoints.txt, restart the app, and run InMemoryFuzzer.py"


if __name__ == "__main__":
	print __doc__
	main()


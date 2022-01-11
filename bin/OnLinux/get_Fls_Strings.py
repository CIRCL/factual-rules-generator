#!/bin/python3

import os
import shutil
import subprocess


def fls(cheminMachine, cheminOut, app_status, listMultiSoft, logFile):
	## get the longer partition
	request = "mmls -t dos %s | cut -c43-55 > %slength_partition" % (cheminMachine, cheminOut)
	subprocess.call(request, shell=True)
	
	f = open(cheminOut + "length_partition")
	lines = f.readlines()

	max = 0
	cp = 0
	cpmax = 0

	for line in lines:
		if line != "\n":
			try:
				if int(line) > max:
					max = int(line)
					cpmax = cp
			except:
				pass
		cp += 1
	
	## get the start of the longer partition
	request = "mmls -t dos %s | cut -c17-26 > %sstart_partition" % (cheminMachine, cheminOut)
	subprocess.call(request, shell=True)
	
	f2 = open(cheminOut + "start_partition", "r")
	ls = f2.readlines()

	offset = int(ls[cpmax].rstrip("\n"))

	pathFls1erProg = "%s@%s@fls_%s.tree" % (cheminOut, app_status.split("_")[0], app_status.split("_")[1])

	r = "fls -r -o %s %s > %s" % (str(offset), cheminMachine, pathFls1erProg)
	print("[+] Fls for %s" % (app_status.split("_")[0]))

	logFile.write("[+] Fls request: %s\n" % (r))

	p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p_status = p.wait()
	
	f.close()
	f2.close()

	flag1erProg = False

	if len(listMultiSoft) > 1:
		logFile.write("[+] Fls display listMultiSoft: %s\n" % (listMultiSoft))
		for l in listMultiSoft:
			if not pathFls1erProg == "%s@%s@fls_%s.tree" % (cheminOut, l, app_status.split("_")[1]):
				logFile.write("[+] Fls multi : True\n")
				shutil.copyfile(pathFls1erProg, "%s@%s@fls_%s.tree" % (cheminOut, l, app_status.split("_")[1]))
			else:
				flag1erProg = True

		if not flag1erProg:
			os.remove(pathFls1erProg)

	os.remove("%slength_partition" % (cheminOut))
	os.remove("%sstart_partition" % (cheminOut))
	
	
def getStrings(appchemin, listMultiSoft, cheminOut, app_status, logFile):
	r = 'strings %s | grep -i -E "' % (appchemin)

	logFile.write("[+] Strings display listMultiSoft: %s\n" % (listMultiSoft))

	for soft in listMultiSoft:
		r += '%s |' % (soft)
	r = r[:-1]
	if len(listMultiSoft) == 1:
		r = r[:-1]

	pathGlob = "%s@%s@%s.txt" % (cheminOut, app_status.split("_")[0], app_status.split("_")[1])
	r += '" > %s' % (pathGlob)

	print("getStrings Request: " + r)
	logFile.write("[+] getStrings Request: %s\n" % (r))

	print("[+] Strings for %s" % (app_status.split("_")[0]))
	
	p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p_status = p.wait()

	flag1erProg = False

	if len(listMultiSoft) > 1:
		for soft in listMultiSoft:
			if not pathGlob == "%s@%s@%s.txt" % (cheminOut, soft, app_status.split("_")[1]):
				request = "grep -i %s %s > %s@%s@%s.txt" % (soft, pathGlob, cheminOut, soft, app_status.split("_")[1])

				logFile.write("[+] Strings multi request: %s\n" % (request))

				p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
				(output, err) = p.communicate()
				p_status = p.wait()
			else:
				flag1erProg = True

		if not flag1erProg:
			os.remove(pathGlob)

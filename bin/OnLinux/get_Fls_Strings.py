#!/bin/python3

import os
import shutil
import subprocess

def fls(cheminMachine, cheminOut, app_status, listMultiSoft):
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

	p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p_status = p.wait()
	
	f.close()
	f2.close()

	flag1erProg = False

	if len(listMultiSoft) > 1:
		for l in listMultiSoft:
			if not pathFls1erProg == "%s@%s@fls_%s.tree" % (cheminOut, l, app_status.split("_")[1]):
				shutil.copyfile(pathFls1erProg, "%s@%s@fls_%s.tree" % (cheminOut, l, app_status.split("_")[1]))
				flag1erProg = True

		if not flag1erProg:
			os.remove(pathFls1erProg)

	os.remove("%slength_partition" % (cheminOut))
	os.remove("%sstart_partition" % (cheminOut))
	
	
def getStrings(appchemin, listMultiSoft, cheminOut, app_status):
	r = 'strings %s | grep -i -E "' % (appchemin)

	for soft in listMultiSoft:
		r += '%s |' % (soft)
	r = r[:-1]
	if len(listMultiSoft) == 1:
		r = r[:-1]

	pathGlob = "%s@%s@%s.txt" % (cheminOut, app_status.split("_")[0], app_status.split("_")[1])
	r += '" > %s' % (pathGlob)

	print("getStrings Request: " + r)

	print("[+] Strings for %s" % (app_status.split("_")[0]))
	
	p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
	(output, err) = p.communicate()
	p_status = p.wait()

	if not len(listMultiSoft) == 1:
		for soft in listMultiSoft:
			request = "grep -i %s %s > %s@%s@%s.txt" % (soft, pathGlob, cheminOut, soft, app_status.split("_")[1])

			p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
			(output, err) = p.communicate()
			p_status = p.wait()

		os.remove(pathGlob)



if __name__ == '__main__':
	chemin = "/media/sf_PartageVM/" ## change the path

	cheminConvert = chemin + "convert/"
	cheminOut = chemin + "Strings_out/"

	for content in os.listdir(cheminConvert):
		appchemin = os.path.join(cheminConvert, content)
		if os.path.isfile(appchemin):
			app_status = content.split(".")[0]
			app = app_status.split("_")[0]
			
			fls(appchemin, cheminOut, app_status)

			getStrings(appchemin, app, cheminOut, app_status)
			
	print("[+] Shutdown in 20 sec")
	

	subprocess.call("shutdown -h -t 20", shell=True)
	
	

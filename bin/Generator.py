import os
import re
import sys
import json
import uuid
import time
import get_pe
import shutil
import datetime
import subprocess
import pathlib
pathProg = pathlib.Path(__file__).parent.absolute()
pathWork = ""
for i in re.split(r"/|\\", str(pathProg))[:-1]:
    pathWork += i + "/"
sys.path.append(pathWork + "etc")
import allVariables
import automatisation_yara
import OnLinux.get_Fls_Strings


# Load of the block list for the name of software
def blockProg():
    f1 = open(pathWork + "etc/blockProg.txt", "r")
    l1 = f1.readlines()
    f1.close()
    return l1

def callSubprocessPopen(request, shellUse = False):
    if shellUse:
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
    else:
        p = subprocess.Popen(request, stdout=subprocess.PIPE)
        (output, err) = p.communicate()
        p_status = p.wait()

# Write the task into a file for the client
def writeFile(app, uninstall):
    if uninstall:
        tmp = open(allVariables.pathToInstaller + "/uninstall.txt", "w")
    else:
        tmp = open(allVariables.pathToInstaller + "/install.txt", "w")

    appSplit = app.split(",")
    app = appSplit[0].split(":")
    installer = appSplit[1].split(":")

    appstr = '{"%s":"%s"' % (app[0], app[1])
    installerstr = '"%s":"%s"}' % (installer[0], installer[1].rstrip("\n"))

    tmp.write(appstr + ", " + installerstr)
    tmp.close()

# Get the list of running vms
def runningVms():
    req = [allVariables.VBoxManage, "list", "runningvms"]
    return subprocess.run(req, capture_output=True)

# Get the new name of the software using blocklist
def nameApp(capp):
    app = capp.split(",")[0].split(":")[1]

    l1 = blockProg()

    for line in l1:
        if line.split(":")[0] == app:
            return line.split(":")[1].rstrip("\n")
    return app

def getUninstall(app, l_app):
    block = blockProg()
    flag = False
    alt = ""
    for b in block:
        if app == b.split(":")[1].rstrip("\n"):
            alt = b.split(":")[0].rstrip("\n")
            flag = True
            break

    listMultiSoft = list()

    softMulti = ""
    flagMulti = False

    with open(pathWork + "etc/MultiSoft.txt", "r") as MultiSoft:
        lines = MultiSoft.readlines()
        for l in lines :
            listMultiSoft = l.split(":")
            soft = listMultiSoft[1].split(",")
            for s in soft:
                if (flag and (s == alt)) or (not flag and (s == app)):
                    softMulti = listMultiSoft[0]
                    flagMulti = True
                    break
    
    for l in l_app:
        loc = l.split(",")

        if flagMulti and (softMulti == loc[0].split(":")[1].rstrip("\n")):
            return loc[2].split(":")[1].rstrip("\n")

        if (flag and (alt == loc[0].split(":")[1].rstrip("\n"))) or (not flag and (app == loc[0].split(":")[1].rstrip("\n"))):
                return loc[2].split(":")[1].rstrip("\n")


# Creation of yara rule for PE informations
def create_rule(ext, hexa, product_version, l_app, uninstaller):
    app = ""
    for l in l_app:
        if l.split(":")[1].rstrip("\n") == ext[0]:
            app = l.split(":")[0].split(".")[0]
    date = datetime.datetime.now()

    ##Headers of yara rule
    if app:
        print("############################### App\n")
        rules = "rule %s_%s {\n\tmeta:\n\t\t" % (app, ext[1])
    else:
        rules = "rule %s_%s {\n\tmeta:\n\t\t" % (ext[0], ext[1])

    rules += 'description = "Auto generation for %s"\n\t\t' % (str(ext[0]))
    rules += 'author = "David Cruciani"\n\t\t'
    rules += 'date = "' + date.strftime('%Y-%m-%d') + '"\n\t\t'
    rules += 'versionApp = "%s"\n\t\t' % (product_version)
    rules += 'uuid = "%s"\n\t\t' % (str(uuid.uuid4()))
    rules += 'uninstaller = "%s"\n\t' % (uninstaller)

    rules += "strings: \n"

    ##Creation of hexa rule
    rules += "\t\t$h = {%s}\n" % (str(hexa))
 
    ##End of yara rule
    rules += "\tcondition:\n\t\t$h\n}"

    return rules

# Creation of yara rule other than PE informations
def runAuto(s, stringProg):
    pathS = os.path.join(allVariables.pathToStrings, s)
    if os.path.isfile(pathS):
        print(s)
        automatisation_yara.inditif(pathS, ProductVersion, l_app, stringProg)

# Parse of Asa Report
def parseAsa(asaReport, currentApp):
    with open(asaReport, "r") as asa_file:
        jsonParse = json.loads(asa_file.read())

    ## Blocklist for unwanted path
    with open(pathWork + "etc/blocklistASA.txt", "r") as blockAsa:
        blocklistASA = blockAsa.readlines()

    path = ""
    ## Important path are in FILE_CREATED
    for i in jsonParse["results"]["FILE_CREATED"]:
        path += i["Compare"]["Path"] + "\n"

    ## Sed is apply to deleted the unwanted path specified in blocklistASA
    filesed = "./" + currentApp + "_Asa_report.txt"
    with open(filesed, "w") as write_file:
        write_file.write(path)

    request = [allVariables.sed, "-r", "-i"]
    s = "/"
    j = True
    for i in blocklistASA:
        if j:
            s += i.rstrip("\n")
            j = False
        else:
            s += "|" + i.rstrip("\n")
    s += "/d"
    request.append(s)
    request.append(filesed)
    #print(request)

    callSubprocessPopen(request)

    return filesed



if __name__ == '__main__':
    logFile = open(pathWork + "bin/logFile.txt", "a")

    ## Get the new name of software and the number of them to install
    list_app_string = list()
    list_block = blockProg()
    fapp = open(allVariables.applist, "r")
    l_app = fapp.readlines()
    line_count = 0
    for line in l_app:
        for block in list_block:
            if line.split(":")[1].rstrip("\n") == block.split(":")[0]:
                list_app_string.append(block.split(":")[1].rstrip("\n"))
                break
            else:
                list_app_string.append(line.split(":")[1].rstrip("\n"))
                break
        if line != "\n":
            line_count += 1
    fapp.close()

    ## Do a special strings-grep for better performance during yara generation
    stringProg = "stringProg"
    if not allVariables.LinuxVM:
        r = 'strings %s | grep -i -E "%s' % (allVariables.pathToFirstStringsMachine, list_app_string[0].split(",")[0])
        for i in range(1, len(list_app_string)):
            r += " | " + list_app_string[i].split(",")[0]
        r += '" > %s' % (stringProg)
        print(r)
        p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()


    pathMnt = ""
    res = runningVms()
    j=0
    uninstall = False
    for i in range(0, line_count*2):
        ## Output to know what the program is doing
        loc = i - j
        if uninstall:
            print("\nBoucle n: %s, Uninstall: %s" % (i, l_app[loc % len(l_app)].split(":")[1].split(",")[0]))
            try:
                os.remove(allVariables.pathToInstaller + "/install.txt")
            except:
                pass
        else:
            print("\nBoucle n: %s, Install: %s" % (i, l_app[loc % len(l_app)].split(":")[1].split(",")[0]))
            try:
                os.remove(allVariables.pathToInstaller + "/uninstall.txt")
            except:
                pass

        writeFile(l_app[loc], uninstall)

        res = runningVms()

        request = [allVariables.VBoxManage, 'startvm', allVariables.WindowsVM, '--type', 'headless']
        if not allVariables.WindowsVM in res.stdout.decode():
            ## Start windows machine
            print("[+] Windows Start")
            p = subprocess.Popen(request, stdout=subprocess.PIPE)
            (output, err) = p.communicate()
            p_status = p.wait()
        else:
            print("[+] Windows Running")

        ## Wait windows machine to shutdown
        res = runningVms()

        ## Output to see the time that the windows machine is running
        cptime = 0
        while allVariables.WindowsVM in res.stdout.decode():
            time.sleep(60)
            cptime += 1
            print("\rTime spent: %s min" % (cptime), end="")
            res = runningVms()

        print("\n[+] Windows stop\n")


        ## Convert windows machine into raw format
        qemu = allVariables.qemu
        vm = allVariables.pathToWindowsVM
        partage = allVariables.pathToConvert
        nApp = nameApp(l_app[loc])
        
        if uninstall:
            convert_file = "%s%s_uninstall.img" %(partage, nApp)
        else:
            convert_file = "%s%s_install.img" %(partage, nApp)

        print("## Convertion ##")
        res = subprocess.call([qemu, "convert", "-f", "vmdk", "-O", "raw", vm, convert_file])
        print("## Convertion Finish ##\n")

        
        if allVariables.LinuxVM:
            res = runningVms()
            
            request = [allVariables.VBoxManage, 'startvm', allVariables.LinuxVM]
            if not allVariables.LinuxVM in res.stdout.decode():
                ## Start ubuntu machine
                print("[+] Ubuntu Start")
                p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
            else:
                print("[+] Ubuntu Running")

            ## Wait linux machine to shutdown
            res = runningVms()

            ## Output to see the time that the linux machine is running
            cptime = 0
            while allVariables.LinuxVM in res.stdout.decode():
                time.sleep(60)
                cptime += 1
                print("\rTime spent: %s min" % (cptime), end="")
                res = runningVms()

            print("\n[+] Ubuntu stop")
        else:
            for content in os.listdir(allVariables.pathToConvert):
                appchemin = os.path.join(allVariables.pathToConvert, content)
                if os.path.isfile(appchemin):
                    app_status = content.split(".")[0]
                    app = app_status.split("_")[0]

                    listMultiSoft = list()

                    with open(pathWork + "etc/MultiSoft.txt", "r") as MultiSoft:
                        lines = MultiSoft.readlines()
                        for l in lines :
                            if app == l.split(":")[0]:
                                listMultiSoft = l.split(":")[1].split(",")
                                listMultiSoft[-1] = listMultiSoft[-1].rstrip("\n")

                    if len(listMultiSoft) == 0:
                        listMultiSoft.append(app)

                    print("listMultiSoft: " + str(listMultiSoft))
                    
                    ## Run the fls command
                    OnLinux.get_Fls_Strings.fls(appchemin, allVariables.pathToStrings, app_status, listMultiSoft)

                    ## Run Strings command
                    OnLinux.get_Fls_Strings.getStrings(appchemin, listMultiSoft, allVariables.pathToStrings, app_status)


        ## Parsing of the Asa Report
        if not uninstall:
            if allVariables.pathToAsaReport:
                logFile.write("[+] Parsing AsA Report \n")
                print("[+] Parsing AsA Report")
                ## Parsing
                content = l_app[loc].split(":")[0].split(".")[0] + "_install_Asa_compare.json"
                logFile.write("AsaReport to search: " + content + "\n")

                chemin = os.path.join(allVariables.pathToAsaReport, content)
                logFile.write("Path to AsaReport: " + chemin + "\n")

                if os.path.isfile(chemin):
                    filesed = parseAsa(chemin, nApp)
                    ## read path collect by parser
                    with open(filesed, "r") as read_file:
                        AsaPath = read_file.readlines()

                    ## create mount directory
                    pathMnt = "./mnt_convert"
                    if not os.path.isdir(pathMnt):
                        os.mkdir(pathMnt)

                    ## mount the convert image
                    print("\t[+] Mount")
                    request = "sudo mount -o loop,ro,noexec,noload,offset=$((512*104448)) " + convert_file + " " + pathMnt
                    callSubprocessPopen(request, True)

                    ## md5 for each file of AsaPath
                    print("\t[+] Md5 Asa")
                    for pathMd5 in AsaPath:
                        pathMd5 = pathMnt + "/" + pathMd5.split(":")[1].rstrip("\n")[1:]
                        pathMd5 = re.sub(r"\\","/", pathMd5)
                        pathMd5 = pathMd5.split("/")

                        ## Add "" for each folder who contains space caracters
                        cp = 0
                        for sp in pathMd5:
                            for car in sp:
                                if car == " ":
                                    pathMd5[cp] = '"' + pathMd5[cp] + '"'
                            cp += 1

                        ## Reassemble the strings
                        stringPath = ""
                        for sp in pathMd5:
                            stringPath += sp + "/"

                        pathMd5 = stringPath[:-1]

                        savePath =  allVariables.pathToYaraSave + "/" + nApp
                        logFile.write("savePath :" + savePath  + "\n")

                        if not os.path.isdir(savePath):
                            os.mkdir(savePath)

                        request = "md5sum " + pathMd5 + " >> " + savePath + "/" + nApp + "_md5"
                        callSubprocessPopen(request, True)

                        request = "sha1sum " + pathMd5 + " >> " + savePath + "/" + nApp + "_sha1"
                        callSubprocessPopen(request, True)

                    ## umount the convert image
                    print("\t[+] Umount")
                    request = "sudo umount " + pathMnt
                    callSubprocessPopen(request, True)

                    ## Delete Asa path 
                    os.remove(filesed)

        if i % 2 == 0:
            j += 1
            uninstall = True
        else:
            uninstall = False

        ## Suppression of the current raw disk
        os.remove(convert_file)

    ## Suppression of mount folder
    try:
        shutil.rmtree(pathMnt)
    except:
        pass
    
    ## AutoGeneYara
    hexa = "" 
    ProductVersion = ""
    listProduct = dict()
    # Rule for Exe
    for content in os.listdir(allVariables.pathToShareWindows):
        l = blockProg()
        c = content.split(".")
        for line in l:
            if line.split(":")[0] == c[0]:
                c[0] = line.split(":")[1].rstrip("\n")

        uninstaller = getUninstall(c[0], l_app)
        
        chemin = os.path.join(allVariables.pathToShareWindows, content)
        if os.path.isfile(chemin):
            (hexa, ProductVersion) = get_pe.pe_yara(chemin)
            rule = create_rule(c, hexa, ProductVersion, l_app, uninstaller)
            print(rule)
            automatisation_yara.save_rule(c[0], c[1], rule, uninstaller)
            listProduct[c[0]] = ProductVersion

    # Rule for strings and fls
    for content in os.listdir(allVariables.pathToStrings):
        chemin = os.path.join(allVariables.pathToStrings, content)
        if os.path.isfile(chemin):
            softName = content.split("@")[1]

            uninstaller = getUninstall(softName, l_app)
            try:
                automatisation_yara.inditif(chemin, listProduct[softName], l_app, stringProg, uninstaller)
            except:
                automatisation_yara.inditif(chemin, None, l_app, stringProg, uninstaller)

    # Hashlookup
    for content in os.listdir(allVariables.pathToYaraSave):
        pathFolder = os.path.join(allVariables.pathToYaraSave, content)
        if os.path.isdir(pathFolder):
            md5File = pathFolder + "/" + content + "_md5"
            sha1File = pathFolder + "/" + content + "_sha1"

            if os.path.isfile(md5File):
                with open(md5File, "r") as md5Read:
                    lines = md5Read.readlines()
                    for line in lines:
                        lineSplit = line.split(" ")
                        request = "%s -s -X 'GET' 'https://hashlookup.circl.lu/lookup/md5/%s' -H 'accept: application/json'" % ( allVariables.curl, lineSplit[0].rstrip("\n") )
                        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()

                        jsonResponse = json.loads(output.decode())

                        if "message" in jsonResponse.keys():
                            print(jsonResponse["message"])
                        else:
                            pathHash = os.path.join(pathFolder, "HashLookup")
                            pathHashMd5 = os.path.join(pathHash, "md5")

                            if not os.path.isdir(pathHash):
                                os.mkdir(pathHash)
                            if not os.path.isdir(pathHashMd5):
                                os.mkdir(pathHashMd5)

                            with open(pathHashMd5 + "/" + lineSplit[0].rstrip("\n"), "w") as fileHash:
                                fileHash.write(str(jsonResponse))
                            #print(jsonResponse)
            """else:
                print("There's no md5 file")"""

            if os.path.isfile(sha1File):
                with open(sha1File, "r") as sha1Read:
                    lines = sha1Read.readlines()
                    for line in lines:
                        request = "%s -s -X 'GET' 'https://hashlookup.circl.lu/lookup/sha1/%s' -H 'accept: application/json'" % ( allVariables.curl, line.split(" ")[0].rstrip("\n") )
                        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                        (output, err) = p.communicate()
                        p_status = p.wait()

                        jsonResponse = json.loads(output.decode())

                        if "message" in jsonResponse.keys():
                            print(jsonResponse["message"])
                        else:
                            pathHash = os.path.join(pathFolder, "HashLookup")
                            pathHashSha1 = os.path.join(pathHash, "sha1")

                            if not os.path.isdir(pathHash):
                                os.mkdir(pathHash)
                            if not os.path.isdir(pathHashSha1):
                                os.mkdir(pathHashSha1)

                            with open(pathHashSha1 + "/" + lineSplit[0].rstrip("\n"), "w") as fileHash:
                                fileHash.write(str(jsonResponse))
                            #print(jsonResponse)
            """else:
                print("There's no sha1 file")"""

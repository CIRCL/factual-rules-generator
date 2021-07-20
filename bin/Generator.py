import os
import re
import sys
import json
import uuid
import time
import get_pe
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

# Creation of yara rule for PE informations
def create_rule(ext, hexa, product_version, l_app):
    app = ""
    for l in l_app:
        if l.split(":")[1].rstrip("\n") == ext[0]:
            app = l.split(":")[0].split(".")[0]
    date = datetime.datetime.now()

    ##Headers of yara rule
    if app:
        rules = "rule %s_%s {\n\tmeta:\n\t\t" % (app, ext[1])
    else:
        rules = "rule %s_%s {\n\tmeta:\n\t\t" % (ext[0], ext[1])

    rules += 'description = "Auto generation for %s"\n\t\t' % (str(ext[0]))
    rules += 'author = "David Cruciani"\n\t\t'
    rules += 'date = "' + date.strftime('%Y-%m-%d') + '"\n\t\t'
    rules += 'versionApp = "%s"\n\t\t' % (product_version)
    rules += 'uuid = "%s"\n\t' % (str(uuid.uuid4()))

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
    filesed = allVariables.pathToYaraSave + "/" + currentApp + "/" + currentApp + "_Asa_report.txt"
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

    p = subprocess.Popen(request, stdout=subprocess.PIPE)
    (output, err) = p.communicate()
    p_status = p.wait()



if __name__ == '__main__':
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
    stringProg = ""
    if not allVariables.LinuxVM:
        r = 'strings %s | grep -i -E "%s' % (allVariables.pathToFirstStringsMachine, list_app_string[0].split(",")[0])
        for i in range(1, len(list_app_string)):
            r += " | " + list_app_string[i].split(",")[0]
        r += '" > %s' % (stringProg)
        print(r)
        p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()


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
                    
                    ## Run the fls command
                    OnLinux.get_Fls_Strings.fls(appchemin, allVariables.pathToStrings, app_status)

                    ## Run Strings command
                    OnLinux.get_Fls_Strings.getStrings(appchemin, app, allVariables.pathToStrings, app_status)

        if i % 2 == 0:
            j += 1
            uninstall = True
        else:
            uninstall = False

        ## Suppression of the current raw disk
        os.remove(convert_file)

    
    ## AutoGeneYara
    hexa = "" 
    ProductVersion = ""
    for content in os.listdir(allVariables.pathToShareWindows):
        l = blockProg()
        c = content.split(".")
        for line in l:
            if line.split(":")[0] == c[0]:
                c[0] = line.split(":")[1].rstrip("\n")
        chemin = os.path.join(allVariables.pathToShareWindows, content)
        if os.path.isfile(chemin):
            (hexa, ProductVersion) = get_pe.pe_yara(chemin)
            rule = create_rule(c, hexa, ProductVersion, l_app)
            print(rule)
            automatisation_yara.save_rule(c[0], c[1], rule)

            s = "@%s@fls_install.tree" % (c[0])
            runAuto(s, stringProg)
            
            s = "@%s@fls_uninstall.tree" % (c[0])
            runAuto(s, stringProg)

            s = "@%s@install.txt" % (c[0])
            runAuto(s, stringProg)

            s = "@%s@uninstall.txt" % (c[0])
            runAuto(s, stringProg)


    ## Parsing of the Asa Report
    if allVariables.pathToAsa:
        for content in os.listdir(allVariables.pathToAsaReport):
            l = blockProg()
            currentApp = content.split("_")[0]
            for line in l:
                if line.split(":")[0] == currentApp:
                    currentApp = line.split(":")[1].rstrip("\n")
            
            chemin = os.path.join(allVariables.pathToAsaReport, content)
            if os.path.isfile(chemin):
                parseAsa(chemin, currentApp)
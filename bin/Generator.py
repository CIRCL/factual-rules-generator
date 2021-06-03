import os
import re
import sys
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
import OnLinux.get_Fls_Strings
import automatisation_yara

def blockProg():
    f1 = open(pathWork + "etc/blockProg.txt", "r")
    l1 = f1.readlines()
    f1.close()
    return l1

def runningVms():
    req = [allVariables.VBoxManage, "list", "runningvms"]
    return subprocess.run(req, capture_output=True)

def readFile():
    f = open(str(pathProg) + "/tmp","r")

    l = f.readline().rstrip()
    l1 = blockProg()

    f.close()

    listTmp = [l.split(":")[0],l.split(":")[1].rstrip("\n")]

    for line in l1:
        if line.split(":")[0] == listTmp[1]:
            return [listTmp[0], line.split(":")[1].rstrip("\n")]
    return listTmp

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

    rules += 'description = "Auto gene for %s"\n\t\t' % (str(ext[0]))
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

def runAuto(s):
    pathS = os.path.join(allVariables.pathToStrings, s)
    if os.path.isfile(pathS):
        print(s)
        automatisation_yara.inditif(pathS, ProductVersion, l_app)


if __name__ == '__main__':
    fapp = open(allVariables.applist, "r")
    l_app = fapp.readlines()
    line_count = 0
    for line in l_app:
        if line != "\n":
            line_count += 1
    fapp.close()

    res = runningVms()

    for i in range(0,line_count*2):
        print("Boucle n: %s, %s" % (i, l_app[i % len(l_app)].split(":")[1]))
        res = runningVms()

        request = [allVariables.VBoxManage, 'startvm', allVariables.WindowsVM]
        if not allVariables.WindowsVM in res.stdout.decode():
            ## Start windows machine
            print("Windows Start")
            p = subprocess.Popen(request, stdout=subprocess.PIPE)
            (output, err) = p.communicate()
            p_status = p.wait()

        ## wait windows machine to shutdown
        res = runningVms()

        cptime = 0
        while allVariables.WindowsVM in res.stdout.decode():
            time.sleep(60)
            cptime += 1
            print("\rTime spent: %s min" % (cptime), end="")
            res = runningVms()

        print("\nWindows stop\n")


        ## Convert windows machine into raw format
        qemu = allVariables.qemu
        vm = allVariables.pathToWindowsVM
        partage = allVariables.pathToConvert
        status = readFile()

        convert_file = "%s%s_%s.img" %(partage, status[1], status[0])

        print("## Convertion ##")
        ############### Mettre plutot le nom de l'exe pour la machine linux pour faire un grep -i direct en fonction du nom
        res = subprocess.call([qemu, "convert", "-f", "vmdk", "-O", "raw", vm, convert_file])
        print("ok\n")

        
        if allVariables.LinuxVM:
            res = runningVms()
            
            request = [allVariables.VBoxManage, 'startvm', allVariables.LinuxVM]
            if not allVariables.LinuxVM in res.stdout.decode():
                ## Start ubuntu machine
                print("Ubuntu Start")
                p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()


            res = runningVms()
            
            cptime = 0
            while allVariables.LinuxVM in res.stdout.decode():
                time.sleep(60)
                cptime += 1
                print("\rTime spent: %s min" % (cptime), end="")
                res = runningVms()

            print("\nUbuntu stop")
        else:
            for content in os.listdir(allVariables.pathToConvert):
                appchemin = os.path.join(allVariables.pathToConvert, content)
                if os.path.isfile(appchemin):
                    app_status = content.split(".")[0]
                    app = app_status.split("_")[0]
                    
                    OnLinux.get_Fls_Strings.fls(appchemin, allVariables.pathToStrings, app_status)

                    OnLinux.get_Fls_Strings.getStrings(appchemin, app, allVariables.pathToStrings, app_status)

        ## Suppresson of the current tmp file 
        os.remove(str(pathProg) + "/tmp")
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
            automatisation_yara.save_rule(c[0], c[1], rule, 3)

            s = "@%s@fls_install.tree" % (c[0])
            runAuto(s)
            
            s = "@%s@fls_uninstall.tree" % (c[0])
            runAuto(s)

            s = "@%s@install.txt" % (c[0])
            runAuto(s)

            s = "@%s@uninstall.txt" % (c[0])
            runAuto(s)
import os
import sys
import time
import get_pe
import subprocess
import allVariables
import automatisation_yara

def runningVms():
    req = '%s list runningvms' % (allVariables.VBoxManage)
    return subprocess.run(req, capture_output=True)

def readFile():
    f = open(os.path.dirname(sys.argv[0]) + "/tmp","r")
    l = f.readline().rstrip()
    f.close()
    return l


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
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
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

    print("\nWindows stop")


    ## Convert windows machine into raw format
    qemu = allVariables.qemu
    vm = allVariables.pathToWindowsVM
    partage = allVariables.pathToConvert
    status = readFile()

    convert_file = "%s%s_%s.img" %(partage, status.split(":")[1], status.split(":")[0])

    print("## Convertion ##")
    ############### Mettre plutot le nom de l'exe pour la machine linux pour faire un grep -i direct en fonction du nom
    res = subprocess.call([qemu, "convert", "-f", "vmdk", "-O", "raw", vm, convert_file])
    print("ok\n")


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

    ## Suppresson of the current tmp file 
    os.remove(os.path.dirname(sys.argv[0]) + "/tmp")
    ## Suppression of the current raw disk
    os.remove(convert_file)


## AutoGeneYara
hexa = "" 
ProductVersion = ""
for content in os.listdir(allVariables.pathToShareWindows):
    chemin = os.path.join(allVariables.pathToShareWindows, content)
    if os.path.isfile(chemin):
        (hexa, ProductVersion) = get_pe.pe_yara(chemin)

for content in os.listdir(allVariables.pathToStrings):
    chemin = os.path.join(allVariables.pathToStrings, content)
    if os.path.isfile(chemin):
        automatisation_yara.inditif(chemin, ProductVersion)
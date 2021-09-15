import os
import ast
import glob
import time
import shutil
import psutil
import VarClient
import subprocess

# put client.exe in the startup folder, "Windows" + "r" and "shell:startup"

logFile = open("\\\VBOXSVR\\PartageVM\\logClient.txt", "a")

## Prepare the request depending on the installer
def appManager(status, installer, app):
    if installer == "choco":
        if status:
            return "choco install -y %s" % (app)
        else:
            return "choco uninstall -y %s" % (app)
    elif installer == "msiexec":
        if status:
            return "msiexec /i %s%s /qn" % (VarClient.pathToInstaller + "\\installer\\", app)
        else:
            return "msiexec /x %s%s /qn" % (VarClient.pathToInstaller + "\\installer\\", app)
    elif installer == "exe":
        if status:
            return "%s\\%s /s /v\"/qn\"" % (VarClient.pathToInstaller, app)
        else:
            return "%s %s" % (VarClient.pathToUninstaller, app)


def callSubprocess(who, request, shellUse = False):
    if shellUse:
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
    else:
        p = subprocess.Popen(request, stdout=subprocess.PIPE)
        (output, err) = p.communicate()
        p_status = p.wait()

    try:
        logFile.write("%s: %s\n" % (who, output.decode()))
    except:
        logFile.write("%s: %s\n" % (who, str(output)))


def sDelete():
    if VarClient.pathToSDelete:
        print("[+] SDelete")
        request = "%s -c C:" % (VarClient.pathToSDelete)

        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()

        try:
            logFile.write("sDelete: " + output.decode('utf-16') + "\n")
        except:
            logFile.write("sDelete: " + str(output) + "\n")

        try:
            logFile.write("sDeleteError: " + err.decode('utf-8') + "\n")
        except:
            logFile.write("sDeleteError: " + str(err) + "\n")



## Run an asa collect for a later compare
def AsACollect():
    if VarClient.pathToAsa:
        print("[+] AsA collect")
        request = [VarClient.pathToAsa, "collect", "-a"]
        callSubprocess("AsaCollect", request)

## Compare two asa collect and move the result to the share folder
def AsAExport(app):
    if VarClient.pathToAsa:
        print("[+] AsA export")
        request = [VarClient.pathToAsa, "export-collect"]
        callSubprocess("AsaExport", request)

        print("[+] Move AsA report")
        request = ["move", ".\\2021*", VarClient.pathToAsaReport + app.split(".")[0] + "_install_Asa_compare.json"]
        
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            logFile.write("Move Asa: " + output.decode() + "\n")
        except:
            logFile.write("Move Asa: " + str(output) + "\n")

        print("[+] Delete Asa Sqlite File")
        files = glob.glob('.\\asa.sqlite*', recursive=True)
        for f in files:
            try:
                os.remove(f)
            except OSError as e:
                print("Error: %s : %s" % (f, e.strerror))

    

if __name__ == '__main__':
    for content in os.listdir(VarClient.pathToInstaller):
        chemin = os.path.join(VarClient.pathToInstaller, content)
        if os.path.isfile(chemin):
            f = open(chemin, "r")
            l = f.readline()
            f.close()
            
            dic = ast.literal_eval(l)
            key = list(dic.keys())

            if "uninstall" in content:
                print("[*] Uninstallation")
                logFile.write("[*] Uninstallation\n")
                request = appManager(False, dic[key[1]], key[0])
                print(request)

                if request:
                    callSubprocess("AppManager", request)

                if "exe" == dic[key[1]]:
                    input("\nEnter when finish")

                sDelete()

                print("[*] Uninstall finish")
            else:
                print("[*] Installation")
                logFile.write("[*] Installation\n")

                AsACollect()

                request = appManager(True, dic[key[1]], key[0])
                print(request)

                if request:
                    callSubprocess("AppManager", request)

                p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                try:
                    logFile.write("AppManager: " + output.decode() + "\n")
                except:
                    logFile.write("AppManager: " + str(output) + "\n")

                if dic[key[1]] == "choco":
                    print("[+] Output installation: " + output.decode())

                print("[*] Install finish\n")
                
                # get the path to the app
                print("[+] Path to exe search...")
                request = ["cd", "/", "&", "dir", "/s", "/b", "%s.exe" % (dic[key[0]])]

                p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                try:
                    logFile.write("Path search " + output.decode() + "\n")
                except:
                    logFile.write("Path search " + str(output) + "\n")

                path = output.decode().split("\n")[0].rstrip("\n\r")
                
                
                # copy the app on the share folder of the vm
                print("[+] Copy exe...")
                r = 'copy "' + path + '" ' + VarClient.pathToExeExtract

                pCopy = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
                (output, err) = pCopy.communicate()
                p_status = pCopy.wait()
                try:
                    logFile.write("Copy Exe: " + output.decode() + "\n")
                except:
                    logFile.write("Copy Exe: " + str(output) + "\n")
                
                # run exe to have more artefacts
                print("[+] Run exe...")
                p = subprocess.Popen(path, stdout=subprocess.PIPE, shell=True)

                time.sleep(20)
                
                # search for the pid created by the above subprocess and kill it
                if psutil.pid_exists(p.pid):
                    parent = psutil.Process(p.pid)
                    children = parent.children(recursive=True)
                    #print(children)
                    #child_pid = children[0].pid
                    for child_pid in children:
                        if psutil.pid_exists(child_pid.pid):
                            try:
                                subprocess.check_output("Taskkill /PID %d /F /T" % child_pid.pid)
                            except:
                                pass
                
                AsACollect()
                AsAExport(key[0])

    os.system("shutdown /s /t 10")
import os
import ast
import time
import psutil
import VarClient
import subprocess

# put client.exe in the startup folder, windows+r and shell:startup
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
            return "%s%s /s /v\"/qn\"" % (VarClient.pathToInstaller, app)
        else:
            return "%s %s" % (VarClient.pathToUninstaller, app)

def sync():
    if VarClient.pathToSync:
        print("[+] Sync")
        request = [VarClient.pathToSync, "c"]
        p = subprocess.Popen(request, stdout=subprocess.PIPE)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            print(output.decode())
        except:
            pass

def copyBigFile():
    if VarClient.pathToCopy:
        print("[+] Copy of big file")
        request = ["copy", VarClient.pathToCopy, "C:\\Users\\Administrateur\\Downloads"]
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        try:
            print(output.decode())
        except:
            pass
    

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
                #exit(0)
                request = appManager(False, dic[key[1]], key[0])
                print(request)
                
                p = subprocess.Popen(request, stdout=subprocess.PIPE)
                (output, err) = p.communicate()
                p_status = p.wait()

                if "exe" == dic[key[1]]:
                    input("\nEnter when finish")

                sync()
                copyBigFile()
                sync()

                print("[*] Uninstall finish")
            else:
                print("[*] Installation")
                #exit(0)
                request = appManager(True, dic[key[1]], key[0])
                print(request)
                p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                
                if dic[key[1]] == "choco":
                    print("[+] Output installation: " + output.decode())

                print("[*] Install finish\n")
                
                # get the past to the app
                print("[+] Path to exe search...")
                request = ["cd", "/", "&", "dir", "/s", "/b", "%s.exe" % (dic[key[0]])]

                p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                
                path = output.decode().split("\n")[0].rstrip("\n\r")
                
                
                # copy the app on the share folder of the vm
                print("[+] Copy exe...")
                r = 'copy "' + path + '"' + VarClient.pathToExeExtract
                
                p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
                (output, err) = p.communicate()
                p_status = p.wait()
                
                
                print("[+] Run exe...")
              
                p = subprocess.Popen(path, stdout=subprocess.PIPE, shell=True)

                time.sleep(10)
                
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
                    
    os.system("shutdown /s /t 10")
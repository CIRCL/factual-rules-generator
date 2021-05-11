import os
import ast
import time
import psutil
import requests
import subprocess

# put client.exe in the startup folder, windows+r and shell:startup


def request(host, port):
    url = "http://%s:%s/installer" % (host, port)

    r = requests.get(url)
    applist = r.text[5:-6]

    dic = ast.literal_eval(applist)

    return r, dic

adress_server = "" #Exemple: 192.168.1.52
port = 5000

(r, dic) = request(adress_server, port)
for d in dic:
    if d == "stop":
        (r, dic) = request(adress_server, port)
    break

if "uninstaller" in r.url:
    for d in dic:
        print("unin")
        print(d + "\n")
        #exit(0)
        request = "choco uninstall %s -y" % (d)
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        
        print("uninstall finish\n")
else:
    for d in dic:
        print("inst")
        print(d + "\n")
        #exit(0)
        request = "choco install %s -y" % (d)
        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        
        print("install finish\n")
        
        # get the past to the app
        request = ["cd", "/", "&", "dir", "/s", "/b", "%s.exe" % (dic[d])]

        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()
        
        path = output.decode().split("\n")[0].rstrip("\n\r")
        
        p = subprocess.Popen(path, stdout=subprocess.PIPE, shell=True)

        time.sleep(10)
        
        parent = psutil.Process(p.pid)
        children = parent.children(recursive=True)
        print(children)
        child_pid = children[0].pid
        
        subprocess.check_output("Taskkill /PID %d /F" % child_pid)
        
        
        # copy the app on the share folder of the vm
        r = 'copy "' + path + '" \\\VBOXSVR\PartageVM\exe_extract' ## change the last paramaeter 
        
        p = subprocess.Popen(r, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        p_status = p.wait()


os.system("shutdown /s /t 10")
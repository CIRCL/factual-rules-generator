# factual-rules-generator

Factual-rules-generator is an open source project which aims to generate yara rules about installed software on a machine.



## Python Dependencies

- pefile
- psutil
- ndjson
- python-tlsh



- pyinstaller (to change client.py to client.exe)

- ssdeep
  - On [Ubuntu](https://python-ssdeep.readthedocs.io/en/latest/installation.html#install-on-ubuntu-16-04): 
    - `sudo apt-get install build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev`
    - `pip install ssdeep`

## Tools requirement

Some tools are required:

- xxd
- cut
- sed 
- curl



For the windows virtual machine:

- SDelete : https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete
- AsA (AttackSurfaceAnalyzer) : https://github.com/microsoft/AttackSurfaceAnalyzer



## Install

- Install all python dependencies find in requirements.txt

- Create a share folder to communicate with VM

- Install a Windows VM
    - Install chocolatey on Windows VM: https://docs.chocolatey.org/en-us/choco/setup
    - Complete `bin/OnWindows/Varclient.py`
    - Change `bin/OnWindows/client.py` in an exe and put in startup folder
    
- Complete `etc/allVariables.py`

  ​    

In `test/` some example of software to install is give, it's use a specific format : 

- First, there's the name of the packages to install using chocolatey (https://community.chocolatey.org/packages) before `:`, or the name of the file in case of msi or exe file.
- Second, after `:` there's the name of the exe to extract and run it (without extension).
- The second part after `,` follow the same system with the word `installer` first and after `:` the type of installer :
  - choco
  - msiexec
  - exe
- Finally, the third part, `uninstaller` follow by `:` and the uninstaller like choco, msiexec or exe



## Run 

 `bin/Generator.py` is the only script to run, but fill `etc/allVariables.py` is very important.



## Yara Rule Repo

[factual-rules](https://github.com/CIRCL/factual-rules)



## Structure



<img src="https://github.com/CIRCL/factual-rules-generator/blob/main/img/StructureAutoGene.png?raw=true" alt="alt text" style="zoom:80%;" />










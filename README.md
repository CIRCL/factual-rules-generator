# factual-rules-generator

Factual-rules-generator is an open source project which aims to generate yara rules about installed software on a machine.



## Python Dependencies

- pefile
- ast
- psutil



- pyinstaller (to change client.py to client.exe)



## Windows requirement

If scripts are run under a Windows machine, some tools are required:

- `xxd` : https://www.vim.org/download.php
- `cut` : http://unxutils.sourceforge.net/
- `sed` : http://unxutils.sourceforge.net/



These tools are not mandatory but recommended:

- Asa (AttackSurfaceAnalyzer) : https://github.com/microsoft/AttackSurfaceAnalyzer
- Sync : https://docs.microsoft.com/en-us/sysinternals/downloads/sync
- Uninstall : https://tarma.com/tools/uninstall



## Linux requirement

There's two tools necessary on the linux machine:

- `fls` contains in The Sleuth Kit (TSK)
- `strings` unix command

## Install

- Install all python dependencies find in requirements.txt

- Install a Windows VM
    - Install chocolatey on Windows VM: https://docs.chocolatey.org/en-us/choco/setup
    
- A Share Folder is needed

- If use a Linux VM, install it
    - put `bin/OnLinux/get_Fls_Strings.py` in Linux VM and the script need to be run on startup
    
- Complete `etc/allVariables.py`

- Compete `bin/OnWindows/VarClient.py`

- Change `bin/OnWindows/client.py` in an exe and put in startup folder

    

In `test/` some example of software to install is give, it's use a specific format : 

- First, there's the name of the packages to install using chocolatey (https://community.chocolatey.org/packages) before `:`
    - Or, you have to put the name of the exe or msi (`test/app.txt`)
- Second, after `:` there's the name of the exe to extract and run it (without extension).
- Finally, after `,` you need to specified the installer: (`putty.msi:putty,installer:msiexec`)
    - choco
    - msiexec
    - exe



## Run 

 `bin/Generator.py` is the only script to run.



## Structure



<img src="https://github.com/CIRCL/factual-rules-generator/blob/main/img/StructureAutoGene.png?raw=true" alt="alt text" style="zoom:80%;" />










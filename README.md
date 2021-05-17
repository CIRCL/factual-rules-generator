# factual-rules-generator

Factual-rules-generator is an open source project which aims to generate yara rules about installed software on a machine.



## Python Dependencies

- pefile
- flask
- ast
- psutil
- requests



## Windows requirement

If scripts are run under a Windows machine, some tools are required:

- xxd : https://www.vim.org/download.php
- cut : http://unxutils.sourceforge.net/



## Install

- Install all python dependencies find in requirements.txt

- Install a Windows VM
    - Install chocolatey on Windows VM: https://docs.chocolatey.org/en-us/choco/setup
    
- If use a Linux VM, install it
    - put `bin/OnLinux/get_Fls_Strings.py` in Linux VM and the script need to be run on startup
    
- Complete `etc/allVariables.py`

- Add IP adress of the server and share folder in `bin/OnWindows/client.py` at specific lines

- Change `bin/OnWindows/client.py` in an exe and put in startup folder

    

In `test/` some example of software to install is give, it's use a specific format : 

- First, there's the name of the packages to install using choclatey (https://community.chocolatey.org/packages) before `:`
- Second, after `:` there's the name of the exe to extract and run it (without extension).



## Run 

`bin/server.py` is the first script to run and `bin/Generator.py` is the second and the last.



## Structure



<img src="https://github.com/CIRCL/factual-rules-generator/blob/main/img/StructureAutoGene.png?raw=true" alt="alt text" style="zoom:80%;" />










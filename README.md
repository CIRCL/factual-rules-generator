# factual-rules-generator

Factual-rules-generator is an open source project which aims to generate [YARA rules](https://github.com/CIRCL/factual-rules) about installed software from a running operating system.

The goal of the software is to be able to use a set of rules against collected or acquired digital forensic evidences and find installed software in a timely fashion.

The software can be used to baseline known software from Windows system and create a set of rules for finding similar installation on other systems.

## Dependencies

- pefile
- psutil
- ndjson
- python-tlsh

- [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/) (to change client.py to client.exe)

- ssdeep
  - On [Ubuntu](https://python-ssdeep.readthedocs.io/en/latest/installation.html#install-on-ubuntu-16-04): 
    - `sudo apt-get install build-essential libffi-dev python3 python3-dev python3-pip libfuzzy-dev`
    - `pip install ssdeep`

## Tools requirement

Some tools are required on the host operating system some are Unix standard tools and some additional ones:

- xxd
- curl

For the Windows virtual machine, the following software is required to be installed:

- [SDelete](https://docs.microsoft.com/en-us/sysinternals/downloads/sdelete)
- [AsA (AttackSurfaceAnalyzer)](https://github.com/microsoft/AttackSurfaceAnalyzer)

## Install

- Install all Python dependencies defined [requirements.txt](https://github.com/CIRCL/factual-rules-generator/blob/main/requirements.txt)
- Create a shared folder to communicate with VM
- Install a Windows VM
    - Install [chocolatey](https://docs.chocolatey.org/en-us/choco/setup) on Windows VM
    - Complete `bin/OnWindows/Varclient.py`
    - Change `bin/OnWindows/client.py` in an executable file with [PyInstaller](https://pyinstaller.readthedocs.io/en/stable/) and put in startup folder
- Update `etc/allVariables.py` to match your desired configuraiton

In `test/` [some examples](https://github.com/CIRCL/factual-rules-generator/blob/main/test/app.txt) of software to install is given, the following specific format is required: 

- First, select the name of the packages to install using [chocolatey](https://community.chocolatey.org/packages) before `:`, or the name of the file in case of msi or exe file.
- Second, after `:` there's the name of the exe to extract and run it (without extension).
- The second part after `,` follow the same system with the word `installer` first and after `:` the type of installer :
  - choco
  - msiexec
  - exe
- Finally, the third part, `uninstaller` follow by `:` and the uninstaller like choco, msiexec or exe

## Run and generate the rules 

-  `bin/Generator.py` is the only script to run, don't forget to update `etc/allVariables.py` (critical step).

## Public YARA rules repository

- [factual-rules](https://github.com/CIRCL/factual-rules)

## Overview of factual rules generator 

- ![Factual rules generator - workflow](https://github.com/CIRCL/factual-rules-generator/blob/main/img/StructureAutoGene.png?raw=true)

## License

~~~
    Factual-rules-generator is an open source project which aims to generate YARA rules about installed software from a machine. 

    Copyright (C) 2021-2022 David Cruciani
    Copyright (C) 2021-2022 CIRCL - Computer Incident Response Center Luxembourg

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
~~~









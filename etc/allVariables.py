#Path to the list that contains software to install: "nameOfPackage":"nameOfExe"
applist = "tests/listapp.txt"

pathToInstaller = ""

#Path to VBoxManage
VBoxManage = "VBoxManage"

#UUID of Windows VM
WindowsVM = "" #Exemple {235f9214-e871-4b75-b091-c90e53b32974}
#Path to Windows VM
pathToWindowsVM = ""
#Path to folder share with Windows VM
pathToShareWindows = ""

#UUID of Linux VM
LinuxVM = ""

#Path to qemu to convert VM into raw format
qemu = ""

#Path to folder who will contain vm in raw format
pathToConvert = ""
#Path to strings after linux execution

#Path to strings of Windows VM without software install
pathToFirstStringsMachine = ""

#Path to fls output of Windows VM without software install
pathToFirstFls = ""

#Path to save yara rule on pc
pathToYaraSave = ""

#Path to the folder who will contains AsaReport
pathToAsaReport = ""

#Option, feed hashlookup, default: N, possibility: N, Y
FeedHashlookup = "N"

#Path to save the result to feed hashlookup
pathToFeedHashlookup = ""

#Path to result of systeminfo
pathToSysInfo = ""
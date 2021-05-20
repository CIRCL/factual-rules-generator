import re
import sys
import pefile
import subprocess
import pathlib
p = pathlib.Path(__file__).parent.absolute()
s = ""
for i in re.split(r"/|\\", str(p))[:-1]:
    s += i + "/"
sys.path.append(s + "etc")
import allVariables
sys.path.append(s + "etc")
import allVariables

def pe_yara(file_pe):
    pe =  pefile.PE(file_pe)

    xxd_entr = ""
    xxd_len = 0
    ProductVersion = ""

    for fileinfo in pe.FileInfo[0]:
        if fileinfo.Key.decode() == 'StringFileInfo':
            string_table = fileinfo.StringTable[0]
            for st in fileinfo.StringTable:
                #print(st.entries.items())
                for i in st.entries.items():
                    if i[0].decode() == "ProductVersion":
                        ProductVersion = i[1].decode()
                xxd_entr = hex(st.entries_offsets[b'CompanyName'][0])
                loc = hex(st.entries_offsets[b'FileVersion'][0])

                xxd_len = st.entries_offsets[b'FileVersion'][0] - st.entries_offsets[b'CompanyName'][0] -6

    request = "%s -s %s -l %s %s | %s -c11-50 " % (allVariables.xxd, str(xxd_entr), str(xxd_len), file_pe, allVariables.cut)

    p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
    (output, err) = p.communicate()
    p_status = p.wait()

    return output.decode(), ProductVersion
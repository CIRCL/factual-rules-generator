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


def pe_yara(file_pe):
    pe =  pefile.PE(file_pe)

    xxd_entr = ""
    xxd_len = 0
    ProductVersion = ""

    try:
        f = pe.FileInfo[0]
        for fileinfo in pe.FileInfo[0]:
            if fileinfo.Key.decode() == 'StringFileInfo':
                string_table = fileinfo.StringTable[0]
                for st in fileinfo.StringTable:
                    #print(st.entries.items())
                    for i in st.entries.items():
                        if i[0].decode() == "ProductVersion":
                            ProductVersion = i[1].decode()

                    xxd_entr = hex(st.entries_offsets[b'CompanyName'][0])
                    xxd_len = st.entries_offsets[b'FileVersion'][0] - st.entries_offsets[b'CompanyName'][0] -6
        
        request = f"xxd -s {str(xxd_entr)} -l {str(xxd_len)} {file_pe} | cut -c11-50"

        p = subprocess.Popen(request, stdout=subprocess.PIPE, shell=True)
        (out, err) = p.communicate()
        p_status = p.wait()

        return out.decode(), ProductVersion

    except Exception as e:
        print(e)
        return "",""
    
import os
import re
import sys
import uuid
import string
import datetime
import pathlib
p = pathlib.Path(__file__).parent.absolute()
s = ""
for i in re.split(r"/|\\", str(p))[:-1]:
    s += i + "/"

sys.path.append(s + "etc")
import allVariables


####Creation of yara rule
def create_rule(ext, s, product_version, l_app):
    app = ""
    for l in l_app:
        if l.split(":")[1].rstrip("\n") == ext[1]:
            app = l.split(":")[0].split(".")[0]

    date = datetime.datetime.now()

    ##Headers of yara rule
    if app:
        rules = "rule %s_%s {\n\tmeta:\n\t\t" % (app, ext[2])
    else:
        rules = "rule %s_%s {\n\tmeta:\n\t\t" % (ext[1], ext[2])

    rules += 'description = "Auto generation for %s"\n\t\t' % (str(ext[1]))
    rules += 'author = "David Cruciani"\n\t\t'
    rules += 'date = "' + date.strftime('%Y-%m-%d') + '"\n\t\t'
    rules += 'versionApp = "%s"\n\t\t' % (product_version)
    rules += 'uuid = "%s"\n\t' % (str(uuid.uuid4()))

    rules += "strings: \n"

    ##Creation of regex to match the differents strings find earlier
    r = -1
    
    for regle in s:
        reg = ""
        r+=1
        for car in regle:
            if car in string.ascii_letters or car in string.digits or car == " ":
                reg += car
            elif car in string.punctuation:
                reg += "\\" + car
 
        rules += "\t\t$s%s = /%s/\n" % (str(r), reg)

    ##End of yara rule
    ## 1.25 is a coefficient to match the rule, which leaves a margin of error
    #rules += "\tcondition:\n\t\t%s of ($s*)\n}" % (str(int(r/1.25)))
    rules += "\tcondition:\n\t\t ext_var of ($s*)\n}" 

    return rules

###Save of the rule on the disk
def save_rule(ext1, ext2, rules, flag = False):
    chemin = os.path.join(allVariables.pathToYaraSave, ext1)
    if flag:
        chemin = os.path.join(chemin, "tree")

    if not os.path.isdir(chemin):
        os.mkdir(chemin)

    yara_rule = open("%s/%s_%s.yar" % (chemin, ext1, ext2), "w")
    yara_rule.write(rules)
    yara_rule.close()


def file_create_rule(chemin, file_version, l_app, stringProg, flag = False):
    s = list()

    f = open(chemin, "r")
    file_strings = f.readlines()

    if stringProg:
        first = open(stringProg)
        full = first.readlines() 
        first.close()
    elif allVariables.pathToFirstStringsMachine:
        first = open(allVariables.pathToFirstStringsMachine)
        full = first.readlines() 
        first.close()   

    if allVariables.pathToFirstFls:
        flsFile = open(allVariables.pathToFirstFls, "r")
        fls = flsFile.readlines()
        flsFile.close()

    ## Extract the term to search
    try:
        ext = chemin.split("@")
    except:
        print('Missing @ in the file name')
        print("Example: C:\\Programe File\\@Chrome@strings")
        exit(1)

    for i in range(0,len(file_strings)):
        ## the file is not a tree
        if not flag:
            ## there's a file who contains some strings about a software on a vanilla machine
            if allVariables.pathToFirstStringsMachine:
                if ((not len(file_strings[i].split(" ")) > 5 and not len(file_strings[i]) > 30) \
                    or (len(file_strings[i].split(" ")) == 1 and not len(file_strings[i]) > 50)) \
                    and ((ext[1] in file_strings[i] or ext[1].lower() in file_strings[i] or ext[1].upper() in file_strings[i]) and file_strings[i] not in s) and file_strings[i] not in full:

                        s.append(file_strings[i])
            else:
                if ((not len(file_strings[i].split(" ")) > 5 and not len(file_strings[i]) > 30) \
                    or (len(file_strings[i].split(" ")) == 1 and not len(file_strings[i]) > 50)) \
                    and (ext[1] in file_strings[i] or ext[1].lower() in file_strings[i] or ext[1].upper() in file_strings[i]) and file_strings[i] not in s:

                        s.append(file_strings[i])
        else:
            f_str = str(file_strings[i]).split("\t")[1]
            if allVariables.pathToFirstFls:
                if ((ext[1] in f_str or ext[1].lower() in f_str or ext[1].upper() in f_str) and f_str not in s) and f_str not in fls:
                    s.append(f_str)
            else:
                if (ext[1] in f_str or ext[1].lower() in f_str or ext[1].upper() in f_str) and f_str not in s:
                    s.append(f_str)

    ## Suppression of the extension
    ext.append(str(ext[-1:][0].split(".")[0]))
    del(ext[-2:-1])

    ####Creation of yara rule
    rules = create_rule(ext, s, file_version, l_app)

    print(rules)
    #exit(0)

    ###Save of the rule on the disk
    save_rule(ext[1], ext[2], rules, flag)




def inditif(fichier, file_version, l_app, stringProg):
    try:
        extension = fichier.split(".")[1]
    except:
        print("Missing extension")
        exit(1)

    ## the file is a tree
    if fichier.split(".")[1] == "tree":
        file_create_rule(fichier, file_version, l_app, stringProg, True)
    else:
        file_create_rule(fichier, file_version, l_app, stringProg)

import os
import subprocess
from zipfile import ZipFile
import shutil
from androguard.misc import AnalyzeDex
import csv

lib_path = "C:/Users/Yigit/Desktop/LIB ANALYSES/androguard/analiz/"
dex_path = "C:/Users/Yigit/Desktop/LIB ANALYSES/androguard/dex/"

"""
Baslangic dosya formati:

- lib_path/                                 Bitiste olusan dosyalar:
    -lib1/
        -lib1+version1.aar  -------------> (lib+version1.aar , lib+version1.zip , lib+version1.jar , lib+version1.dex)
        -lib1+version2.aar
        -lib1+version3.jar  -------------> (lib1+version3.jar , lib1+version3.dex) 
    -lib2/                                  ...
        -lib2+version1.aar  
        -lib2+version2.aar
        -lib2+version3.jar
    ...                                                             
        
"""


def convertAARtoZIP():
    for root, directories, files in os.walk(lib_path):
        for file in files:
            if file.endswith('.aar'):
                pre, ext = os.path.splitext(file)
                # copying existing aar
                shutil.copyfile(f"{root}/{file}", f"{root}/{pre}-copied{ext}")
                # converting copied .aar to .zip to extract 'classes.jar' inside of it
                os.rename(f"{root}/{pre}-copied{ext}", f"{root}/{pre}.zip")


# convertAARtoZIP()

def extractJARfilesFromZIP():
    for root, directories, files in os.walk(lib_path):
        for file in files:

            if file.endswith('.zip'):
                pre, ext = os.path.splitext(file)

                with ZipFile(f"{root}/{file}", 'r') as zipObj:
                    listOfiles = zipObj.namelist()

                    for element in listOfiles:
                        if element == "classes.jar":
                            zipObj.extract(element, root + "/")
                            os.rename(f"{root}/classes.jar", f"{root}/{pre}.jar")


# extractJARfilesFromZIP()


def convertJARtoDEX():
    for root, directories, files in os.walk(lib_path):
        for file in files:
            if file.endswith('.jar'):
                pre, ext = os.path.splitext(file)
                subprocess.call([f"{dex_path}d2j-jar2dex.bat", f"{root}/{file}", "-o", f"{root}/{pre}.dex"])


# convertJARtoDEX()

def analyzeDEXfiles():
    for root, directories, files in os.walk(lib_path):
        for file in files:
            if file.endswith('.dex'):
                a, b, c = AnalyzeDex(filename=root + "/" + file)

                # dangerous permissions
                for meth, perm in c.get_permissions():
                    print("Using API method {} for permission {}".format(meth, perm))
                    print("used in:")
                    for _, m, _ in meth.get_xref_from():
                        print(f"{m.full_name}")

                # class loading
                for item1 in c.find_methods(methodname="loadClass()"):
                    print(item1)

                # package manager
                for item2 in c.find_classes("Landroid/content/pm/PackageManager"):
                    print(item2)

                # javascript
                for item3 in c.find_methods(methodname="evaluateJavascript()"):
                    print(item3)


analyzeDEXfiles()

with open('employee_file.csv', mode='w') as employee_file:
    employee_writer = csv.writer(employee_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    employee_writer.writerow(['John Smith', 'Accounting', 'November'])
    employee_writer.writerow(['Erica Meyers', 'IT', 'March'])
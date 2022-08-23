import os
import subprocess
from zipfile import ZipFile
import shutil

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
    for root, dir, files in os.walk(lib_path):
        for file in files:
            if file.endswith('.aar'):

                pre, ext = os.path.splitext(file)
                # copying existing aar
                shutil.copyfile(f"{root}/{file}", f"{root}/{pre}-copied{ext}")
                # converting copied .aar to .zip to extract 'classes.jar' inside of it
                os.rename(f"{root}/{pre}-copied{ext}", f"{root}/{pre}.zip")


convertAARtoZIP()

def extractJARfilesFromZIP():
    for root, dir, files in os.walk(lib_path):
        for file in files:

            if file.endswith('.zip'):
                pre, ext = os.path.splitext(file)

                with ZipFile(f"{root}/{file}", 'r') as zipObj:
                    listOfiles = zipObj.namelist()

                    for element in listOfiles:
                        if element == "classes.jar":
                            zipObj.extract(element, root+"/")
                            os.rename(f"{root}/classes.jar",f"{root}/{pre}.jar")


extractJARfilesFromZIP()


def convertJARtoDEX():
    for root, dir, files in os.walk(lib_path):
        for file in files:
            if(file.endswith('.jar')):
                pre, ext = os.path.splitext(file)
                subprocess.call([f"{dex_path}d2j-jar2dex.bat", f"{root}/{file}" , "-o" , f"{root}/{pre}.dex"])


convertJARtoDEX()

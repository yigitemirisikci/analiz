from curses import meta
import os
import subprocess
from sys import meta_path
from zipfile import ZipFile
import shutil
from androguard.misc import AnalyzeDex
import csv
import os.path
import json
from typing import List

lib_path = "/Users/betul/Desktop/libsec-scraper/updated-libs"
dex_path = "./dex_files"
output_file = "output.csv"
output_file_permission = "permission.csv"
blacklist_file_path = "./blacklist.txt"
metadata_path= "/Users/betul/Desktop/libsec-scraper/libdata"


headers = ['id', 'artifact_id', 'group_id','version', 'permission', 'api', 'method']
file_exists = os.path.isfile(output_file)
file_output = open('output.csv', mode='a+')
file_output.seek(0,0)
writer = csv.DictWriter(file_output, delimiter=',', lineterminator='\n',fieldnames=headers)
if not file_exists:
    writer.writeheader()


file_blacklist = open(blacklist_file_path, mode='a+')
file_blacklist.seek(0,0)

blacklist = file_blacklist.readlines()
blacklist = [s.strip() for s in blacklist]



# writer.writerow({'id': "1", 'artifact_id': "12", 'group_id': "3","version": "123"})

class Version:
    def __init__(self, d: dict = None) -> None:
        self.version = ""
        self.usages = 0
        self.date = "not found"
        self.filetype = ""  # <aar|jar>
        self.downloaded = False
        self.applied_analyzes: List[str] = []

        if d is not None:
            for key, value in d.items():
                setattr(self, key, value)

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Version) and self.version == __o.version

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __hash__(self) -> int:
        return hash(self.version)


class Repo:
    def __init__(self, d: dict = None) -> None:
        self.name = ""
        self.base_url = ""
        self.versions: List[Version] = []

        if d is not None:
            for key, value in d.items():
                if key == "versions":
                    setattr(self, key, [Version(x) for x in value])
                else:
                    setattr(self, key, value)

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, Repo) and self.base_url == __o.base_url

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __hash__(self) -> int:
        return hash(self.base_url)

    def serialize(self) -> dict:
        return dict(name=self.name, base_url=self.base_url,
                    versions=[vars(v) for v in self.versions])

    def get_version(self, version: str) -> Version:
        for v in self.versions:
            if v.version == version:
                return v


class LibMetadata:
    def __init__(self, d: dict = None) -> None:
        self.id = ""
        self.artifact_id = ""
        self.group_id = ""
        self.tag = ""
        self.repos: List[Repo] = []

        if d is not None:
            for key, value in d.items():
                if key == "repos":
                    setattr(self, key, [Repo(x) for x in value])
                else:
                    setattr(self, key, value)

    def __eq__(self, __o: object) -> bool:
        return isinstance(__o, LibMetadata) and self.id == __o.id

    def __ne__(self, __o: object) -> bool:
        return not self.__eq__(__o)

    def __hash__(self) -> int:
        return hash(self.id)

    def serialize(self) -> dict:
        return dict(id=self.id, artifact_id=self.artifact_id, group_id=self.group_id,
                    tag=self.tag, repos=[r.serialize() for r in self.repos])

    def get_repo(self, repo_name: str) -> Repo:
        for repo in self.repos:
            if repo.name == repo_name:
                return repo

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
# extractJARfilesFromZIP()


def convertJARtoDEX(file):
    if file.endswith('.jar') and not file in blacklist:
        result = subprocess.call(["./dex-tools/d2j-jar2dex.sh", file, "-o", file[:-4] + ".dex"])
        file_exists = os.path.isfile(file[:-4] + ".dex")
        if file_exists == False: 
            file_blacklist.write(file + "\n")
            file_blacklist.flush()
    return file[:-4] + ".dex"

# convertJARtoDEX()

def analyzeDEXfiles():
    for root, directories, files in os.walk(lib_path):
    
        for file in files:
      
            if file.endswith('.dex'):
          
                a, b, c = AnalyzeDex(filename=root + "/" + file)
                # for item in c.get_methods():
                #     print(item.full_name)

# Using API method <analysis.MethodAnalysis Landroid/bluetooth/BluetoothAdapter;->getProfileConnectionState(I)I> for permission ['android.permission.BLUETOOTH']
# used in:
# Lcom/journeyOS/i007Service/core/detect/HeadSetMonitor$HeadSetPlugBroadcastReceiver; onReceive (Landroid/content/Context; Landroid/content/Intent;)V
# Lcom/journeyOS/i007Service/core/detect/HeadSetMonitor; onStart ()V
                # dangerous permissions
             

                path = root + "/" + file
                path = path.replace("/" , "+")
                splited_path = path.split("+")
                splited_path = splited_path[-3:]
                

                for meth, perm in c.get_permissions():
                    #print("Using API method {} for permission {}".format(meth, perm))
                    #print("used in:")
                    meth_list = []
                    for _, m, _ in meth.get_xref_from():
                        meth_list.append(m.full_name)
                       # print(f"{m.full_name}")
                    writer.writerow({'id': splited_path[0] + "+" + splited_path[1] , 'artifact_id': splited_path[0], 'group_id': splited_path[1],"version": splited_path[2][:-4], 'permission': perm, 'api': meth.full_name, 'method': meth_list})

                # # class loading
                # for item1 in c.find_methods(methodname="start()"):
                #     print(item1)

                # # package manager
                # for item2 in c.find_classes("Landroid/content/pm/PackageManager"):
                #     print(item2)

                # # javascript
                # for item3 in c.find_methods(methodname="evaluateJavascript()"):
                #     print(item3)


#analyzeDEXfiles()

def read_metadata_files():
    metadata_path_list = [] 
    for root, _, files in os.walk(metadata_path):
        for file in files:
            metadata_path_list.append(root+"/"+file)
    return metadata_path_list

metadata_paths = read_metadata_files()

def read_metadata_json(lib_path):
    file = open(lib_path,mode ="r" )
    data = json.loads(file.read())
    return LibMetadata(data)

def get_lib_paths(metadata_paths):
    lib_paths = []
    for item_metadata_path in metadata_paths:
        metadata = read_metadata_json(item_metadata_path)
        for item_repo in metadata.repos:
            for item_version in item_repo.versions:
                if(item_version.downloaded == True):
                    lib_paths.append(metadata.id + "/" + item_version.version + "." +item_version.filetype)
    return lib_paths

lib_paths = get_lib_paths(metadata_paths)

dex_paths = []
for item_lib_path in lib_paths:
    file_exists2 = os.path.isfile(item_lib_path[:-4] + ".aar")  or os.path.isfile(item_lib_path[:-4] + ".jar")
    if(file_exists2):
        continue
    item_lib_path = lib_path+"/"+item_lib_path
    file_exists = os.path.isfile(item_lib_path[:-4] + ".dex")
    if(file_exists):
        dex_paths.append(item_lib_path[:-4] + ".dex")
        continue
    if item_lib_path[-3:] == "aar":
            pre, ext = os.path.splitext(item_lib_path)
            # copying existing aar
            shutil.copyfile(item_lib_path, item_lib_path[:-4] + "-copy.aar")
            # converting copied .aar to .zip to extract 'classes.jar' inside of it
            os.rename( item_lib_path[:-4] + "-copy.aar", item_lib_path[:-4] + ".zip")
            with ZipFile(item_lib_path[:-4] + ".zip", 'r') as zipObj:
                listOfiles = zipObj.namelist()
                for element in listOfiles:
                    if element == "classes.jar":
                        zipObj.extract(element, "./")
                        os.rename("./classes.jar", item_lib_path[:-4] + ".jar")
                        dex_path =convertJARtoDEX(item_lib_path[:-4] + ".jar")
                        dex_paths.append(dex_path)
    elif item_lib_path[-3:] == "jar":
        dex_path = convertJARtoDEX(item_lib_path)
        dex_paths.append(dex_path)
    



analyzeDEXfiles()

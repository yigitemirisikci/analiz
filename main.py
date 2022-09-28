from cgitb import reset
import os
import subprocess
from typing import Tuple
from zipfile import ZipFile
import shutil
from androguard.misc import AnalyzeDex
from androguard.core.analysis.analysis import Analysis
import csv
import os.path
import json
from libmetadata import LibMetadata
from javascriptresult import JavascriptResult

lib_path = "/Users/betul/Desktop/libsec-scraper/updated-libs"
dex_path = "./dex_files"
blacklist_file_path = "./blacklist.txt"
metadata_path = "/Users/betul/Desktop/libsec-scraper/libdata"


headers = ['id', 'artifact_id', 'group_id',
           'version', 'permission', 'api', 'method']
output_file_permission = "permission.csv"
file_exists_permission = os.path.isfile(output_file_permission)
file_output_permission = open(output_file_permission, mode='a+')
file_output_permission.seek(0, 0)
writer_permission = csv.DictWriter(file_output_permission, delimiter=',',
                        lineterminator='\n', fieldnames=headers)
if not file_exists_permission:
    writer_permission.writeheader()

headers = ['id', 'artifact_id', 'group_id',
           'version', 'signature', 'method']
output_file_classloader = "classloader.csv"
file_exists_classloader = os.path.isfile(output_file_classloader)
file_output_classloader = open(output_file_classloader, mode='a+')
file_output_classloader.seek(0, 0)
writer_classloader = csv.DictWriter(file_output_classloader, delimiter=',',
                        lineterminator='\n', fieldnames=headers)
if not file_exists_classloader:
    writer_classloader.writeheader()

headers = ['id', 'artifact_id', 'group_id',
           'version', 'signature', 'method']
output_file_javascript = "javascript.csv"
file_exists_javascript = os.path.isfile(output_file_javascript)
file_output_javascript = open(output_file_javascript, mode='a+')
file_output_javascript.seek(0, 0)
writer_javascript = csv.DictWriter(file_output_javascript, delimiter=',',
                        lineterminator='\n', fieldnames=headers)
if not file_exists_javascript:
    writer_javascript.writeheader()

headers = ['id', 'artifact_id', 'group_id',
           'version', 'signature', 'method']
output_file_reflection = "reflection.csv"
file_exists_reflection = os.path.isfile(output_file_reflection)
file_output_reflection = open(output_file_reflection, mode='a+')
file_output_reflection.seek(0, 0)
writer_reflection = csv.DictWriter(file_output_reflection, delimiter=',',
                        lineterminator='\n', fieldnames=headers)
if not file_exists_reflection:
    writer_reflection.writeheader()

headers = ['id', 'artifact_id', 'group_id',
           'version', 'signature', 'method']
output_file_installed_packages = "installed_packages.csv"
file_exists_installed_packages = os.path.isfile(output_file_installed_packages)
file_output_installed_packages = open(output_file_installed_packages, mode='a+')
file_output_installed_packages.seek(0, 0)
writer_installed_packages = csv.DictWriter(file_output_installed_packages, delimiter=',',
                        lineterminator='\n', fieldnames=headers)
if not file_exists_installed_packages:
    writer_installed_packages.writeheader()

file_blacklist = open(blacklist_file_path, mode='a+')
file_blacklist.seek(0, 0)

blacklist = file_blacklist.readlines()
blacklist = [s.strip() for s in blacklist]


# writer.writerow({'id': "1", 'artifact_id': "12", 'group_id': "3","version": "123"})


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


def check_classloader(analysis: Analysis) -> bool:
    return bool(list(analysis.find_methods(classname="Ldalvik/system/DexClassLoader;", methodname="loadClass()"))) or\
        bool(list(analysis.find_methods(classname="Ldalvik/system/PathClassLoader;", methodname="loadClass()"))) or\
        bool(list(analysis.find_methods(classname="Ljava/net/URLClassLoader;", methodname="loadClass()"))) or\
        bool(list(analysis.find_methods(classname="Ldalvik/system/DelegateLastClassLoader;", methodname="loadClass()"))) or\
        bool(list(analysis.find_methods(
            classname="Ldalvik/system/InMemoryDexClassLoader;", methodname="loadClass()")))

# com.example.start(){
#     com.library.start()
# }

def check_javascript(analysis: Analysis) -> JavascriptResult:
    return JavascriptResult(
        addJavascriptInterface=bool(list(analysis.find_methods(
            classname="Landroid.webkit.WebView;", methodname="addJavascriptInterface"))),
        setJavaScriptEnabled=bool(list(analysis.find_methods(
            classname="Landroid.webkit.WebSettings;", methodname="setJavaScriptEnabled"))),
        evaluateJavascript=bool(list(analysis.find_methods(
            classname="Landroid.webkit.WebView;", methodname="evaluateJavascript")))
    )


def check_reflection(analysis: Analysis) -> bool:
    return bool(list(analysis.find_classes("Ljava/lang/reflect/.*;"))) or \
        bool(list(analysis.find_classes("Lkotlin/reflect/.*;")))


def check_installed_packages(analysis: Analysis) -> bool:
    return bool(list(analysis.find_methods("Landroid/content/pm/PackageManager;", "getInstallSourceInfo"))) or \
        bool(list(analysis.find_methods("Landroid/content/pm/PackageManager;", "getInstalledApplications"))) or \
        bool(list(analysis.find_methods("Landroid/content/pm/PackageManager;", "getInstalledPackages"))) or \
        bool(list(analysis.find_methods("Landroid/content/pm/PackageManager;", "getPackageInfo"))) or \
        bool(list(analysis.find_methods("Landroid/content/pm/PackageManager;", "getApplicationInfo")))


def convertJARtoDEX(file):
    if file.endswith('.jar') and not file in blacklist:
        result = subprocess.call(
            ["./dex-tools/d2j-jar2dex.sh", file, "-o", file[:-4] + ".dex"])
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

                analysis_results: Tuple[_, _, Analysis] = AnalyzeDex(filename=root + "/" + file)
                a, b, analysis = analysis_results
                # for item in c.get_methods():
                #     print(item.full_name)

                result = analysis.find_methods(
                    classname="Landroid.webkit.WebSettings;", methodname="setJavaScriptEnabled")
               
                for item in result:
                    meth_list = []
                    for _, m, _ in item.get_xref_from():
                        meth_list.append(m.full_name)
                    writer_javascript.writerow({'id': splited_path[0] + "+" + splited_path[1], 'artifact_id': splited_path[0], 'group_id': splited_path[1],
                                                    "version": splited_path[2][:-4], 'signature': "Landroid.webkit.WebSettings;->setJavaScriptEnabled", 'method': meth_list})
                
                
                result = analysis.find_methods(
                                    classname="Landroid.webkit.WebView;", methodname="addJavascriptInterface")
            
                for item in result:
                    meth_list = []
                    for _, m, _ in item.get_xref_from():
                        meth_list.append(m.full_name)
                    writer_javascript.writerow({'id': splited_path[0] + "+" + splited_path[1], 'artifact_id': splited_path[0], 'group_id': splited_path[1],
                                    "version": splited_path[2][:-4], 'signature': "Landroid.webkit.WebView;->addJavascriptInterface", 'method': meth_list})
               
               
                result = analysis.find_methods(
                                    classname="Landroid.webkit.WebView;", methodname="evaluateJavascript")
             
                for item in result:
                    meth_list = []
                    for _, m, _ in item.get_xref_from():
                        meth_list.append(m.full_name)
                    writer_javascript.writerow({'id': splited_path[0] + "+" + splited_path[1], 'artifact_id': splited_path[0], 'group_id': splited_path[1],
                                    "version": splited_path[2][:-4], 'signature': "Landroid.webkit.WebView;->addJavascriptInterface", 'method': meth_list})
# Using API method <analysis.MethodAnalysis Landroid/bluetooth/BluetoothAdapter;->getProfileConnectionState(I)I> for permission ['android.permission.BLUETOOTH']
# used in:
# Lcom/journeyOS/i007Service/core/detect/HeadSetMonitor$HeadSetPlugBroadcastReceiver; onReceive (Landroid/content/Context; Landroid/content/Intent;)V
# Lcom/journeyOS/i007Service/core/detect/HeadSetMonitor; onStart ()V
                # dangerous permissions

                path = root + "/" + file
                path = path.replace("/", "+")
                splited_path = path.split("+")
                splited_path = splited_path[-3:]


                uses_classloader = check_classloader(analysis)
                javascript_result = check_javascript(analysis)
                uses_reflection = check_reflection(analysis)
                uses_pm = check_installed_packages(analysis)


                for meth, perm in analysis.get_permissions():
                    #print("Using API method {} for permission {}".format(meth, perm))
                    #print("used in:")
                    meth_list = []
                    for _, m, _ in meth.get_xref_from():
                        meth_list.append(m.full_name)
                       # print(f"{m.full_name}")
                    writer_permission.writerow({'id': splited_path[0] + "+" + splited_path[1], 'artifact_id': splited_path[0], 'group_id': splited_path[1],
                                    "version": splited_path[2][:-4], 'permission': perm, 'api': meth.full_name, 'method': meth_list})

                # # class loading
                # for item1 in c.find_methods(methodname="start()"):
                #     print(item1)

                # # package manager
                # for item2 in c.find_classes("Landroid/content/pm/PackageManager"):
                #     print(item2)

                # # javascript
                # for item3 in c.find_methods(methodname="evaluateJavascript()"):
                #     print(item3)


# analyzeDEXfiles()

def read_metadata_files():
    metadata_path_list = []
    for root, _, files in os.walk(metadata_path):
        for file in files:
            metadata_path_list.append(root+"/"+file)
    return metadata_path_list


metadata_paths = read_metadata_files()


def read_metadata_json(lib_path):
    file = open(lib_path, mode="r")
    data = json.loads(file.read())
    return LibMetadata(data)


def get_lib_paths(metadata_paths):
    lib_paths = []
    for item_metadata_path in metadata_paths:
        metadata = read_metadata_json(item_metadata_path)
        for item_repo in metadata.repos:
            for item_version in item_repo.versions:
                if(item_version.downloaded == True):
                    lib_paths.append(
                        metadata.id + "/" + item_version.version + "." + item_version.filetype)
    return lib_paths



lib_paths = get_lib_paths(metadata_paths)

dex_paths = []
for item_lib_path in lib_paths:
    file_exists2 = os.path.isfile(
        item_lib_path[:-4] + ".aar") or os.path.isfile(item_lib_path[:-4] + ".jar")
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
        os.rename(item_lib_path[:-4] + "-copy.aar",
                  item_lib_path[:-4] + ".zip")
        with ZipFile(item_lib_path[:-4] + ".zip", 'r') as zipObj:
            listOfiles = zipObj.namelist()
            for element in listOfiles:
                if element == "classes.jar":
                    zipObj.extract(element, "./")
                    os.rename("./classes.jar", item_lib_path[:-4] + ".jar")
                    dex_path = convertJARtoDEX(item_lib_path[:-4] + ".jar")
                    dex_paths.append(dex_path)
    elif item_lib_path[-3:] == "jar":
        dex_path = convertJARtoDEX(item_lib_path)
        dex_paths.append(dex_path)


analyzeDEXfiles()

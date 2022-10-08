import os
import subprocess
from typing import Any, List, Tuple
from zipfile import ZipFile
import shutil
from androguard.misc import AnalyzeDex
from androguard.core.analysis.analysis import Analysis
import os.path
import json
from libmetadata import LibMetadata
from analysis_tools import AnalysisWriter, JavascriptResult, MethodSignature

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

lib_path = "libs"
dex_path = "./dex_files"
blacklist_file_path = "./blacklist.txt"
metadata_path = "metadata"


writer_permission = AnalysisWriter(['id', 'artifact_id', 'group_id', 'version', 'permission', 'api', 'method'],
                                   "permission.csv")
writer_classloader = AnalysisWriter(['id', 'artifact_id', 'group_id', 'version', 'signature', 'method'],
                                    "classloader.csv")
writer_javascript = AnalysisWriter(['id', 'artifact_id', 'group_id', 'version', 'signature', 'method'],
                                   "javascript.csv")
writer_reflection = AnalysisWriter(['id', 'artifact_id', 'group_id', 'version', 'signature', 'method'],
                                   "reflection.csv")
writer_inspackages = AnalysisWriter(['id', 'artifact_id', 'group_id', 'version', 'signature', 'method'],
                                    "installed_packages.csv")


file_blacklist = open(blacklist_file_path, mode='a+')
file_blacklist.seek(0, 0)

blacklist = file_blacklist.readlines()
blacklist = [s.strip() for s in blacklist]


def check_classloader(analysis: Analysis) -> bool:
    return bool(list(analysis.find_methods("Ldalvik/system/DexClassLoader;", "loadClass()"))) or\
        bool(list(analysis.find_methods("Ldalvik/system/PathClassLoader;", "loadClass()"))) or\
        bool(list(analysis.find_methods("Ljava/net/URLClassLoader;", "loadClass()"))) or\
        bool(list(analysis.find_methods("Ldalvik/system/DelegateLastClassLoader;", "loadClass()"))) or\
        bool(list(analysis.find_methods(
            "Ldalvik/system/InMemoryDexClassLoader;", "loadClass()")))


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
        bool(list(analysis.find_methods(
            "Landroid/content/pm/PackageManager;", "getApplicationInfo")))


def convertJARtoDEX(file):
    if file.endswith('.jar') and not file in blacklist:
        result = subprocess.call(
            ["./dex-tools/d2j-jar2dex.sh", file, "-o", file[:-4] + ".dex"])
        file_exists = os.path.isfile(file[:-4] + ".dex")
        if file_exists == False:
            file_blacklist.write(file + "\n")
            file_blacklist.flush()
    return file[:-4] + ".dex"


def check_signature(analysis: Analysis, signature: MethodSignature, splitted_path: List[str], writer: AnalysisWriter) -> None:
    result = analysis.find_methods(
        classname=signature.classname, methodname=signature.methodname)

    for item in result:
        meth_list = []
        for _, m, _ in item.get_xref_from():
            meth_list.append(m.full_name)

        writer.write_signature(splitted_path, signature, meth_list)


def check_permissions(analysis: Analysis, splitted_path: List[str]) -> None:
    for meth, perm in analysis.get_permissions():
        meth_list = []
        for _, m, _ in meth.get_xref_from():
            meth_list.append(m.full_name)

        writer_permission.write_permission(splitted_path, perm, meth, meth_list)


def analyzeDEXfiles():
    for root, directories, files in os.walk(lib_path):
        for file in files:
            if file.endswith('.dex'):
                path = root + "/" + file
                path = path.replace("/", "+")
                splitted_path = path.split("+")
                splitted_path = splitted_path[-3:]

                analysis_results: Tuple[Any, Any, Analysis] = AnalyzeDex(
                    filename=root + "/" + file)
                a, b, analysis = analysis_results

                # Javascript
                signature_jsenabled = MethodSignature(
                    "Landroid.webkit.WebSettings;", "setJavaScriptEnabled")
                signature_jsinterface = MethodSignature(
                    "Landroid.webkit.WebView;", "addJavascriptInterface")
                signature_jseval = MethodSignature(
                    "Landroid.webkit.WebView;", "evaluateJavascript"
                )

                check_signature(analysis, signature_jsenabled,
                                splitted_path, writer_javascript)
                check_signature(analysis, signature_jsinterface,
                                splitted_path, writer_javascript)
                check_signature(analysis, signature_jseval,
                                splitted_path, writer_javascript)

                # Class loader
                sign_cloader1 = MethodSignature("Ldalvik/system/DexClassLoader;", "loadClass()")
                sign_cloader2 = MethodSignature("Ldalvik/system/PathClassLoader;", "loadClass()")
                sign_cloader3 = MethodSignature("Ljava/net/URLClassLoader;", "loadClass()")
                sign_cloader4 = MethodSignature("Ldalvik/system/DelegateLastClassLoader;", "loadClass()")
                sign_cloader5 = MethodSignature("Ldalvik/system/InMemoryDexClassLoader;", "loadClass()")

                check_signature(analysis, sign_cloader1, splitted_path, writer_classloader)
                check_signature(analysis, sign_cloader2, splitted_path, writer_classloader)
                check_signature(analysis, sign_cloader3, splitted_path, writer_classloader)
                check_signature(analysis, sign_cloader4, splitted_path, writer_classloader)
                check_signature(analysis, sign_cloader5, splitted_path, writer_classloader)

                # Reflection
                sign_ref1 = MethodSignature("Ljava/lang/reflect/", "")
                sign_ref2 = MethodSignature("Lkotlin/reflect/", "")

                check_signature(analysis, sign_ref1, splitted_path, writer_reflection)
                check_signature(analysis, sign_ref2, splitted_path, writer_reflection)
                
                # Installed packages
                sign_insp1 = MethodSignature("Landroid/content/pm/PackageManager;", "getInstallSourceInfo")
                sign_insp2 = MethodSignature("Landroid/content/pm/PackageManager;", "getInstalledApplications")
                sign_insp3 = MethodSignature("Landroid/content/pm/PackageManager;", "getInstalledPackages")
                sign_insp4 = MethodSignature("Landroid/content/pm/PackageManager;", "getPackageInfo")
                sign_insp5 = MethodSignature("Landroid/content/pm/PackageManager;", "getApplicationInfo")

                check_signature(analysis, sign_insp1, splitted_path, writer_inspackages)
                check_signature(analysis, sign_insp2, splitted_path, writer_inspackages)
                check_signature(analysis, sign_insp3, splitted_path, writer_inspackages)
                check_signature(analysis, sign_insp4, splitted_path, writer_inspackages)
                check_signature(analysis, sign_insp5, splitted_path, writer_inspackages)

                # dangerous permissions
                check_permissions(analysis, splitted_path)

                # Genel sonuçlar (şimdilik kullanılmadı)
                uses_classloader = check_classloader(analysis)
                javascript_result = check_javascript(analysis)
                uses_reflection = check_reflection(analysis)
                uses_pm = check_installed_packages(analysis)


def get_metadata_paths() -> List[str]:
    metadata_path_list: List[str] = []
    for root, _, files in os.walk(metadata_path):
        for file in files:
            metadata_path_list.append(root+"/"+file)

    return metadata_path_list


def read_metadata_json(lib_path: str) -> LibMetadata:
    with open(lib_path, mode="r") as file:
        data = json.loads(file.read())
        return LibMetadata(data)


def get_lib_paths(metadata_paths: List[str]) -> List[str]:
    lib_paths: List[str] = []
    for item_metadata_path in metadata_paths:
        metadata = read_metadata_json(item_metadata_path)

        for item_repo in metadata.repos:
            for item_version in item_repo.versions:
                if item_version.downloaded:
                    lib_paths.append(
                        metadata.id + "/" + item_version.version + "." + item_version.filetype)

    return lib_paths


metadata_paths = get_metadata_paths()
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
    try:
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
    except:
        file_blacklist.write(item_lib_path[:-4] + ".jar\n")
        file_blacklist.flush()


analyzeDEXfiles()

writer_classloader.close()
writer_inspackages.close()
writer_javascript.close()
writer_permission.close()
writer_reflection.close()
file_blacklist.close()

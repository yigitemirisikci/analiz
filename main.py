import os
import subprocess
from androguard.misc import AnalyzeDex
from zipfile import ZipFile
from tinydb import table, TinyDB, Query
from tinydb.database import Document, Table
import shutil

lib_path = "C:/Users/Yigit/Desktop/LIB ANALYSES/androguard/analiz/"

for root, dir, files in os.walk(lib_path):
    for file in files:
        pre, ext = os.path.splitext(file)

        if(ext == ".aar"):
            shutil.copyfile(root+"/"+file, root)
            #os.rename(root + "/" + file, root + "/" + pre + ".zip")


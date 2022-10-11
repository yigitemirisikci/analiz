from csv import DictWriter
from dataclasses import dataclass
import os
from typing import Any, List, Mapping, Set


@dataclass
class JavascriptResult:
    addJavascriptInterface: bool
    setJavaScriptEnabled: bool
    evaluateJavascript: bool


@dataclass(frozen=True)
class MethodSignature:
    classname: str
    methodname: str


class AnalysisWriter:
    def __init__(self, headers: List[str], path: str) -> None:
        file_exists = os.path.isfile(path)
        self.path = path
        self.headers = headers

        if not file_exists:
            with open(self.path, "w") as file:
                DictWriter(file, delimiter=",", lineterminator="\n",
                           fieldnames=headers).writeheader()

    def writerow(self, rowdict: Mapping[str, Any]) -> None:
        with open(self.path, 'a') as file:
            writer = DictWriter(file, delimiter=",",
                                lineterminator="\n", fieldnames=self.headers)
            writer.writerow(rowdict)

    def write_signature(self, splitted_path: List[str], signature: MethodSignature, meth_list: List[str]) -> None:
        self.writerow({'id': splitted_path[0] + "+" + splitted_path[1], 'artifact_id': splitted_path[0], 'group_id': splitted_path[1],
                       "version": splitted_path[2][:-4], 'signature': f"{signature.classname}->{signature.methodname}", 'method': meth_list})

    def write_permission(self, splitted_path: List[str], perm, meth, meth_list) -> None:
        self.writerow({'id': splitted_path[0] + "+" + splitted_path[1], 'artifact_id': splitted_path[0], 'group_id': splitted_path[1],
                       "version": splitted_path[2][:-4], 'permission': perm, 'api': meth.full_name, 'method': meth_list})


class Blacklist:
    def __init__(self, path: str = None) -> None:
        if path == None:
            path = "./blacklist.txt"

        self.path = path

        self.blacklisted: Set[str] = set()
        with open(path, "r") as file:
            for line in file:
                self.blacklisted.add(line.strip())

    def write_all(self) -> None:
        with open(self.path, "w") as file:
            for item in self.blacklisted:
                file.write(item + "\n")

    def add(self, item: str) -> None:
        self.blacklisted.add(item)
        self.write_all()

    def contains(self, item: str) -> bool:
        return item in self.blacklisted

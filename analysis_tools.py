from csv import DictWriter
from dataclasses import dataclass
import os
from typing import Any, List, Mapping


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
    def __init__(self, headers: List[str], output: str) -> None:
        file_exists = os.path.isfile(output)
        self.file = open(output, mode='a+')
        self.file.seek(0, 0)
        self.writer = DictWriter(self.file, delimiter=',',
                                 lineterminator='\n', fieldnames=headers)
        if not file_exists:
            self.writer.writeheader()

    def close(self) -> None:
        self.file.close()

    def writerow(self, rowdict: Mapping[str, Any]) -> Any:
        return self.writer.writerow(rowdict)

    def write_signature(self, splitted_path: List[str], signature: MethodSignature, meth_list: List[str]) -> Any:
        return self.writerow({'id': splitted_path[0] + "+" + splitted_path[1], 'artifact_id': splitted_path[0], 'group_id': splitted_path[1],
                              "version": splitted_path[2][:-4], 'signature': f"{signature.classname}->{signature.methodname}", 'method': meth_list})

    def write_permission(self, splitted_path: List[str], perm, meth, meth_list) -> Any:
        return self.writerow({'id': splitted_path[0] + "+" + splitted_path[1], 'artifact_id': splitted_path[0], 'group_id': splitted_path[1],
                                    "version": splitted_path[2][:-4], 'permission': perm, 'api': meth.full_name, 'method': meth_list})

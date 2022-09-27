from dataclasses import dataclass


@dataclass
class JavascriptResult:
    addJavascriptInterface: bool
    setJavaScriptEnabled: bool
    evaluateJavascript: bool
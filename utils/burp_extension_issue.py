import json
from typing import Any

from burp import (  # pyright: ignore[reportMissingImports]
    IBurpExtender,
    IBurpExtenderCallbacks,
    IHttpListener,
    IHttpRequestResponse,
    IScanIssue,
)


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks: IBurpExtenderCallbacks) -> None:
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Issue Creator")
        callbacks.registerHttpListener(self)
        print("Issue Creator Extension active")

    def processHttpMessage(
        self, toolFlag: int, messageIsRequest: bool, messageInfo: IHttpRequestResponse
    ) -> None:
        if not messageIsRequest:
            return

        request = messageInfo.getRequest()
        requestInfo = self._helpers.analyzeRequest(request)
        headers = requestInfo.getHeaders()

        for header in headers:
            if "X-Create-Burp-Issue:" in header:
                try:
                    issue_data = header.split("X-Create-Burp-Issue:")[1].strip()
                    data = json.loads(issue_data)

                    self.createCustomIssue(
                        messageInfo,
                        data.get("title", "Unknown Issue"),
                        data.get("description", "No description"),
                        data.get("severity", "Medium"),
                    )
                    print("Issue created: " + data.get("title"))
                except Exception as e:
                    print("Error creating issue: " + str(e))

    def createCustomIssue(
        self,
        messageInfo: IHttpRequestResponse,
        title: str,
        description: str,
        severity: str,
    ) -> None:
        issue = CustomIssue(messageInfo, title, description, severity)
        self._callbacks.addScanIssue(issue)


class CustomIssue(IScanIssue):
    def __init__(
        self,
        messageInfo: IHttpRequestResponse,
        title: str,
        description: str,
        severity: str,
    ) -> None:
        self._messageInfo = messageInfo
        self._title = title
        self._description = description
        self._severity = severity

    def getUrl(self) -> Any:
        # Returns java.net.URL object - cannot be typed precisely in Python
        return self._messageInfo.getUrl()

    def getIssueName(self) -> str:
        return self._title

    def getIssueType(self) -> int:
        if self._severity.lower() in ["low", "medium"]:
            return 0x08000001
        else:
            return 0x08000002

    def getIssueDetail(self) -> str:
        return self._description

    def getIssueBackground(self) -> str:
        return "Issue created automatically via extension."

    def getRemediationBackground(self) -> str:
        return "Review and fix the identified vulnerability."

    def getRemediationDetail(self) -> str:
        return "Analyze and correct the security issue."

    def getSeverity(self) -> str:
        return self._severity

    def getConfidence(self) -> str:
        return "Certain"

    def getHttpMessages(self) -> list[IHttpRequestResponse]:
        return [self._messageInfo]

    def getHttpService(self) -> Any:
        # Returns IHttpService object - Java interface
        return self._messageInfo.getHttpService()

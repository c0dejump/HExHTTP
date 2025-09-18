from burp import IBurpExtender, IHttpListener, IScanIssue
from java.net import URL
import json

class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Issue Creator")
        callbacks.registerHttpListener(self)
        print("Issue Creator Extension active")
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
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
                        data.get("severity", "Medium")
                    )
                    print("Issue created: " + data.get('title'))
                except Exception as e:
                    print("Error creating issue: " + str(e))
    
    def createCustomIssue(self, messageInfo, title, description, severity):
        issue = CustomIssue(messageInfo, title, description, severity)
        self._callbacks.addScanIssue(issue)

class CustomIssue(IScanIssue):
    def __init__(self, messageInfo, title, description, severity):
        self._messageInfo = messageInfo
        self._title = title
        self._description = description
        self._severity = severity
    
    def getUrl(self):
        return self._messageInfo.getUrl()
    
    def getIssueName(self):
        return self._title
    
    def getIssueType(self):
        if self._severity.lower() in ["low", "medium"]:
            return 0x08000001
        else:
            return 0x08000002
    
    def getIssueDetail(self):
        return self._description
    
    def getIssueBackground(self):
        return "Issue created automatically via extension."
    
    def getRemediationBackground(self):
        return "Review and fix the identified vulnerability."
    
    def getRemediationDetail(self):
        return "Analyze and correct the security issue."
    
    def getSeverity(self):
        return self._severity
    
    def getConfidence(self):
        return "Certain"
    
    def getHttpMessages(self):
        return [self._messageInfo]
    
    def getHttpService(self):
        return self._messageInfo.getHttpService()
import platform

if platform.system() == 'Darwin':  # 'Darwin' OS for Macos
    from pync import Notifier as Notify
else:
    from notifypy import Notify

def vuln_found_notify(url, payload):
    """
    notify_scan_completed: Send a notification when the scan is finished
    """
    notification = Notify()
    notification.title = "HExHTTP"
    notification.message = "VULNERABILITY FOUND\nURL: {}\nPAYLOAD: {}".format(url, payload)
    #notification.send()

if __name__ == '__main__':
    vuln_found_notify()
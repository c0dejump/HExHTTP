#!/usr/bin/env python3

from utils.style import Colors


def potential_verbose_message(message: str, url: str = "default") -> None:
    verbose = False
    if verbose:
        if message == "ERROR":
            print(f"[VERBOSE] Request Error for {url}")
        elif message == "CANARY":
            print(
                f"[VERBOSE] CANARY reflection in {url}. Confirming cache poisoning in progress ..."
            )
        elif message == "STATUS_CODE":
            print(
                f"[VERBOSE] STATUS_CODE difference in {url}. Confirming cache poisoning in progress ..."
            )
        elif message == "LENGTH":
            print(
                f"[VERBOSE] LENGTH difference in {url}. Confirming cache poisoning in progress ..."
            )
        elif message == "UNSUCCESSFUL":
            print(f"[VERBOSE] Unsuccessful vulnerability confirmation on {url}\n")
        elif message == "CRAWLING":
            print(f"[VERBOSE] Crawling. Scanning : {url}")


def behavior_or_confirmed_message(
    uri: str,
    behaviorOrConfirmed: str,
    behaviorType: str,
    explicitCache: str,
    status_codes: str = "default",
    header: str = "default",
) -> None:

    explicitCache = (
        f"{Colors.RED}{explicitCache}{Colors.RESET}"
        if explicitCache == "FALSE"
        else f"{Colors.GREEN}{explicitCache}{Colors.RESET}"
    )

    messageDict = {
        "REFLECTION": "HEADER REFLECTION",
        "STATUS": f"DIFFERENT STATUS-CODE: {status_codes}",
        "LENGTH": "DIFFERENT RESPONSE LENGTH",
        "BEHAVIOR": f"{Colors.YELLOW}INTERESTING BEHAVIOR{Colors.RESET}",
        "CONFIRMED": f"{Colors.RED}VULNERABILITY CONFIRMED{Colors.RESET}",
    }

    if header != "default":
        message = f" └──   {messageDict[behaviorOrConfirmed]}   | {messageDict[behaviorType]} | CACHETAG : {explicitCache} | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD : {Colors.THISTLE}{header}{Colors.RESET}"
    else:
        message = f" └──   {messageDict[behaviorOrConfirmed]}   | PORT {messageDict[behaviorType]} | CACHETAG : {explicitCache} | {Colors.BLUE}{uri}{Colors.RESET} | PAYLOAD : {Colors.THISTLE}{header}{Colors.RESET}"
    print(message)

#!/usr/bin/python3

"""
This module provides functionality to load payloads from files into lists.
"""


from modules.lists.all_payload_keys import all_payload_keys
from modules.lists.payloads_errors import payloads_keys

__all__ = [
    "load_payloads_from",
    "user_agents_list",
    "payloads_keys",
    "all_payload_keys",
    "wcp_headers",
]

header_list = []
user_agents_list = []
paraminer_list = []


def load_payloads_from(file_path: str) -> list[str]:
    """
    Load payloads from a file into a list.

    :param file_path: Path to the file containing payloads.
    :return: A list of payloads.
    """
    results: list[str] = []
    try:
        with open(file_path, encoding="utf-8") as f:
            results = [line for line in f.read().split("\n") if line]
    except FileNotFoundError:
        print(f"The file '{file_path}' was not found.")
    return results


user_agents_list = load_payloads_from("./modules/lists/user-agent.lst")
wcp_headers = load_payloads_from("./modules/lists/wcp_headers.lst")

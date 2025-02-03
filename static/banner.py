#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Prints a colorful ASCII art banner along with a brief description of the HExHTTP tool.
"""

try:
    from _version import __version__
except ImportError:
    __version__ = "v1.7.4"



def print_banner() -> None:
    """
    The banner is displayed using ANSI escape codes for colors and formatting.
    The description includes the tool's name and version.

    Returns:
        None
    """
    banner_text = """\033[0m                                                                                                                               \033[m
\033[0m                                                             \033[38;5;78;48;5;78m▄\033[38;5;35;48;5;36m▄\033[0m\033[38;5;23;48;5;235m▄\033[38;5;29;48;5;235m▄\033[38;5;35;48;5;235m▄\033[38;5;235;48;5;235m▄\033[0m                                                          \033[m
\033[0m                                                           \033[38;5;78;48;5;235m▄\033[48;5;78m \033[38;5;78;48;5;23m▄\033[0m\033[38;5;23;48;5;235m▄\033[38;5;29;48;5;235m▄\033[38;5;235;48;5;238m▄\033[0m\033[38;5;235;48;5;237m▄\033[0m                                                          \033[m
\033[0m         \033[38;5;29;48;5;235m▄\033[38;5;236;48;5;235m▄\033[38;5;23;48;5;235m▄\033[38;5;29;48;5;235m▄\033[38;5;236;48;5;235m▄\033[38;5;29;48;5;235m▄\033[0m       \033[38;5;29;48;5;235m▄\033[0m\033[38;5;29;48;5;235m▄\033[0m\033[38;5;29;48;5;235m▄\033[0m\033[38;5;29;48;5;235m▄\033[0m \033[38;5;29;48;5;235m▄\033[0m\033[38;5;29;48;5;235m▄\033[0m\033[38;5;29;48;5;235m▄\033[0m\033[38;5;29;48;5;235m▄▄▄▄▄▄▄▄▄▄\033[0m         \033[38;5;42;48;5;235m▄\033[38;5;238;48;5;78m▄\033[38;5;235;48;5;78m▄▄\033[38;5;29;48;5;235m▄\033[0m\033[38;5;235;48;5;235m▄\033[38;5;78;48;5;235m▄▄\033[38;5;78;48;5;29m▄\033[38;5;35;48;5;29m▄\033[38;5;36;48;5;235m▄\033[38;5;29;48;5;235m▄\033[0m     \033[38;5;36;48;5;235m▄▄\033[38;5;237;48;5;235m▄\033[0m\033[38;5;36;48;5;235m▄\033[0m\033[38;5;36;48;5;235m▄▄▄▄▄▄▄▄▄▄\033[0m\033[38;5;36;48;5;235m▄▄▄▄▄▄▄▄▄▄\033[0m\033[38;5;35;48;5;235m▄\033[38;5;36;48;5;235m▄▄▄▄▄▄▄▄\033[38;5;35;48;5;235m▄\033[38;5;23;48;5;235m▄\033[0m          \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[0m       \033[48;5;42m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[38;5;78;48;5;29m▄\033[38;5;78;48;5;235m▄▄▄▄▄▄▄▄▄\033[0m         \033[38;5;29;48;5;235m▄\033[0m  \033[38;5;78;48;5;29m▄\033[38;5;78;48;5;235m▄\033[0m \033[48;5;29m \033[0m\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[0m     \033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m\033[38;5;78;48;5;235m▄▄▄▄▄▄▄▄▄▄\033[0m\033[38;5;78;48;5;235m▄▄▄▄▄▄▄▄▄▄\033[0m\033[48;5;36m \033[38;5;235;48;5;235m▄\033[38;5;78;48;5;235m▄▄▄▄▄▄▄▄▄\033[38;5;235;48;5;78m▄\033[38;5;78;48;5;236m▄\033[38;5;235;48;5;235m▄\033[0m       \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[0m       \033[48;5;42m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[38;5;29;48;5;29m▄\033[38;5;237;48;5;238m▄▄▄▄▄▄▄▄▄\033[0m     \033[38;5;78;48;5;235m▄▄▄▄▄\033[38;5;29;48;5;238m▄\033[0m\033[48;5;78m \033[38;5;78;48;5;78m\033[48;5;78m  \033[0m\033[38;5;35;48;5;78m▄\033[38;5;29;48;5;78m▄\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[0m     \033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m\033[38;5;235;48;5;29m▄▄▄▄\033[38;5;36;48;5;29m▄\033[38;5;78;48;5;29m▄\033[38;5;238;48;5;29m▄\033[38;5;235;48;5;29m▄▄▄\033[0m\033[38;5;235;48;5;29m▄▄▄\033[38;5;237;48;5;29m▄\033[38;5;78;48;5;29m▄▄\033[38;5;235;48;5;29m▄▄▄▄\033[0m\033[48;5;36m \033[0m\033[48;5;236m \033[38;5;78;48;5;29m▄\033[38;5;235;48;5;29m▄▄▄▄▄\033[38;5;235;48;5;23m▄\033[38;5;78;48;5;235m▄\033[38;5;235;48;5;78m▄\033[38;5;78;48;5;235m▄\033[38;5;235;48;5;78m▄\033[38;5;238;48;5;235m▄\033[0m      \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[0m       \033[48;5;42m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;29m \033[0m            \033[38;5;35;48;5;235m▄\033[48;5;78m \033[38;5;235;48;5;78m▄▄\033[48;5;78m \033[38;5;78;48;5;78m▄\033[38;5;235;48;5;78m▄▄\033[38;5;78;48;5;29m▄\033[0m\033[38;5;235;48;5;78m▄▄\033[0m \033[48;5;29m \033[0m\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[0m     \033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m    \033[48;5;36m \033[48;5;78m \033[48;5;238m \033[0m      \033[48;5;237m \033[48;5;78m  \033[0m    \033[48;5;36m \033[0m\033[48;5;236m \033[48;5;78m  \033[38;5;235;48;5;78m▄▄▄▄▄\033[38;5;78;48;5;236m▄\033[38;5;23;48;5;78m▄\033[38;5;235;48;5;236m▄\033[38;5;23;48;5;235m▄\033[48;5;78m \033[0m      \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[38;5;235;48;5;36m▄▄▄▄▄▄▄\033[38;5;42;48;5;78m▄\033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[38;5;29;48;5;78m▄\033[38;5;235;48;5;36m▄▄▄▄\033[38;5;235;48;5;23m▄\033[0m       \033[48;5;78m  \033[38;5;78;48;5;235m▄\033[38;5;78;48;5;23m▄\033[38;5;235;48;5;36m▄\033[38;5;29;48;5;78m▄\033[38;5;78;48;5;235m▄\033[38;5;78;48;5;42m▄\033[48;5;78m \033[0m   \033[48;5;29m \033[0m\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[38;5;235;48;5;36m▄▄▄▄▄\033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m    \033[48;5;36m \033[48;5;78m \033[48;5;238m \033[0m      \033[48;5;237m \033[48;5;78m  \033[0m    \033[48;5;36m \033[0m\033[48;5;236m \033[48;5;78m  \033[38;5;29;48;5;235m▄\033[38;5;78;48;5;235m▄▄▄▄\033[38;5;23;48;5;78m▄\033[38;5;78;48;5;23m▄\033[38;5;236;48;5;235m▄\033[38;5;236;48;5;23m▄\033[48;5;78m \033[0m      \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[38;5;23;48;5;78m▄▄▄▄▄▄▄\033[38;5;78;48;5;78m▄\033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[38;5;35;48;5;78m▄\033[38;5;23;48;5;78m▄▄▄▄\033[38;5;237;48;5;23m▄\033[0m      \033[38;5;78;48;5;235m▄\033[38;5;36;48;5;235m▄\033[38;5;235;48;5;36m▄\033[48;5;78m     \033[38;5;29;48;5;78m▄\033[38;5;235;48;5;23m▄\033[38;5;78;48;5;235m▄\033[38;5;235;48;5;235m▄\033[0m \033[48;5;29m \033[0m\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[38;5;29;48;5;78m▄▄▄▄▄\033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m    \033[48;5;36m \033[48;5;78m \033[48;5;238m \033[0m      \033[48;5;237m \033[48;5;78m  \033[0m    \033[48;5;36m \033[0m\033[48;5;236m \033[48;5;78m  \033[38;5;29;48;5;235m▄\033[38;5;36;48;5;235m▄▄▄▄\033[38;5;235;48;5;35m▄\033[38;5;35;48;5;23m▄\033[38;5;236;48;5;78m▄\033[38;5;78;48;5;235m▄\033[38;5;235;48;5;23m▄\033[0m      \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[38;5;235;48;5;235m▄▄▄▄▄▄▄\033[38;5;42;48;5;42m▄\033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[38;5;29;48;5;29m▄\033[38;5;235;48;5;235m▄▄▄▄▄\033[0m     \033[38;5;78;48;5;235m▄\033[48;5;78m  \033[38;5;78;48;5;235m▄\033[38;5;23;48;5;78m▄\033[38;5;235;48;5;78m▄▄▄▄\033[38;5;42;48;5;235m▄\033[38;5;78;48;5;236m▄\033[48;5;78m \033[38;5;78;48;5;36m▄\033[38;5;235;48;5;235m▄\033[0m\033[48;5;29m \033[0m\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[0m     \033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m    \033[48;5;36m \033[48;5;78m \033[48;5;238m \033[0m      \033[48;5;237m \033[48;5;78m  \033[0m    \033[48;5;36m \033[0m\033[48;5;236m \033[48;5;78m  \033[38;5;235;48;5;29m▄\033[38;5;235;48;5;78m▄▄▄▄▄\033[38;5;78;48;5;237m▄\033[38;5;29;48;5;29m▄\033[38;5;235;48;5;23m▄\033[0m       \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[0m       \033[48;5;42m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[38;5;42;48;5;29m▄\033[38;5;36;48;5;235m▄▄▄▄▄▄▄▄▄\033[0m \033[38;5;235;48;5;35m▄\033[38;5;235;48;5;78m▄\033[0m\033[38;5;235;48;5;36m▄\033[38;5;23;48;5;78m▄\033[48;5;78m \033[38;5;78;48;5;35m▄\033[48;5;78m  \033[38;5;235;48;5;78m▄\033[38;5;235;48;5;237m▄\033[38;5;235;48;5;23m▄\033[38;5;235;48;5;78m▄\033[0m  \033[48;5;29m \033[0m\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[0m     \033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m    \033[48;5;36m \033[48;5;78m \033[48;5;238m \033[0m      \033[48;5;237m \033[48;5;78m  \033[0m    \033[48;5;36m \033[0m\033[48;5;236m \033[48;5;78m  \033[38;5;235;48;5;29m▄\033[38;5;235;48;5;78m▄▄▄▄\033[38;5;235;48;5;29m▄\033[0m          \033[m
\033[0m         \033[48;5;78m \033[48;5;237m \033[48;5;35m \033[48;5;36m \033[48;5;237m \033[48;5;78m \033[0m       \033[48;5;42m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m \033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[48;5;78m \033[0m\033[38;5;78;48;5;29m▄\033[38;5;78;48;5;235m▄▄▄▄▄▄▄▄▄\033[0m \033[38;5;23;48;5;78m▄\033[48;5;78m \033[38;5;78;48;5;78m▄\033[38;5;237;48;5;78m▄\033[38;5;235;48;5;78m▄\033[38;5;235;48;5;35m▄\033[0m \033[38;5;235;48;5;78m▄▄\033[38;5;78;48;5;78m▄\033[48;5;78m  \033[38;5;235;48;5;235m▄\033[0m \033[48;5;29m \033[0m\033[48;5;23m \033[48;5;78m \033[48;5;35m \033[0m     \033[48;5;78m  \033[48;5;237m \033[0m\033[48;5;78m \033[0m    \033[48;5;36m \033[48;5;78m \033[48;5;238m \033[0m      \033[48;5;237m \033[48;5;78m  \033[0m    \033[48;5;36m \033[0m\033[48;5;236m \033[48;5;78m  \033[0m                \033[m
\033[0m         \033[38;5;235;48;5;78m▄\033[38;5;235;48;5;237m▄\033[38;5;235;48;5;35m▄\033[38;5;235;48;5;36m▄\033[38;5;235;48;5;237m▄\033[38;5;235;48;5;78m▄\033[0m       \033[38;5;235;48;5;42m▄\033[0m\033[38;5;235;48;5;78m▄\033[0m\033[38;5;235;48;5;78m▄\033[0m\033[38;5;235;48;5;78m▄\033[0m \033[38;5;235;48;5;78m▄\033[0m\033[38;5;235;48;5;78m▄\033[0m\033[38;5;235;48;5;78m▄\033[0m\033[38;5;235;48;5;35m▄\033[38;5;235;48;5;29m▄▄▄▄▄▄▄▄▄\033[0m  \033[38;5;235;48;5;78m▄▄\033[0m      \033[38;5;235;48;5;237m▄\033[38;5;235;48;5;78m▄\033[38;5;235;48;5;42m▄\033[0m  \033[38;5;235;48;5;29m▄\033[0m\033[38;5;235;48;5;23m▄\033[38;5;235;48;5;78m▄\033[38;5;235;48;5;35m▄\033[0m     \033[38;5;235;48;5;78m▄▄\033[38;5;235;48;5;237m▄\033[0m\033[38;5;235;48;5;78m▄\033[0m    \033[38;5;235;48;5;36m▄\033[38;5;235;48;5;78m▄\033[38;5;235;48;5;238m▄\033[0m      \033[38;5;235;48;5;237m▄\033[38;5;235;48;5;78m▄▄\033[0m    \033[38;5;235;48;5;36m▄\033[38;5;235;48;5;235m▄\033[38;5;235;48;5;78m▄▄\033[0m                \033[m
\033[0m"""
    print(f"{banner_text}")
    print(
        f"HExHTTP({__version__}) is a tool designed to perform tests on HTTP headers."
    )


if __name__ == "__main__":
    print_banner()

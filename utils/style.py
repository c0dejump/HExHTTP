class Colors:
    """Colors constants for the output messages"""

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    SALMON = "\033[38;2;255;174;157m"
    THISTLE = "\033[38;2;197;197;169m"
    REDIR = "\033[38;2;245;203;92m"
    RESET = "\033[0m"


class Identify:
    behavior = f"{Colors.YELLOW}└──   INTERESTING BEHAVIOR  {Colors.RESET}"
    confirmed = f"{Colors.RED}└── VULNERABILITY CONFIRMED {Colors.RESET}"

class Colors:
    """Colors constants for the output messages"""
    RED = "\033[31m"
    YELLOW = "\033[33m"
    GREEN = "\033[32m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    MAGENTA = "\033[35m"
    SALMON = "\033[38;2;255;174;157m"
    THISTLE = "\033[38;2;197;197;169m"
    REDIR = "\033[38;2;245;203;92m"
    RESET = "\033[0m"

class Identify:
    behavior =  "\033[33m└──   INTERESTING BEHAVIOR  \033[0m"
    confirmed = "\033[31m└── VULNERABILITY CONFIRMED \033[0m"
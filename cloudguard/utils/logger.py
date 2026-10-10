import os
import re
from datetime import datetime
from cloudguard.constants import LOGGER_PATH
from cloudguard.findings import COLORS

ANSI_ESCAPE = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def write_log(message: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    os.makedirs(LOGGER_PATH, exist_ok=True)
    log_file_path = os.path.join(LOGGER_PATH, "cloudguard.log")

    with open(log_file_path, "a", encoding="utf-8") as f:
        f.write(f"[{timestamp}] {message.strip()}\n")


def feeder(message: object, plain_text_log: str = "") -> None:
    """Prints colorized output to console while recording clean, unformatted text to log files."""
    text_to_print = str(message)
    print(text_to_print)

    if plain_text_log:
        write_log(plain_text_log)
    else:
        clean_text = ANSI_ESCAPE.sub('', text_to_print)
        write_log(clean_text)
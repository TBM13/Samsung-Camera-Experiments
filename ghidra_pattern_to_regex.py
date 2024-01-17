import re
import sys

print(
    re.sub(
        r'([^\.\n][^\.\n])', r'\\x\1', re.sub(r'\[.+?\]', '.', sys.argv[1]).replace(' ', '')
    )
)
import re

# A document name followed by an image / executable extension ('invoice.pdf.png'). Standard document
# extensions only: misspellings seen in the corpus file names are not hard-coded (honest metrics, BACKLOG A1).
DOUBLE_EXT_PATTERN = re.compile(
    r'(?i)\.(?:pdf|xlsx?|docx?|pptx?|txt|rtf|csv)\s*\.(?:png|jpe?g|gif|html?|shtml|svg|exe|scr|js|zip|iso|img)$'
)

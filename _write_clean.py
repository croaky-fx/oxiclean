
import os
path = "src/clean.rs"
# Read the file from a separate text file
with open("_clean_content.txt", "r") as c:
    content = c.read()
with open(path, "w") as out:
    out.write(content)
print("Written: " + path)

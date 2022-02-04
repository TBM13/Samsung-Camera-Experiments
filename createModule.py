#!/usr/bin/python3

import os
import shutil
import sys
import zipfile

def validateDirectory(dir: str):
    if not os.path.isdir(dir):
        print('Error: Directory "%s" not found' % dir)
        sys.exit(1)

def main():
    if len(sys.argv) < 2:
        print('Usage: createModule.py <device>')
        print('Example: createModule.py A20')
        sys.exit(1)

    validateDirectory(sys.argv[1])

    moduleDir = os.path.join(os.getcwd(), "_Module")
    tmpDir = moduleDir + "Temp"
    deviceModuleDir = os.path.join(sys.argv[1], "Module")

    validateDirectory(moduleDir)
    validateDirectory(deviceModuleDir)

    if os.path.isdir(tmpDir):
        shutil.rmtree(tmpDir)

    shutil.copytree(moduleDir, tmpDir)
    
    for file in os.listdir(deviceModuleDir):
        src = os.path.join(deviceModuleDir, file)
        dst = os.path.join(tmpDir, file)

        print('Copying "%s"' % src)
        if os.path.isfile(src):
            shutil.copy(src, dst)
        else:
            shutil.copytree(src, dst)

    zipFile = 'Module_%s.zip' % sys.argv[1]
    with zipfile.ZipFile(zipFile, 'w') as zip:
        for dir, _, files in os.walk(tmpDir):
            for file in files:
                filePath = os.path.join(dir, file)
                zip.write(filePath, filePath.replace(tmpDir, ""))

    print('\nModule saved as "%s"' % zipFile)
    shutil.rmtree(tmpDir)

if __name__ == "__main__":
    main()
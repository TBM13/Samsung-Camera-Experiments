import os
import re
import shutil
import sys
import zipfile

def abort(msg: str):
    print(f'\nAbort: {msg}')
    sys.exit(1)

def create_magisk_module(
        lib_name: str,
        libs: list[str], 
        model: str, android_version: int,
        module_version: int, description: str
    ):
    if len(libs) == 0:
        abort('No libs were provided')
    if len(libs) > 2:
        abort('A Magisk module can only contain up to 2 libs (32-bit and 64-bit)')

    lib32 = None
    lib64 = None
    for lib in libs:
        with open(lib, 'rb') as f:
            magic = f.read(5)
            if magic[4] == 2:
                lib64 = lib
            else:
                lib32 = lib

    if len(libs) == 2 and (lib32 is None or lib64 is None):
        abort('A Magisk module can only contain two libs if one is 32-bit and the other 64-bit')

    module_base_dir = os.path.join(os.getcwd(), 'common', 'ModuleBase')
    if not os.path.isdir(module_base_dir):
        abort(f'"{module_base_dir}" not found')

    tmp_dir = module_base_dir + 'Temp'
    if os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir)
    shutil.copytree(module_base_dir, tmp_dir)

    dst_32 = os.path.join(tmp_dir, 'system/vendor/lib/' + lib_name)
    dst_64 = os.path.join(tmp_dir, 'system/vendor/lib64/' + lib_name)
    if lib32 is not None:
        os.makedirs(os.path.dirname(dst_32), exist_ok=True)
        shutil.copy(lib32, dst_32)
    if lib64 is not None:
        os.makedirs(os.path.dirname(dst_64), exist_ok=True)
        shutil.copy(lib64, dst_64)

    # Update module.prop
    sanitized_model = re.sub(r'[^a-zA-Z0-9._]', '', model)
    with open(os.path.join(tmp_dir, 'module.prop'), 'r+') as f:
        data = f.read()
        data = data.replace('$ID$', f'SamsungCameraExperiments-{sanitized_model}-{android_version}')
        data = data.replace('$NAME$', f'Patched camera lib ({model}) (Android {android_version})')
        data = data.replace('$VERSION$', str(module_version))
        data = data.replace('$DESCRIPTION$', description)
        f.seek(0)
        f.truncate(0)
        f.write(data)

    zip_file = f'Module_{sanitized_model}.zip'
    with zipfile.ZipFile(zip_file, 'w') as zip:
        for dir, _, files in os.walk(tmp_dir):
            for file in files:
                file_path = os.path.join(dir, file)
                zip.write(file_path, file_path.replace(tmp_dir, ''))

    shutil.rmtree(tmp_dir)
    print(f'[*] Module saved as "{zip_file}"')
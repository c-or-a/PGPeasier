"""
PGPeasier - GUI PGP Tool

Original code Copyright © 2026 c.o.r.a.
Licensed under GNU General Public License v3.0 (GPLv3).
See LICENSE.txt for full license text.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

THIRD-PARTY COMPONENTS:
- pgpy (BSD 3-Clause) - PGP implementation
- cryptography (Apache 2.0/BSD) - Encryption functions
- dearpygui (MIT) - User interface
- pywin32 (PSF License) - Windows integration
- wmi (MIT) - Windows Management
- psutil (BSD) - Process utilities
- Python Standard Library (PSF License)

See THIRD_PARTY_LICENSES.txt for complete license texts.

DISCLAIMER:
This software is provided "AS IS" without warranty of any kind.
Users are responsible for their own key security and backup practices.
Use at your own risk.
"""

try:
    from icon_fix import set_windows_icon
except ImportError:
    def set_windows_icon():
        return False

#------security imports------#
import ctypes
import sys
import os
import hashlib
import subprocess
import json
import re
from ctypes import wintypes
#---------------------------#

def resource_path(relative_path):
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    sys.exit(0)

#--------------more security imports--------------#
try:
    import wmi
    import win32api
    import win32gui
    import win32process
    import win32con
except ImportError:
    os.system("python -m pip install pywin32 wmi")
    import wmi
    import win32api
    import win32gui
    import win32process
    import win32con
#-------------------------------------------------#

#---------------security checks---------------#
def check_debuggers():
    suspicious = []
    debugger_processes = [
        'x64dbg.exe', 'x32dbg.exe', 'ollydbg.exe', 'ida.exe', 'ida64.exe',
        'windbg.exe', 'dbgview.exe', 'procexp.exe', 'procmon.exe', 'tcpview.exe',
        'processhacker.exe', 'cheatengine.exe', 'hxd.exe', '010editor.exe',
        'dnspy.exe', 'ilspy.exe', 'reflexil.exe', 'peid.exe', 'cff.exe',
        'lordpe.exe', 'importrec.exe', 'de4dot.exe', 'upx.exe', 'die.exe',
        'recstudio.exe', 'ghidra.exe', 'binaryninja.exe', 'radare2.exe',
        'r2.exe', 'immunitydebugger.exe', 'sysinternals.exe', 'vmmap.exe',
        'regmon.exe', 'filemon.exe', 'hiew.exe', 'petools.exe'
    ]
    try:
        import psutil
        for proc in psutil.process_iter(['name', 'exe']):
            try:
                proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                proc_exe = proc.info['exe'].lower() if proc.info['exe'] else ''
                for debugger in debugger_processes:
                    debugger_lower = debugger.lower()
                    if debugger_lower in proc_name or debugger_lower in proc_exe:
                        suspicious.append(f"Debugger detected: {proc_name}")
                        break
                try:
                    if proc.pid:
                        def enum_windows_callback(hwnd, results):
                            if win32gui.IsWindowVisible(hwnd):
                                window_text = win32gui.GetWindowText(hwnd).lower()
                                debug_keywords = ['debug', 'dbg', 'ollydbg', 'ida', 'windbg', 'x64dbg', 'x32dbg', 'disassembler', 'hex editor', 'cheat engine']
                                for keyword in debug_keywords:
                                    if keyword in window_text:
                                        results.append(f"Debugger window: {window_text}")
                            return True
                        results = []
                        win32gui.EnumWindows(enum_windows_callback, results)
                        suspicious.extend(results)
                except:
                    pass
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
    except ImportError:
        try:
            output = subprocess.check_output('tasklist /fo csv', shell=True, text=True)
            for line in output.split('\n')[1:]:
                if line.strip():
                    parts = line.split(',')
                    if len(parts) > 0:
                        proc_name = parts[0].strip('"').lower()
                        for debugger in debugger_processes:
                            if debugger.lower() in proc_name:
                                suspicious.append(f"Debugger detected: {proc_name}")
        except:
            pass
    try:
        is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
        if is_debugger_present:
            suspicious.append("Debugger detected via IsDebuggerPresent API")
        ProcessDebugPort = 7
        h_process = ctypes.windll.kernel32.GetCurrentProcess()
        debug_port = ctypes.c_ulong()
        ctypes.windll.ntdll.NtQueryInformationProcess(
            h_process, ProcessDebugPort, 
            ctypes.byref(debug_port), ctypes.sizeof(debug_port), None
        )
        if debug_port.value != 0:
            suspicious.append("Debugger detected via NtQueryInformationProcess")
    except:
        pass
    return suspicious

def check_virtual_machine():
    suspicious = []
    try:
        #virtual machine indicators
        c = wmi.WMI()
        # Check manufacturer
        for computer in c.Win32_ComputerSystem():
            manufacturer = computer.Manufacturer.lower()
            model = computer.Model.lower()
            
            vm_indicators = ['vmware', 'virtualbox', 'qemu', 'xen', 'hyper-v', 'microsoft corporation', 'innotek gmbh']
            for indicator in vm_indicators:
                if indicator in manufacturer or indicator in model:
                    suspicious.append(f"Running in VM: {manufacturer} {model}")
        #VM processes
        vm_processes = ['vmtoolsd.exe', 'vboxservice.exe', 'vboxtray.exe', 'qemu-ga.exe']
        try:
            import psutil
            for proc in psutil.process_iter(['name']):
                try:
                    proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                    for vm_proc in vm_processes:
                        if vm_proc in proc_name:
                            suspicious.append(f"VM tool detected: {proc_name}")
                except:
                    continue
        except ImportError:
            pass
    except:
        pass
    return suspicious

def comprehensive_security_check():
    all_suspicious = []
    
    #debuggers and binary analysis tools
    debugger_suspicious = check_debuggers()
    all_suspicious.extend(debugger_suspicious)
    
    #virtual machines
    vm_suspicious = check_virtual_machine()
    all_suspicious.extend(vm_suspicious)

    try:
        c = wmi.WMI()
        
        #Known legitimate vendor dirs
        trusted_vendors = [
            "amd", "nvidia", "intel", "microsoft", "realtek", "qualcomm",
            "broadcom", "marvell", "synaptics", "logitech", "creative",
            "asmedia", "asustek", "gigabyte", "msi", "dell", "hp", "lenovo"
        ]
        
        #Known safe locations
        safe_locations = [
            r"C:\\Windows\\System32\\drivers",
            r"C:\\Windows\\System32\\DriverStore",
            r"C:\\Windows\\System32\\DriverStore\\FileRepository",
            r"C:\\Windows\\WinSxS",
            r"C:\\Program Files",
            r"C:\\Program Files (x86)",
            r"C:\\AMD",
            r"C:\\NVIDIA",
            r"C:\Intel",
            r"C:\\DRIVERS",
            r"C:\\SWSetup",
            r"C:\\Dell",
            r"C:\\HP",
            r"C:\\ProgramData"
        ]
        drivers = c.Win32_SystemDriver(State="Running")
        for driver in drivers:
            try:
                driver_name = driver.Name
                path_name = driver.PathName
                if not path_name:
                    continue
                #Skip Windows drivers
                if driver_name.lower().startswith(('microsoft', 'ms')):
                    continue
                #Skip known vendor drivers
                driver_lower = driver_name.lower()
                if any(vendor in driver_lower for vendor in trusted_vendors):
                    continue
                #Ghost drivers
                if not os.path.exists(path_name):
                    all_suspicious.append(f"Ghost driver: {driver_name} (file missing)")
                    continue
                #Suspicious locations
                path_lower = path_name.lower()
                in_safe_location = any(path_lower.startswith(loc.lower()) for loc in safe_locations)
                if in_safe_location:
                    continue
                suspicious_locations = [
                    r"\\temp", r"\\tmp", r"\\users\\", r"\\appdata\\", r"\\downloads",
                    r"\\desktop", r"\\documents", r"\\onedrive", r"\\dropbox",
                    r"\\google", r"\\mega"
                ]
                
                if any(susp in path_lower for susp in suspicious_locations):
                    all_suspicious.append(f"Suspicious location: {driver_name} -> {path_name}")
                
                #Unusual file extensions or names
                suspicious_extensions = ['.vbs', '.js', '.bat', '.cmd', '.ps1']
                file_ext = os.path.splitext(path_name)[1].lower()
                if file_ext in suspicious_extensions:
                    all_suspicious.append(f"Unusual driver extension: {driver_name} ({file_ext})")
                
                #Check for rootkit-like behavior
                rootkit_indicators = [
                    'rootkit', 'hook', 'stealth', 'invisible', 'hidden',
                    'tdss', 'zeroaccess', 'mebroot', 'alureon', 'rustock'
                ]
                if any(indicator in driver_lower for indicator in rootkit_indicators):
                    all_suspicious.append(f"Rootkit indicator: {driver_name}")
                
                #Check for keyloggers
                keylogger_indicators = ['keylog', 'klog', 'klg', 'keylogger', 'spy', 'monitor', 'recorder', 'sniffer', 'hookkb', 'hookmouse']
                if any(indicator in driver_lower for indicator in keylogger_indicators):
                    all_suspicious.append(f"Keylogger indicator: {driver_name}")
            except Exception as e:
                if "DEBUG" in globals() and DEBUG:
                    print(f"Error checking driver {driver_name}: {str(e)}")
                continue
    except Exception as e:
        if "DEBUG" in globals() and DEBUG:
            print(f"Driver check failed: {str(e)}")
    
    return all_suspicious

suspicious = comprehensive_security_check()

if suspicious:
    filtered_suspicious = []
    false_positive_patterns = [
        'amd', 'nvidia', 'intel', 'microsoft', 'realtek', 'qualcomm',
        'broadcom', 'marvell', 'synaptics', 'logitech', 'vmware tools', 'monitor'
    ]
    for item in suspicious:
        item_lower = item.lower()
        if not any(fp in item_lower for fp in false_positive_patterns):
            filtered_suspicious.append(item)
    if filtered_suspicious:
        details = "\n".join(filtered_suspicious[:15])  # Show more issues
        if len(filtered_suspicious) > 15:
            details += f"\n... and {len(filtered_suspicious) - 15} more security warnings"
        message = "Security Alert\n\n"
        #warnings
        debugger_warnings = [s for s in filtered_suspicious if any(word in s.lower() for word in ['debug', 'dbg', 'ida', 'ollydbg', 'windbg'])]
        vm_warnings = [s for s in filtered_suspicious if any(word in s.lower() for word in ['vm', 'virtual', 'qemu', 'hyper-v'])]
        driver_warnings = [s for s in filtered_suspicious if any(word in s.lower() for word in ['driver', 'sys'])]
        if debugger_warnings:
            message += "⚠️ Debuggers detected (potential reverse engineering):\n"
            for warning in debugger_warnings[:3]:
                message += f"  • {warning}\n"
            message += "\n"
        if vm_warnings:
            message += "⚠️ Virtual environment detected:\n"
            for warning in vm_warnings[:3]:
                message += f"  • {warning}\n"
            message += "\n"
        if driver_warnings:
            message += "⚠️ Suspicious drivers detected:\n"
            for warning in driver_warnings[:3]:
                message += f"  • {warning}\n"
            message += "\n"
        message += "For maximum security, please close these tools before continuing."
        response = ctypes.windll.user32.MessageBoxW(0, 
            message,
            "Security Alert - Binary Analysis Detected", 0x30 | 0x1)  # MB_ICONWARNING | MB_OKCANCEL
        if response == 2:  # IDCANCEL
            sys.exit(1)
        else:
            print("Security warnings were acknowledged but application continues:")
            for item in filtered_suspicious:
                print(f"  - {item}")

#---------------------------------------------#

#------------------default python libs------------------#
import os
import json
import base64
import hashlib
import threading
import tkinter as tk
from tkinter import filedialog
from time import sleep
import warnings
import sys

warnings.filterwarnings("ignore", category=UserWarning) 
#-------------------------------------------------------#

#---Globals---#
def get_base_path():
    if hasattr(sys, '_MEIPASS'):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))
BASE_DIR = get_base_path()
KEYS_PATH = os.path.join(BASE_DIR, 'keys')

unlocked_encrypted_data = None
encryption_key = None
encryption_salt = None
encryption_nonce = None
keynames_cache = []
dF = ''
DEBUG = False
width = 550
height = 265
#-------------#

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import pgpy
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    import dearpygui.dearpygui as dpg
except ImportError:
    os.system("python -m pip install cryptography pgpy dearpygui")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    import pgpy
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    import dearpygui.dearpygui as dpg

#--------------------------Functions--------------------------#

def get_cipher(password, salt=None):
    if not password: 
        password = "default_init_pass"
    if salt is None:
        salt = os.urandom(16) 
    key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 1200000, dklen=32)
    return key, salt

def UpdateList2():
    global keynames_cache, unlocked_encrypted_data, encryption_key
    while True:
        if unlocked_encrypted_data is not None and encryption_key is not None:
            if keynames_cache:
                dpg.configure_item("pub", items=keynames_cache)
            else:
                dpg.configure_item("pub", items=[])
        else:
            dpg.configure_item("pub", items=["Keys Encrypted"])
        sleep(1)

def decrypt_single_keypair(keyname):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    
    if not unlocked_encrypted_data or not encryption_key:
        return None, None
    try:
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        keypairs = json.loads(decrypted.decode('utf-8'))
        for pair in keypairs:
            if pair['keyname'] == keyname:
                private_key = str(pair['private_key'])
                public_key = str(pair['public_key'])
                pair['private_key'] = None
                pair['public_key'] = None
                return private_key, public_key
    except:
        pass
    return None, None

def get_keypair(keyname):
    return decrypt_single_keypair(keyname)

def decrypt_all_keynames():
    global unlocked_encrypted_data, encryption_key, encryption_nonce, keynames_cache

    if not unlocked_encrypted_data or not encryption_key:
        keynames_cache = []
        return []
    try:
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        keypairs = json.loads(decrypted.decode('utf-8'))
        keynames = [pair['keyname'] for pair in keypairs]
        decrypted = None
        keypairs = None
        keynames_cache = keynames
        return keynames
    except:
        keynames_cache = []
        return []

def clear_sensitive_memory():
    global encryption_key, encryption_salt, encryption_nonce
    
    if encryption_key:
        if isinstance(encryption_key, bytearray):
            for i in range(len(encryption_key)):
                encryption_key[i] = 0
        encryption_key = None
    encryption_salt = None
    encryption_nonce = None

def unlock_keys(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_salt, encryption_nonce, keynames_cache
    
    password = dpg.get_value("input_")
    if unlocked_encrypted_data is not None:
        key, salt = get_cipher(password)
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        aesgcm_new = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm_new.encrypt(nonce, decrypted, None)
        with open(KEYS_PATH, 'wb') as f:
            f.write(salt + nonce + ciphertext)
        clear_sensitive_memory()
        unlocked_encrypted_data = None
        keynames_cache = []
        dpg.set_value("input_", "") 
        return
    if not os.path.exists(KEYS_PATH):
        empty_data = json.dumps([]).encode('utf-8')
        key, salt = get_cipher(password)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, empty_data, None)
        encryption_key = key
        encryption_salt = salt
        encryption_nonce = nonce
        unlocked_encrypted_data = ciphertext
        keynames_cache = []
        decrypt_all_keynames()
        dpg.set_value("input_", "")  # Clear password field after successful unlock
        return
    try:
        with open(KEYS_PATH, 'rb') as f:
            content = f.read()
        if len(content) < 44:
            # Create empty data
            empty_data = json.dumps([]).encode('utf-8')
            key, salt = get_cipher(password)
            aesgcm = AESGCM(key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, empty_data, None)
            encryption_key = key
            encryption_salt = salt
            encryption_nonce = nonce
            unlocked_encrypted_data = ciphertext
            keynames_cache = []
            decrypt_all_keynames()
            dpg.set_value("input_", "")  # Clear password field
            return
        salt = content[:16]
        nonce = content[16:28]
        ciphertext_with_tag = content[28:]
        key, _ = get_cipher(password, salt=salt)
        aesgcm = AESGCM(key)
        try:
            decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            encryption_key = bytearray(key)
            encryption_salt = salt
            encryption_nonce = nonce
            unlocked_encrypted_data = ciphertext_with_tag
            decrypt_all_keynames()
            dpg.set_value("input_", "")  # Clear password field after successful unlock
        except:
            clear_sensitive_memory()
            unlocked_encrypted_data = None
            keynames_cache = []
            if DEBUG:
                print("Decryption failed - incorrect password")
    except Exception as e: 
        if DEBUG:
            print(f"Error: {e}")
        clear_sensitive_memory()
        unlocked_encrypted_data = None
        keynames_cache = []

def create_keys(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_salt, encryption_nonce
    if not unlocked_encrypted_data or not encryption_key:
        return
    name = dpg.get_value("input2")
    size = dpg.get_value("Ks")
    aesgcm = AESGCM(encryption_key)
    decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
    keypairs = json.loads(decrypted.decode('utf-8'))
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, size)
    uid = pgpy.PGPUID.new(name)
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128],
                compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed])
    keypairs.append({"keyname": name, "private_key": str(key), "public_key": str(key.pubkey)})
    new_data = json.dumps(keypairs).encode('utf-8')
    aesgcm = AESGCM(encryption_key)
    new_nonce = os.urandom(12)
    new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
    encryption_nonce = new_nonce
    unlocked_encrypted_data = new_ciphertext
    with open(KEYS_PATH, 'wb') as f:
        f.write(encryption_salt + new_nonce + new_ciphertext)
    decrypt_all_keynames()
    decrypted = None
    keypairs = None
    new_data = None

def encrypt_string(sender, app_data):
    _, pub_blob = get_keypair(dpg.get_value("pub"))
    if pub_blob:
        pub_key, _ = pgpy.PGPKey.from_blob(str(pub_blob))
        msg = pgpy.PGPMessage.new(dpg.get_value("input"), encoding="utf-8")
        dpg.set_value("input", str(pub_key.encrypt(msg)))

def decrypt_string(sender, app_data):
    priv_blob, _ = get_keypair(dpg.get_value("pub"))
    if priv_blob:
        priv_key, _ = pgpy.PGPKey.from_blob(str(priv_blob))
        try:
            msg = pgpy.PGPMessage.from_blob(dpg.get_value("input"))
            dec = priv_key.decrypt(msg)
            result = dec.message
            if isinstance(result, (bytes, bytearray)):
                result = result.decode('utf-8', errors='replace')
            dpg.set_value("input", str(result))
            priv_key = None
            dec = None
        except Exception as e: 
            if DEBUG:
                print(f"Text Decrypt Error: {e}")

def sign_string(sender, app_data):
    priv_blob, _ = get_keypair(dpg.get_value("pub"))
    if priv_blob:
        priv_key, _ = pgpy.PGPKey.from_blob(str(priv_blob))
        msg = pgpy.PGPMessage.new(dpg.get_value("input"), encoding="utf-8")
        msg |= priv_key.sign(msg)
        dpg.set_value("input", str(msg))
        priv_key = None

def select_file(sender, appdata):
    global dF
    root = tk.Tk(); root.withdraw()
    dF = filedialog.askopenfilename()
    root.destroy()

def encrypt_file(sender, app_data):
    global dF
    _, pub_blob = get_keypair(dpg.get_value("pub"))
    if pub_blob and dF and os.path.exists(dF):
        try:
            pub_key, _ = pgpy.PGPKey.from_blob(str(pub_blob))
            with open(dF, 'rb') as f:
                file_data = f.read()
            msg = pgpy.PGPMessage.new(file_data)
            encrypted_msg = pub_key.encrypt(msg)
            out = bytes(encrypted_msg)
            with open(dF, 'wb') as f:
                f.write(out)
        except Exception as e: 
            if DEBUG:
                print(f"Encryption failed: {e}")

def decrypt_file(sender, app_data):
    global dF
    priv_blob, _ = get_keypair(dpg.get_value("pub"))
    if priv_blob and dF and os.path.exists(dF):
        priv_key, _ = pgpy.PGPKey.from_blob(str(priv_blob))
        try:
            msg = pgpy.PGPMessage.from_file(dF)
            decrypted_msg = priv_key.decrypt(msg)
            dec_data = decrypted_msg.message
            if isinstance(dec_data, str):
                dec_data = dec_data.encode('utf-8')
            with open(dF, 'wb') as f:
                f.write(dec_data)
            priv_key = None
            decrypted_msg = None
        except Exception as e: 
            if DEBUG:
                print(f"Decryption failed: {e}")

def display_public_key(sender, app_data):
    _, pub = get_keypair(dpg.get_value("pub"))
    if pub: 
        dpg.set_value("input", str(pub))

def display_private_key(sender, app_data):
    prv, _ = get_keypair(dpg.get_value("pub"))
    if prv: 
        dpg.set_value("input", str(prv))
        prv = None

def delete_keys(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    target = dpg.get_value("pub")
    if not unlocked_encrypted_data or not encryption_key:
        return
    aesgcm = AESGCM(encryption_key)
    decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
    keypairs = json.loads(decrypted.decode('utf-8'))
    keypairs = [k for k in keypairs if k['keyname'] != target]
    new_data = json.dumps(keypairs).encode('utf-8')
    new_nonce = os.urandom(12)
    new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
    encryption_nonce = new_nonce
    unlocked_encrypted_data = new_ciphertext
    with open(KEYS_PATH, 'wb') as f:
        f.write(encryption_salt + new_nonce + new_ciphertext)
    decrypt_all_keynames()
    decrypted = None
    keypairs = None
    new_data = None

def set_public_key(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    
    target = dpg.get_value("pub")
    new_pub_key = dpg.get_value("input")
    if not unlocked_encrypted_data or not encryption_key:
        return
    aesgcm = AESGCM(encryption_key)
    decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
    keypairs = json.loads(decrypted.decode('utf-8'))
    for k in keypairs:
        if k['keyname'] == target:
            k['public_key'] = new_pub_key
            break
    new_data = json.dumps(keypairs).encode('utf-8')
    new_nonce = os.urandom(12)
    new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
    encryption_nonce = new_nonce
    unlocked_encrypted_data = new_ciphertext
    with open(KEYS_PATH, 'wb') as f:
        f.write(encryption_salt + new_nonce + new_ciphertext)
    decrypted = None
    keypairs = None
    new_data = None

def set_private_key(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    target = dpg.get_value("pub")
    new_priv_key = dpg.get_value("input")
    if not unlocked_encrypted_data or not encryption_key:
        return
    aesgcm = AESGCM(encryption_key)
    decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
    keypairs = json.loads(decrypted.decode('utf-8'))
    for k in keypairs:
        if k['keyname'] == target:
            k['private_key'] = new_priv_key
            break
    new_data = json.dumps(keypairs).encode('utf-8')
    new_nonce = os.urandom(12)
    new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
    encryption_nonce = new_nonce
    unlocked_encrypted_data = new_ciphertext
    with open(KEYS_PATH, 'wb') as f:
        f.write(encryption_salt + new_nonce + new_ciphertext)
    decrypted = None
    keypairs = None
    new_data = None

#---------------------------GUI---------------------------#

if not os.path.exists(KEYS_PATH):
    if DEBUG:
        print(f"File not found. Creating at: {KEYS_PATH}")
    key, salt = get_cipher("")
    data = json.dumps([]).encode('utf-8')
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    with open(KEYS_PATH, "wb") as f:
        f.write(salt + nonce + ciphertext)
    encryption_key = bytearray(key)
    encryption_salt = salt
    encryption_nonce = nonce
    unlocked_encrypted_data = ciphertext
    decrypt_all_keynames()
    if DEBUG:
        print("New key file created and automatically unlocked")
else:
    if DEBUG:
        print(f"Found existing file at: {KEYS_PATH}")
    try:
        with open(KEYS_PATH, 'rb') as f:
            content = f.read()
        if len(content) >= 44:
            salt = content[:16]
            nonce = content[16:28]
            ciphertext_with_tag = content[28:]
            key, _ = get_cipher("", salt=salt)
            aesgcm = AESGCM(key)
            try:
                decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
                encryption_key = bytearray(key)
                encryption_salt = salt
                encryption_nonce = nonce
                unlocked_encrypted_data = ciphertext_with_tag
                decrypt_all_keynames()
            except:
                clear_sensitive_memory()
                unlocked_encrypted_data = None
                keynames_cache = []
    except Exception as e:
        if DEBUG:
            print(f"Auto-unlock error: {e}")
        clear_sensitive_memory()
        unlocked_encrypted_data = None
        keynames_cache = []

dpg.create_context()
dpg.create_viewport(title='pgpeasier -- by c.o.r.a.', width=width, height=height)
icon_path = resource_path("1.ico")
dpg.set_viewport_small_icon(icon_path)
dpg.set_viewport_large_icon(icon_path)
dpg.set_viewport_resizable(False)
dpg.set_viewport_max_height(height)
dpg.set_viewport_max_width(width)
dpg.set_viewport_min_height(height)
dpg.set_viewport_min_width(width)
dpg.setup_dearpygui()

with dpg.window(label="pgpeasier -- by c.o.r.a.", width=width, height=height, no_title_bar=True, no_move=True, no_resize=True):
    with dpg.tab_bar():
        with dpg.tab(label="Text"):
            dpg.add_input_text(tag="input", multiline=True, width=420)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Encrypt", callback=encrypt_string)
                dpg.add_button(label="Display public key", callback=display_public_key)
                dpg.add_button(label="Set public key", callback=set_public_key)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Decrypt", callback=decrypt_string)
                dpg.add_button(label="Display private key", callback=display_private_key)
                dpg.add_button(label="Set private key", callback=set_private_key)
            dpg.add_button(label="Sign Message", callback=sign_string)
        with dpg.tab(label="Files"):
            dpg.add_button(label="Select File", callback=select_file)
            with dpg.group(horizontal=True):
                dpg.add_button(label="Encrypt", callback=encrypt_file)
                dpg.add_button(label="Decrypt", callback=decrypt_file)
        with dpg.tab(label="Keys"):
            with dpg.group(horizontal=True):
                dpg.add_input_text(tag="input_", width=250, password=True)
                dpg.add_button(label="Unlock / Lock Keys", callback=unlock_keys)
            with dpg.group():
                dpg.add_listbox(label="Key pair", width=175, tag="pub")
                threading.Thread(target=UpdateList2, daemon=True).start()
            with dpg.group(horizontal=True):
                dpg.add_input_text(label="Key name", tag="input2", width=100)
                dpg.add_input_int(label="Key Strength", default_value=2048, width=100,tag="Ks", step=1024, min_value=1024, max_value=9216, max_clamped=True ,min_clamped=True)
                dpg.add_button(label="Create new Keypair", callback=create_keys)
            dpg.add_button(label="Delete Keypair", callback=delete_keys)
set_windows_icon()
dpg.show_viewport()
while dpg.is_dearpygui_running():
    dpg.render_dearpygui_frame()
dpg.destroy_context()

clear_sensitive_memory()

# Copyright © 2026 c.o.r.a., licensed under GNU GPL v3.
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
import time
import hmac
import threading
import queue
from ctypes import wintypes
#---------------------------#

kernel32 = ctypes.WinDLL('kernel32')
user32 = ctypes.WinDLL('user32')
SW_HIDE = 0
hwnd = kernel32.GetConsoleWindow()
if hwnd:
    user32.ShowWindow(hwnd, SW_HIDE)

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
def constant_time_compare(a, b):
    if isinstance(a, str):
        a = a.encode()
    if isinstance(b, str):
        b = b.encode()
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0

class SecurityMonitor:
    def __init__(self):
        self.running = True
        self.suspicious_count = 0
        self.max_suspicious = 10
        self.detected_threats = []
        self.thread = None
        self.check_queue = queue.Queue()
        self.last_check_time = {}

        self.debugger_processes = [
            'x64dbg.exe', 'x32dbg.exe', 'ollydbg.exe', 'ida.exe', 'ida64.exe',
            'windbg.exe', 'dbgview.exe', 'procexp.exe', 'procmon.exe',
            'processhacker.exe', 'cheatengine.exe'
        ]
        
        self.keylogger_indicators = [
            'keylog', 'klog', 'klg', 'keylogger', 'spy', 'monitor',
            'recorder', 'sniffer', 'hookkb', 'hookmouse'
        ]
    
    def start(self):
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
    
    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)
    
    def _should_check(self, check_name, interval):
        current_time = time.time()
        last_time = self.last_check_time.get(check_name, 0)
        return current_time - last_time >= interval
    
    def _update_check_time(self, check_name):
        self.last_check_time[check_name] = time.time()
    
    def _check_debuggers(self):
        suspicious = []
        
        try:
            is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
            if is_debugger_present:
                suspicious.append("Debugger detected via IsDebuggerPresent")
            
            try:
                import psutil
                count = 0
                for proc in psutil.process_iter(['name']):
                    try:
                        proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                        for debugger in self.debugger_processes[:10]:
                            if debugger in proc_name:
                                suspicious.append(f"Debugger process: {proc_name}")
                                break
                        count += 1
                        if count > 50:
                            break
                    except:
                        continue
            except ImportError:
                pass
                
        except Exception as e:
            if "DEBUG" in globals() and DEBUG:
                print(f"Debugger check error: {e}")
        
        return suspicious
    
    def _check_virtualization(self):
        suspicious = []
        
        try:
            c = wmi.WMI()
            for computer in c.Win32_ComputerSystem()[:2]:
                manufacturer = computer.Manufacturer.lower()
                model = computer.Model.lower()
                vm_indicators = ['vmware', 'virtualbox', 'qemu', 'hyper-v']
                for indicator in vm_indicators:
                    if indicator in manufacturer or indicator in model:
                        suspicious.append(f"VM: {manufacturer} {model}")
                        break    
        except Exception as e:
            if "DEBUG" in globals() and DEBUG:
                print(f"VM check error: {e}")
        return suspicious
    
    def _check_drivers(self):
        suspicious = []
        
        try:
            c = wmi.WMI()
            trusted_vendors = ['amd', 'nvidia', 'intel', 'microsoft', 'realtek']
            drivers = list(c.Win32_SystemDriver(State="Running"))[:20]
            for driver in drivers:
                try:
                    driver_name = driver.Name.lower()
                    if any(vendor in driver_name for vendor in trusted_vendors):
                        continue
                    if any(indicator in driver_name for indicator in self.keylogger_indicators):
                        suspicious.append(f"Suspicious driver: {driver.Name}")
                except:
                    continue
        except Exception as e:
            if "DEBUG" in globals() and DEBUG:
                print(f"Driver check error: {e}")
        
        return suspicious
    
    def _check_keyloggers(self):
        suspicious = []
        try:
            try:
                import psutil
                count = 0
                for proc in psutil.process_iter(['name']):
                    try:
                        proc_name = proc.info['name'].lower() if proc.info['name'] else ''
                        for indicator in self.keylogger_indicators[:10]:
                            if indicator in proc_name:
                                suspicious.append(f"Keylogger process: {proc_name}")
                                break
                        count += 1
                        if count > 30:
                            break
                    except:
                        continue
            except ImportError:
                pass
                
        except Exception as e:
            if "DEBUG" in globals() and DEBUG:
                print(f"Keylogger check error: {e}")
        
        return suspicious
    
    def _check_memory(self):
        suspicious = []
        
        try:
            import psutil
            process = psutil.Process(os.getpid())
            mem_info = process.memory_info()
            if mem_info.rss > 300 * 1024 * 1024:
                suspicious.append(f"High memory: {mem_info.rss // (1024*1024)}MB")
        except Exception as e:
            if "DEBUG" in globals() and DEBUG:
                print(f"Memory check error: {e}")
        
        return suspicious
    
    def _run_checks(self):
        all_suspicious = []
        if self._should_check('debuggers', 3):
            all_suspicious.extend(self._check_debuggers())
            self._update_check_time('debuggers')
        if self._should_check('virtualization', 7):
            all_suspicious.extend(self._check_virtualization())
            self._update_check_time('virtualization')
        if self._should_check('drivers', 10):
            all_suspicious.extend(self._check_drivers())
            self._update_check_time('drivers')
        if self._should_check('keyloggers', 5):
            all_suspicious.extend(self._check_keyloggers())
            self._update_check_time('keyloggers')
        if self._should_check('memory', 8):
            all_suspicious.extend(self._check_memory())
            self._update_check_time('memory')
        
        return all_suspicious
    
    def _monitor_loop(self):
        while self.running:
            try:
                suspicious = self._run_checks()
                if suspicious:
                    self.detected_threats.extend(suspicious)
                    self.suspicious_count += len(suspicious)
                    if len(self.detected_threats) > 20:
                        self.detected_threats = self.detected_threats[-20:]
                    if self.suspicious_count >= self.max_suspicious:
                        self._critical_response()
                time.sleep(1)
            except Exception as e:
                if "DEBUG" in globals() and DEBUG:
                    print(f"Monitor loop error: {e}")
                time.sleep(2)
    
    def _critical_response(self):
        if self.detected_threats:
            recent_threats = self.detected_threats[-5:]
            
            message = "CRITICAL SECURITY THREAT\n\n"
            message += "Multiple security violations detected:\n"
            for threat in recent_threats:
                message += f"• {threat}\n"
            message += "\nApplication will now exit."
            ctypes.windll.user32.MessageBoxW(0, message, "Critical Security Alert", 0x10)
    
            os._exit(1)

def comprehensive_security_check():
    all_suspicious = []
    
    security_monitor = SecurityMonitor()
    security_monitor.start()
    globals()['security_monitor'] = security_monitor
    try:
        is_debugger_present = ctypes.windll.kernel32.IsDebuggerPresent()
        if is_debugger_present:
            all_suspicious.append("Debugger detected on startup")
    except:
        pass
    
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
        message = "Security Alert\n\n"
        debugger_warnings = [s for s in filtered_suspicious if any(word in s.lower() for word in ['debug', 'dbg', 'ida', 'ollydbg', 'windbg'])]
        vm_warnings = [s for s in filtered_suspicious if any(word in s.lower() for word in ['vm', 'virtual', 'qemu', 'hyper-v'])]
        
        if debugger_warnings:
            message += "⚠️ Debuggers detected:\n"
            for warning in debugger_warnings[:2]:
                message += f"  • {warning}\n"
            message += "\n"
        
        if vm_warnings:
            message += "⚠️ Virtual environment detected:\n"
            for warning in vm_warnings[:2]:
                message += f"  • {warning}\n"
            message += "\n"
        
        message += "For maximum security, please close these tools before continuing."
        response = ctypes.windll.user32.MessageBoxW(0, 
            message,
            "Security Alert", 0x30 | 0x1)
        if response == 2:
            if 'security_monitor' in globals():
                globals()['security_monitor'].stop()
            sys.exit(1)
        else:
            pass

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
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import pgpy
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    import dearpygui.dearpygui as dpg
except ImportError:
    os.system("python -m pip install cryptography pgpy dearpygui")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    import pgpy
    from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
    import dearpygui.dearpygui as dpg

#--------------------------Functions--------------------------#

def get_cipher(password, salt=None):
    if not password: 
        password = ""
    if salt is None:
        salt = os.urandom(16) 
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=1200000,
    )
    key = kdf.derive(password.encode())
    return key, salt

def get_combined_hash(priv_blob, encryption_key):
    combined_material = str(priv_blob).encode() + bytes(encryption_key)
    split_point = len(combined_material) // 2
    salt_part = combined_material[:split_point]
    password_part = combined_material[split_point:]
    if len(salt_part) < 16:
        padding = hashlib.sha256(combined_material).digest()
        salt_part = (salt_part + padding)[:16]
    elif len(salt_part) > 16:
        salt_part = hashlib.sha256(salt_part).digest()[:16]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt_part,
        iterations=3100000,
    )
    derived_key = kdf.derive(password_part)
    return hashlib.sha512(derived_key).hexdigest()

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
        sleep(2)

def decrypt_single_keypair(keyname):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    if not unlocked_encrypted_data or not encryption_key:
        return None, None
    try:
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        keypairs = json.loads(decrypted.decode('utf-8'))
        for pair in keypairs:
            if constant_time_compare(pair['keyname'], keyname):
                private_key = str(pair['private_key'])
                public_key = str(pair['public_key'])
                return private_key, public_key
    except Exception as e:
        if DEBUG:
            print(f"Decrypt keypair error: {e}")
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
    if constant_time_compare(password, ""):
        password = ""
    
    if unlocked_encrypted_data is not None:
        try:
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
        except:
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
        dpg.set_value("input_", "")
        return
    try:
        with open(KEYS_PATH, 'rb') as f:
            content = f.read()
        if len(content) < 44:
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
            dpg.set_value("input_", "")
            return
        
        salt = content[:16]
        nonce = content[16:28]
        ciphertext_with_tag = content[28:]
        key, _ = get_cipher(password, salt=salt)
        
        aesgcm = AESGCM(key)
        try:
            decrypted = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
            encryption_key = key
            encryption_salt = salt
            encryption_nonce = nonce
            unlocked_encrypted_data = ciphertext_with_tag
            decrypt_all_keynames()
            dpg.set_value("input_", "")
        except:
            clear_sensitive_memory()
            unlocked_encrypted_data = None
            keynames_cache = []
            if DEBUG:
                print("Decryption failed - incorrect password")
    except Exception as e: 
        if DEBUG:
            print(f"Unlock error: {e}")
        clear_sensitive_memory()
        unlocked_encrypted_data = None
        keynames_cache = []

def create_keys(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_salt, encryption_nonce
    if not unlocked_encrypted_data or not encryption_key:
        return
    
    name = dpg.get_value("input2")
    size = dpg.get_value("Ks")
    
    if not name or len(name.strip()) == 0:
        return
    
    try:
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        keypairs = json.loads(decrypted.decode('utf-8'))
        for pair in keypairs:
            if constant_time_compare(pair['keyname'], name):
                return
        key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, size)
        uid = pgpy.PGPUID.new(name)
        key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
                    hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA512],
                    ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES128,
                            SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.Camellia256],
                    compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.Uncompressed])
        keypairs.append({
            "keyname": name, 
            "private_key": str(key), 
            "public_key": str(key.pubkey)
        })
        new_data = json.dumps(keypairs).encode('utf-8')
        new_nonce = os.urandom(12)
        new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
        encryption_nonce = new_nonce
        unlocked_encrypted_data = new_ciphertext
        
        with open(KEYS_PATH, 'wb') as f:
            f.write(encryption_salt + new_nonce + new_ciphertext)
        decrypt_all_keynames()
        
    except Exception as e:
        if DEBUG:
            print(f"Error creating key: {e}")
        import traceback
        traceback.print_exc()

def encrypt_string(sender, app_data):
    _, pub_blob = get_keypair(dpg.get_value("pub"))
    if pub_blob:
        try:
            pub_key, _ = pgpy.PGPKey.from_blob(str(pub_blob))
            msg = pgpy.PGPMessage.new(dpg.get_value("input"), encoding="utf-8")
            encrypted = pub_key.encrypt(msg)
            dpg.set_value("input", str(encrypted))
        except Exception as e:
            if DEBUG:
                print(f"Encrypt string error: {e}")

def decrypt_string(sender, app_data):
    priv_blob, _ = get_keypair(dpg.get_value("pub"))
    if priv_blob:
        try:
            priv_key, _ = pgpy.PGPKey.from_blob(str(priv_blob))
            msg = pgpy.PGPMessage.from_blob(dpg.get_value("input"))
            dec = priv_key.decrypt(msg)
            result = dec.message
            if isinstance(result, (bytes, bytearray)):
                result = result.decode('utf-8', errors='replace')
            dpg.set_value("input", str(result))
        except Exception as e: 
            if DEBUG:
                print(f"Text Decrypt Error: {e}")

def sign_string(sender, app_data):
    priv_blob, _ = get_keypair(dpg.get_value("pub"))
    if priv_blob:
        try:
            priv_key, _ = pgpy.PGPKey.from_blob(str(priv_blob))
            msg = pgpy.PGPMessage.new(dpg.get_value("input"), encoding="utf-8")
            msg |= priv_key.sign(msg)
            dpg.set_value("input", str(msg))
        except Exception as e:
            if DEBUG:
                print(f"Sign string error: {e}")

def select_file(sender, appdata):
    global dF
    root = tk.Tk()
    root.withdraw()
    dF = filedialog.askopenfilename()
    root.destroy()

def encrypt_file(sender, app_data):
    global dF, encryption_key
    priv_blob, _ = get_keypair(dpg.get_value("pub"))
    if priv_blob and encryption_key and dF and os.path.exists(dF):
        try:
            derived_password = get_combined_hash(priv_blob, encryption_key)
            with open(dF, 'rb') as f:
                file_data = f.read()
            msg = pgpy.PGPMessage.new(file_data)
            encrypted_msg = msg.encrypt(derived_password, symmetric_algorithm=SymmetricKeyAlgorithm.AES256)
            out = bytes(encrypted_msg)
            with open(dF, 'wb') as f:
                f.write(out)
        except Exception as e:
            if DEBUG:
                print(f"Encryption failed: {e}")

def decrypt_file(sender, app_data):
    global dF, encryption_key
    priv_blob, _ = get_keypair(dpg.get_value("pub"))
    if priv_blob and encryption_key and dF and os.path.exists(dF):
        try:
            derived_password = get_combined_hash(priv_blob, encryption_key)
            msg = pgpy.PGPMessage.from_file(dF)
            decrypted_msg = msg.decrypt(derived_password)
            dec_data = decrypted_msg.message
            if isinstance(dec_data, str):
                dec_data = dec_data.encode('utf-8')
            with open(dF, 'wb') as f:
                f.write(dec_data)
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

def delete_keys(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    target = dpg.get_value("pub")
    if not unlocked_encrypted_data or not encryption_key:
        return
    try:
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        keypairs = json.loads(decrypted.decode('utf-8'))
        keypairs = [k for k in keypairs if not constant_time_compare(k['keyname'], target)]
        new_data = json.dumps(keypairs).encode('utf-8')
        new_nonce = os.urandom(12)
        new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
        encryption_nonce = new_nonce
        unlocked_encrypted_data = new_ciphertext
        with open(KEYS_PATH, 'wb') as f:
            f.write(encryption_salt + new_nonce + new_ciphertext)
        decrypt_all_keynames()
    except Exception as e:
        if DEBUG:
            print(f"Error deleting key: {e}")

def set_public_key(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    target = dpg.get_value("pub")
    new_pub_key = dpg.get_value("input")
    if not unlocked_encrypted_data or not encryption_key:
        return
    try:
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        keypairs = json.loads(decrypted.decode('utf-8'))
        for k in keypairs:
            if constant_time_compare(k['keyname'], target):
                k['public_key'] = new_pub_key
                break
        new_data = json.dumps(keypairs).encode('utf-8')
        new_nonce = os.urandom(12)
        new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
        encryption_nonce = new_nonce
        unlocked_encrypted_data = new_ciphertext
        with open(KEYS_PATH, 'wb') as f:
            f.write(encryption_salt + new_nonce + new_ciphertext)
    except Exception as e:
        if DEBUG:
            print(f"Error setting public key: {e}")

def set_private_key(sender, app_data):
    global unlocked_encrypted_data, encryption_key, encryption_nonce
    target = dpg.get_value("pub")
    new_priv_key = dpg.get_value("input")
    if not unlocked_encrypted_data or not encryption_key:
        return
    try:
        aesgcm = AESGCM(encryption_key)
        decrypted = aesgcm.decrypt(encryption_nonce, unlocked_encrypted_data, None)
        keypairs = json.loads(decrypted.decode('utf-8'))
        for k in keypairs:
            if constant_time_compare(k['keyname'], target):
                k['private_key'] = new_priv_key
                break
        new_data = json.dumps(keypairs).encode('utf-8')
        new_nonce = os.urandom(12)
        new_ciphertext = aesgcm.encrypt(new_nonce, new_data, None)
        encryption_nonce = new_nonce
        unlocked_encrypted_data = new_ciphertext
        with open(KEYS_PATH, 'wb') as f:
            f.write(encryption_salt + new_nonce + new_ciphertext)
    except Exception as e:
        if DEBUG:
            print(f"Error setting private key: {e}")

#---------------------------GUI---------------------------#

if not os.path.exists(KEYS_PATH):
    if DEBUG:
        print(f"Creating new key file at: {KEYS_PATH}")
    key, salt = get_cipher("")
    data = json.dumps([]).encode('utf-8')
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    with open(KEYS_PATH, "wb") as f:
        f.write(salt + nonce + ciphertext)
    encryption_key = key
    encryption_salt = salt
    encryption_nonce = nonce
    unlocked_encrypted_data = ciphertext
    decrypt_all_keynames()
    if DEBUG:
        print("New key file created and unlocked")
else:
    if DEBUG:
        print(f"Found existing key file at: {KEYS_PATH}")
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
                encryption_key = key
                encryption_salt = salt
                encryption_nonce = nonce
                unlocked_encrypted_data = ciphertext_with_tag
                decrypt_all_keynames()
                if DEBUG:
                    print("Auto-unlock successful")
            except:
                clear_sensitive_memory()
                unlocked_encrypted_data = None
                keynames_cache = []
                if DEBUG:
                    print("Auto-unlock failed")
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
                dpg.add_listbox(label="Key pair", width=175, num_items=6, tag="pub")
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

# Clean up security monitor
if 'security_monitor' in globals():
    globals()['security_monitor'].stop()

clear_sensitive_memory()

# Copyright © 2026 c.o.r.a., licensed under GNU GPL v3.

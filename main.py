import sys
import os
import ctypes
from ctypes import wintypes
from PyQt5.QtWidgets import (
    QApplication, QWidget, QPushButton, QLabel, QLineEdit,
    QFileDialog, QVBoxLayout, QHBoxLayout, QMessageBox, QSpinBox
)
from PyQt5.QtGui import QPixmap
from PyQt5.QtCore import Qt, QTimer
import platform

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
MEM_RELEASE = 0x8000

class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(wintypes.ULONG)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_char * 260)
    ]

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

def get_process_id_by_name(process_name):
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot == -1:
        return 0
    
    pe32 = PROCESSENTRY32()
    pe32.dwSize = ctypes.sizeof(PROCESSENTRY32)
    
    if kernel32.Process32First(snapshot, ctypes.byref(pe32)):
        while True:
            try:
                current_process = pe32.szExeFile.decode('utf-8', errors='ignore').lower()
                if current_process == process_name.lower():
                    pid = pe32.th32ProcessID
                    kernel32.CloseHandle(snapshot)
                    return pid
            except:
                pass
            
            if not kernel32.Process32Next(snapshot, ctypes.byref(pe32)):
                break
    
    kernel32.CloseHandle(snapshot)
    return 0

def inject_dll(process_id, dll_path):
    try:
        h_process = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_id)
        if not h_process:
            error_code = ctypes.get_last_error()
            return False, f"Failed to open process (Error: {error_code})"
        
        dll_path_bytes = dll_path.encode('utf-8') + b'\x00'
        dll_path_size = len(dll_path_bytes)
        
        remote_memory = kernel32.VirtualAllocEx(
            h_process, None, dll_path_size,
            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE
        )
        
        if not remote_memory:
            error_code = ctypes.get_last_error()
            kernel32.CloseHandle(h_process)
            return False, f"Memory allocation failed (Error: {error_code})"
        
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(
            h_process, remote_memory, dll_path_bytes,
            dll_path_size, ctypes.byref(written)
        ):
            error_code = ctypes.get_last_error()
            kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
            kernel32.CloseHandle(h_process)
            return False, f"Write to memory failed (Error: {error_code})"
        
        h_kernel32 = kernel32.GetModuleHandleA(b"kernel32.dll")
        load_library_addr = kernel32.GetProcAddress(h_kernel32, b"LoadLibraryA")
        
        if not load_library_addr:
            kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
            kernel32.CloseHandle(h_process)
            return False, "Could not get LoadLibraryA address"
        
        thread_id = wintypes.DWORD(0)
        h_thread = kernel32.CreateRemoteThread(
            h_process, None, 0, load_library_addr,
            remote_memory, 0, ctypes.byref(thread_id)
        )
        
        if not h_thread:
            error_code = ctypes.get_last_error()
            kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
            kernel32.CloseHandle(h_process)
            return False, f"Remote thread creation failed (Error: {error_code})"
        
        kernel32.WaitForSingleObject(h_thread, 0xFFFFFFFF)
        kernel32.VirtualFreeEx(h_process, remote_memory, 0, MEM_RELEASE)
        kernel32.CloseHandle(h_thread)
        kernel32.CloseHandle(h_process)
        
        return True, "DLL injected successfully"
        
    except Exception as e:
        return False, f"Exception: {str(e)}"

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class DLLInjectorUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Astolfo DLL Injector 2.0")
        self.setFixedSize(760, 500)
        self.setStyleSheet("background-color: #fce9ed;")
        
        self.python_arch = platform.architecture()[0]
        self.is_32bit = self.python_arch == "32bit"
        self.target_process = "left4dead2.exe"
        self.dll_slots = []
        self.injecting = False
        
        left_panel = QVBoxLayout()
        left_panel.setAlignment(Qt.AlignCenter)
        left_panel.setSpacing(15)
        left_panel.setContentsMargins(20, 20, 10, 20)
        
        self.inject_button = QPushButton("Inject")
        self.inject_button.setFixedSize(300, 80)
        self.inject_button.setStyleSheet("""
            QPushButton {
                background-color: #e91e63;
                color: white;
                font-size: 16px;
                font-weight: bold;
                padding: 10px;
                border: none;
                border-radius: 15px;
            }
            QPushButton:hover {
                background-color: #c2185b;
            }
        """)
        self.inject_button.clicked.connect(self.start_injection)
        left_panel.addWidget(self.inject_button, alignment=Qt.AlignHCenter)
        
        delay_layout = QHBoxLayout()
        delay_layout.setSpacing(10)
        delay_layout.addStretch()
        delay_label = QLabel("Delay (sec):")
        delay_label.setStyleSheet("font-size: 12px; font-weight: bold;")
        self.delay_spinbox = QSpinBox()
        self.delay_spinbox.setMinimum(0)
        self.delay_spinbox.setMaximum(60)
        self.delay_spinbox.setValue(1)
        self.delay_spinbox.setFixedSize(80, 50)
        self.delay_spinbox.setStyleSheet("""
            QSpinBox {
                background-color: white;
                border: 3px solid #9c27b0;
                border-radius: 10px;
                padding: 5px;
                font-size: 12px;
                font-weight: bold;
                color: #9c27b0;
            }
            QSpinBox::up-button {
                background-color: #9c27b0;
                border: none;
                width: 20px;
            }
            QSpinBox::down-button {
                background-color: #9c27b0;
                border: none;
                width: 20px;
            }
        """)
        delay_layout.addWidget(delay_label)
        delay_layout.addWidget(self.delay_spinbox)
        delay_layout.addStretch()
        left_panel.addLayout(delay_layout)
        
        self.add_space_button = QPushButton("+ Add Slot")
        self.add_space_button.setFixedSize(300, 50)
        self.add_space_button.setStyleSheet("""
            QPushButton {
                background-color: #9c27b0;
                color: white;
                font-size: 12px;
                font-weight: bold;
                border: none;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #7b1fa2;
            }
        """)
        self.add_space_button.clicked.connect(self.add_dll_slot)
        left_panel.addWidget(self.add_space_button, alignment=Qt.AlignHCenter)
        
        self.slots_container = QVBoxLayout()
        self.slots_container.setSpacing(10)
        left_panel.addLayout(self.slots_container)
        
        self.add_dll_slot()
        
        left_panel.addStretch()
        
        right_panel = QVBoxLayout()
        right_panel.setContentsMargins(0, 0, 0, 0)
        right_panel.setSpacing(0)
        right_panel.addStretch()
        self.bg_image = QLabel()
        image_path = resource_path("Astolfo.png")
        
        if os.path.exists(image_path):
            self.bg_image.setPixmap(QPixmap(image_path).scaled(350, 480, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            self.bg_image.setText("🌸\n\nAstolfo\nnot found\n\n🌸\n\nPlace Astolfo.png\nin the same folder")
            self.bg_image.setStyleSheet("color: #9c27b0; font-size: 12px;")
        
        self.bg_image.setAlignment(Qt.AlignCenter | Qt.AlignBottom)
        self.bg_image.setContentsMargins(0, 0, 0, 0)
        right_panel.addWidget(self.bg_image, 0, Qt.AlignBottom)
        
        main_layout = QHBoxLayout()
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addLayout(left_panel, 1)
        main_layout.addLayout(right_panel, 1)
        
        self.setLayout(main_layout)
    
    def add_dll_slot(self):
        if len(self.dll_slots) >= 3:
            QMessageBox.warning(self, "Limit Reached", "Maximum 3 DLLs allowed.")
            return
        
        slot_layout = QHBoxLayout()
        slot_layout.setSpacing(8)
        
        dll_input = QLineEdit()
        dll_input.setPlaceholderText("Select a DLL...")
        dll_input.setReadOnly(True)
        dll_input.setFixedSize(220, 50)
        dll_input.setStyleSheet("""
            QLineEdit {
                padding: 8px;
                font-size: 11px;
                background-color: white;
                border: 3px solid #e1bee7;
                border-radius: 10px;
                color: #999999;
            }
        """)
        
        browse_btn = QPushButton("📁")
        browse_btn.setFixedSize(50, 50)
        browse_btn.setStyleSheet("""
            QPushButton {
                background-color: #9c27b0;
                color: white;
                font-size: 18px;
                border: 3px solid #ce93d8;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #7b1fa2;
            }
        """)
        
        remove_btn = QPushButton("✕")
        remove_btn.setFixedSize(50, 50)
        remove_btn.setStyleSheet("""
            QPushButton {
                background-color: #f44336;
                color: white;
                font-size: 18px;
                border: none;
                border-radius: 10px;
            }
            QPushButton:hover {
                background-color: #d32f2f;
            }
        """)
        
        slot_index = len(self.dll_slots)
        slot_data = {
            'input': dll_input,
            'browse_btn': browse_btn,
            'remove_btn': remove_btn,
            'layout': slot_layout,
            'full_path': '',
            'index': slot_index
        }
        
        self.dll_slots.append(slot_data)
        
        browse_btn.clicked.connect(lambda: self.browse_dll(slot_index))
        remove_btn.clicked.connect(lambda: self.remove_dll_slot(slot_index))
        
        slot_layout.addWidget(dll_input)
        slot_layout.addWidget(browse_btn)
        slot_layout.addWidget(remove_btn)
        
        self.slots_container.addLayout(slot_layout)
    
    def browse_dll(self, slot_index):
        dll_path, _ = QFileDialog.getOpenFileName(self, "Select DLL", "", "DLL Files (*.dll)")
        if dll_path:
            self.dll_slots[slot_index]['full_path'] = dll_path
            file_name = os.path.basename(dll_path)
            self.dll_slots[slot_index]['input'].setText(file_name)
    
    def remove_dll_slot(self, slot_index):
        if len(self.dll_slots) <= 1:
            QMessageBox.warning(self, "Error", "At least one slot is required.")
            return
        
        slot = self.dll_slots[slot_index]
        slot['layout'].itemAt(0).widget().deleteLater()
        slot['layout'].itemAt(1).widget().deleteLater()
        slot['layout'].itemAt(2).widget().deleteLater()
        
        self.dll_slots.pop(slot_index)
        
        for i, slot in enumerate(self.dll_slots):
            slot['index'] = i
    
    def start_injection(self):
        
        dlls_to_inject = []
        for slot in self.dll_slots:
            if not slot['full_path']:
                QMessageBox.warning(self, "Error", "Please fill all DLL slots.")
                return
            
            dll_path = os.path.abspath(slot['full_path'])
            if not os.path.exists(dll_path):
                QMessageBox.critical(self, "Error", f"DLL not found: {dll_path}")
                return
            
            dlls_to_inject.append(dll_path)
        
        process_id = get_process_id_by_name(self.target_process)
        
        if process_id == 0:
            QMessageBox.critical(
                self,
                "Error",
                f"Process {self.target_process} not found.\n\nMake sure it's running."
            )
            return
        
        self.injecting = True
        self.inject_button.setEnabled(False)
        delay_ms = self.delay_spinbox.value() * 1000
        
        self.inject_sequential(dlls_to_inject, process_id, 0, delay_ms)
    
    def inject_sequential(self, dlls, process_id, index, delay_ms):
        if index >= len(dlls):
            self.injecting = False
            self.inject_button.setEnabled(True)
            QMessageBox.information(
                self,
                "Success",
                f"All DLLs injected successfully into {self.target_process}"
            )
            return
        
        dll_path = dlls[index]
        success, message = inject_dll(process_id, dll_path)
        
        if not success:
            self.injecting = False
            self.inject_button.setEnabled(True)
            QMessageBox.critical(
                self,
                "Error",
                f"Failed to inject: {os.path.basename(dll_path)}\n\nDetails: {message}"
            )
            return
        
        if index < len(dlls) - 1:
            QTimer.singleShot(delay_ms, lambda: self.inject_sequential(dlls, process_id, index + 1, delay_ms))
        else:
            self.inject_sequential(dlls, process_id, index + 1, delay_ms)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = DLLInjectorUI()
    window.show()
    sys.exit(app.exec_())
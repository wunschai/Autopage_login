import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QPushButton, QLabel, QLineEdit, 
                            QTableWidget, QTableWidgetItem, QMessageBox, 
                            QInputDialog)
from PyQt6.QtCore import Qt
import json
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, WebDriverException, NoSuchWindowException
from PyQt6.QtGui import QIcon
import time
import os

class AutoLoginApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.target_url = "http://your_target_url"  # 目標網站
        self._master_key = b"YourSecretKey114514!@#$%^&*()" # 內建金鑰（請更換為您自己的隨機字串）
        self.cipher_suite = None
        self.accounts = {}
        self.admin_password = "114514"
        self.is_admin_mode = False
        self.init_encryption()
        
        self.setWindowIcon(QIcon('icon.png'))
        self.setStyleSheet("""
            QPushButton {
                background-color: #4CAF50;
                color: white;
                padding: 5px;
                border-radius: 3px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            #adminButton {
                background-color: #2196F3;
            }
            #adminButton:hover {
                background-color: #1976D2;
            }
        """)
        self.init_ui()
        self.load_accounts()

    def init_ui(self):
        """初始化圖形介面"""
        self.setWindowTitle('自動登入工具')
        self.setGeometry(100, 100, 600, 400)

        # 主要佈局
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # 管理按鈕
        self.admin_button = QPushButton('管理模式')
        self.admin_button.setObjectName('adminButton')
        self.admin_button.clicked.connect(self.toggle_admin_mode)
        
        # 帳號列表
        self.table = QTableWidget()
        self.table.setColumnCount(2)  # 只顯示帳號名稱和登入按鈕
        self.table.setHorizontalHeaderLabels(['帳號名稱', '操作'])
        self.table.horizontalHeader().setStretchLastSection(True)

        # 新增帳號區域（預設隱藏）
        self.add_account_widget = QWidget()
        add_layout = QHBoxLayout(self.add_account_widget)

        self.account_name = QLineEdit()
        self.account_name.setPlaceholderText('帳號名稱')
        self.username = QLineEdit()
        self.username.setPlaceholderText('使用者名稱')
        self.password = QLineEdit()
        self.password.setPlaceholderText('密碼')
        self.password.setEchoMode(QLineEdit.EchoMode.Password)

        add_btn = QPushButton('新增帳號')
        add_btn.clicked.connect(self.add_account)

        add_layout.addWidget(self.account_name)
        add_layout.addWidget(self.username)
        add_layout.addWidget(self.password)
        add_layout.addWidget(add_btn)

        self.add_account_widget.hide()  # 預設隱藏

        # 添加到主佈局
        layout.addWidget(self.admin_button)
        layout.addWidget(self.add_account_widget)
        layout.addWidget(self.table)

    def init_encryption(self):
        """初始化加密系統"""
        # 使用 PBKDF2 來產生加密金鑰
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self._master_key[:16],  # 使用金鑰的前16位作為salt
            iterations=100000,
            backend=default_backend()
        )
        self.key = kdf.derive(self._master_key)

    def encrypt_data(self, data):
        """加密數據"""
        try:
            # 生成隨機 IV
            iv = os.urandom(16)
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            encryptor = cipher.encryptor()
            
            # 確保數據長度是16的倍數（填充）
            padded_data = data.encode()
            padding_length = 16 - (len(padded_data) % 16)
            padded_data += bytes([padding_length]) * padding_length
            
            # 加密
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # 組合 IV 和加密數據
            return base64.b64encode(iv + encrypted_data).decode('utf-8')
        except Exception as e:
            raise Exception(f"加密失敗：{str(e)}")

    def decrypt_data(self, encrypted_data):
        """解密數據"""
        try:
            # 解碼並分離 IV 和加密數據
            raw_data = base64.b64decode(encrypted_data.encode('utf-8'))
            iv = raw_data[:16]
            encrypted_content = raw_data[16:]
            
            cipher = Cipher(
                algorithms.AES(self.key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            
            # 解密
            padded_data = decryptor.update(encrypted_content) + decryptor.finalize()
            
            # 移除填充
            padding_length = padded_data[-1]
            data = padded_data[:-padding_length]
            
            return data.decode('utf-8')
        except Exception as e:
            raise Exception(f"解密失敗：{str(e)}")

    def toggle_admin_mode(self):
        """切換管理模式"""
        if not self.is_admin_mode:
            password, ok = QInputDialog.getText(
                self, '管理員驗證', 
                '請輸入管理密碼：',
                QLineEdit.EchoMode.Password
            )
            if ok and password == self.admin_password:
                self.is_admin_mode = True
                self.add_account_widget.show()
                self.update_table(show_delete=True)
                self.admin_button.setText('退出管理模式')
                QMessageBox.information(self, '提示', '已進入管理模式')
            else:
                QMessageBox.warning(self, '錯誤', '密碼錯誤')
        else:
            self.is_admin_mode = False
            self.add_account_widget.hide()
            self.update_table(show_delete=False)
            self.admin_button.setText('管理模式')
            QMessageBox.information(self, '提示', '已退出管理模式')

    def update_table(self, show_delete=False):
        """更新帳號列表"""
        self.table.setRowCount(len(self.accounts))
        if show_delete:
            self.table.setColumnCount(3)  # 顯示刪除按鈕
            self.table.setHorizontalHeaderLabels(['帳號名稱', '操作', ''])
        else:
            self.table.setColumnCount(2)  # 隱藏刪除按鈕
            self.table.setHorizontalHeaderLabels(['帳號名稱', '操作'])

        for row, (name, data) in enumerate(self.accounts.items()):
            self.table.setItem(row, 0, QTableWidgetItem(name))

            login_btn = QPushButton('執行登入')
            login_btn.clicked.connect(lambda checked, n=name: self.auto_login(n))
            self.table.setCellWidget(row, 1, login_btn)

            if show_delete:
                delete_btn = QPushButton('刪除')
                delete_btn.clicked.connect(lambda checked, n=name: self.delete_account(n))
                self.table.setCellWidget(row, 2, delete_btn)

    def delete_account(self, account_name):
        """刪除帳號"""
        if not self.is_admin_mode:
            QMessageBox.warning(self, '警告', '需要管理員權限')
            return

        reply = QMessageBox.question(
            self, '確認', 
            f'確定要刪除帳號 {account_name} 嗎？',
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            del self.accounts[account_name]
            self.save_accounts()
            self.update_table(show_delete=True)

    def add_account(self):
        """新增帳號"""
        account_name = self.account_name.text()
        username = self.username.text()
        password = self.password.text()

        if not all([account_name, username, password]):
            QMessageBox.warning(self, '警告', '請填寫所有欄位')
            return

        try:
            # 直接儲存明文，加密會在save_accounts中進行
            self.accounts[account_name] = {
                'username': username,
                'password': password
            }

            self.save_accounts()
            self.update_table(show_delete=self.is_admin_mode)
            self.clear_inputs()
            QMessageBox.information(self, '成功', f'帳號 {account_name} 新增成功！')
            
        except Exception as e:
            QMessageBox.critical(self, '錯誤', f'新增帳號失敗：{str(e)}')

    def save_accounts(self):
        """儲存帳號資訊到檔案"""
        try:
            # 加密帳號資料
            encrypted_data = {}
            for name, data in self.accounts.items():
                encrypted_data[name] = {
                    'username': self.encrypt_data(data['username']),
                    'password': self.encrypt_data(data['password'])
                }
                
            # 儲存加密後的帳號資料
            with open('accounts.dat', 'w') as f:
                json.dump(encrypted_data, f)
                
        except Exception as e:
            QMessageBox.critical(self, '錯誤', f'儲存帳號資料失敗：{str(e)}')

    def load_accounts(self):
        """從檔案載入帳號資訊"""
        try:
            # 讀取帳號資料
            try:
                with open('accounts.dat', 'r') as f:
                    encrypted_data = json.load(f)
                    
                    # 解密帳號資料
                    self.accounts = {}
                    for name, data in encrypted_data.items():
                        self.accounts[name] = {
                            'username': self.decrypt_data(data['username']),
                            'password': self.decrypt_data(data['password'])
                        }
                        
            except FileNotFoundError:
                self.accounts = {}
                
            self.update_table()
            
        except Exception as e:
            QMessageBox.critical(self, '錯誤', f'載入帳號資料失敗：{str(e)}')
            self.accounts = {}

    def clear_inputs(self):
        """清空輸入欄位"""
        self.account_name.clear()
        self.username.clear()
        self.password.clear()

    def auto_login(self, account_name):
        """執行自動登入"""
        driver = None
        try:
            account = self.accounts[account_name]
            username = account['username']
            password = account['password']

            chrome_options = webdriver.ChromeOptions()
            chrome_options.add_argument('--start-maximized')
            chrome_options.add_argument('--disable-gpu')
            chrome_options.add_argument('--no-sandbox')
            chrome_options.add_argument('--disable-dev-shm-usage')
            chrome_options.add_argument('--disable-blink-features=AutomationControlled')
            chrome_options.add_experimental_option("excludeSwitches", ["enable-automation"])
            chrome_options.add_experimental_option('useAutomationExtension', False)
            
            try:
                driver = webdriver.Chrome(options=chrome_options)
                wait = WebDriverWait(driver, 10)
                
                # 訪問主頁面
                driver.get("http://203.71.86.73/Admin/")
                
                try:
                    # 等待 frameset 加載完成
                    main_frame = wait.until(
                        EC.presence_of_element_located((By.NAME, "frmMainArea"))
                    )
                    
                    # 切換到 MainArea frame
                    driver.switch_to.frame("frmMainArea")
                    
                    # 等待登入表單元素出現
                    username_field = wait.until(
                        EC.presence_of_element_located((By.NAME, "txtAccount"))
                    )
                    
                    password_field = wait.until(
                        EC.element_to_be_clickable((By.NAME, "txtPassword"))
                    )
                    
                    # 確保元素可互動後再輸入
                    wait.until(EC.element_to_be_clickable((By.NAME, "txtAccount")))
                    username_field.clear()
                    username_field.send_keys(username)
                    
                    password_field.clear()
                    password_field.send_keys(password)

                    # 等待登入按鈕可點擊
                    submit_button = wait.until(
                        EC.element_to_be_clickable((By.ID, "btnLogin"))
                    )
                    
                    submit_button.click()
                    
                    try:
                        # 等待登入成功後的頁面變化
                        driver.switch_to.default_content()
                        success_element = wait.until(
                            EC.presence_of_element_located((By.ID, "ctl00_ContentPlaceHolder1_lblSchoolName"))
                        )
                        school_name = success_element.text
                        
                        # 登入成功
                        QMessageBox.information(self, '成功', f'登入成功！\n學校名稱: {school_name}')
                        return True
                        
                    except NoSuchWindowException:
                        # 用戶手動關閉瀏覽器，不顯示錯誤
                        print("瀏覽器已被關閉")
                        return True
                        
                except TimeoutException:
                    QMessageBox.warning(self, '警告', '網頁載入超時，請檢查網路連接')
                    return False
                    
                except NoSuchWindowException:
                    # 用戶手動關閉瀏覽器，不顯示錯誤
                    print("瀏覽器已被關閉")
                    return True
                    
                except Exception as e:
                    if not isinstance(e, NoSuchWindowException):
                        QMessageBox.critical(self, '錯誤', f'操作失敗：{str(e)}')
                    return False
                    
            except WebDriverException as e:
                if "chrome not reachable" not in str(e).lower():
                    QMessageBox.critical(self, '錯誤', f'瀏覽器啟動失敗：{str(e)}')
                return False
                
        finally:
            if driver:
                try:
                    driver.quit()
                except:
                    pass

        return False

def main():
    app = QApplication(sys.argv)
    window = AutoLoginApp()
    window.show()
    sys.exit(app.exec())

if __name__ == '__main__':
    main() 
# 自動登入工具 (Auto Login Tool)

## 基本介紹
這是一個使用 Python 開發的自動登入工具，主要用於網頁的自動化登入。專案使用 PyQt6 建立圖形介面，並整合了 Selenium 進行網頁自動化操作。主要撰寫過程使用 ChatGPT 4o 和 VSCode 進行撰寫。感謝Cursor的幫助。

### 主要依賴
- Python 3.8+
- PyQt6
- Selenium
- cryptography
- Chrome WebDriver

## 功能說明
### 核心功能
- 帳號管理系統
  - 加密儲存帳號資訊
  - 新增/刪除帳號
  - 管理員權限控制
  
- 自動化登入
  - 自動填寫表單
  - 智能等待頁面載入
  - 錯誤處理機制


## 使用方法
### 環境設置

安裝必要套件
```
bash
pip install -r requirements.txt
```
確保已安裝 Chrome 瀏覽器和對應版本的 WebDriver

### 執行程式
```
python
python auto_login.py
```
1. 修改加密金鑰

```python
self.master_key = b"YOUR-SECRET-KEY" # 在 AutoLoginApp 類別中
```

2. 設定管理員密碼
```python
self.admin_password = "YOUR-ADMIN-PASSWORD" # 在 AutoLoginApp 類別中
```

### 打包執行檔
使用 PyInstaller 打包
```
bash
pyinstaller build_config.spec
```
## 安全性說明
### 資料加密
- 使用 AES-CBC 模式進行加密
- 使用 PBKDF2 進行金鑰派生
- 所有敏感資訊均以加密形式儲存

### 程式保護
- 管理員模式密碼驗證
- 防止重複執行機制
- 完整的錯誤處理流程

### 注意事項
1. 請勿在原始碼中保留實際使用的金鑰
2. 建議定期更換加密金鑰
3. 確保 `accounts.dat` 檔案的存取權限
4. 不建議將加密後的資料直接傳輸

### 安全建議
- 定期更新依賴套件
- 妥善保管管理員密碼
- 避免在公共環境中使用
- 定期備份加密資料

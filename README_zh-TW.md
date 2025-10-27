# ELF Binary Labeler

[English Version](README.md)

一個強大的 Python 工具，用於分析和標記 ELF 二進制數據集，專為惡意軟體和良性軟體分類設計。此工具可從二進制文件中提取完整的元數據，包括 CPU 架構、位元順序、打包資訊和惡意軟體家族分類。

## 功能特色

- **雙模式運作**
  - **惡意軟體模式**：分析 VirusTotal JSON 報告結合二進制文件
  - **良性軟體模式**：直接分析二進制文件，無需 JSON 報告

- **全面的二進制分析**
  - ELF 標頭資訊（CPU、架構、位元順序、文件類型）
  - 二進制元數據（位元數、載入段、節區標頭）
  - 文件雜湊（MD5、SHA256）
  - 使用 DiE（Detect It Easy）進行打包偵測
  - 使用 AVClass 進行惡意軟體家族分類

- **效能優化**
  - 多進程平行處理
  - 使用 tqdm 追蹤進度
  - 高效的單次檔案讀取

## 系統需求

### 必需工具

1. **Python 3.8+** 及以下套件：
   ```bash
   pip install tqdm
   ```

2. **readelf**（binutils 的一部分）
   ```bash
   # Ubuntu/Debian
   sudo apt-get install binutils

   # RHEL/CentOS
   sudo yum install binutils
   ```

3. **DiE (Detect It Easy)** - 用於打包偵測
   - 下載位置：https://github.com/horsicq/Detect-It-Easy
   - 確保 `diec` 命令在 PATH 中可用

4. **AVClass**（選用，僅惡意軟體模式需要）
   - 複製自：https://github.com/malicialab/avclass
   - 依照 AVClass 安裝說明
   - 確保 `avclass` 命令在 PATH 中可用

## 安裝步驟

1. 複製此儲存庫：
   ```bash
   git clone https://github.com/louiskyee/elf-binary-labeler.git
   cd elf-binary-labeler
   ```

2. 安裝 Python 相依套件：
   ```bash
   pip install -r requirements.txt
   ```

3. 驗證工具相依性：
   ```bash
   readelf --version
   diec --version
   avclass --help  # 選用，僅惡意軟體模式需要
   ```

## 使用方式

### 惡意軟體模式

分析 VirusTotal JSON 報告結合二進制文件：

```bash
python3 label.py --mode malware \
    -i /path/to/json_reports \
    -b /path/to/malware/binaries \
    -o malware_output.csv
```

**預期的目錄結構：**
```
/path/to/json_reports/
├── sample1.json
├── sample2.json
└── ...

/path/to/malware/binaries/
├── 01/
│   └── 01a2b3c4...  (SHA256 雜湊)
├── 02/
│   └── 02d5e6f7...
└── ...
```

### 良性軟體模式

直接分析二進制文件，無需 JSON 報告：

```bash
python3 label.py --mode benignware \
    -b /path/to/benignware/binaries \
    -o benignware_output.csv
```

### 命令列選項

| 選項 | 簡寫 | 說明 | 必需 |
|-----|------|------|------|
| `--mode` | `-m` | 分析模式：`malware` 或 `benignware` | 否（預設：malware）|
| `--input_folder` | `-i` | 包含 JSON 報告的資料夾 | 是（僅惡意軟體模式）|
| `--binary_folder` | `-b` | 包含二進制文件的資料夾 | 是（兩種模式）|
| `--output` | `-o` | 輸出 CSV 文件路徑 | 否（自動產生）|

## 輸出格式

此工具生成包含以下欄位的 CSV 文件：

| 欄位 | 說明 |
|-----|------|
| `file_name` | 二進制文件的 SHA256 雜湊 |
| `md5` | MD5 雜湊 |
| `label` | 分類：`Malware` 或 `Benignware` |
| `file_type` | ELF 文件類型（EXEC、DYN、REL、CORE）|
| `CPU` | CPU 架構（例如 x86-64、ARM）|
| `bits` | 二進制位元數（32 或 64）|
| `endianness` | 位元組順序（小端序/大端序）|
| `load_segments` | PT_LOAD 段的數量 |
| `has_section_name` | 是否存在節區標頭 |
| `family` | 惡意軟體家族（僅惡意軟體模式）|
| `first_seen` | 首次發現時間戳（惡意軟體模式）|
| `size` | 文件大小（位元組）|
| `diec_is_packed` | 二進制是否被打包（True/False）|
| `diec_packer_info` | 打包器名稱和版本 |
| `diec_packing_method` | 打包方法詳情 |

### 輸出範例

```csv
file_name,md5,label,file_type,CPU,bits,endianness,load_segments,has_section_name,family,first_seen,size,diec_is_packed,diec_packer_info,diec_packing_method
01a2b3c4...,5e6f7g8h...,Malware,EXEC,Advanced Micro Devices X86-64,64,2's complement little endian,2,True,mirai,2024-01-15,45678,True,UPX(3.95),NRV
```

## 錯誤處理

- 錯誤和警告會記錄到 `{輸出檔名}_errors.log`
- 單一文件分析失敗不會中斷其他文件的處理
- 日誌文件中提供詳細的除錯資訊

## 效能表現

- 利用所有可用的 CPU 核心進行平行處理
- 優化的單次 ELF 分析檔案讀取
- 即時狀態更新的進度條

效能範例（在 8 核心系統上測試）：
- 約 1000 個文件在 5-10 分鐘內處理完成（取決於二進制大小和分析深度）

## 疑難排解

### 常見問題

1. **"AVClass not found"**
   - 確保 AVClass 已安裝且在 PATH 中
   - 惡意軟體模式需要 AVClass 進行家族分類

2. **"readelf failed"**
   - 驗證 binutils 已安裝：`which readelf`
   - 某些非 ELF 文件會跳過 readelf 分析

3. **"diec command failed"**
   - 確保 DiE 已正確安裝
   - 檢查 `diec` 是否可訪問：`which diec`

4. **權限被拒**
   - 確保對輸入目錄具有讀取權限
   - 確保對輸出 CSV 位置具有寫入權限

## 貢獻

歡迎貢獻！請隨時提交 Pull Request。

1. Fork 此儲存庫
2. 建立您的功能分支（`git checkout -b feature/AmazingFeature`）
3. 提交您的更改（`git commit -m 'Add some AmazingFeature'`）
4. 推送到分支（`git push origin feature/AmazingFeature`）
5. 開啟 Pull Request

## 授權條款

此專案為開源專案，採用 [MIT 授權條款](LICENSE)。

## 引用

如果您在研究中使用此工具，請引用：

```bibtex
@software{elf_binary_labeler,
  title={ELF Binary Labeler: 惡意軟體數據集分析工具},
  author={louiskyee},
  year={2024},
  url={https://github.com/louiskyee/elf-binary-labeler}
}
```

## 致謝

- [AVClass](https://github.com/malicialab/avclass) - 惡意軟體家族分類
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) - 打包器偵測
- [tqdm](https://github.com/tqdm/tqdm) - 進度條

## 聯絡方式

如有問題、議題或建議，請在 GitHub 上開啟 issue。

---

**注意**：此工具專為資安研究和教育目的設計。請負責任且合乎道德地使用。

# ELF Binary Labeler

[English Version](README.md)

一個強大的 Python 工具，用於分析和標記 ELF 二進制數據集，專為惡意軟體和良性軟體分類設計。此工具可從二進制文件中提取完整的元數據，包括 CPU 架構、位元順序、加殼資訊和惡意軟體家族分類。

## 功能特色

- **雙模式運作**
  - **惡意軟體模式**：分析 VirusTotal JSON 報告結合二進制文件
  - **良性軟體模式**：直接分析二進制文件，無需 JSON 報告

- **全面的二進制分析**
  - ELF 標頭資訊（CPU、架構、位元順序、文件類型）
  - 二進制元數據（位元數、載入段、節區標頭）
  - 文件雜湊（MD5、SHA256）
  - 使用 DiE（Detect It Easy）進行加殼偵測
  - 使用 AVClass 進行惡意軟體家族分類

- **效能優化**
  - 多進程平行處理
  - 使用 tqdm 追蹤進度
  - 高效的單次檔案讀取

- **現代化架構**
  - 模組化設計，關注點分離
  - 工廠模式提供擴展性
  - 抽象基底類別便於擴展
  - 使用現代 Python 工具管理（uv、pyproject.toml）

## 系統需求

### 必需工具

1. **Python 3.10+**

2. **DiE (Detect It Easy)** - 用於加殼偵測
   - 下載位置：https://github.com/horsicq/Detect-It-Easy
   - 確保 `diec` 命令在 PATH 中可用

3. **AVClass** - 惡意軟體家族分類（惡意軟體模式）
   - 會透過 Python 相依套件自動安裝
   - 或手動安裝：`pip install avclass-malicialab`

## 安裝步驟

### 方法 1：從 PyPI 安裝（推薦）

```bash
pip install pyelflabeler
```

安裝後，可以使用 `pyelflabeler` 命令執行工具：

```bash
pyelflabeler --help
```

### 方法 2：使用 uv 從原始碼安裝

[uv](https://github.com/astral-sh/uv) 是快速的 Python 套件安裝器和解析器。

1. 安裝 uv：
   ```bash
   curl -LsSf https://astral.sh/uv/install.sh | sh
   ```

2. 複製並安裝：
   ```bash
   git clone https://github.com/louiskyee/pyelflabeler.git
   cd pyelflabeler
   uv sync
   ```

3. 執行工具：
   ```bash
   uv run pyelflabeler --help
   # 或直接使用 Python 模組
   uv run python -m src.main --help
   ```

### 方法 3：使用 pip 從原始碼安裝

1. 複製此儲存庫：
   ```bash
   git clone https://github.com/louiskyee/pyelflabeler.git
   cd pyelflabeler
   ```

2. 以可編輯模式安裝：
   ```bash
   pip install -e .
   ```

3. 驗證安裝：
   ```bash
   pyelflabeler --help
   diec --version
   ```

## 使用方式

### 惡意軟體模式

分析 VirusTotal JSON 報告結合二進制文件：

```bash
pyelflabeler --mode malware \
    -i /path/to/json_reports \
    -b /path/to/malware/binaries \
    -o malware_output.csv
```

**預期的目錄結構：**

JSON 報告和二進制文件都按 SHA256 雜湊前綴組織：

```
/path/to/json_reports/
├── 00/
│   ├── 0000002158d35c2bb5e7d96a39ff464ea4c83de8c5fd72094736f79125aaca11.json
│   ├── 0000002a10959ec38b808d8252eed2e814294fbb25d2cd016b24bf853a44857e.json
│   └── ...
├── 01/
│   └── ...
└── ...

/path/to/malware/binaries/
├── 00/
│   ├── 0000002158d35c2bb5e7d96a39ff464ea4c83de8c5fd72094736f79125aaca11
│   ├── 0000002a10959ec38b808d8252eed2e814294fbb25d2cd016b24bf853a44857e
│   └── ...
├── 01/
│   └── ...
└── ...
```

檔案以其 SHA256 雜湊的前兩個字符命名的子目錄中組織。

### 良性軟體模式

直接分析二進制文件，無需 JSON 報告：

```bash
pyelflabeler --mode benignware \
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
| `is_stripped` | 符號表是否被移除（True/False）|
| `has_section_name` | 是否存在節區標頭 |
| `family` | 惡意軟體家族（僅惡意軟體模式）|
| `first_seen` | 首次發現時間戳（惡意軟體模式）|
| `size` | 文件大小（位元組）|
| `diec_is_packed` | 二進制是否被加殼（True/False）|
| `diec_packer_info` | 加殼器名稱和版本 |
| `diec_packing_method` | 加殼方法詳情 |

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

- 高速平行處理，利用所有可用的 CPU 核心
- 優化的單次 ELF 分析檔案讀取
- 即時狀態更新的進度條

## 專案結構

此專案遵循現代 Python 最佳實踐，採用模組化架構：

```
dataset_labeler/
├── main.py                    # CLI 入口點
├── pyproject.toml             # 專案配置（uv）
├── requirements.txt           # 傳統 pip 支援
├── src/
│   ├── main.py                # 主要 CLI 邏輯
│   ├── config.py              # 配置管理
│   ├── constants.py           # CSV 欄位定義
│   ├── factory.py             # 分析器工廠模式
│   ├── analyzers/
│   │   ├── base_analyzer.py       # 抽象基底類別
│   │   ├── malware_analyzer.py    # 惡意軟體分析
│   │   └── benignware_analyzer.py # 良性軟體分析
│   └── utils/
│       ├── elf_utils.py       # ELF 二進制工具
│       ├── hash_utils.py      # 文件雜湊
│       └── packer_utils.py    # 加殼偵測與 AVClass
└── tests/                     # 單元測試（即將推出）
```

### 擴展性

新增分析器類型很簡單：

1. 在 `src/analyzers/` 中建立新的分析器類別，繼承自 `BaseAnalyzer`
2. 實作 `collect_files()` 和 `process_single_file()` 方法
3. 在工廠模式中註冊（`src/factory.py`）

範例：
```python
from src.analyzers.base_analyzer import BaseAnalyzer

class CustomAnalyzer(BaseAnalyzer):
    def collect_files(self):
        # 您的實作
        pass

    def process_single_file(self, file_path):
        # 您的實作
        pass
```

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
@software{pyelflabeler,
  title={PyELFLabeler: ELF 二進制數據集分析工具},
  author={louiskyee},
  year={2024},
  url={https://github.com/louiskyee/pyelflabeler}
}
```

## 致謝

- [AVClass](https://github.com/malicialab/avclass) - 惡意軟體家族分類
- [Detect It Easy](https://github.com/horsicq/Detect-It-Easy) - 加殼器偵測
- [tqdm](https://github.com/tqdm/tqdm) - 進度條

## 聯絡方式

如有問題、議題或建議，請在 GitHub 上開啟 issue。

---

**注意**：此工具專為資安研究和教育目的設計。請負責任且合乎道德地使用。

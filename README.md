# Email Security Analysis Tool

이메일 보안 분석 도구로 Sublime Security 규칙을 사용하여 피싱 및 악성 이메일을 탐지합니다.

## 설치 및 실행

### 1. 프로젝트 Clone
```bash
git clone <your-repository-url>
```

### 2. 프로젝트 디렉토리로 이동
```bash
cd <project-directory>
```

### 3. Sublime Rules 저장소 Clone
```bash
git clone https://github.com/sublime-security/sublime-rules.git
```

### 4. 설정 변경
`main.py` 파일의 `Config` 클래스에서 경로를 적절히 수정하세요:

```python
class Config:
    DEFAULT_RULES_PATH = "./sublime-rules/detection-rules/"  # Don't change this path
    DEFAULT_EML_ROOT_PATH = "./dataset/eml"  # Please change your raw eml file path
    DEFAULT_CSV_FILENAME = "./dataset/email_analysis_results.csv"  # Please change csv path you want
```

- `DEFAULT_EML_ROOT_PATH`: 분석할 EML 파일들이 있는 디렉토리 경로
- `DEFAULT_CSV_FILENAME`: 결과를 저장할 CSV 파일 경로

### 5. 실행
```bash
python main.py
```
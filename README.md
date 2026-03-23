# SCA 자동화

BlackDuck SCA(Software Composition Analysis) 취약점을 자동으로 수집·분석하여 Slack으로 리포트를 전송하는 도구입니다.

---

## 1. 목적

BlackDuck에서 탐지된 Critical/High 등급의 오픈소스 컴포넌트 취약점을 자동으로 분석하고, 조치 방안을 포함한 리포트를 Slack 채널에 전송합니다.

**주요 기능:**

- BlackDuck SCA 결과에서 취약 컴포넌트 목록 추출
- NVD, CISA KEV, OSV, GitHub Advisory DB, BlackDuck Advisory 5개 소스 교차 분석
- Claude AI(claude-sonnet-4-6)를 활용한 한국어 취약점 분석 및 조치 방안 생성
- Slack Block Kit 메시지 또는 Canvas 문서 형식으로 리포트 전송

---

## 2. 환경 설정 파일 (.env) 발급 방법

프로젝트 루트에 `.env` 파일을 생성하고 아래 항목을 설정합니다.

```
BLACKDUCK_URL="https://<BlackDuck 서버 주소>"
BLACKDUCK_API_TOKEN="<BlackDuck API 토큰>"
ANTHROPIC_API_KEY="<Anthropic API 키>"
SLACK_BOT_TOKEN="<Slack Bot 토큰>"
SLACK_CHANNEL_ID="<Slack 채널 ID>"
SLACK_SIGNING_SECRET="<Slack Signing Secret>"
SLACK_CANVAS_ID="<Slack Canvas ID>"        # 선택 사항 (최초 실행 후 자동 저장)
NVD_API_KEY="<NVD API 키>"
GITHUB_TOKEN="<GitHub Personal Access Token>"
```

### BlackDuck API Token

1. BlackDuck 웹 UI에 로그인
2. 우측 상단 사용자 아이콘 > **My Access Tokens** 클릭
3. **Generate New Token** 버튼 클릭 후 토큰 이름 입력
4. 생성된 토큰을 `BLACKDUCK_API_TOKEN`에 설정

### Anthropic API Key

1. [https://console.anthropic.com](https://console.anthropic.com) 접속 후 로그인
2. 좌측 메뉴 **API Keys** > **Create Key** 클릭
3. 생성된 키(`sk-ant-...`)를 `ANTHROPIC_API_KEY`에 설정

### Slack Bot Token / Signing Secret

1. [https://api.slack.com/apps](https://api.slack.com/apps) 접속 후 **Create New App** (From scratch)
2. 앱 이름 및 워크스페이스 선택 후 생성
3. **OAuth & Permissions** > **Scopes** 에서 아래 Bot Token Scopes 추가:
   - `chat:write`
   - `canvases:write`
   - `canvases:read`
   - `channels:read`
4. **Install to Workspace** 클릭 후 **Bot User OAuth Token**(`xoxb-...`)을 `SLACK_BOT_TOKEN`에 설정
5. **Basic Information** > **App Credentials** > **Signing Secret**을 `SLACK_SIGNING_SECRET`에 설정

### Slack Channel ID

1. Slack 앱에서 리포트를 받을 채널 우클릭 > **채널 세부 정보 보기**
2. 하단에 표시되는 채널 ID(`C`로 시작)를 `SLACK_CHANNEL_ID`에 설정

### Slack Canvas ID

- 최초 실행 시 `--canvas` 옵션을 사용하면 Canvas가 자동 생성되고 ID가 `.env`에 저장됩니다.
- 이후 실행 시 기존 Canvas를 덮어씁니다.

### NVD API Key

1. [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key) 접속
2. 이메일 주소 입력 후 API 키 신청 (이메일로 수신)
3. 수신된 키를 `NVD_API_KEY`에 설정

> API 키 없이도 동작하지만 요청 속도 제한이 낮아집니다.

### GitHub Personal Access Token

1. GitHub 로그인 후 **Settings** > **Developer settings** > **Personal access tokens** > **Tokens (classic)**
2. **Generate new token** 클릭
3. Scopes에서 `public_repo` (또는 `read:packages`) 선택 후 생성
4. 생성된 토큰(`ghp_...`)을 `GITHUB_TOKEN`에 설정

---

## 3. 디렉토리 구조

```
vuln/
├── main.py                      # 진입점 (CLI 옵션 처리 및 전체 흐름 제어)
├── scanner.py                   # BlackDuck 취약점 스캔 및 데이터 수집
├── claude_client.py             # Claude AI 취약점 분석 요청
├── slack_client.py              # Slack 메시지 / Canvas 전송
├── auth.py                      # BlackDuck 인증 처리
├── nvd_client.py                # NVD API 조회
├── cisa_client.py               # CISA KEV 조회
├── osv_client.py                # OSV API 조회
├── github_advisory_client.py    # GitHub Advisory DB 조회
├── blackduck_advisory_client.py # BlackDuck Advisory 조회
├── pyproject.toml               # 프로젝트 의존성 정의
├── uv.lock                      # 의존성 lock 파일
└── .env                         # 환경변수 (git 제외)
```

---

## 4. 기동 방법

### 사전 준비

Python 3.10 이상이 설치되어 있어야 합니다.

```bash
# 의존성 설치
pip install -r requirements.txt
```

### 실행 명령어

```bash
# 기본 실행 (Critical 취약점 분석 후 Slack 메시지 전송)
python main.py

# 특정 심각도 지정 (예: Critical + High)
python main.py --severity critical high

# 특정 프로젝트만 조회
python main.py --project "프로젝트명"

# 취약 컴포넌트 목록만 출력 (Slack 전송 없음)
python main.py --scan-only

# Critical + High 목록 출력
python main.py --scan-only --severity critical high

# Slack 전송 없이 Block Kit 페이로드 미리보기 (dry-run)
python main.py --dry-run

# Slack Canvas 문서로 리포트 생성
python main.py --canvas
```

### 옵션 설명

| 옵션 | 설명 |
|---|---|
| `--scan-only` | 취약 컴포넌트 목록만 콘솔 출력 (Claude 분석 및 Slack 전송 생략) |
| `--dry-run` | Claude 분석까지 실행 후 Slack 전송 없이 Block Kit 페이로드를 콘솔에 출력 |
| `--canvas` | Slack Block Kit 메시지 대신 Canvas 문서로 리포트 생성/업데이트 |
| `--project <이름>` | 특정 프로젝트 이름으로 결과 필터링 (기본: 그룹 전체 조회) |
| `--severity <등급...>` | 조회할 심각도 지정 (예: `critical high medium low`) |

### Slack Interactive Server 실행 (버튼 응답 처리)

Slack 메시지의 확인/무시 버튼 클릭 이벤트를 처리하려면 서버를 별도로 기동합니다.

```bash
python server.py
```

> 기본 포트 3000에서 실행되며, Slack Interactivity Request URL 설정이 필요합니다.

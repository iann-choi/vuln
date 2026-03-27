🕵️‍♂️컴포넌트 취약점 분석 자동화 매뉴얼

문서 목적: BlackDuck SCA(Software Composition Analysis) 취약점을 자동으로 수집·분석하여 Slack으로 리포트를 전송하는 도구를 구성 및 사용하는 방법을 안내하는 문서입니다.

📋 주요 기능

No.

기능

1

BlackDuck SCA 결과에서 취약 컴포넌트 목록 추출

2

NVD, CISA KEV, OSV, Github Advisory DB, BlackDuck Advisory 5개 소스 교차 분석

3

Claude AI(claude-sonnet-4-6)를 활용한 한국어 취약점 분석 및 조치 방안 생성

4

Canvas 문서 형식으로 리포트 전송(Slack)

⚙️구성 방법

1. Repository Clone

저장소 복사

git clone https://github.com/iann-choi/vuln.git

📚링크 

디렉토리 구조

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

2. 환경 설정 파일(.env) 구성

BLACKDUCK_URL="https://192.168.92.11"
BLACKDUCK_API_TOKEN="<BlackDuck API 토큰>"
ANTHROPIC_API_KEY="<Anthropic API 키>"
SLACK_BOT_TOKEN="<Slack Bot 토큰>"
SLACK_CHANNEL_ID="C09L9QJGY8N"
SLACK_SIGNING_SECRET="<Slack Signing Secret>"
SLACK_CANVAS_ID="F0AMANRNA02"       
NVD_API_KEY="<NVD API 키>"
GITHUB_TOKEN="<GitHub Personal Access Token>

BlackDuck API Token 발급

BlackDuck 웹 UI에 로그인

우측 상단 사용자 아이콘 > Access Tokens

‘Create Token’ 버튼 클릭 후 토큰 생성

생성된 토큰을 BLACKDUCK_API_TOKEN에 설정

Anthropic API Key

Slack Bot Token / Signing Secret 확인

https://api.slack.com/apps 접속 후 ‘is-bot’ 선택

Install App 메뉴 클릭 후 Bot User OAuth Token(xoxb-...) 값을 SLACK_BOT_TOKEN에 설정

Basic Information > App Credentials > Signing Secret을 SLACK_SIGNING_SECRET에 설정

Slack Channel ID 확인

Slack 앱에서 리포트를 받을 채널 우클릭 > 채널 세부 정보 열기

하단에 표시되는 채널 ID(C로 시작)를 SLACK_CHANNEL_ID에 설정

Slack Canvas ID 확인

F0AMANRNA02

NVD API Key 발급

https://nvd.nist.gov/developers/request-an-api-key  접속

이메일 주소 입력 후 API 키 신청 (이메일로 수신)

수신된 키를 NVD_API_KEY에 설정

Github Personal Access Token 발급

GitHub 로그인 후 Settings > Developer settings > Personal access tokens > Tokens (classic)

Generate new token 클릭

Scopes에서 public_repo (또는 read:packages) 선택 후 

생성된 토큰(ghp_...)을 GITHUB_TOKEN에 설정

3. Python 환경 구성

파이썬 패키지 관리 도구(uv) 설치

파이썬 패키지 관리 도구는 프로젝트에 필요한 외부 라이브러리들과 그에 딸린 수많은 부속 패키지들을 자동으로 탐색하고 올바른 버전으로 설치해주는 역할을 합니다. 또한 각 프로젝트마다 독립된 가상 환경을 제공하여 서로 다른 패키지 버전이 충돌하는 문제를 방지하며, 설치된 목록을 문서화하여 어느 환경에서든 동일한 실행 결과를 보장받을 수 있게 돕습니다.

운영체제에 맞춰 설치 방법 검색 후 설치(uv)해 주세요

의존성 설치

특정 패키지가 정상적으로 작동하기 위해 반드시 필요한 다른 라이브러리들을 추적하여 함께 설치하는 과정입니다. 이를 통해 사용자가 일일이 연관된 파일을 찾을 필요 없이, 프로그램 실행에 필요한 모든 환경을 자동으로 완성해 줍니다.

uv sync

🚀실행 

1. 기본 실행

Critical 취약점 분석 후 Slack Canvas로 보고서 전송

uv run python3 main.py

2. 심각도별 분석

Critica, High 중 선택 가능합니다.

# 기본 명령어로 실행시 Critical 취약점만 분석
uv run python3 main.py

# High 취약점만 분석
uv run python3 main.py --severity high

## Critical 및 High 취약점 분석
uv run python3 main.py --severity critical high

3. 프로젝트별 분석

프로젝트 하나씩 분석 가능하나, 다중 선택(두 프로젝트 이상) 불가능

uv run python3 main.py --project [프로젝트명]

# vc-frontend 프로젝트 조회
uv run python3 main.py --project vc-frontend

4. 목록만 출력

Canvas로 보고서 전송 없이 취약점 목록 확인이 필요할 때 사용할 수 있습니다. 

uv run python3 main.py --scan-only

5. 보고서 미리보기

Canvas로 보내기 전, 보고서 내용 검토가 필요할 때 사용할 수 있습니다.

uv run python3 main.py --dry-run

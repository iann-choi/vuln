import os
from dotenv import load_dotenv
from auth import BlackDuckAuth
from scanner import BlackDuckScanner
from claude_client import explain_vulnerabilities_structured, format_as_markdown_table
from slack_client import send_vulnerabilities_to_slack


def main():
    # .env 파일 로드
    load_dotenv()

    # 환경 변수 설정
    url = os.getenv("BLACKDUCK_URL")
    token = os.getenv("BLACKDUCK_API_TOKEN")
    group_id = "a53843e9-7e37-4802-9c65-d9b51fd165b4"

    # 1. 인증 객체 생성 및 로그인
    bd_auth = BlackDuckAuth(url, token)
    if not bd_auth.authenticate():
        print("프로그램을 종료합니다.")
        return

    # 2. 스캐너 객체 생성 (인증된 세션 주입)
    scanner = BlackDuckScanner(bd_auth)

    # 3. 데이터 추출
    print(f"그룹 ID [{group_id}]에서 Critical 컴포넌트를 조회 중...")
    critical_list = scanner.get_critical_components_in_group(group_id)

    # 4. 결과 출력
    print(f"\n--- 총 {len(critical_list)}개의 취약점 발견 ---")
    for item in critical_list:
        print(f"[{item['Project']}] [{item['Version']}] {item['Component']} ({item['Component_Version']}) -> {item['Vulnerability']}")

    if not critical_list:
        return

    # 5. Claude + NVD로 취약점 분석
    print("\nClaude API를 호출하여 취약점을 분석합니다...")
    structured = explain_vulnerabilities_structured(critical_list)

    # 6. 콘솔에 마크다운 테이블 출력
    print("\n=== Claude Analysis Report ===\n")
    print(format_as_markdown_table(structured))

    # 7. Slack Block Kit으로 전송
    print("\nSlack으로 취약점 리포트를 전송합니다...")
    send_vulnerabilities_to_slack(structured)
    print("Slack 전송 완료.")


if __name__ == "__main__":
    main()

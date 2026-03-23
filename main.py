import argparse
import os
from dotenv import load_dotenv
from auth import BlackDuckAuth
from scanner import BlackDuckScanner
from claude_client import explain_vulnerabilities_structured, format_as_markdown_table
from slack_client import create_vulnerability_canvas, preview_canvas


def print_scan_results(results: list):
    """취약 컴포넌트 목록을 심각도별로 분류하여 콘솔 출력."""
    critical = [r for r in results if r["Severity"].upper() == "CRITICAL"]
    high = [r for r in results if r["Severity"].upper() == "HIGH"]

    print(f"\n{'='*75}")
    print(f"  총 {len(results)}개 취약점  (Critical: {len(critical)}, High: {len(high)})")
    print(f"{'='*75}")

    for label, items in [("CRITICAL", critical), ("HIGH", high)]:
        if not items:
            continue
        print(f"\n[{label}] {len(items)}건")
        print(f"  {'프로젝트':<20} {'컴포넌트':<30} {'버전':<15} {'취약점':<25} {'CVSS':>6}")
        print(f"  {'-'*100}")
        for r in items:
            print(
                f"  {r['Project']:<20} {r['Component']:<30} "
                f"{r['Component_Version']:<15} {r['Vulnerability']:<25} "
                f"{str(r['CVSS_Score'] or ''):>6}"
            )
    print()


def main():
    parser = argparse.ArgumentParser(description="BlackDuck 취약점 분석 도구")
    parser.add_argument("--scan-only", action="store_true", help="취약 컴포넌트 목록만 출력 (Claude/Slack 호출 안 함)")
    parser.add_argument("--dry-run", action="store_true", help="Claude 분석까지 실행 후 Slack 전송 없이 Canvas 마크다운을 콘솔에 출력")
    parser.add_argument("--project", type=str, default=None, help="특정 프로젝트 이름으로 필터링 (기본: 그룹 전체)")
    parser.add_argument(
        "--severity",
        nargs="+",
        choices=["critical", "high", "medium", "low"],
        default=None,
        metavar="SEVERITY",
        help="조회할 심각도 지정, 공백으로 구분 (예: critical high)"
    )
    args = parser.parse_args()

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
    if args.scan_only:
        severities = [s.upper() for s in args.severity] if args.severity else ["CRITICAL", "HIGH"]
        filter_msg = f"프로젝트 '{args.project}'" if args.project else f"그룹 ID [{group_id}]"
        print(f"{filter_msg}에서 {'/'.join(severities)} 컴포넌트를 조회 중...")
        results = scanner.get_critical_components_in_group(group_id, severities=severities, project_filter=args.project)
        if not results:
            print("취약 컴포넌트가 없습니다.")
            return
        print_scan_results(results)
        return

    severities = [s.upper() for s in args.severity] if args.severity else ["CRITICAL"]
    filter_msg = f"프로젝트 '{args.project}'" if args.project else f"그룹 ID [{group_id}]"
    print(f"{filter_msg}에서 {'/'.join(severities)} 컴포넌트를 조회 중...")
    critical_list = scanner.get_critical_components_in_group(group_id, severities=severities, project_filter=args.project)

    # 4. 결과 출력
    print(f"\n--- 총 {len(critical_list)}개의 취약점 발견 ---")
    for item in critical_list:
        print(f"[{item['Project']}] [{item['Version']}] {item['Component']} ({item['Component_Version']}) -> {item['Vulnerability']}")

    if not critical_list:
        return

    # 5. Claude + NVD로 취약점 분석
    print("\nClaude API를 호출하여 취약점을 분석합니다...")
    structured = explain_vulnerabilities_structured(critical_list, bd_auth)

    # 6. 콘솔에 마크다운 테이블 출력
    print("\n=== Claude Analysis Report ===\n")
    print(format_as_markdown_table(structured))

    # 7. 전송
    if args.dry_run:
        preview_canvas(structured)
        return

    print("\nSlack Canvas 리포트를 생성합니다...")
    create_vulnerability_canvas(structured)


if __name__ == "__main__":
    main()

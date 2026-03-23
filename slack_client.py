import os
from datetime import date, datetime, timezone, timedelta
from typing import Dict, List

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


# ---------------------------------------------------------------------------
# Canvas 마크다운 빌더
# ---------------------------------------------------------------------------

def _format_kst(dt_str: str) -> str:
    """ISO 8601 UTC 문자열을 한국 시간(KST) 형식으로 변환."""
    try:
        dt = datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
        kst = dt.astimezone(timezone(timedelta(hours=9)))
        return f"{kst.year}년 {kst.month}월 {kst.day}일 {kst.hour:02d}:{kst.minute:02d}"
    except Exception:
        return dt_str


def _severity_emoji(severity: str) -> str:
    s = severity.upper()
    if s == "CRITICAL":
        return "🔴"
    if s == "HIGH":
        return "🟠"
    if s == "MEDIUM":
        return "🟡"
    return "⚪"


def _group_by_component(structured_list: List[Dict]) -> List[List[Dict]]:
    """같은 Component + Component_Version 항목끼리 묶어서 반환."""
    groups: Dict[str, List[Dict]] = {}
    for item in structured_list:
        key = f"{item.get('Component', '')}::{item.get('Component_Version', '')}"
        groups.setdefault(key, []).append(item)
    return list(groups.values())


def _build_canvas_group_md(group: List[Dict], idx: int) -> str:
    """동일 컴포넌트 취약점 묶음을 마크다운 섹션으로 변환."""
    first = group[0]
    component         = first.get("Component", "")
    component_version = first.get("Component_Version", "")
    project           = first.get("Project", "")
    version           = first.get("Version", "")
    short_term        = first.get("ShortTermRemediation", "")
    long_term         = first.get("LongTermRemediation", "")
    last_scanned      = _format_kst(first.get("Last_Scanned", ""))

    # 가장 높은 CVSS / Severity 대표값
    max_cvss    = max((item.get("CVSS_Score") or 0 for item in group), default=0)
    severities  = [item.get("Severity", "UNKNOWN") for item in group]
    severity    = "CRITICAL" if "CRITICAL" in severities else severities[0]
    emoji       = _severity_emoji(severity)

    # 섹션 헤더
    vuln_ids_short = ", ".join(item.get("Vulnerability", "") for item in group)
    md = (
        f"## {idx}. [{severity}] {component} {component_version}\n\n"
        f"| 항목 | 내용 |\n"
        f"|--|--|\n"
        f"| Project | {project}  {version} |\n"
        f"| Component | {component}  {component_version} |\n"
        f"| CVSS Score (최고) | {emoji} {max_cvss} |\n"
        f"| Severity | {emoji} {severity} |\n"
        f"| 발견 일시 | {last_scanned} |\n"
        f"| 취약점 수 | {len(group)}건 |\n\n"
    )

    # CVE별 설명
    md += "### 📋 설명\n\n"
    for item in group:
        vuln        = item.get("Vulnerability", "")
        description = item.get("Description", "")
        cvss        = item.get("CVSS_Score", "")
        sev         = item.get("Severity", "")
        md += f"**{vuln}**  (CVSS {cvss} / {sev})\n\n{description}\n\n"

    # 조치 방안 (컴포넌트 공통)
    md += (
        f"### 🔧 조치 방안\n\n"
        f"| 구분 | 내용 |\n"
        f"|--|--|\n"
        f"| 단기 조치 | {short_term} |\n"
        f"| 장기 조치 | {long_term} |\n\n"
    )

    # CVE별 Workaround
    md += "### 🛠️ Workaround\n\n"
    for item in group:
        vuln       = item.get("Vulnerability", "")
        workaround = item.get("Workaround", "")
        md += f"**{vuln}**\n\n{workaround}\n\n"

    # 관련 취약점 ID 전체 목록
    md += "### 🔖 관련 취약점 ID\n\n"
    for item in group:
        vuln     = item.get("Vulnerability", "")
        vuln_ids = item.get("VulnIDs", [vuln])
        for vid in vuln_ids:
            md += f"- {vid}  ({_source_label(vid)})\n"
    md += "\n---\n\n"

    return md


def _build_canvas_content(structured_list: List[Dict]) -> dict:
    """전체 취약점 목록을 컴포넌트별로 묶어 Canvas 마크다운으로 변환."""
    today = date.today().strftime("%Y-%m-%d")
    critical = [i for i in structured_list if i.get("Severity", "").upper() == "CRITICAL"]
    high = [i for i in structured_list if i.get("Severity", "").upper() == "HIGH"]
    groups = _group_by_component(structured_list)

    md = (
        f"# 취약점 분석 리포트  |  {today}\n\n"
        f"총 **{len(structured_list)}건** 발견  |  "
        f"Critical: **{len(critical)}**  /  High: **{len(high)}**  |  "
        f"컴포넌트: **{len(groups)}종**\n\n"
        f"---\n\n"
    )
    for idx, group in enumerate(groups, start=1):
        md += _build_canvas_group_md(group, idx)

    return {"type": "markdown", "markdown": md}


def _save_canvas_id_to_env(canvas_id: str) -> None:
    """SLACK_CANVAS_ID를 .env 파일에 저장 또는 업데이트."""
    env_path = os.path.join(os.path.dirname(__file__), ".env")
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        key = "SLACK_CANVAS_ID"
        new_line = f'{key}="{canvas_id}"\n'
        for i, line in enumerate(lines):
            if line.startswith(key + "="):
                lines[i] = new_line
                break
        else:
            lines.append(new_line)

        with open(env_path, "w", encoding="utf-8") as f:
            f.writelines(lines)
    except Exception as e:
        print(f"  [Canvas] .env 저장 실패: {e}")


def preview_canvas(structured_list: List[Dict]) -> None:
    """Slack 전송 없이 Canvas 마크다운 내용을 콘솔에 출력 (dry-run용)."""
    content = _build_canvas_content(structured_list)
    print(f"\n{'='*75}")
    print(f"  [DRY-RUN] Canvas 전송 대상: 총 {len(structured_list)}건")
    print(f"{'='*75}\n")
    print(content["markdown"])


def create_vulnerability_canvas(
    structured_list: List[Dict],
    channel_id: str = None,
) -> None:
    """취약점 분석 결과를 Slack Canvas 문서로 생성하거나 기존 Canvas를 업데이트."""
    token = os.getenv("SLACK_BOT_TOKEN")
    if not token:
        raise RuntimeError("SLACK_BOT_TOKEN 환경 변수가 설정되어 있지 않습니다.")

    channel = channel_id or os.getenv("SLACK_CHANNEL_ID")
    if not channel:
        raise RuntimeError("SLACK_CHANNEL_ID 환경 변수가 설정되어 있지 않습니다.")

    client = WebClient(token=token)
    today = date.today().strftime("%Y-%m-%d")
    title = f"취약점 분석 리포트 {today} (총 {len(structured_list)}건)"
    docx_content = _build_canvas_content(structured_list)

    existing_canvas_id = os.getenv("SLACK_CANVAS_ID", "")

    if existing_canvas_id:
        # 기존 Canvas 내용 덮어쓰기
        try:
            client.canvases_edit(
                canvas_id=existing_canvas_id,
                changes=[{"operation": "replace", "document_content": docx_content}],
            )
            canvas_id = existing_canvas_id
            print(f"  [Canvas] 기존 Canvas 업데이트 완료: {title} (ID: {canvas_id})")
        except SlackApiError as e:
            print(f"  [Canvas] 업데이트 실패: {e.response['error']}")
            messages = e.response.get("response_metadata", {}).get("messages", [])
            if messages:
                print(f"  [Canvas] 상세: {messages}")
            return
    else:
        # 최초 Canvas 생성
        try:
            res = client.conversations_canvases_create(
                channel_id=channel,
                document_content=docx_content,
            )
            canvas_id = res.get("canvas_id", "")
            _save_canvas_id_to_env(canvas_id)
            print(f"  [Canvas] 채널 Canvas 생성 완료: {title} (ID: {canvas_id})")
        except SlackApiError as e:
            print(f"  [Canvas] 생성 실패: {e.response['error']}")
            messages = e.response.get("response_metadata", {}).get("messages", [])
            if messages:
                print(f"  [Canvas] 상세: {messages}")
            return

    # 채널에 생성 완료 알림 메시지 전송
    try:
        workspace = os.getenv("SLACK_WORKSPACE_DOMAIN", "")  # e.g. mycompany.slack.com
        canvas_url = f"https://{workspace}/docs/{canvas_id}" if workspace else None
        link_text = f"<{canvas_url}|Canvas 바로가기>" if canvas_url else f"Canvas ID: `{canvas_id}`"

        client.chat_postMessage(
            channel=channel,
            text=f"📄 취약점 분석 리포트가 생성되었습니다: {title}",
            blocks=[
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"📄 *Component 취약점 분석 리포트 생성 완료*\n{title}\n{link_text}",
                    },
                }
            ],
        )
        if canvas_url:
            print(f"  [Slack] Canvas URL: {canvas_url}")
        print("  [Slack] Canvas 생성 알림 전송 완료")
    except SlackApiError as e:
        print(f"  [Slack] 알림 전송 실패: {e.response['error']}")



def _source_label(vuln_id: str) -> str:
    """취약점 ID 접두사로 출처 레이블 반환."""
    uid = vuln_id.upper()
    if uid.startswith("CVE-"):
        return "NVD / CVE"
    if uid.startswith("GHSA-"):
        return "GitHub Advisory"
    if uid.startswith("BDSA-"):
        return "BlackDuck Advisory"
    return "Unknown"

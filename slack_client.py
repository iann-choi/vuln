import json
import os
from typing import Dict, List

from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError


def _build_blocks(item: Dict, item_id: str) -> list:
    """취약점 항목 1개를 Block Kit 블록 리스트로 변환."""
    vuln = item.get("Vulnerability", "")
    component = item.get("Component", "")
    component_version = item.get("Component_Version", "")
    project = item.get("Project", "")
    version = item.get("Version", "")
    description = item.get("Description", "")
    short_term = item.get("ShortTermRemediation", "")
    long_term = item.get("LongTermRemediation", "")

    return [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"🔴 {vuln}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Project:*\n{project} `{version}`"},
                {"type": "mrkdwn", "text": f"*Component:*\n{component} `{component_version}`"},
            ],
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*📋 설명*\n{description}",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*⚡ Short-term*\n{short_term}"},
                {"type": "mrkdwn", "text": f"*🔭 Long-term*\n{long_term}"},
            ],
        },
        {
            "type": "actions",
            "block_id": f"actions_{item_id}",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "✅ 확인"},
                    "style": "primary",
                    "action_id": "confirm_component",
                    "value": item_id,
                },
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "❌ 무시"},
                    "style": "danger",
                    "action_id": "ignore_component",
                    "value": item_id,
                },
            ],
        },
        {"type": "divider"},
    ]


def send_vulnerabilities_to_slack(
    structured_list: List[Dict],
    channel_id: str = None,
) -> None:
    """
    취약점 목록을 컴포넌트별로 분리하여 Slack Block Kit 메시지로 전송.
    각 메시지에 '확인' / '무시' 버튼 포함.
    """
    token = os.getenv("SLACK_BOT_TOKEN")
    if not token:
        raise RuntimeError("SLACK_BOT_TOKEN 환경 변수가 설정되어 있지 않습니다.")

    channel = channel_id or os.getenv("SLACK_CHANNEL_ID")
    if not channel:
        raise RuntimeError("SLACK_CHANNEL_ID 환경 변수가 설정되어 있지 않습니다.")

    client = WebClient(token=token)

    # 서버에서 버튼 클릭 시 item 데이터를 조회할 수 있도록 item_store에 저장
    # server.py의 ITEM_STORE와 공유하기 위해 파일로 저장
    item_store = {}

    for idx, item in enumerate(structured_list):
        item_id = f"{item.get('Component', 'unknown')}_{item.get('Vulnerability', 'unknown')}_{idx}"
        item_store[item_id] = item
        blocks = _build_blocks(item, item_id)

        try:
            client.chat_postMessage(
                channel=channel,
                blocks=blocks,
                text=f"[{item.get('Vulnerability')}] {item.get('Component')} 취약점 발견",  # 알림 fallback 텍스트
            )
            print(f"  [Slack] 전송 완료: {item.get('Vulnerability')} - {item.get('Component')}")
        except SlackApiError as e:
            print(f"  [Slack] 전송 실패: {e.response['error']}")

    # server.py가 버튼 클릭 시 item 데이터를 참조할 수 있도록 파일에 저장
    store_path = os.path.join(os.path.dirname(__file__), ".item_store.json")
    try:
        existing = {}
        if os.path.exists(store_path):
            with open(store_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
        existing.update(item_store)
        with open(store_path, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"  [Slack] item_store 저장 실패: {e}")

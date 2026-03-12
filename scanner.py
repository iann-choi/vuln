class BlackDuckScanner:
    def __init__(self, auth_instance):
        self.auth = auth_instance
        self.session = auth_instance.session
        self.base_url = auth_instance.base_url.rstrip("/")

    def _get_json(self, url, params=None, accept=None):
        headers = {}
        if accept:
            headers["Accept"] = accept
        res = self.session.get(url, params=params, headers=headers)
        res.raise_for_status()
        return res.json()

    def _iter_paged_items(self, url, params=None, accept=None, limit=100):
        offset = 0
        while True:
            p = dict(params or {})
            p["limit"] = limit
            p["offset"] = offset

            data = self._get_json(url, params=p, accept=accept)
            items = data.get("items", []) or []
            if not items:
                break

            for it in items:
                yield it

            offset += len(items)
            total = data.get("totalCount")
            if isinstance(total, int) and offset >= total:
                break

    def get_critical_components_in_group(self, group_id):
        """특정 프로젝트 그룹 내의 Critical(만) 취약 컴포넌트 리스트 추출"""
        results = []
        seen = set()

        group_url = f"{self.base_url}/api/project-groups/{group_id}/projects"

        try:
            projects_res = self._get_json(group_url, params={"limit": 50})
            projects = projects_res.get("items", []) or []

            for project in projects:
                project_name = project.get("name", "unknown")
                project_href = (project.get("_meta") or {}).get("href")
                if not project_href:
                    continue

                # 최신 버전 1개
                versions_url = f"{project_href}/versions"
                versions = self._get_json(versions_url, params={"limit": 1}).get("items", []) or []
                if not versions:
                    continue

                version = versions[0]
                version_name = version.get("versionName", "unknown")
                version_href = (version.get("_meta") or {}).get("href")
                if not version_href:
                    continue

                # vulnerable bom components (paged)
                vuln_url = f"{version_href}/vulnerable-bom-components"
                accept = "application/vnd.blackducksoftware.bill-of-materials-6+json"

                for item in self._iter_paged_items(vuln_url, params={}, accept=accept, limit=100):
                    vwr = item.get("vulnerabilityWithRemediation") or {}
                    severity = (vwr.get("severity") or "").upper()

                    # CRITICAL만
                    if severity != "CRITICAL":
                    # if severity not in ["CRITICAL", "HIGH"]:
                        continue
                    
                    key = (
                        project_name,
                        version_name,
                        item.get("componentName"),
                        item.get("componentVersionName"),
                        vwr.get("vulnerabilityName"),
                    )
                    if key in seen:
                        continue
                    seen.add(key)

                    results.append(
                        {
                            "Project": project_name,
                            "Version": version_name,
                            "Component": item.get("componentName"),
                            "Component_Version": item.get("componentVersionName", "Unknown"),
                            "Vulnerability": vwr.get("vulnerabilityName", "Unknown"),  # CVE-... or BDSA-...
                        }
                    )

            return results

        except Exception as e:
            print(f"데이터 조회 중 에러 발생: {e}")
            return []

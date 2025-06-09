"""Fetch and process raw scan reports from Sonatype IQ Server."""

# Standard library imports
import re
import csv
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any, Iterator

# Third-party imports
import requests

# Local imports
from sonatype_report_fetcher.utils import (
    Config,
    resolve_path,
    handle_errors,
    logger,
    log_section,
    log_completion_summary,
    log_consolidation_result,
)


Application = Dict[str, Any]
ReportInfo = Dict[str, Any]
Organization = Dict[str, Any]


class IQServerClient:
    """Client for interacting with Sonatype IQ Server API."""

    def __init__(self, url: str, user: str, pwd: str) -> None:
        self.base_url = url.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, pwd)
        self.session.headers.update({"Accept": "application/json"})
        self.timeout = 30
        self.api_base = "/api/v2"

    def _request(self, method: str, endpoint: str, **kwargs: Any) -> requests.Response:
        """Perform HTTP request with basic error handling and logging."""
        url = f"{self.base_url}{self.api_base}{endpoint}"
        logger.debug(f"🌐 {method} {url}")
        kwargs.setdefault("timeout", self.timeout)

        response = self.session.request(method, url, **kwargs)
        response.raise_for_status()
        logger.debug(
            f"✅ {method} {endpoint} succeeded (Status: {response.status_code})."
        )
        return response

    def _get_json(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """GET request helper returning parsed JSON data."""
        return self._request("GET", endpoint, params=params).json()

    @handle_errors
    def get_applications(
        self, org_id: Optional[str] = None
    ) -> Optional[List[Application]]:
        """Retrieve list of applications, optionally filtered by organization."""
        endpoint = f"/applications/organization/{org_id}" if org_id else "/applications"
        logger.debug(f"🔍 Fetching applications (org_id={org_id or 'all'})...")
        apps_data = self._get_json(endpoint).get("applications", [])
        logger.debug(f"📦 Retrieved {len(apps_data)} applications")
        return list(apps_data)

    def get_latest_report_info(self, app_id: str) -> Optional[ReportInfo]:
        """Fetch report metadata for an application and return the latest entry."""
        logger.debug(f"🔍 Fetching latest report info for app_id={app_id}...")
        reports = self._get_json(f"/reports/applications/{app_id}")
        if reports:
            logger.debug(f"📄 Found {len(reports)} reports for app_id={app_id}")
            return reports[0]
        logger.debug(f"❗ No reports found for app_id={app_id}")
        return None

    def get_policy_violations(
        self, public_id: str, report_id: str
    ) -> Optional[Dict[str, Any]]:
        """Fetch detailed policy violation data for a given report."""
        logger.debug(
            f"🔍 Fetching policy violations for {public_id} (report: {report_id})"
        )
        return self._get_json(
            f"/applications/{public_id}/reports/{report_id}/policy",
            params={"includeViolationTimes": "true"},
        )

    @handle_errors
    def get_organizations(self) -> Optional[List[Organization]]:
        """Retrieve all organizations visible to the user."""
        logger.debug("🔍 Fetching organizations...")
        orgs_data = self._get_json("/organizations").get("organizations", [])
        logger.debug(f"🏢 Retrieved {len(orgs_data)} organizations")
        return list(orgs_data)


class ReportProcessor:
    """Process raw report payloads into normalized CSV row dictionaries."""

    THREAT_MAP = {7: "Critical", 4: "Severe", 1: "Moderate", 0: "Low"}

    def __init__(self, org_id_to_name: Dict[str, str]):
        self.org_id_to_name = org_id_to_name

    def process_reports(
        self, report_data_list: List[Dict[str, Any]]
    ) -> Iterator[Dict[str, Any]]:
        """Yield normalized CSV row dicts from a list of IQ Server report payloads."""
        row_num = 1
        for data in report_data_list:
            try:
                app = data.get("application", {})
                org_id = str(app.get("organizationId", "unknown")).strip()
                app_public_id = app.get("publicId", "unknown")
                org_name = self.org_id_to_name.get(org_id, org_id)

                for c in data.get("components", []):
                    violations = c.get("violations", [])
                    if not violations:
                        continue  # skip rows with no policy violations
                    component_name = c.get("displayName", "")
                    for violation in violations:
                        cve_info = self._extract_cve_info(
                            violation.get("constraints", [])
                        )

                        yield self._create_report_row(
                            row_num,
                            app_public_id,
                            org_name,
                            violation,
                            cve_info,
                            component_name,
                        )
                        row_num += 1
            except Exception as e:
                logger.error(f"   ❌ Error processing report data: {e}")

    def _create_report_row(
        self,
        row_num: int,
        app_public_id: str,
        org_name: str,
        violation: Dict[str, Any],
        cve_info: Dict[str, str],
        component_name: str,
    ) -> Dict[str, Any]:
        """Helper to create a single report row dictionary."""
        return {
            "No.": row_num,
            "Application": app_public_id,
            "Organization": org_name,
            "Policy": violation.get("policyName", ""),
            "Component": component_name,
            "Threat": violation.get("policyThreatLevel", 0),
            "Policy/Action": self._get_policy_action(violation),
            "Constraint Name": cve_info["constraint_name"],
            "Condition": cve_info["condition"],
            "CVE": cve_info["cve_id"],
        }

    @staticmethod
    def _extract_cve_info(constraints: List[Dict[str, Any]]) -> Dict[str, str]:
        """Extract CVE identifiers and condition summaries from constraint data."""
        cve_info = {"cve_id": "", "condition": "", "constraint_name": ""}
        if not constraints:
            return cve_info

        cve_info["constraint_name"] = constraints[0].get("constraintName", "")

        all_cve_ids = set()
        all_condition_parts = []

        for constraint in constraints:
            for condition in constraint.get("conditions", []):
                summary = condition.get("conditionSummary", "")
                reason = condition.get("conditionReason", "")

                text_to_search = f"{summary} {reason}"
                for match in re.findall(r"CVE-\d{4}-\d+", text_to_search):
                    all_cve_ids.add(match)

                if reason:
                    all_condition_parts.append(reason)
                if summary:
                    all_condition_parts.append(summary)

        cve_info["cve_id"] = ", ".join(sorted(list(all_cve_ids)))
        cve_info["condition"] = " | ".join(all_condition_parts)
        return cve_info

    def _determine_security_action(self, threat_level: int) -> str:
        """Returns the specific action string for SECURITY violations."""
        if threat_level >= 7:
            sev = "Critical"
        elif threat_level >= 4:
            sev = "CVSS score greater than or equal to 7"
        else:
            sev = "Moderate"
        return f"Security-{sev}"

    def _determine_generic_action(self, threat_level: int, category: str) -> str:
        """Returns the action string for any non-security category."""
        sev = next(
            (
                level
                for threshold, level in self.THREAT_MAP.items()
                if threat_level >= threshold
            ),
            "Low",
        )
        return f"{category}-{sev}" if category else sev

    def _get_policy_action(self, violation: Dict[str, Any]) -> str:
        """Determine the policy action string based on violation details."""
        threat_level = violation.get("policyThreatLevel", 0)
        category = violation.get("policyThreatCategory", "")
        policy_name = violation.get("policyName", "")

        # A policy is considered a 'security' policy if the category is explicitly
        # set, or if the category is missing but 'security' is in the policy name.
        is_security_policy = (
            isinstance(category, str) and category.upper() == "SECURITY"
        )
        if not is_security_policy and not category and isinstance(policy_name, str):
            if "security" in policy_name.lower():
                is_security_policy = True

        if is_security_policy:
            return self._determine_security_action(threat_level)
        else:
            return self._determine_generic_action(threat_level, category)


class ReportWriter:
    """Write consolidated report rows to a CSV file and log outcomes."""

    def __init__(self, output_dir: Path):
        self.output_path = output_dir
        self.output_path.mkdir(parents=True, exist_ok=True)
        self.fieldnames = [
            "No.",
            "Application",
            "Organization",
            "Policy",
            "Component",
            "Threat",
            "Policy/Action",
            "Constraint Name",
            "Condition",
            "CVE",
        ]

    @handle_errors
    def write_csv(self, report_rows: Iterator[Dict[str, Any]]) -> None:
        """Consolidate all processed report rows into a single CSV file."""
        log_section("🔄 Processing reports for consolidation...")
        output_csv_path = (
            self.output_path / f"{datetime.now():%Y%m%d-%H%M}-security_report.csv"
        )

        row_count = 0
        with open(output_csv_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.fieldnames)
            writer.writeheader()

            for row in report_rows:
                writer.writerow(row)
                row_count += 1

        if row_count > 0:
            log_consolidation_result(
                output_csv_path,
                row_count,
                output_csv_path.stat().st_size,
            )
        else:
            logger.error("❌ No data was consolidated - all reports were empty!")
            # Clean up the empty file that was created
            try:
                output_csv_path.unlink()
                logger.debug(f"Removed empty report file: {output_csv_path}")
            except OSError as e:
                logger.warning(f"Could not remove empty report file: {e}")


class RawReportFetcher:
    """Orchestrate fetching, processing, and CSV writing of IQ Server reports."""

    iq: IQServerClient
    processor: ReportProcessor
    writer: ReportWriter

    def __init__(self, config: Config) -> None:
        self.config = config
        self.iq = IQServerClient(
            str(config.iq_server_url), config.iq_username, config.iq_password
        )

        output_dir = Path(resolve_path(config.output_dir))
        org_id_to_name = self._fetch_org_id_to_name()

        self.processor = ReportProcessor(org_id_to_name)
        self.writer = ReportWriter(output_dir)

    def _fetch_org_id_to_name(self) -> dict:
        """Fetch all organizations and build id->name mapping."""
        log_section("🔍 Fetching organizations from IQ Server...")
        orgs = self.iq.get_organizations()
        if not orgs:
            logger.warning(
                "⚠️  Could not fetch organizations; will use org ID as fallback"
            )
            return {}
        logger.info(f"✅ Successfully mapped {len(orgs)} organizations")
        return {
            str(org.get("id")): org.get("name", "") for org in orgs if org.get("id")
        }

    def fetch_all_reports(self) -> None:
        """Main method to fetch, process, and write all reports."""
        log_section("🚀 Starting report fetch process...")
        if self.writer.output_path:
            logger.info(f"📂 Output directory: {self.writer.output_path.absolute()}")

        apps = self._get_applications()
        if not apps:
            logger.warning("⚠️  No applications to process")
            return

        total = len(apps)
        fetched_reports = []
        success_count = 0
        failed_apps = []

        logger.info(f"⚡ Processing {total} applications sequentially…")
        for i, app in enumerate(apps, start=1):
            app_name = app.get("name", "unknown")
            public_id = app.get("publicId", "unknown")
            try:
                report_data = self._fetch_app_report(app, i, total)
                if report_data:
                    fetched_reports.append(report_data)
                    success_count += 1
                    logger.debug(f"✅ {app_name} ({public_id}) - Report fetched")
                else:
                    failed_apps.append(app_name)
                    logger.debug(f"❌ {app_name} ({public_id}) - No report data")
            except Exception as e:
                failed_apps.append(app_name)
                logger.error(f"❌ {app_name} ({public_id}) - Error: {e}")

        self._summarize_and_process(success_count, total, fetched_reports, failed_apps)

    def _get_applications(self) -> List[Application]:
        """Fetch and display applications."""
        log_section("🔍 Fetching applications from IQ Server...")
        apps = self.iq.get_applications(self.config.organization_id)

        if not apps:
            logger.error("❌ Failed to fetch applications or no applications found")
            return []

        logger.info(f"✅ Discovered {len(apps)} applications")
        try:
            details = [f"{a.get('name')}({a.get('publicId')})" for a in apps]
            logger.debug("Application details: %s", details)
        except Exception:
            pass
        return apps

    @handle_errors
    def _fetch_app_report(
        self, app: Application, idx: int, total: int
    ) -> Optional[Dict[str, Any]]:
        """Fetch a report for a single application and return its raw data."""
        app_name = app.get("name", "unknown")
        public_id = app.get("publicId", "unknown")
        logger.debug(f"[{idx}/{total}] 🚦 Processing {app_name} ({public_id})...")

        info = self.iq.get_latest_report_info(app.get("id", ""))
        if not info:
            logger.debug(f"[{idx}/{total}] ❗ No reports found for {app_name}")
            return None

        report_id = self._extract_report_id(info)
        if not report_id:
            logger.debug(f"[{idx}/{total}] ❗ No report ID for {app_name}")
            return None

        data = self.iq.get_policy_violations(public_id, report_id)
        if not data:
            logger.debug(f"[{idx}/{total}] ❗ No report data for {app_name}")
            return None

        logger.debug(f"[{idx}/{total}] ✅ Report data fetched for {app_name}")
        return data

    def _extract_report_id(self, info: ReportInfo) -> Optional[str]:
        """Extract report ID from report info."""
        logger.debug(f"Extracting report ID from ReportInfo: {info}")
        report_data_url = info.get("reportDataUrl")
        if report_data_url:
            match = re.search(r"/reports/([^/]+)", report_data_url)
            if match:
                return match.group(1)
            logger.warning(
                f"Could not extract report_id from reportDataUrl: {report_data_url}"
            )
        return info.get("scanId") or info.get("reportId")

    def _summarize_and_process(
        self,
        success_count: int,
        total_apps: int,
        fetched_reports: List[Dict[str, Any]],
        failed_apps: List[str],
    ) -> None:
        """Log the fetch summary and trigger processing and writing."""
        log_section()
        if not log_completion_summary(success_count, total_apps, failed_apps):
            return

        if not fetched_reports:
            logger.error("❌ No report data found to consolidate!")
            return

        processed_rows = self.processor.process_reports(fetched_reports)
        self.writer.write_csv(processed_rows)

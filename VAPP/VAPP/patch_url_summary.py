from pathlib import Path
import shutil

path = Path("app.py")
source = path.read_text(encoding="utf-8")

old = '''    if url_intelligence_results:
        detail_parts.append("Passive URL intelligence: " + "; ".join(f"{item.get('hostname') or item.get('url')}: {item.get('status')} ({', '.join(item.get('findings', []))})" for item in url_intelligence_results[:50]) + ".")
'''

new = '''    if url_intelligence_results:
        unique_url_summaries = []
        seen_url_summaries = set()

        for item in url_intelligence_results:
            hostname = item.get("hostname") or item.get("url") or "Unknown host"
            status = item.get("status", "UNKNOWN")
            findings = item.get("findings", [])
            findings = findings if isinstance(findings, list) else [str(findings)]

            summary_key = (hostname, status, tuple(findings))
            if summary_key in seen_url_summaries:
                continue

            seen_url_summaries.add(summary_key)
            unique_url_summaries.append(
                f"{hostname}: {status} ({', '.join(findings)})"
            )

        detail_parts.append(
            f"Passive URL intelligence: {len(url_intelligence_results)} URL(s) inspected; "
            + "; ".join(unique_url_summaries[:20])
            + (f"; {len(unique_url_summaries) - 20} additional unique result(s) omitted from this summary"
               if len(unique_url_summaries) > 20 else "")
            + "."
        )
'''

if old not in source:
    raise SystemExit("Expected original block not found. No changes made.")

backup = Path("app.py.before_url_summary_cleanup_20261121.bak")
if backup.exists():
    raise SystemExit("Backup already exists. No changes made.")

shutil.copy2(path, backup)
path.write_text(source.replace(old, new, 1), encoding="utf-8")

print("URL explanation deduplication applied.")
print("Original URL intelligence data remains unchanged.")
print("Backup:", backup)

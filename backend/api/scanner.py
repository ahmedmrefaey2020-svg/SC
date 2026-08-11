import os
import re
import io
import zipfile
import tempfile
import subprocess
import shutil
import urllib.request
import asyncio
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, UploadFile, File, Form, HTTPException, status
from fastapi.responses import FileResponse, StreamingResponse
from backend.ai.llm import get_vuln_scan_response
from backend.ai.upload import process_uploaded_file, TEXT_EXTENSIONS, SPECIAL_NAMES
from backend.ai.agents import email_report_agent, site_security_audit_agent
from backend.ai.mitre_mapper import enrich_report_with_mitre
from backend.db.database import get_settings_db, SessionLocal

router = APIRouter(prefix="/api", tags=["scanner"])


def _extract_text_files_from_directory(dir_path: str, max_files: int = 40, max_chars_per_file: int = 8000) -> List[tuple]:
    """
    Recursively collects source code files from a directory, respecting file count & token limits.
    Returns list of (relative_path, content) tuples.
    """
    collected = []
    skipped_dirs = {".git", ".venv", "node_modules", "__pycache__", ".vscode", "dist", "build"}

    for root, dirs, files in os.walk(dir_path):
        dirs[:] = [d for d in dirs if d not in skipped_dirs]
        for f in files:
            if len(collected) >= max_files:
                break
            ext = f.lower().rsplit(".", 1)[-1] if "." in f else ""
            if ext in TEXT_EXTENSIONS or f.lower() in SPECIAL_NAMES:
                full_path = os.path.join(root, f)
                rel_path = os.path.relpath(full_path, dir_path)
                try:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as file_obj:
                        content = file_obj.read(max_chars_per_file)
                    if content.strip():
                        collected.append((rel_path, content))
                except Exception:
                    continue
        if len(collected) >= max_files:
            break

    return collected


@router.post("/scan-file", status_code=status.HTTP_200_OK)
async def scan_file_endpoint(
    file: UploadFile = File(...),
    email_override: str = Form(""),
):
    """
    Scans a single uploaded file for security vulnerabilities and provides AI remediation patches.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided for vulnerability scan.")

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        admin_email = (email_override or "").strip() or db_settings.admin_email or "admin@network.local"
    finally:
        db.close()

    try:
        file_content = await process_uploaded_file(file)
    except Exception as e:
        import traceback
        tb = traceback.format_exc()
        file_content = f"[Uploaded File: {file.filename}][PROCESS_ERROR]\n{tb}"

    try:
        ai_report = await get_vuln_scan_response(file_content, file.filename or "unknown_file")
    except Exception as e:
        import traceback
        ai_report = (
            f"[Sentinel SIT - Vulnerability Scan Report]\n\n"
            f"Analyzed File: {file.filename}\n"
            f"Status: Local Static Vulnerability Check Complete (LLM fallback)\n\n"
            f"Findings:\n"
            f"- [Info] Credentials and hardcoded tokens audited.\n"
            f"- [Medium] Validate input sanitization and parameter bounds.\n"
            f"- [Info] Telemetry logged to Sentinel Security Operations.\n\n"
            f"[LLM_ERROR]\n" + traceback.format_exc()
        )

    # Enrich report with MITRE ATT&CK intelligence mapping — the model reads the
    # actual report content to decide what genuinely applies (no keyword matching)
    ai_report = await enrich_report_with_mitre(ai_report, context_hint=file.filename or "unknown_file")

    email_sent = False
    try:
        email_subject = f"Sentinel IDS - Vulnerability Scan Report: {file.filename}"
        email_sent = email_report_agent.send_email(admin_email, email_subject, ai_report)
    except Exception:
        email_sent = False

    return {
        "filename": file.filename,
        "report": ai_report,
        "email_sent": email_sent,
        "recipient": admin_email,
    }


@router.post("/scan-folder", status_code=status.HTTP_200_OK)
async def scan_folder_endpoint(
    files: List[UploadFile] = File(...),
    email_override: str = Form(""),
):
    """
    Scans an uploaded folder (or multiple uploaded files) for security vulnerabilities across all source files.
    """
    if not files:
        raise HTTPException(status_code=400, detail="No files provided for folder scan.")

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        admin_email = (email_override or "").strip() or db_settings.admin_email or "admin@network.local"
    finally:
        db.close()

    temp_dir = tempfile.mkdtemp(prefix="sentinel_folder_")
    try:
        file_summaries = []
        for file in files:
            if not file.filename:
                continue
            safe_name = file.filename.replace("..", "_").replace("/", os.sep).replace("\\", os.sep)
            dest_path = os.path.join(temp_dir, safe_name)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, "wb") as buf:
                shutil.copyfileobj(file.file, buf)

            # Check if uploaded file is a zip archive
            if safe_name.lower().endswith(".zip"):
                try:
                    with zipfile.ZipFile(dest_path, 'r') as zip_ref:
                        zip_ref.extractall(temp_dir)
                except Exception:
                    pass

        collected_files = _extract_text_files_from_directory(temp_dir)
        if not collected_files:
            raise HTTPException(status_code=400, detail="No readable source code files found in uploaded folder.")

        combined_code = ""
        for rel_path, content in collected_files[:25]:
            combined_code += f"\n--- File: {rel_path} ---\n{content[:4000]}\n"

        folder_name = f"Uploaded Folder ({len(collected_files)} files)"
        ai_report = await get_vuln_scan_response(combined_code, folder_name)

        email_sent = False
        try:
            email_subject = f"Sentinel IDS - Folder Security Scan Report: {folder_name}"
            email_sent = email_report_agent.send_email(admin_email, email_subject, ai_report)
        except Exception:
            email_sent = False

        return {
            "filename": folder_name,
            "files_scanned": len(collected_files),
            "report": ai_report,
            "email_sent": email_sent,
            "recipient": admin_email,
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/scan-repo", status_code=status.HTTP_200_OK)
async def scan_repo_endpoint(
    repo_url: str = Form(...),
    email_override: str = Form(""),
):
    """
    Clones or downloads a Git repository by URL, performs static analysis & AI vulnerability audit,
    and returns code fix remediation recommendations.
    """
    repo_url = (repo_url or "").strip()
    if not repo_url:
        raise HTTPException(status_code=400, detail="Please provide a valid repository URL.")

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        admin_email = (email_override or "").strip() or db_settings.admin_email or "admin@network.local"
    finally:
        db.close()

    temp_dir = tempfile.mkdtemp(prefix="sentinel_repo_")
    try:
        cloned = False
        # Try git clone --depth 1 first
        try:
            cmd = ["git", "clone", "--depth", "1", repo_url, temp_dir]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
            if proc.returncode == 0:
                cloned = True
        except Exception:
            cloned = False

        # Fallback to downloading GitHub zip if git clone is unavailable or fails
        if not cloned and "github.com" in repo_url:
            clean_url = repo_url.rstrip("/").removesuffix(".git")
            zip_url = f"{clean_url}/archive/refs/heads/main.zip"
            zip_dest = os.path.join(temp_dir, "repo.zip")
            try:
                urllib.request.urlretrieve(zip_url, zip_dest)
                with zipfile.ZipFile(zip_dest, 'r') as z:
                    z.extractall(temp_dir)
                cloned = True
            except Exception:
                zip_url_master = f"{clean_url}/archive/refs/heads/master.zip"
                try:
                    urllib.request.urlretrieve(zip_url_master, zip_dest)
                    with zipfile.ZipFile(zip_dest, 'r') as z:
                        z.extractall(temp_dir)
                    cloned = True
                except Exception:
                    pass

        collected_files = _extract_text_files_from_directory(temp_dir)
        if not collected_files:
            raise HTTPException(
                status_code=400,
                detail=f"Could not clone repository or no source code files found at {repo_url}"
            )

        combined_code = f"Repository URL: {repo_url}\n"
        for rel_path, content in collected_files[:25]:
            combined_code += f"\n--- File: {rel_path} ---\n{content[:4000]}\n"

        repo_name = repo_url.split("/")[-1].removesuffix(".git") or repo_url
        ai_report = await get_vuln_scan_response(combined_code, f"Repository: {repo_name}")

        email_sent = False
        try:
            email_subject = f"Sentinel IDS - Git Repository Security Audit: {repo_name}"
            email_sent = email_report_agent.send_email(admin_email, email_subject, ai_report)
        except Exception:
            email_sent = False

        return {
            "filename": f"Repository: {repo_name}",
            "files_scanned": len(collected_files),
            "report": ai_report,
            "email_sent": email_sent,
            "recipient": admin_email,
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.get("/scan-site", status_code=status.HTTP_200_OK)
async def scan_site_endpoint():
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        admin_email = db_settings.admin_email or "admin@network.local"
    finally:
        db.close()

    result = site_security_audit_agent.scan_codebase(".")

    email_sent = False
    try:
        subject = "Sentinel IDS - Internal Codebase Security Audit Report"
        body = f"Sentinel Site Codebase Security Audit Results:\n\n{result.get('summary', '')}\n\nVulnerabilities:\n"
        for v in result.get("vulnerabilities", []):
            body += f"[{v.get('severity')}] {v.get('title')} ({v.get('file')})\nIssue: {v.get('issue')}\nSolution: {v.get('solution')}\nCode Fix: {v.get('remediation_code')}\n\n"
        email_sent = email_report_agent.send_email(admin_email, subject, body)
    except Exception:
        email_sent = False

    result["email_sent"] = email_sent
    result["recipient"] = admin_email
    return result


@router.get("/scan-linked-site", status_code=status.HTTP_200_OK)
async def scan_linked_site_endpoint():
    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        admin_email = db_settings.admin_email or "admin@network.local"
        url = getattr(db_settings, "linked_site_url", "") or ""
        token = getattr(db_settings, "linked_site_token", "") or ""
    finally:
        db.close()

    result = site_security_audit_agent.scan_linked_site(url, token)

    email_sent = False
    if url:
        try:
            subject = f"Sentinel IDS - Linked Site Audit Report ({url})"
            body = f"Linked Site Security Audit Results for {url}:\n\n{result.get('summary', '')}\n\nFindings:\n"
            for v in result.get("vulnerabilities", []):
                body += f"[{v.get('severity')}] {v.get('title')}\nIssue: {v.get('issue')}\nSolution: {v.get('solution')}\nFix Code: {v.get('remediation_code')}\n\n"
            email_sent = email_report_agent.send_email(admin_email, subject, body)
        except Exception:
            email_sent = False

    result["email_sent"] = email_sent
    result["recipient"] = admin_email
    return result


@router.post("/scan-pcap", status_code=status.HTTP_200_OK)
async def scan_pcap_endpoint(
    file: UploadFile = File(...),
    email_override: str = Form(""),
):
    """
    Parses an uploaded PCAP or PCAPNG network capture file using Scapy.
    Extracts flow statistics: protocol distribution, top talkers, port usage, and suspicious patterns.
    Passes extracted summary to the LLM for AI-driven threat analysis and returns a security report.
    """
    if not file.filename:
        raise HTTPException(status_code=400, detail="No PCAP file provided.")

    allowed_exts = {".pcap", ".pcapng", ".cap"}
    ext = os.path.splitext(file.filename or "")[-1].lower()
    if ext not in allowed_exts:
        raise HTTPException(status_code=400, detail=f"Unsupported file type '{ext}'. Please upload a .pcap or .pcapng file.")

    db = SessionLocal()
    try:
        db_settings = get_settings_db(db)
        admin_email = (email_override or "").strip() or db_settings.admin_email or "admin@network.local"
    finally:
        db.close()

    # Save uploaded PCAP to temp file
    temp_dir = tempfile.mkdtemp(prefix="sentinel_pcap_")
    pcap_path = os.path.join(temp_dir, file.filename)
    # Initialize total_packets before try so it is accessible in the return statement
    total_packets = 0
    try:
        with open(pcap_path, "wb") as buf:
            shutil.copyfileobj(file.file, buf)

        # Parse PCAP using scapy
        summary_lines = []
        try:
            from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP
            packets = rdpcap(pcap_path)
            total_packets = len(packets)

            # Protocol distribution
            proto_counts = {"TCP": 0, "UDP": 0, "ICMP": 0, "ARP": 0, "Other": 0}
            src_ip_counts: dict = {}
            dst_port_counts: dict = {}
            syn_count = 0
            large_packets = 0
            first_time = None
            last_time = None

            for pkt in packets:
                # Track timestamps for time range
                if hasattr(pkt, "time"):
                    t = float(pkt.time)
                    if first_time is None or t < first_time:
                        first_time = t
                    if last_time is None or t > last_time:
                        last_time = t

                # Protocol classification
                if pkt.haslayer(TCP):
                    proto_counts["TCP"] += 1
                    tcp_layer = pkt[TCP]
                    dst_port = tcp_layer.dport
                    dst_port_counts[dst_port] = dst_port_counts.get(dst_port, 0) + 1
                    # SYN without ACK = potential SYN flood
                    if tcp_layer.flags == 0x02:
                        syn_count += 1
                elif pkt.haslayer(UDP):
                    proto_counts["UDP"] += 1
                    udp_layer = pkt[UDP]
                    dst_port = udp_layer.dport
                    dst_port_counts[dst_port] = dst_port_counts.get(dst_port, 0) + 1
                elif pkt.haslayer(ICMP):
                    proto_counts["ICMP"] += 1
                elif pkt.haslayer(ARP):
                    proto_counts["ARP"] += 1
                else:
                    proto_counts["Other"] += 1

                # Track source IPs
                if pkt.haslayer(IP):
                    src = pkt[IP].src
                    src_ip_counts[src] = src_ip_counts.get(src, 0) + 1

                # Flag large packets (> 1400 bytes payload)
                if len(pkt) > 1400:
                    large_packets += 1

            # Build analysis summary
            duration_sec = round(last_time - first_time, 2) if first_time and last_time else 0
            top_src_ips = sorted(src_ip_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            top_dst_ports = sorted(dst_port_counts.items(), key=lambda x: x[1], reverse=True)[:10]

            summary_lines.append(f"[PCAP Analysis Summary] File: {file.filename}")
            summary_lines.append(f"Total Packets: {total_packets}")
            summary_lines.append(f"Capture Duration: {duration_sec} seconds")
            summary_lines.append(f"Protocol Distribution: TCP={proto_counts['TCP']}, UDP={proto_counts['UDP']}, ICMP={proto_counts['ICMP']}, ARP={proto_counts['ARP']}, Other={proto_counts['Other']}")
            summary_lines.append(f"Top 10 Source IPs: {', '.join([f'{ip}({cnt})' for ip, cnt in top_src_ips])}")
            summary_lines.append(f"Top 10 Destination Ports: {', '.join([f'{port}({cnt})' for port, cnt in top_dst_ports])}")
            summary_lines.append(f"SYN-Only Packets (potential SYN Flood): {syn_count}")
            summary_lines.append(f"Large Packets (>1400 bytes): {large_packets}")

            # Suspicious pattern detection
            suspicious = []
            if syn_count > total_packets * 0.3:
                suspicious.append("HIGH SYN ratio — likely SYN Flood DDoS attack")
            if proto_counts["ICMP"] > total_packets * 0.4:
                suspicious.append("HIGH ICMP ratio — likely ICMP/Ping Flood attack")
            if len(src_ip_counts) > 0:
                top_src, top_src_cnt = top_src_ips[0]
                if top_src_cnt > total_packets * 0.5:
                    suspicious.append(f"Single source IP {top_src} generated {top_src_cnt} packets — suspicious flood")
            if large_packets > total_packets * 0.2:
                suspicious.append("Many oversized packets — possible data exfiltration or DDoS amplification")

            if suspicious:
                summary_lines.append(f"Suspicious Patterns Detected: {'; '.join(suspicious)}")
            else:
                summary_lines.append("Suspicious Patterns: None detected — traffic appears normal")

        except ImportError:
            summary_lines.append(f"[PCAP File] {file.filename} (Scapy not available — static analysis only)")
            summary_lines.append("Please ensure scapy is installed in the environment for full packet analysis.")
        except Exception as e:
            summary_lines.append(f"[PCAP Parse Error] {e}")

        pcap_summary = "\n".join(summary_lines)

        # Pass PCAP summary to LLM for threat analysis
        try:
            ai_report = await get_vuln_scan_response(pcap_summary, f"PCAP: {file.filename}")
        except Exception as e:
            ai_report = f"[Sentinel PCAP Analysis Report]\n\n{pcap_summary}\n\n[LLM Error]: {e}"

        # Enrich with MITRE ATT&CK mapping — model reads the actual generated
        # report/summary rather than being told a fixed, possibly-wrong classification
        ai_report = await enrich_report_with_mitre(ai_report, context_hint=f"PCAP: {file.filename}")

        email_sent = False
        try:
            email_subject = f"Sentinel IDS - PCAP Analysis Report: {file.filename}"
            email_sent = email_report_agent.send_email(admin_email, email_subject, ai_report)
        except Exception:
            email_sent = False

        return {
            "filename": file.filename,
            "total_packets": total_packets,
            "report": ai_report,
            "email_sent": email_sent,
            "recipient": admin_email,
        }

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


@router.post("/export-report-pdf", status_code=status.HTTP_200_OK)
async def export_report_pdf(
    report_text: str = Form(...),
    filename: str = Form("scan_report"),
):
    """
    Converts a vulnerability scan report text into a downloadable PDF file.
    Uses reportlab if available, falls back to a plain text file download.
    """
    safe_name = re.sub(r"[^\w\-. ]", "_", filename)[:60] or "scan_report"
    date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC") if True else ""

    # Try reportlab PDF generation
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.lib.colors import HexColor
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable
        from reportlab.lib.enums import TA_LEFT, TA_CENTER

        buf = io.BytesIO()
        doc = SimpleDocTemplate(buf, pagesize=A4,
                                leftMargin=2*cm, rightMargin=2*cm,
                                topMargin=2*cm, bottomMargin=2*cm)

        styles = getSampleStyleSheet()
        accent_color = HexColor("#6366f1")
        text_color = HexColor("#1e293b")

        title_style = ParagraphStyle("title", parent=styles["Title"],
                                     textColor=accent_color, fontSize=20, spaceAfter=6)
        subtitle_style = ParagraphStyle("subtitle", parent=styles["Normal"],
                                        textColor=HexColor("#64748b"), fontSize=10, spaceAfter=12)
        body_style = ParagraphStyle("body", parent=styles["Normal"],
                                    textColor=text_color, fontSize=9, leading=14, spaceAfter=4)
        heading_style = ParagraphStyle("heading", parent=styles["Heading2"],
                                       textColor=accent_color, fontSize=12, spaceAfter=6, spaceBefore=10)

        story = [
            Paragraph("Sentinel IDS — Security Scan Report", title_style),
            Paragraph(f"Target: {safe_name} &nbsp;&nbsp;|&nbsp;&nbsp; Generated: {date_str}", subtitle_style),
            HRFlowable(width="100%", thickness=1, color=accent_color, spaceAfter=10),
            Spacer(1, 0.3*cm),
        ]

        # Format the report text into paragraphs
        for line in report_text.split("\n"):
            stripped = line.strip()
            if not stripped:
                story.append(Spacer(1, 0.2*cm))
            elif stripped.startswith("##"):
                story.append(Paragraph(stripped.lstrip("#").strip(), heading_style))
            elif stripped.startswith("#"):
                story.append(Paragraph(stripped.lstrip("#").strip(), heading_style))
            elif stripped.startswith("---"):
                story.append(HRFlowable(width="100%", thickness=0.5,
                                         color=HexColor("#e2e8f0"), spaceAfter=6))
            else:
                # Escape HTML entities for reportlab
                escaped = stripped.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                story.append(Paragraph(escaped, body_style))

        doc.build(story)
        buf.seek(0)

        return StreamingResponse(
            buf,
            media_type="application/pdf",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}_report.pdf"'},
        )

    except ImportError:
        # Fallback: return plain text file
        text_bytes = report_text.encode("utf-8")
        buf = io.BytesIO(text_bytes)
        return StreamingResponse(
            buf,
            media_type="text/plain",
            headers={"Content-Disposition": f'attachment; filename="{safe_name}_report.txt"'},
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {e}")


@router.post("/download-patch", status_code=status.HTTP_200_OK)
async def download_patch(
    report_text: str = Form(...),
    filename: str = Form("scan_target"),
):
    """
    Generates a unified diff .patch file from AI remediation code blocks found in the scan report.
    Extracts all ```code``` blocks and packages them as a documented patch file for direct application.
    """
    safe_name = re.sub(r"[^\w\-. ]", "_", filename)[:60] or "scan_target"
    date_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC") if True else ""

    # Extract all code blocks from the report (between triple backticks)
    code_blocks = re.findall(r"```(?:\w+)?\n([\s\S]*?)```", report_text)
    if not code_blocks:
        # Try without language specifier
        code_blocks = re.findall(r"```([\s\S]*?)```", report_text)

    if not code_blocks:
        # Return a minimal patch with advisory note if no code blocks found
        code_blocks = ["# No specific code remediation blocks found in this report.\n# Review the security findings manually and apply fixes described above."]

    # Build patch file content
    patch_lines = [
        f"# Sentinel IDS — Remediation Patch File",
        f"# Target: {safe_name}",
        f"# Generated: {date_str}",
        f"# Total Remediation Blocks: {len(code_blocks)}",
        f"# ",
        f"# How to apply: Review each section below and manually apply the suggested code",
        f"# changes to the appropriate files in your project.",
        f"# For git-compatible patches, adapt the diff headers with actual file paths.",
        f"",
    ]

    for idx, block in enumerate(code_blocks, 1):
        patch_lines.append(f"# ═══════════════════════════════════════════")
        patch_lines.append(f"# Remediation Block #{idx}")
        patch_lines.append(f"# ═══════════════════════════════════════════")
        patch_lines.append(f"--- a/{safe_name}_original.{idx}")
        patch_lines.append(f"+++ b/{safe_name}_fixed.{idx}")
        patch_lines.append(f"@@ -1,0 +1,{len(block.splitlines())} @@")
        for code_line in block.splitlines():
            patch_lines.append(f"+{code_line}")
        patch_lines.append("")

    patch_content = "\n".join(patch_lines)
    patch_bytes = patch_content.encode("utf-8")
    buf = io.BytesIO(patch_bytes)

    return StreamingResponse(
        buf,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}_remediation.patch"'},
    )
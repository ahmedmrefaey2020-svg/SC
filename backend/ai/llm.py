import os
import hashlib
import logging
import asyncio
from pathlib import Path
from huggingface_hub import AsyncInferenceClient  # Async Client بدلاً من Sync
from dotenv import load_dotenv
from backend.ai.agent_cache import agent_cache

# Resolve .env path robustly
env_file = Path(__file__).resolve().parent.parent.parent / ".env"
if env_file.exists():
    load_dotenv(dotenv_path=env_file)
else:
    load_dotenv()

TOKEN = (os.getenv("HF_TOKEN") or "").strip().strip('"\'')
logger = logging.getLogger("sentinel.llm")

CANDIDATE_MODELS = [
    'meta-llama/Llama-3.3-70B-Instruct',
    'Qwen/Qwen2.5-Coder-32B-Instruct',
    'Qwen/Qwen2.5-72B-Instruct',
    'mistralai/Mistral-7B-Instruct-v0.3'
]

SYSTEM_PROMPT = (
    "You are an elite, autonomous Cyber Security Specialist and AI Intelligence Analyst from the "
    "Sentinel Intelligence Team (SIT). You operate as the primary intelligence core of the Sentinel IDS platform. "
    "Analyze context and meaning deeply and respond organically in your own authentic voice without rigid templates. "
    "Provide authoritative, technical, articulate, and direct cybersecurity answers with concrete code fixes where applicable. "
    "Always match the language of the user's prompt (Arabic if prompt is Arabic, English if prompt is English)."
)

VULN_SCANNER_SYSTEM_PROMPT = (
    "You are an elite Vulnerability Assessment Specialist from the Sentinel Intelligence Team (SIT). "
    "Read and understand the provided file/code content deeply, in its actual context — don't rely on surface "
    "keyword matching. Explain what you genuinely find in your own authentic voice, the way a senior security "
    "engineer would write up a real audit, not a rigid fill-in-the-blank template. "
    "For each real vulnerability, flaw, misconfiguration, or risk you identify: mention its severity naturally "
    "using one of these tags — [Critical] [High] [Medium] [Low] [Info] — so the finding can be parsed "
    "automatically, explain why it matters in context, and give the precise code fix in a ```code``` block. "
    "Close with an overall Risk Score (0-100) that reflects what you actually found, not a generic estimate. "
    "Respond in English."
)


def _is_arabic(text: str) -> bool:
    return any('\u0600' <= char <= '\u06FF' for char in text)


def _generate_offline_security_response(user_message: str, history: list[dict] | None = None) -> str:
    is_ar = _is_arabic(user_message)

    if is_ar:
        return (
            f"أهلاً بك! تم استلام رسالتك: \"{user_message.strip()}\".\n\n"
            f"بصفتي المساعد الذكي لنظام Sentinel IDS، أنا جاهز لمساعدتك في تحليل التهديدات، فحص الثغرات الأمنية، "
            f"وتقديم التوصيات البرمجية اللازمة. نظراً لعدم توفر الاتصال بموديل الذكاء الاصطناعي السحابي حالياً، "
            f"يرجى التحقق من اتصال الإنترنت أو مفتاح الـ API الخاص بك لمعالجة الطلب بدقة أعلى عبر موديلات Llama."
        )
    else:
        return (
            f"Sentinel AI Core online. Received query: \"{user_message.strip()}\".\n\n"
            f"I am ready to assist you with intrusion detection analysis, threat response, and static vulnerability auditing. "
            f"Note: Cloud LLM connection is currently offline, so this is a standard offline fallback response. "
            f"Please verify your API token and connection to fully leverage the Llama-3.3 intelligence core."
        )


async def get_ai_response(user_message: str, history: list[dict] | None = None) -> str:
    # إصلاح التخزين المؤقت: تضمين محتوى الـ history المقتطع في الـ Hash
    hist_str = "".join([f"{h.get('role')}:{h.get('content','')}" for h in (history[-8:] if history else [])])
    cache_raw = f"{hist_str}_{user_message.strip()}"
    cache_key = "chat_" + hashlib.md5(cache_raw.encode("utf-8")).hexdigest()
    
    cached_val = agent_cache.get(cache_key)
    if cached_val:
        return cached_val

    # Re-check TOKEN dynamically if env changed
    token = TOKEN or (os.getenv("HF_TOKEN") or "").strip().strip('"\'')
    if token:
        messages = [{"role": "system", "content": SYSTEM_PROMPT}]
        if history:
            for h in history[-8:]:
                role = h.get("role", "user")
                content = h.get("content", "")
                if role in ("user", "assistant") and content:
                    messages.append({"role": role, "content": content[:1500]})
        messages.append({"role": "user", "content": user_message[:3000]})

        client = AsyncInferenceClient(api_key=token, timeout=15.0)
        for model_id in CANDIDATE_MODELS:
            try:
                response = await client.chat.completions.create(
                    model=model_id,
                    messages=messages,
                    max_tokens=1500,
                )
                if response and response.choices:
                    content = response.choices[0].message.content
                    if content and content.strip():
                        result = content.strip()
                        agent_cache.set(cache_key, result, ttl=300.0)
                        return result
            except Exception as e:
                logger.warning("LLM call failed for model %s: %s", model_id, e)
                continue

    offline_reply = _generate_offline_security_response(user_message, history)
    # Don't cache offline failures so subsequent requests retry immediately
    return offline_reply


async def get_vuln_scan_response(file_content: str, filename: str) -> str:
    truncated_content = file_content[:12000] if len(file_content) > 12000 else file_content
    cache_key = "scan_" + hashlib.md5(f"{filename}_{truncated_content}".encode("utf-8")).hexdigest()
    cached_report = agent_cache.get(cache_key)
    if cached_report:
        return cached_report

    scan_prompt = (
        f"Perform a comprehensive vulnerability assessment and code remediation review on the following target:\n"
        f"Target: {filename}\n"
        f"Content Preview:\n{truncated_content}\n\n"
        f"Identify all security vulnerabilities, misconfigurations, and secrets. "
        f"For EACH finding, provide the Description AND the exact CODE FIX / REMEDIATION snippet in ```code``` blocks."
    )
    if TOKEN:
        messages = [
            {"role": "system", "content": VULN_SCANNER_SYSTEM_PROMPT},
            {"role": "user", "content": scan_prompt},
        ]
        client = AsyncInferenceClient(api_key=TOKEN)
        for model_id in CANDIDATE_MODELS:
            try:
                response = await client.chat.completions.create(
                    model=model_id,
                    messages=messages,
                    max_tokens=2200,
                )
                if response and response.choices:
                    content = response.choices[0].message.content
                    if content and content.strip():
                        result = content.strip()
                        agent_cache.set(cache_key, result, ttl=600.0)
                        return result
            except Exception as e:
                logger.warning("Vuln scan LLM call failed for model %s: %s", model_id, e)
                continue

    return _offline_static_scan(truncated_content, filename, cache_key)


# إصلاح الشروط المنطقية للأوفلاين شيكس
_OFFLINE_CHECKS = [
    {
        "severity": "Critical",
        "title": "Dynamic Code Execution (eval/exec)",
        "match": lambda c: ("eval(" in c or "exec(" in c),
        "issue": "Use of eval()/exec() detected, which can allow arbitrary code execution if fed untrusted input.",
        "fix": "# Replace eval()/exec() with explicit, parameterized logic instead of dynamic code execution.",
    },
    {
        "severity": "Critical",
        "title": "OS Command Injection Risk",
        "match": lambda c: ("os.system(" in c) or ("subprocess." in c and "shell=True" in c),
        "issue": "Shell command execution with shell=True (or os.system) detected — vulnerable to command injection if arguments include user input.",
        "fix": "import subprocess\nsubprocess.run([cmd, *args], shell=False, check=True)",
    },
    {
        "severity": "High",
        "title": "Potential Hardcoded Secret / Credential",
        "match": lambda line: any(tok in line.lower() for tok in ["password =", "password=", "api_key =", "api_key=", "secret =", "secret="]) 
                              and "getenv" not in line.lower() and "os.environ" not in line.lower(),
        "issue": "A password, API key, or secret appears to be assigned as a literal value rather than loaded from a secure source.",
        "fix": "import os\napi_key = os.getenv('API_KEY', '')",
    },
    {
        "severity": "High",
        "title": "SQL Query Built via String Concatenation/Formatting",
        "match": lambda c: any(q in c.lower() for q in ["select ", "insert ", "update "]) and ("%s" in c or "+ " in c or "f\"" in c or "f'" in c) and "execute(" in c.lower(),
        "issue": "SQL statements appear to be built via string interpolation/concatenation, which is vulnerable to SQL injection.",
        "fix": "cursor.execute(\"SELECT * FROM users WHERE id = %s\", (user_id,))",
    },
    {
        "severity": "Medium",
        "title": "Wildcard CORS / Host Policy",
        "match": lambda c: "allow_origins=[\"*\"]" in c or "allow_origins=['*']" in c or "allowed_hosts=[\"*\"]" in c,
        "issue": "Wildcard '*' origin/host policy allows requests from any client, weakening origin-based access control.",
        "fix": "app.add_middleware(CORSMiddleware, allow_origins=['https://yourdomain.com'])",
    },
    {
        "severity": "Medium",
        "title": "Debug Mode Enabled",
        "match": lambda c: ("debug=true" in c.lower() or "debug = true" in c.lower() or "app.run(debug=true)" in c.lower()),
        "issue": "Debug mode appears enabled, which can leak stack traces, source paths, and internal state to end users in production.",
        "fix": "app.run(debug=False)  # never enable debug mode in production",
    },
    {
        "severity": "Low",
        "title": "Insecure Deserialization (pickle)",
        "match": lambda c: "pickle.load" in c or "pickle.loads" in c,
        "issue": "pickle deserialization of untrusted data can lead to arbitrary code execution.",
        "fix": "import json\ndata = json.loads(payload)  # prefer JSON over pickle for untrusted input",
    },
]


def _offline_static_scan(content: str, filename: str, cache_key: str) -> str:
    # تعديل فحص الأسرار ليفحص سطر بسطر بدلاً من الملف كاملاً
    findings = []
    for chk in _OFFLINE_CHECKS:
        if chk["title"] == "Potential Hardcoded Secret / Credential":
            if any(chk["match"](line) for line in content.splitlines()):
                findings.append(chk)
        else:
            if chk["match"](content):
                findings.append(chk)

    severity_weight = {"Critical": 30, "High": 20, "Medium": 10, "Low": 5}
    computed_score = min(95, sum(severity_weight.get(f["severity"], 5) for f in findings))
    risk_label = (
        "Critical Risk" if computed_score >= 70 else
        "High Risk" if computed_score >= 45 else
        "Medium Risk" if computed_score >= 20 else
        "Low Risk"
    )

    lines = [
        "===========================================================",
        " SENTINEL INTELLIGENCE TEAM (SIT) — VULNERABILITY REPORT",
        f" Target: {filename}",
        " Scan Engine: Autonomous SIT Static Pattern Audit (Offline Mode — Cloud LLM Unreachable)",
        "===========================================================",
        "",
        f"Risk Score: {computed_score}/100 ({risk_label})",
        "",
        "Findings:",
    ]

    if findings:
        for idx, f in enumerate(findings, 1):
            lines.append(f"{idx}. [{f['severity']}] {f['title']}")
            lines.append(f"   Location: {filename}")
            lines.append(f"   Risk: {f['issue']}")
            lines.append("   Remediation Code:")
            lines.append("```python")
            lines.append(f["fix"])
            lines.append("```")
            lines.append("")
    else:
        lines.append("[Info] No offline static-pattern matches found in this file.")
        lines.append(
            "   Note: this is a lightweight fallback scan run because the cloud LLM was unreachable — "
            "it does not replace a full AI-driven review. Restore the HF_TOKEN/connection for a deeper assessment."
        )

    report = "\n".join(lines)
    agent_cache.set(cache_key, report, ttl=120.0)
    return report

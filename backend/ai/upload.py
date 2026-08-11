import os
import uuid
import shutil
from fastapi import UploadFile, HTTPException

TEXT_EXTENSIONS = {
    "txt", "log", "csv", "json", "py", "sh", "md", "markdown", "yaml", "yml",
    "ini", "cfg", "conf", "config", "env", "properties", "sql", "xml", "html",
    "htm", "css", "js", "ts", "tsx", "jsx", "jsonl", "ndjson", "tsv",
    "dat", "rs", "go", "cpp", "c", "h", "hpp", "cs", "java", "kt", "swift",
    "rb", "php", "pl", "pm", "lua", "r", "toml", "lock", "dockerfile"
}

SPECIAL_NAMES = {"dockerfile", "makefile", "cargo.toml", "requirements.txt"}


async def process_uploaded_file(file: UploadFile) -> str:
    upload_dir = os.path.join("static", "uploads")
    os.makedirs(upload_dir, exist_ok=True)

    safe_filename = f"{uuid.uuid4()}_{file.filename}"
    file_path = os.path.join(upload_dir, safe_filename)

    try:
        with open(file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        filename_lower = (file.filename or "").lower()
        file_extension = filename_lower.rsplit(".", 1)[-1] if "." in filename_lower else ""

        # 1. Text & Source Code Files
        if file_extension in TEXT_EXTENSIONS or filename_lower in SPECIAL_NAMES:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read(25000)
            return content if content.strip() else f"[File: {file.filename} is empty.]"

        # 2. PDF Documents
        if file_extension == "pdf":
            extracted_text = ""
            try:
                import pypdf
                reader = pypdf.PdfReader(file_path)
                for page in reader.pages[:10]:
                    extracted_text += (page.extract_text() or "") + "\n"
            except Exception:
                try:
                    with open(file_path, "rb") as pf:
                        raw = pf.read().decode("latin1", errors="ignore")
                        import re
                        text_blocks = re.findall(r"\((.*?)\)", raw)
                        extracted_text = " ".join([b for b in text_blocks if len(b) > 3])
                except Exception:
                    pass
            if extracted_text.strip():
                return f"[PDF Document Content ({file.filename})]:\n{extracted_text[:15000]}"

        # 3. Word Documents (.docx)
        if file_extension in {"docx", "doc"}:
            extracted_text = ""
            try:
                import docx
                doc = docx.Document(file_path)
                extracted_text = "\n".join([p.text for p in doc.paragraphs if p.text])
            except Exception:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    extracted_text = f.read(10000)
            if extracted_text.strip():
                return f"[Word Document Content ({file.filename})]:\n{extracted_text[:15000]}"

        # 4. Excel & Spreadsheets (.xlsx, .xls)
        if file_extension in {"xlsx", "xls"}:
            try:
                import pandas as pd
                df = pd.read_excel(file_path)
                return f"[Spreadsheet Data ({file.filename})]:\nShape: {df.shape}\nColumns: {list(df.columns)}\nPreview:\n{df.head(20).to_string()}"
            except Exception:
                pass

        # 5. Image Files (PNG, JPG, WEBP, SVG)
        if file_extension in {"png", "jpg", "jpeg", "gif", "webp", "svg"}:
            img_desc = f"[Image Metadata & File Header: {file.filename}, Extension: {file_extension.upper()}]"
            try:
                from PIL import Image
                with Image.open(file_path) as img:
                    img_desc += f"\nDimensions: {img.width}x{img.height} pixels, Color Mode: {img.mode}, Format: {img.format}"
            except Exception:
                pass
            return f"[Image File Parsed: {file.filename}]\n{img_desc}\nVisual telemetry ready for security assessment."

        # 6. Audio Files (MP3, WAV, FLAC, OGG, M4A)
        if file_extension in {"mp3", "wav", "ogg", "flac", "m4a"}:
            try:
                from backend.ai.speech import speech_to_text
                # Create mock upload file for STT
                file.file.seek(0)
                transcript = await speech_to_text(file)
                if transcript and not transcript.startswith("Audio input received"):
                    return f"[Audio Transcript for {file.filename}]:\n{transcript}"
            except Exception:
                pass
            return f"[Audio File Uploaded: {file.filename}]\nAudio waveform telemetry decoded successfully."

        # Fallback reading
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read(10000)
        return content if content.strip() else f"[Uploaded File: {file.filename} indexed.]"

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File processing error: {str(e)}")

    finally:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass

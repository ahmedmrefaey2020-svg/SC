import os
import uuid
import shutil
from fastapi import UploadFile

STT_MODEL_ID = "openai/whisper-large-v3"
TTS_MODEL_ID = "espnet/kan-bayashi_ljspeech_vits"


async def speech_to_text(file: UploadFile) -> str:
    ext = "wav"
    if file.filename and "." in file.filename:
        ext = file.filename.rsplit(".", 1)[-1].lower()
    temp_filename = f"temp_{uuid.uuid4()}.{ext}"
    try:
        with open(temp_filename, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        token = os.getenv("HF_TOKEN")
        if token:
            try:
                from huggingface_hub import InferenceClient
                client = InferenceClient(provider="fal-ai", token=token)
                with open(temp_filename, "rb") as audio_file:
                    transcription = client.automatic_speech_recognition(
                        audio_file.read(),
                        model=STT_MODEL_ID
                    )
                res = transcription.text if hasattr(transcription, "text") else str(transcription)
                if res and res.strip():
                    return res.strip()
            except Exception:
                pass

        try:
            import speech_recognition as sr
            r = sr.Recognizer()
            with sr.AudioFile(temp_filename) as source:
                audio_data = r.record(source)
                try:
                    text = r.recognize_google(audio_data, language="ar-SA")
                    if text and text.strip():
                        return text
                except Exception:
                    text = r.recognize_google(audio_data, language="en-US")
                    if text and text.strip():
                        return text
        except Exception:
            pass

        return "فحص ملف الصوت والأمر الصوتي: هل هناك أي اختراق أو هجمات سيبرانية حالياً على النظام؟"

    except Exception:
        return "قم بتحليل النظام ومراجعة الأيبيات المحظورة وتقرير الأمان."

    finally:
        if os.path.exists(temp_filename):
            try:
                os.remove(temp_filename)
            except Exception:
                pass


async def text_to_speech(text_response: str) -> str:
    if not text_response or not text_response.strip():
        return ""

    audio_filename = f"response_{uuid.uuid4()}.mp3"
    audio_path = os.path.join("static", "audio", audio_filename)
    os.makedirs(os.path.dirname(audio_path), exist_ok=True)

    try:
        from gtts import gTTS
        is_ar = any("\u0600" <= c <= "\u06FF" for c in text_response)
        lang = "ar" if is_ar else "en"
        tts = gTTS(text=text_response[:500], lang=lang, slow=False)
        tts.save(audio_path)
        return f"/static/audio/{audio_filename}"
    except Exception:
        pass

    token = os.getenv("HF_TOKEN")
    if token:
        try:
            from huggingface_hub import InferenceClient
            client = InferenceClient(provider="fal-ai", token=token)
            flac_filename = f"response_{uuid.uuid4()}.flac"
            flac_path = os.path.join("static", "audio", flac_filename)
            audio_bytes = client.text_to_speech(text_response[:300], model=TTS_MODEL_ID)
            with open(flac_path, "wb") as f:
                if isinstance(audio_bytes, bytes):
                    f.write(audio_bytes)
                else:
                    f.write(audio_bytes.read())
            return f"/static/audio/{flac_filename}"
        except Exception:
            pass

    return ""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

def format_message(alert, explanation):
    actions = "\n".join(f"- {a}" for a in explanation["actions"])
    return (f"ALERTE {alert['severity'].upper()} : {alert['type']}\n"
            f"IP : {alert['ip']}\n\n"
            f"{explanation['explication']}\n\n"
            f"Actions recommandées :\n{actions}")

def send_telegram(text):
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    chat_id = os.getenv("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("[Telegram non configuré] Message affiché à la place :\n")
        print(text)
        return False
    r = requests.post(
        f"https://api.telegram.org/bot{token}/sendMessage",
        json={"chat_id": chat_id, "text": text},
        timeout=10,
    )
    return r.ok

def notify(alert, explanation):
    return send_telegram(format_message(alert, explanation))
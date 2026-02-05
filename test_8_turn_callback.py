import requests
import time

URL = "http://localhost:5000/process"

session_id = "callback-test-8"
history = []

def send(msg):
    global history

    payload = {
        "sessionId": session_id,
        "message": {
            "sender": "scammer",
            "text": msg,
            "timestamp": int(time.time() * 1000)
        },
        "conversationHistory": history,
        "metadata": {
            "channel": "SMS",
            "language": "English",
            "locale": "IN"
        }
    }

    r = requests.post(URL, json=payload)
    data = r.json()

    print(f"\nSCAMMER: {msg}")
    print(f"AGENT  : {data['reply']}")

    history.append({
        "sender": "scammer",
        "text": msg,
        "timestamp": payload["message"]["timestamp"]
    })
    history.append({
        "sender": "user",
        "text": data["reply"],
        "timestamp": int(time.time() * 1000)
    })


messages = [
    "Your bank account will be blocked today.",
    "Send your UPI to avoid suspension.",
    "Transfer 5000 to help@paytm urgently.",
    "Click https://evil.com/verify now.",
    "We are from RBI fraud department.",
    "Why are you delaying? Send immediately.",
    "Share phone number for verification.",
    "Final warning. Send money to help@paytm now."
]

for m in messages:
    send(m)
    time.sleep(0.5)

print("\nFinished 8 scammer turns. Check server logs for callback.")


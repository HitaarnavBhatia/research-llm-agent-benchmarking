import requests

api_key = "sk-proj-... # REMOVED BEFORE UPLOAD"
url = "https://api.openai.com/v1/chat/completions"
payload = {
    "model": "gpt-5.4-mini",
    "messages": [{"role": "user", "content": "test json response please"}],
    "temperature": 0,
    "max_tokens": 1024
}
headers = {
    "Authorization": f"Bearer {api_key}",
    "Content-Type": "application/json"
}

resp = requests.post(url, json=payload, headers=headers)
print(resp.status_code)
print(resp.text)

import requests
import json
from typing import Dict

class LLMClient:
    def __init__(self, api_key: str, model: str = "gpt-5.4-mini"):
        self.api_key = api_key
        self.model = model
        self.url = "https://api.openai.com/v1/chat/completions"
    
    def analyze_code(self, prompt: str, method_code: str) -> Dict:
        """
        分析代码片段是否调用了大模型
        
        Args:
            prompt: 提示词模板
            method_code: 要分析的代码片段
            
        Returns:
            大模型返回的JSON响应
        """
        full_prompt = prompt.format(method_code=method_code)
        
        try:
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": full_prompt}],
                "temperature": 0,
                "max_completion_tokens": 1024
            }

            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }

            response = requests.post(self.url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
            
        except requests.exceptions.RequestException as e:
            return {"error": f"Request Error: {e}", "analysis": None}
        except Exception as e:
            return {"error": f"Unexpected error: {e}", "analysis": None}
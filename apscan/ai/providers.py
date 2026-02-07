import os
import logging
from typing import Optional
from apscan.ai.base import AIProvider
from apscan.core.context import Vulnerability

logger = logging.getLogger(__name__)

class GeminiProvider(AIProvider):
    def __init__(self, api_key: str, model_name: str = "gemini-1.5-flash"):
        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            self.model = genai.GenerativeModel(model_name)
        except ImportError:
            logger.error("google-generativeai package not installed.")
            self.model = None

    def analyze_finding(self, finding: Vulnerability) -> str:
        if not self.model:
            return "AI Analysis Unavailable: Dependency missing."

        prompt = self._build_prompt(finding)
        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            logger.error(f"Gemini API Error: {e}")
            return f"AI Analysis Failed: {e}"

    def _build_prompt(self, finding: Vulnerability) -> str:
        return f"""
        You are an expert Application Security Engineer. Analyze the following vulnerability found by an automated scanner.
        
        **Vulnerability**: {finding.name}
        **Endpoint**: {finding.method} {finding.endpoint}
        **Severity**: {finding.severity.value}
        **Evidence**: {finding.evidence}
        **Reproduce Params**: {finding.reproduce_curl}
        
        **Task**:
        1. Explain WHY this is a vulnerability in simple terms.
        2. Assess if this could be a False Positive based on the evidence (Confidence check).
        3. Provide specific code remediation steps (Python/Node.js examples if relevant).
        
        Keep the response concise (max 300 words). Format in Markdown.
        """

class OpenAIProvider(AIProvider):
    def __init__(self, api_key: str, model_name: str = "gpt-4o-mini"):
        try:
            from openai import OpenAI
            self.client = OpenAI(api_key=api_key)
            self.model_name = model_name
        except ImportError:
            self.client = None

    def analyze_finding(self, finding: Vulnerability) -> str:
        if not self.client:
            return "AI Analysis Unavailable: Dependency missing."
            
        prompt = f"""
        Analyze this security finding:
        Name: {finding.name}
        Evidence: {finding.evidence}
        
        Provide: 1. Explanation, 2. False Positive likelihood, 3. Remediation.
        """
        
        try:
            response = self.client.chat.completions.create(
                model=self.model_name,
                messages=[
                    {"role": "system", "content": "You are a Security Expert."},
                    {"role": "user", "content": prompt}
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"OpenAI API Error: {e}")
            return f"AI Analysis Failed: {e}"

class LocalProvider(OpenAIProvider):
    # Compatible with Ollama / LocalLLM offering OpenAI-compatible API
    def __init__(self, base_url: str, api_key: str = "lm-studio", model_name: str = "local-model"):
        try:
            from openai import OpenAI
            self.client = OpenAI(base_url=base_url, api_key=api_key)
            self.model_name = model_name
        except ImportError:
            self.client = None

class MockAIProvider(AIProvider):
    def analyze_finding(self, finding: Vulnerability) -> str:
        return f"**AI Analysis**: Validated {finding.name}. This appears to be a TRUE POSITIVE. Recommendation: Fix immediately."

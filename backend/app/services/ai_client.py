import httpx

from app.core.config import settings
from app.core.logging_config import logger


class AIClient:
    """
    Async client for Groq API inference.
    Used for security insight generation and interactive chat.
    """

    def __init__(self):
        self.api_key = settings.GROQ_API_KEY
        self.model = settings.GROQ_MODEL
        self.base_url = "https://api.groq.com/openai/v1"

    async def generate(self, prompt: str) -> str | None:
        """
        Send a prompt to Groq and return the generated text.
        Returns None if API is unavailable or misconfigured.
        """
        if not self.api_key:
            logger.warning("Groq API key is not configured — skipping AI generation")
            return None

        url = f"{self.base_url}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.4,
            "top_p": 0.8,
            "max_tokens": 1024,
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(url, headers=headers, json=payload)

                if response.status_code != 200:
                    logger.error(f"Groq API error ({response.status_code}): {response.text}")
                    return None

                data = response.json()
                choices = data.get("choices", [])
                if choices:
                    message = choices[0].get("message", {})
                    result = message.get("content", "").strip()
                    if result:
                        logger.info(f"Groq response received ({len(result)} chars)")
                        return result

                logger.warning("Groq response format unrecognized or empty")
                return None

        except httpx.TimeoutException:
            logger.warning("Groq request timed out")
            return None
        except Exception as e:
            logger.error(f"Groq client communication error: {e}")
            return None

    async def is_available(self) -> bool:
        """Check if Groq API is configured."""
        return bool(self.api_key)

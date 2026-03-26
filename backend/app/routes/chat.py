"""
Chat Route — POST /chat
Handles contextual AI conversations based on log analysis findings.
"""

from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel

from app.core.logging_config import logger
from app.models.schemas import ChatRequest, ChatResponse
from app.services.ai_engine import AIEngine

router = APIRouter()

def get_ai_engine() -> AIEngine:
    return AIEngine()


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    ai_engine: AIEngine = Depends(get_ai_engine),
) -> ChatResponse:
    """
    Interactive contextual chat endpoint.
    Passes the user message and previous analysis context to Groq (Llama 3).
    """
    try:
        reply = await ai_engine.chat_with_context(
            message=request.message,
            context=request.context or {}
        )
        return ChatResponse(reply=reply)
    except Exception as e:
        logger.error(f"Chat error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to process chat request.")

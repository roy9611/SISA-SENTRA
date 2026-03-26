"""Pydantic schemas for strict API contract compliance."""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, Field, field_validator


class Options(BaseModel):
    """Analysis options controlling masking, blocking, and log analysis."""

    mask: bool = False
    block_high_risk: bool = False
    log_analysis: bool = True

    model_config = {"extra": "ignore"}


class AnalyzeRequest(BaseModel):
    """
    Request schema for POST /analyze.
    Supports: text, file, sql, chat, log input types.
    """

    input_type: str = Field(
        ...,
        description="Type of input: text | file | sql | chat | log",
    )
    content: str = Field(
        ...,
        description="The content to analyze (raw text or base64-encoded file)",
    )
    file_name: str | None = Field(
        default=None,
        description="Optional original filename for proper MIME parsing"
    )
    options: Options = Field(default_factory=Options)

    @field_validator("input_type")
    @classmethod
    def validate_input_type(cls, v: str) -> str:
        allowed = {"text", "file", "sql", "chat", "log"}
        if v.lower() not in allowed:
            raise ValueError(f"input_type must be one of {allowed}")
        return v.lower()

    @field_validator("content")
    @classmethod
    def validate_content_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("content must not be empty")
        return v


class Finding(BaseModel):
    """A single detection finding — strict: only type, risk, line."""

    type: str
    risk: str
    line: int


class AnalyzeResponse(BaseModel):
    """
    Response schema for POST /analyze.
    Matches the exact API contract with no extra fields.
    """

    summary: str
    content_type: str
    findings: list[Finding]
    risk_score: int
    risk_level: str
    action: str
    insights: list[str]
    risks: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    fix_instructions: str = ""
    extracted_entities: dict[str, str] = Field(default_factory=dict)

    model_config = {"extra": "ignore"}


class ChatRequest(BaseModel):
    """Request schema for POST /chat."""

    message: str
    context: Optional[AnalyzeResponse] = None

    model_config = {"extra": "ignore"}


class ChatResponse(BaseModel):
    """Response schema for POST /chat."""

    reply: str

    model_config = {"extra": "ignore"}

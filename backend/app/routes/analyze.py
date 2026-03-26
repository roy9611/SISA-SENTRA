"""
Analysis Route — POST /analyze orchestrator.
Orchestrates Input → Parse → Detect → Risk → AI → Response.
"""

from fastapi import APIRouter, HTTPException, Depends

from app.core.logging_config import logger
from app.models.schemas import AnalyzeRequest, AnalyzeResponse, Finding
from app.services.parser import Parser
from app.services.detector import Detector
from app.services.risk_engine import RiskEngine
from app.services.ai_engine import AIEngine

router = APIRouter()

def get_parser() -> Parser:
    return Parser()

def get_detector() -> Detector:
    return Detector()

def get_risk_engine() -> RiskEngine:
    return RiskEngine()

def get_ai_engine() -> AIEngine:
    return AIEngine()


@router.post("/analyze", response_model=AnalyzeResponse)
async def analyze(
    request: AnalyzeRequest,
    parser: Parser = Depends(get_parser),
    detector: Detector = Depends(get_detector),
    risk_engine: RiskEngine = Depends(get_risk_engine),
    ai_engine: AIEngine = Depends(get_ai_engine),
) -> AnalyzeResponse:
    """
    Primary analysis endpoint.
    Processes content through a clean pipeline.
    """
    try:
        logger.info(f"Analysis Started: type={request.input_type}")

        # 1. Parse content
        content = parser.parse(request.input_type, request.content, request.file_name)
        content_type = parser.get_content_type_label(request.input_type)

        # 2. Detect Findings
        is_log = (request.input_type == "log" or request.options.log_analysis)
        findings = detector.detect(content, is_log)

        # 3. Calculate Risk
        risk_result = risk_engine.calculate_risk(findings)
        risk_score = risk_result["score"]
        risk_level = risk_result["level"]

        # 4. Apply Policy (Masking/Blocking)
        policy_result = risk_engine.apply_policy(
            content=content,
            findings=findings,
            risk_level=risk_level,
            mask=request.options.mask,
            block_high_risk=request.options.block_high_risk,
        )
        action = policy_result["action"]

        # 5. Generate AI Insights
        ai_result = await ai_engine.generate_insights(
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            content_type=content_type,
        )
        summary = ai_result["summary"]
        risks = ai_result["risks"]
        recommendations = ai_result["recommendations"]
        fix_instructions = ai_result.get("fix_instructions", "")

        # 6. Return Structured Response
        findings.sort(key=lambda f: f.line)
        
        response = AnalyzeResponse(
            summary=summary,
            content_type=content_type,
            findings=findings,
            risk_score=risk_score,
            risk_level=risk_level,
            action=action,
            insights=risks,  # Map 'risks' from AI to 'insights'
            recommendations=recommendations,
            fix_instructions=fix_instructions,
        )

        logger.info(f"Analysis Finished: action={action}, findings={len(findings)}")
        return response

    except ValueError as e:
        logger.error(f"Validation error: {e}")
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Analysis error: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Internal analysis failure")

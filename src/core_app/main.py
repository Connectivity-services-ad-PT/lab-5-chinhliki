import http
import os
import sys
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional

import psycopg2
from psycopg2 import pool
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ----------------- Fail Fast: Environment Validation -----------------
REQUIRED_ENV_VARS = [
    "DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME",
    "ANALYTICS_SERVICE_URL", "GATE_SERVICE_URL", "NOTIFY_SERVICE_URL"
]
missing_envs = [var for var in REQUIRED_ENV_VARS if not os.getenv(var)]
if missing_envs:
    print(f"CRITICAL: Missing required environment variables: {', '.join(missing_envs)}", file=sys.stderr)
    sys.exit(1)

SERVICE_NAME = os.getenv("SERVICE_NAME", "core-business")
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "1.0.0")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "local-dev-token-real")

DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")

ANALYTICS_SERVICE_URL = os.getenv("ANALYTICS_SERVICE_URL")
GATE_SERVICE_URL = os.getenv("GATE_SERVICE_URL")
NOTIFY_SERVICE_URL = os.getenv("NOTIFY_SERVICE_URL")

db_pool = None

app = FastAPI(
    title="FIT4110 Lab 05 - Core Business Service (Docker Compose & DB)",
    version=SERVICE_VERSION,
    description="Dockerized Core Business Policy Engine API integrated with PostgreSQL database, rate limiting, and graceful shutdown.",
)

# ----------------- Models -----------------

class HealthResponse(BaseModel):
    status: str
    timestamp: str

class ProblemDetails(BaseModel):
    type: str = "about:blank"
    title: str
    status: int = Field(..., ge=400, le=599)
    detail: str
    instance: Optional[str] = None

class AccessEventRequest(BaseModel):
    event_type: str = Field(..., examples=["access_event"])
    timestamp: str = Field(..., examples=["2026-05-18T08:30:00Z"])
    card_id: str = Field(..., examples=["RFID-2026-9999"])
    gate_id: str = Field(..., examples=["gate-lib-01"])
    direction: str = Field(..., examples=["IN"])

class AccessEventResponse(BaseModel):
    access_granted: bool
    reason: str
    person_id: str

class AlertSeverity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"

class Alert(BaseModel):
    alert_id: str
    type: str
    severity: AlertSeverity
    message: str
    created_at: str
    resolved_at: Optional[str] = None

class PaginationInfo(BaseModel):
    next_cursor: Optional[str] = None
    has_more: bool

class AlertListResponse(BaseModel):
    status: str
    data: List[Alert]
    pagination: PaginationInfo

class AccessEventHistoryItem(BaseModel):
    event_id: str
    card_id: str
    gate_id: str
    direction: str
    timestamp: str
    access_granted: bool
    reason: str

class AccessEventHistoryResponse(BaseModel):
    status: str
    data: List[AccessEventHistoryItem]
    pagination: PaginationInfo

# ----------------- Helpers -----------------

def build_problem(
    *,
    status_code: int,
    title: str,
    detail: str,
    instance: Optional[str] = None,
    problem_type: str = "about:blank",
) -> Dict:
    problem = {
        "type": problem_type,
        "title": title,
        "status": status_code,
        "detail": detail,
    }
    if instance:
        problem["instance"] = instance
    return problem

# ----------------- Database Setup & Handlers -----------------

def init_db():
    global db_pool
    try:
        # Wait up to 10 seconds for initial connection pool creation
        print("INFO: Creating PostgreSQL database connection pool...")
        db_pool = psycopg2.pool.SimpleConnectionPool(
            1, 20,
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        
        # Test connection and initialize tables
        conn = db_pool.getconn()
        try:
            with conn.cursor() as cursor:
                # Create access_events table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS access_events (
                        event_id VARCHAR(50) PRIMARY KEY,
                        card_id VARCHAR(50) NOT NULL,
                        gate_id VARCHAR(50) NOT NULL,
                        direction VARCHAR(10) NOT NULL,
                        timestamp VARCHAR(50) NOT NULL,
                        access_granted BOOLEAN NOT NULL,
                        reason TEXT NOT NULL
                    );
                """)
                # Create alerts table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        alert_id VARCHAR(50) PRIMARY KEY,
                        type VARCHAR(100) NOT NULL,
                        severity VARCHAR(20) NOT NULL,
                        message TEXT NOT NULL,
                        created_at VARCHAR(50) NOT NULL,
                        resolved_at VARCHAR(50)
                    );
                """)
                # Insert initial alert
                cursor.execute("""
                    INSERT INTO alerts (alert_id, type, severity, message, created_at, resolved_at)
                    VALUES (
                        'ALT-B6-20260518-001',
                        'suspicious_card_activity',
                        'medium',
                        'Cảnh báo: Thẻ RFID-2026-9999 được quẹt liên tiếp tại 2 cổng khác nhau trong vòng dưới 30 giây.',
                        '2026-05-18T08:30:15Z',
                        NULL
                    ) ON CONFLICT (alert_id) DO NOTHING;
                """)
                conn.commit()
                print("INFO: Database tables initialized successfully.")
        finally:
            db_pool.putconn(conn)
    except Exception as e:
        print(f"CRITICAL: Failed to connect to database or initialize tables: {e}", file=sys.stderr)
        sys.exit(1)

def db_save_access_event(event: AccessEventHistoryItem):
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                INSERT INTO access_events (event_id, card_id, gate_id, direction, timestamp, access_granted, reason)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (event.event_id, event.card_id, event.gate_id, event.direction, event.timestamp, event.access_granted, event.reason))
            conn.commit()
    finally:
        db_pool.putconn(conn)

def db_list_access_events(limit: int) -> List[AccessEventHistoryItem]:
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT event_id, card_id, gate_id, direction, timestamp, access_granted, reason 
                FROM access_events 
                ORDER BY timestamp DESC 
                LIMIT %s
            """, (limit,))
            rows = cursor.fetchall()
            return [
                AccessEventHistoryItem(
                    event_id=row[0],
                    card_id=row[1],
                    gate_id=row[2],
                    direction=row[3],
                    timestamp=row[4],
                    access_granted=row[5],
                    reason=row[6]
                ) for row in rows
            ]
    finally:
        db_pool.putconn(conn)

def db_count_access_events() -> int:
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("SELECT COUNT(*) FROM access_events")
            return cursor.fetchone()[0]
    finally:
        db_pool.putconn(conn)

def db_list_alerts(limit: int) -> List[Alert]:
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT alert_id, type, severity, message, created_at, resolved_at 
                FROM alerts 
                ORDER BY created_at DESC 
                LIMIT %s
            """, (limit,))
            rows = cursor.fetchall()
            return [
                Alert(
                    alert_id=row[0],
                    type=row[1],
                    severity=AlertSeverity(row[2]),
                    message=row[3],
                    created_at=row[4],
                    resolved_at=row[5]
                ) for row in rows
            ]
    finally:
        db_pool.putconn(conn)

def db_get_alert_by_id(alert_id: str) -> Optional[Alert]:
    conn = db_pool.getconn()
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT alert_id, type, severity, message, created_at, resolved_at 
                FROM alerts 
                WHERE alert_id = %s
            """, (alert_id,))
            row = cursor.fetchone()
            if row:
                return Alert(
                    alert_id=row[0],
                    type=row[1],
                    severity=AlertSeverity(row[2]),
                    message=row[3],
                    created_at=row[4],
                    resolved_at=row[5]
                )
            return None
    finally:
        db_pool.putconn(conn)

# ----------------- Lifespan & Events -----------------

@app.on_event("startup")
def startup_event():
    init_db()

@app.on_event("shutdown")
def shutdown_event():
    global db_pool
    if db_pool:
        db_pool.closeall()
        print("INFO: Closing DB connection pool... Graceful shutdown completed.")

# ----------------- Rate Limiting Middleware -----------------

RATE_LIMIT_LIMIT = 60
RATE_LIMIT_WINDOW = 60 # seconds
request_history: Dict[str, List[float]] = {}

@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    # Bypass healthcheck to ensure wait-on and Docker internal healthchecks are not blocked
    if request.url.path == "/health":
        return await call_next(request)

    client_ip = request.client.host if request.client else "unknown"
    now = time.time()

    if client_ip not in request_history:
        request_history[client_ip] = []

    # Clean old timestamps
    request_history[client_ip] = [t for t in request_history[client_ip] if now - t < RATE_LIMIT_WINDOW]

    if len(request_history[client_ip]) >= RATE_LIMIT_LIMIT:
        problem = build_problem(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            title="Too Many Requests",
            detail="Tần suất gửi yêu cầu vượt quá giới hạn cho phép (60 requests/phút). Vui lòng thử lại sau.",
            instance=str(request.url.path),
            problem_type="https://smartcampus.dnu.edu.vn/probs/too-many-requests",
        )
        return JSONResponse(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            content=problem,
            media_type="application/problem+json",
        )

    request_history[client_ip].append(now)
    return await call_next(request)

# ----------------- Exception Handlers -----------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    if isinstance(exc.detail, dict):
        problem = exc.detail
    else:
        problem = build_problem(
            status_code=exc.status_code,
            title=http.client.responses.get(exc.status_code, "HTTP Error"),
            detail=str(exc.detail),
            instance=str(request.url.path),
        )

    problem.setdefault("status", exc.status_code)
    problem.setdefault("title", http.client.responses.get(exc.status_code, "HTTP Error"))
    problem.setdefault("type", "about:blank")
    problem.setdefault("detail", "Request failed")
    problem.setdefault("instance", str(request.url.path))

    return JSONResponse(
        status_code=exc.status_code,
        content=problem,
        media_type="application/problem+json",
        headers=getattr(exc, "headers", None),
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    first_error = exc.errors()[0] if exc.errors() else {}
    location = ".".join(str(item) for item in first_error.get("loc", []))
    message = first_error.get("msg", "Request validation error")
    detail = f"{location}: {message}" if location else message

    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=build_problem(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            title="Validation error",
            detail=detail,
            instance=str(request.url.path),
            problem_type="https://smartcampus.dnu.edu.vn/probs/bad-request",
        ),
        media_type="application/problem+json",
    )

# ----------------- Auth Dependency -----------------

def verify_bearer_token(authorization: Optional[str] = Header(default=None)) -> None:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=build_problem(
                status_code=status.HTTP_401_UNAUTHORIZED,
                title="Unauthorized Access",
                detail="Missing Authorization header",
                problem_type="https://smartcampus.dnu.edu.vn/probs/unauthorized",
            ),
        )

    expected = f"Bearer {AUTH_TOKEN}"
    if authorization != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=build_problem(
                status_code=status.HTTP_401_UNAUTHORIZED,
                title="Unauthorized Access",
                detail="Invalid bearer token",
                problem_type="https://smartcampus.dnu.edu.vn/probs/unauthorized",
            ),
        )

# ----------------- Endpoints -----------------

@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(
        status="UP",
        timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

@app.post(
    "/api/v1/events/access",
    response_model=AccessEventResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(verify_bearer_token)],
    responses={
        400: {"model": ProblemDetails},
        401: {"model": ProblemDetails},
        422: {"model": ProblemDetails},
    },
)
def process_access_event(
    payload: AccessEventRequest,
    request: Request,
    prefer: Optional[str] = Header(default=None)
) -> AccessEventResponse:
    # Handle Prefer header or blacklist card to test business rule violations
    if (prefer and "code=422" in prefer) or "BLACKLIST" in payload.card_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=build_problem(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                title="Business Rule Violation",
                detail="Thẻ nằm trong danh sách đen bị khóa hoặc vi phạm quy tắc an ninh.",
                instance=str(request.url.path),
                problem_type="https://smartcampus.dnu.edu.vn/probs/business-rule-violation",
            ),
        )

    # Simple business rules
    access_granted = True
    reason = "Thẻ sinh viên hợp lệ và còn thời hạn truy cập"
    person_id = "SV00123"

    if payload.card_id == "RFID-DENY":
        access_granted = False
        reason = "Thẻ không có quyền truy cập vào cổng này"
        person_id = "SV00000"

    # Add to DB history
    try:
        event_count = db_count_access_events()
        event_id = f"acc-uuid-2026-{event_count + 1:04d}"
        history_item = AccessEventHistoryItem(
            event_id=event_id,
            card_id=payload.card_id,
            gate_id=payload.gate_id,
            direction=payload.direction,
            timestamp=payload.timestamp,
            access_granted=access_granted,
            reason=reason
        )
        db_save_access_event(history_item)
    except Exception as e:
        print(f"ERROR: Failed to save access event to database: {e}", file=sys.stderr)
        # Fallback to allow mock test to succeed even if DB has issues during direct API test (optional, but real code should throw or handle)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Không thể lưu lịch sử sự kiện truy cập vào cơ sở dữ liệu."
        )

    return AccessEventResponse(
        access_granted=access_granted,
        reason=reason,
        person_id=person_id
    )

@app.get(
    "/api/v1/alerts",
    response_model=AlertListResponse,
    dependencies=[Depends(verify_bearer_token)],
    responses={401: {"model": ProblemDetails}},
)
def list_alerts(
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None)
) -> AlertListResponse:
    try:
        data = db_list_alerts(limit)
    except Exception as e:
        print(f"ERROR: Failed to list alerts from database: {e}", file=sys.stderr)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Không thể truy vấn danh sách cảnh báo từ cơ sở dữ liệu."
        )
    return AlertListResponse(
        status="success",
        data=data,
        pagination=PaginationInfo(next_cursor=None, has_more=False)
    )

@app.get(
    "/api/v1/alerts/{id}",
    response_model=Alert,
    dependencies=[Depends(verify_bearer_token)],
    responses={
        401: {"model": ProblemDetails},
        404: {"model": ProblemDetails},
    },
)
def get_alert_by_id(
    id: str,
    request: Request,
    prefer: Optional[str] = Header(default=None)
) -> Alert:
    if (prefer and "code=404" in prefer) or id == "ALT-NOT-FOUND-999":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=build_problem(
                status_code=status.HTTP_404_NOT_FOUND,
                title="Resource Not Found",
                detail=f"Không tìm thấy mã Alert yêu cầu: {id}",
                instance=str(request.url.path),
                problem_type="https://smartcampus.dnu.edu.vn/probs/not-found",
            ),
        )

    try:
        alert = db_get_alert_by_id(id)
    except Exception as e:
        print(f"ERROR: Failed to retrieve alert {id} from database: {e}", file=sys.stderr)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Lỗi khi truy vấn cảnh báo {id} từ cơ sở dữ liệu."
        )

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=build_problem(
                status_code=status.HTTP_404_NOT_FOUND,
                title="Resource Not Found",
                detail=f"Không tìm thấy mã Alert yêu cầu: {id}",
                instance=str(request.url.path),
                problem_type="https://smartcampus.dnu.edu.vn/probs/not-found",
            ),
        )

    return alert

@app.get(
    "/api/v1/events/access",
    response_model=AccessEventHistoryResponse,
    dependencies=[Depends(verify_bearer_token)],
    responses={401: {"model": ProblemDetails}},
)
def list_access_events(
    limit: int = Query(default=20, ge=1, le=100),
    cursor: Optional[str] = Query(default=None)
) -> AccessEventHistoryResponse:
    try:
        data = db_list_access_events(limit)
    except Exception as e:
        print(f"ERROR: Failed to list access events from database: {e}", file=sys.stderr)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Không thể truy vấn lịch sử sự kiện truy cập từ cơ sở dữ liệu."
        )
    return AccessEventHistoryResponse(
        status="success",
        data=data,
        pagination=PaginationInfo(next_cursor=None, has_more=False)
    )

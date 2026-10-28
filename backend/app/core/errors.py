"""Uniform error responses. Internal details never reach the client."""

from __future__ import annotations

from fastapi import HTTPException


class ApiError(HTTPException):
    def __init__(self, status_code: int, code: str, message: str | None = None):
        super().__init__(status_code=status_code, detail={"code": code, "message": message or code})


def not_found(kind: str = "resource") -> ApiError:
    # Same answer for "does not exist" and "not allowed" to prevent enumeration (IDOR).
    return ApiError(404, "not_found", f"{kind} not found")


def forbidden(code: str = "forbidden") -> ApiError:
    return ApiError(403, code)


def bad_request(code: str, message: str | None = None) -> ApiError:
    return ApiError(400, code, message)


def conflict(code: str, message: str | None = None) -> ApiError:
    return ApiError(409, code, message)

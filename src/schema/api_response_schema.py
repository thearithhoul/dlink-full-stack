from __future__ import annotations

from typing import Generic, TypeVar

from pydantic import BaseModel, Field

DataT = TypeVar("DataT")


class ApiResponse(BaseModel, Generic[DataT]):
    success: bool = Field(default=True, description="Whether the request succeeded.")
    message: str = Field(default="Request successful.")
    data: DataT | None = None

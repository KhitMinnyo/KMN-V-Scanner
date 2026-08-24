"""API request schemas."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    profile: Literal["quick", "standard", "deep"] = "standard"
    include_nse: bool = True
    include_nuclei: bool = True
    include_tls: bool = True
    include_zap: bool = False
    include_udp: bool = False
    authorization_confirmed: bool = Field(
        default=False,
        description="The operator confirms they own or are authorized to scan the target.",
    )

    @field_validator("target")
    @classmethod
    def clean_target(cls, value: str) -> str:
        return value.strip()


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)

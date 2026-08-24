"""API request schemas."""

from typing import Literal

from pydantic import BaseModel, Field, field_validator


class ScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=253)
    profile: Literal["quick", "standard", "deep"] = "standard"
    include_nse: bool = True
    include_cve_match: bool = True
    include_nuclei: bool = True
    include_tls: bool = True
    include_zap: bool = False
    include_udp: bool = False
    include_ssh_audit: bool = False
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


class ArtifactScanRequest(BaseModel):
    target: str = Field(min_length=1, max_length=512)
    mode: Literal["fs", "image"] = "fs"
    authorization_confirmed: bool = False


class WindowsScanRequest(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=5986, ge=1, le=65535)
    authorization_confirmed: bool = False


class CloudScanRequest(BaseModel):
    provider: Literal["aws", "azure", "gcp"]
    authorization_confirmed: bool = False


class ScheduleRequest(ScanRequest):
    interval_minutes: int = Field(ge=5, le=525600)


class ScheduleStateRequest(BaseModel):
    enabled: bool

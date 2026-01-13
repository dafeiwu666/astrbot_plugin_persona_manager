from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class PersonaEditStage(str, Enum):
    INTRO = "intro"
    TAGS = "tags"
    WRAPPER = "wrapper"
    CONTENT = "content"
    CONTINUE = "continue"


class PersonaEditState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    stage: PersonaEditStage = PersonaEditStage.INTRO
    name: str
    intro: str = ""
    tags: list[str] = Field(default_factory=list)
    parts: list[str] = Field(default_factory=list)
    use_wrapper: bool = True

    def add_part(self, text: str) -> None:
        t = (text or "").strip()
        if t:
            self.parts.append(t)

    def build_content(self) -> str:
        return "\n".join([p for p in self.parts if str(p).strip()])

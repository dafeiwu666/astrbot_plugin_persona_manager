from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

from pydantic import ValidationError

from .models import Store


class StoreRepository:
    def __init__(self, path: Path, *, logger):
        self._path = path
        self._logger = logger

    @property
    def path(self) -> Path:
        return self._path

    def _load_sync(self) -> Store:
        if not self._path.exists():
            return Store.empty()

        try:
            with self._path.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict):
                return Store.empty()
            return Store.model_validate(data)
        except ValidationError as e:
            self._logger.error(f"persona_manager: store validate failed: {e!s}")
            return Store.empty()
        except Exception as e:
            self._logger.error(f"persona_manager: load store failed: {e!s}")
            return Store.empty()

    async def load(self) -> Store:
        return await asyncio.to_thread(self._load_sync)

    def _save_sync(self, store: Store) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp = Path(str(self._path) + ".tmp")
        with tmp.open("w", encoding="utf-8") as f:
            json.dump(store.model_dump(mode="json"), f, ensure_ascii=False, indent=2)
        os.replace(tmp, self._path)

    async def save(self, store: Store) -> None:
        await asyncio.to_thread(self._save_sync, store)

# Base parser
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class BaseParser(ABC):
    @abstractmethod
    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        raise NotImplementedError

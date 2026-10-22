# Generic CSV/JSON parser
import csv
import json
from pathlib import Path
from typing import Any
from app.parsers.base_parser import BaseParser


class GenericCSVJSONParser(BaseParser):
    
    def parse(
        self,
        file_path: Path,
        original_filename: str | None = None,
    ) -> list[dict[str, Any]]:
        extension = (
            Path(original_filename).suffix.lower()
            if original_filename
            else file_path.suffix.lower()
        )

        if extension == ".csv":
            return self._parse_csv(file_path)

        if extension == ".json":
            return self._parse_json(file_path)

        if extension in {".log", ".txt"}:
            with file_path.open(
                "r", encoding="utf-8-sig", errors="replace"
            ) as file:
                first_char = ""
                while True:
                    char = file.read(1)
                    if not char or not char.isspace():
                        first_char = char
                        break

            if first_char in {"{", "["}:
                return self._parse_json(file_path)

        if extension == ".txt":
            from app.parsers.txt_parser import TextFileParser
            return TextFileParser().parse(file_path, original_filename=original_filename)

        raise ValueError(f"Unsupported file extension or content: {extension}")


    def _parse_csv(self,file_path:Path)->list[dict[str,Any]]:
        with file_path.open("r",encoding="utf-8-sig",newline="") as file:
            reader=csv.DictReader(file)
            return [dict(row) for row in reader]

    def _parse_json(self,file_path:Path)->list[dict[str,Any]]:
        with file_path.open("r", encoding="utf-8-sig") as file:
            data=json.load(file)

        if isinstance(data,dict):
            return [data]

        if isinstance(data,list) and all(
            isinstance(item,dict) for item in data
        ):
            return data
        raise ValueError(
            "JSON must contain an object or a list of objects."
        )
    
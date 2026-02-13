from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Any, Optional

from src.utils import getSolidityVersion, ASTExtractor


@dataclass
class LoadedContract:
    path: Path
    content: bytes
    source_code: str
    solidity_version: str
    ast: Dict[str, Any]


class ContractLoadError(Exception):
    pass


class ContractLoader:
    DEFAULT_VERSION = "0.4.18"
    
    def __init__(self, default_version: Optional[str] = None):
        self.default_version = default_version or self.DEFAULT_VERSION
    
    def load(self, contract_path: str | Path) -> LoadedContract:
        path = Path(contract_path)
        
        if not path.exists():
            raise ContractLoadError(f"Contract file not found: {path}")
        
        if not path.suffix == '.sol':
            raise ContractLoadError(f"Invalid file type: {path.suffix} (expected .sol)")
        
        try:
            content = path.read_bytes()
            source_code = content.decode("utf-8", errors="ignore")
        except IOError as e:
            raise ContractLoadError(f"Failed to read contract: {e}")
        
        # Detect Solidity version
        sol_version = getSolidityVersion(source_code)
        if not sol_version:
            sol_version = self.default_version
        
        # Extract AST
        try:
            ast = ASTExtractor(content)
        except Exception as e:
            raise ContractLoadError(f"AST extraction failed: {e}")
        
        return LoadedContract(
            path=path,
            content=content,
            source_code=source_code,
            solidity_version=sol_version,
            ast=ast
        )
    
    def load_multiple(self, contract_paths: list[Path]) -> list[tuple[Path, Optional[LoadedContract], Optional[str]]]:
        results = []
        for path in contract_paths:
            try:
                contract = self.load(path)
                results.append((path, contract, None))
            except ContractLoadError as e:
                results.append((path, None, str(e)))
        return results

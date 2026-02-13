import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

import solcx

# Import centralized version detection
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from services.version_detector import VersionDetector, get_best_version


@dataclass
class CompilationResult:
    success: bool
    error: Optional[str] = None
    version_used: Optional[str] = None
    
    @property
    def error_short(self) -> Optional[str]:
        """Get truncated error message."""
        if self.error and len(self.error) > 200:
            return self.error[:200] + "..."
        return self.error


class SolidityCompiler:
    # Version fallback mapping for when exact version isn't available
    VERSION_FALLBACKS = {
        '0.4': '0.4.26',
        '0.5': '0.5.17',
        '0.6': '0.6.12',
        '0.7': '0.7.6',
        '0.8': '0.8.19',
    }
    
    DEFAULT_VERSION = '0.8.19'
    
    def __init__(self, auto_install: bool = True):
        self.auto_install = auto_install
    
    def compile_file(self, file_path: str | Path) -> CompilationResult:
        try:
            source_code = Path(file_path).read_text(encoding='utf-8', errors='ignore')
            return self.compile_source(source_code)
        except IOError as e:
            return CompilationResult(success=False, error=f"File read error: {e}")
    
    def compile_source(self, source_code: str) -> CompilationResult:
        version = self.detect_version(source_code)
        
        try:
            version = self._ensure_version_available(version)
        except Exception as e:
            return CompilationResult(
                success=False, 
                error=f"Could not install solc {version}: {e}",
                version_used=version
            )
        
        try:
            solcx.compile_source(source_code, solc_version=version)
            return CompilationResult(success=True, version_used=version)
        except Exception as e:
            return CompilationResult(
                success=False, 
                error=str(e),
                version_used=version
            )
    
    def detect_version(self, source_code: str) -> str:
        # Use centralized syntax-aware version detection
        try:
            version = get_best_version(source_code)
            if version:
                return version
        except Exception:
            pass
        
        # Fallback to simple regex if centralized detection fails
        pattern = r'pragma\s+solidity\s+[\^~>=<]*(\d+\.\d+\.\d+)'
        match = re.search(pattern, source_code)
        if match:
            return match.group(1)
        
        # Try major.minor match (e.g., 0.8)
        pattern2 = r'pragma\s+solidity\s+.*?(\d+\.\d+)'
        match = re.search(pattern2, source_code)
        if match:
            major_minor = match.group(1)
            return self.VERSION_FALLBACKS.get(major_minor, f"{major_minor}.0")
        
        return self.DEFAULT_VERSION
    
    def _ensure_version_available(self, version: str) -> str:
        installed = [str(v) for v in solcx.get_installed_solc_versions()]
        
        if version in installed:
            return version
        
        if self.auto_install:
            try:
                solcx.install_solc(version)
                return version
            except Exception:
                # Try fallback version
                major_minor = '.'.join(version.split('.')[:2])
                fallback = self.VERSION_FALLBACKS.get(major_minor, self.DEFAULT_VERSION)
                
                if fallback not in installed:
                    solcx.install_solc(fallback)
                return fallback
        
        raise RuntimeError(f"Compiler version {version} not available")
    
    @staticmethod
    def get_installed_versions() -> list[str]:
        return [str(v) for v in solcx.get_installed_solc_versions()]

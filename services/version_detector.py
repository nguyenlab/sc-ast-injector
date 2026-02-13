import re
from typing import Optional, Tuple, List, Dict
from dataclasses import dataclass
from enum import Enum


class VersionConstraint(Enum):
    """Types of version constraints in pragma statements."""
    EXACT = "exact"           # pragma solidity 0.4.24;
    CARET = "caret"           # pragma solidity ^0.4.24;
    GREATER_EQUAL = "gte"     # pragma solidity >=0.4.24;
    GREATER = "gt"            # pragma solidity >0.4.24;
    LESS = "lt"               # pragma solidity <0.5.0;
    LESS_EQUAL = "lte"        # pragma solidity <=0.5.0;
    RANGE = "range"           # pragma solidity >=0.4.24 <0.5.0;


@dataclass
class SolidityVersion:
    """Represents a parsed Solidity version."""
    major: int
    minor: int
    patch: int
    
    def __str__(self) -> str:
        return f"{self.major}.{self.minor}.{self.patch}"
    
    def __lt__(self, other: "SolidityVersion") -> bool:
        return (self.major, self.minor, self.patch) < (other.major, other.minor, other.patch)
    
    def __le__(self, other: "SolidityVersion") -> bool:
        return (self.major, self.minor, self.patch) <= (other.major, other.minor, other.patch)
    
    def __eq__(self, other: "SolidityVersion") -> bool:
        return (self.major, self.minor, self.patch) == (other.major, other.minor, other.patch)
    
    def __ge__(self, other: "SolidityVersion") -> bool:
        return (self.major, self.minor, self.patch) >= (other.major, other.minor, other.patch)
    
    def __gt__(self, other: "SolidityVersion") -> bool:
        return (self.major, self.minor, self.patch) > (other.major, other.minor, other.patch)
    
    def __hash__(self) -> int:
        return hash((self.major, self.minor, self.patch))
    
    @classmethod
    def from_string(cls, version_str: str) -> "SolidityVersion":
        """Parse version from string like '0.4.24' or '0.4'."""
        version_str = version_str.strip()
        parts = version_str.split(".")
        
        major = int(parts[0]) if len(parts) > 0 else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        patch = int(parts[2]) if len(parts) > 2 else 0
        
        return cls(major, minor, patch)


@dataclass
class PragmaInfo:
    """Information extracted from pragma statement."""
    raw_pragma: str
    constraint_type: VersionConstraint
    min_version: Optional[SolidityVersion]
    max_version: Optional[SolidityVersion]
    recommended_version: SolidityVersion


# Minimum version supported by py-solc-x
MIN_SUPPORTED_VERSION = SolidityVersion(0, 4, 11)

# Tool-specific minimum versions
TOOL_MIN_VERSIONS = {
    "mythril": SolidityVersion(0, 4, 11),
    "slither": SolidityVersion(0, 4, 0),
    "solcx": SolidityVersion(0, 4, 11),
    "solc": SolidityVersion(0, 4, 11),
}

# Known stable versions for each minor version
STABLE_VERSIONS = {
    (0, 4): SolidityVersion(0, 4, 26),
    (0, 5): SolidityVersion(0, 5, 17),
    (0, 6): SolidityVersion(0, 6, 12),
    (0, 7): SolidityVersion(0, 7, 6),
    (0, 8): SolidityVersion(0, 8, 24),
}

# Fallback versions when upgrading from unsupported versions
FALLBACK_VERSIONS = {
    # Old 0.4.x versions fall back to 0.4.11 (minimum supported)
    (0, 4, 0): SolidityVersion(0, 4, 11),
    (0, 4, 1): SolidityVersion(0, 4, 11),
    (0, 4, 2): SolidityVersion(0, 4, 11),
    (0, 4, 3): SolidityVersion(0, 4, 11),
    (0, 4, 4): SolidityVersion(0, 4, 11),
    (0, 4, 5): SolidityVersion(0, 4, 11),
    (0, 4, 6): SolidityVersion(0, 4, 11),
    (0, 4, 7): SolidityVersion(0, 4, 11),
    (0, 4, 8): SolidityVersion(0, 4, 11),
    (0, 4, 9): SolidityVersion(0, 4, 11),
    (0, 4, 10): SolidityVersion(0, 4, 11),
}


def get_tool_min_version(tool_name: str) -> SolidityVersion:
    return TOOL_MIN_VERSIONS.get(tool_name.lower(), MIN_SUPPORTED_VERSION)


def get_tool_compatible_version(pragma_version: SolidityVersion, tool_name: str = "mythril") -> SolidityVersion:
    tool_min = get_tool_min_version(tool_name)
    
    if pragma_version < tool_min:
        return tool_min
    
    return pragma_version


class VersionDetector:
    # Patterns for pragma detection
    PRAGMA_PATTERNS = [
        # Range: >=0.4.24 <0.5.0 or >=0.4.24 <=0.5.0
        re.compile(
            r'pragma\s+solidity\s+>=?\s*(\d+\.\d+(?:\.\d+)?)\s+<?=?\s*(\d+\.\d+(?:\.\d+)?)\s*;',
            re.IGNORECASE
        ),
        # Caret: ^0.4.24
        re.compile(
            r'pragma\s+solidity\s+\^\s*(\d+\.\d+(?:\.\d+)?)\s*;',
            re.IGNORECASE
        ),
        # Greater/GreaterEqual: >=0.4.24 or >0.4.24
        re.compile(
            r'pragma\s+solidity\s+(>=?)\s*(\d+\.\d+(?:\.\d+)?)\s*;',
            re.IGNORECASE
        ),
        # Less/LessEqual: <0.5.0 or <=0.5.0
        re.compile(
            r'pragma\s+solidity\s+(<=?)\s*(\d+\.\d+(?:\.\d+)?)\s*;',
            re.IGNORECASE
        ),
        # Exact: 0.4.24 (no operator)
        re.compile(
            r'pragma\s+solidity\s+(\d+\.\d+(?:\.\d+)?)\s*;',
            re.IGNORECASE
        ),
    ]
    
    @classmethod
    def detect_version(cls, source_code: str) -> Optional[PragmaInfo]:
        # Try range pattern first (most specific)
        match = cls.PRAGMA_PATTERNS[0].search(source_code)
        if match:
            min_ver = SolidityVersion.from_string(match.group(1))
            max_ver = SolidityVersion.from_string(match.group(2))
            recommended = cls._get_recommended_version(min_ver, max_ver)
            return PragmaInfo(
                raw_pragma=match.group(0),
                constraint_type=VersionConstraint.RANGE,
                min_version=min_ver,
                max_version=max_ver,
                recommended_version=recommended
            )
        
        # Try caret pattern
        match = cls.PRAGMA_PATTERNS[1].search(source_code)
        if match:
            base_ver = SolidityVersion.from_string(match.group(1))
            # Caret allows changes up to next minor version
            max_ver = SolidityVersion(base_ver.major, base_ver.minor + 1, 0)
            recommended = cls._get_recommended_version(base_ver, max_ver)
            return PragmaInfo(
                raw_pragma=match.group(0),
                constraint_type=VersionConstraint.CARET,
                min_version=base_ver,
                max_version=max_ver,
                recommended_version=recommended
            )
        
        # Try greater/greater-equal pattern
        match = cls.PRAGMA_PATTERNS[2].search(source_code)
        if match:
            operator = match.group(1)
            ver = SolidityVersion.from_string(match.group(2))
            constraint = VersionConstraint.GREATER_EQUAL if operator == ">=" else VersionConstraint.GREATER
            recommended = cls._get_recommended_version(ver, None)
            return PragmaInfo(
                raw_pragma=match.group(0),
                constraint_type=constraint,
                min_version=ver,
                max_version=None,
                recommended_version=recommended
            )
        
        # Try less/less-equal pattern
        match = cls.PRAGMA_PATTERNS[3].search(source_code)
        if match:
            operator = match.group(1)
            ver = SolidityVersion.from_string(match.group(2))
            constraint = VersionConstraint.LESS_EQUAL if operator == "<=" else VersionConstraint.LESS
            # For less-than constraints, use the highest version below the limit
            max_ver = ver
            min_ver = SolidityVersion(0, 4, 11)  # Assume at least 0.4.11
            recommended = cls._get_recommended_version(min_ver, max_ver)
            return PragmaInfo(
                raw_pragma=match.group(0),
                constraint_type=constraint,
                min_version=min_ver,
                max_version=max_ver,
                recommended_version=recommended
            )
        
        # Try exact pattern (most lenient, try last)
        match = cls.PRAGMA_PATTERNS[4].search(source_code)
        if match:
            ver = SolidityVersion.from_string(match.group(1))
            recommended = cls._get_fallback_version(ver)
            return PragmaInfo(
                raw_pragma=match.group(0),
                constraint_type=VersionConstraint.EXACT,
                min_version=ver,
                max_version=ver,
                recommended_version=recommended
            )
        
        return None
    
    @classmethod
    def _get_recommended_version(
        cls, 
        min_ver: SolidityVersion, 
        max_ver: Optional[SolidityVersion]
    ) -> SolidityVersion:
        # If min version is too old, use fallback
        if min_ver < MIN_SUPPORTED_VERSION:
            return cls._get_fallback_version(min_ver)
        
        # Try to use a stable version for the minor version
        stable = STABLE_VERSIONS.get((min_ver.major, min_ver.minor))
        if stable:
            if max_ver is None or stable < max_ver:
                return stable
        
        # If no stable version fits, use the min version
        return min_ver
    
    @classmethod
    def _get_fallback_version(cls, ver: SolidityVersion) -> SolidityVersion:
        # Check explicit fallback mapping
        key = (ver.major, ver.minor, ver.patch)
        if key in FALLBACK_VERSIONS:
            return FALLBACK_VERSIONS[key]
        
        # If version is already supported, return as-is
        if ver >= MIN_SUPPORTED_VERSION:
            return ver
        
        # Default fallback to minimum supported
        return MIN_SUPPORTED_VERSION
    
    @classmethod
    def get_version_string(cls, source_code: str, tool_name: str = None) -> str:
        info = cls.detect_version(source_code)
        if not info:
            return "0.4.24"  # Default fallback
        
        version = info.recommended_version
        
        # If tool is specified, ensure version meets tool minimum
        if tool_name:
            tool_min = get_tool_min_version(tool_name)
            if version < tool_min:
                version = tool_min
        
        return str(version)
    
    @classmethod
    def needs_version_upgrade(cls, source_code: str) -> Tuple[bool, str, str]:
        info = cls.detect_version(source_code)
        if not info:
            return False, "unknown", "0.4.24"
        
        original = str(info.min_version) if info.min_version else "unknown"
        recommended = str(info.recommended_version)
        
        needs_upgrade = info.min_version and info.min_version < MIN_SUPPORTED_VERSION
        return needs_upgrade, original, recommended


class VersionUpgrader:
    
    @classmethod
    def upgrade_source(cls, source_code: str, target_version: Optional[str] = None) -> Tuple[str, str]:
        detector = VersionDetector()
        info = detector.detect_version(source_code)
        
        if not info:
            return source_code, "0.4.24"
        
        if target_version:
            new_version = SolidityVersion.from_string(target_version)
        else:
            new_version = info.recommended_version
        
        # If no upgrade needed, return as-is
        if info.min_version and info.min_version >= MIN_SUPPORTED_VERSION:
            return source_code, str(info.min_version)
        
        # Replace the pragma statement
        new_pragma = f"pragma solidity {new_version};"
        upgraded_source = source_code.replace(info.raw_pragma, new_pragma)
        
        return upgraded_source, str(new_version)
    
    @classmethod
    def upgrade_file(cls, filepath: str, target_version: Optional[str] = None) -> Tuple[str, str, str]:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        info = VersionDetector.detect_version(source_code)
        original_version = str(info.min_version) if info and info.min_version else "unknown"
        
        upgraded_source, new_version = cls.upgrade_source(source_code, target_version)
        
        return upgraded_source, original_version, new_version


def get_mythril_compatible_version(source_code: str) -> str:
    return VersionDetector.get_version_string(source_code)


def upgrade_for_mythril(source_code: str) -> Tuple[str, str]:
    return VersionUpgrader.upgrade_source(source_code)


def get_best_version(source_code: str, tool_name: str = "mythril") -> str:
    return VersionDetector.get_version_string(source_code, tool_name)


def is_version_compatible_with_template(
    contract_version: str,
    template_min_version: str,
    template_max_version: str
) -> bool:
    try:
        ver = SolidityVersion.from_string(contract_version)
        min_v = SolidityVersion.from_string(template_min_version)
        max_v = SolidityVersion.from_string(template_max_version)
        return min_v <= ver <= max_v
    except (ValueError, AttributeError):
        return False


def get_compatible_templates_for_version(templates: Dict, version: str) -> Dict:
    compatible = {}
    for name, template in templates.items():
        min_ver = template.get("min_version", "0.4.0")
        max_ver = template.get("max_version", "0.9.99")
        if is_version_compatible_with_template(version, min_ver, max_ver):
            compatible[name] = template
    return compatible


# CLI interface for testing
if __name__ == "__main__":
    import sys
    import argparse
    
    parser = argparse.ArgumentParser(description="Detect and upgrade Solidity versions")
    parser.add_argument("file", help="Solidity file to analyze")
    parser.add_argument("--upgrade", action="store_true", help="Output upgraded source")
    parser.add_argument("--target", help="Target version for upgrade")
    parser.add_argument("--tool", help="Tool to check compatibility for (mythril, slither)")
    
    args = parser.parse_args()
    
    with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
        source = f.read()
    
    info = VersionDetector.detect_version(source)
    
    if not info:
        print("Could not detect Solidity version from pragma")
    else:
        print(f"Pragma: {info.raw_pragma}")
        print(f"Constraint: {info.constraint_type.value}")
        print(f"Min version (pragma): {info.min_version}")
        print(f"Max version: {info.max_version}")
        print(f"Recommended: {info.recommended_version}")
    
    # Show tool-compatible version
    if args.tool:
        best_version = get_best_version(source, args.tool)
        print(f"Best version for {args.tool}: {best_version}")
    
    needs_upgrade, orig, rec = VersionDetector.needs_version_upgrade(source)
    print(f"\nNeeds upgrade: {needs_upgrade} ({orig} -> {rec})")
    
    if args.upgrade:
        upgraded, version = VersionUpgrader.upgrade_source(source, args.target)
        print(f"\n--- Upgraded to {version} ---")
        print(upgraded)

import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

import solcx


class VulnType(Enum):
    """Vulnerability types supported for injection."""
    OVERFLOW = "overflow"
    UNDERFLOW = "underflow"
    TX_ORIGIN = "tx_origin"
    UNCHECKED_SEND = "unchecked_send"
    UNHANDLED_EXCEPTION = "unhandled_exception"
    TIMESTAMP = "timestamp"
    REENTRANCY = "reentrancy"


# =============================================================================
# SLITHER DETECTOR MAPPINGS
# =============================================================================

# Expected Slither detectors for each vulnerability type
SLITHER_DETECTORS = {
    VulnType.OVERFLOW: [],  # Slither doesn't detect integer overflow
    VulnType.UNDERFLOW: [],  # Slither doesn't detect integer underflow
    VulnType.TX_ORIGIN: ["tx-origin"],
    VulnType.UNCHECKED_SEND: ["unchecked-send"],
    VulnType.UNHANDLED_EXCEPTION: ["unchecked-lowlevel"],
    VulnType.TIMESTAMP: ["timestamp"],
    VulnType.REENTRANCY: [
        "reentrancy-eth",
        "reentrancy-no-eth",
        "reentrancy-benign",
        "reentrancy-unlimited-gas",
        "reentrancy-events",
    ],
}

# String-based mapping for convenience
SLITHER_DETECTORS_BY_NAME = {
    "overflow": [],
    "underflow": [],
    "tx_origin": ["tx-origin"],
    "unchecked_send": ["unchecked-send"],
    "unhandled_exception": ["unchecked-lowlevel"],
    "timestamp": ["timestamp"],
    "reentrancy": [
        "reentrancy-eth",
        "reentrancy-no-eth",
        "reentrancy-benign",
        "reentrancy-unlimited-gas",
        "reentrancy-events",
    ],
}

# Slither warnings to ignore (informational, not vulnerabilities)
SLITHER_IGNORE_DETECTORS = [
    "solc-version",
    "naming-convention",
    "pragma",
    "external-function",
    "dead-code",
    "constable-states",
    "immutable-states",
    "low-level-calls",
    "deprecated-standards",
    "assembly",
    "controlled-array-length",
    "too-many-digits",
    "similar-names",
    "unused-state",
    "events-maths",
    "missing-zero-check",
]


# =============================================================================
# MYTHRIL SWC MAPPINGS (for reference, Mythril is slow for real contracts)
# =============================================================================

# SWC IDs for each vulnerability type (Mythril)
# https://swcregistry.io/
SWC_MAPPING = {
    VulnType.OVERFLOW: ["101"],
    VulnType.UNDERFLOW: ["101"],
    VulnType.TX_ORIGIN: ["115"],
    VulnType.UNCHECKED_SEND: ["104"],
    VulnType.UNHANDLED_EXCEPTION: ["104"],
    VulnType.TIMESTAMP: ["116"],
    VulnType.REENTRANCY: ["107"],
}

SWC_MAPPING_BY_NAME = {
    "overflow": ["101"],
    "underflow": ["101"],
    "tx_origin": ["115"],
    "unchecked_send": ["104"],
    "unhandled_exception": ["104"],
    "timestamp": ["116"],
    "reentrancy": ["107"],
}


# =============================================================================
# DETECTION RESULT DATACLASSES
# =============================================================================

@dataclass
class SlitherResult:
    success: bool
    detected: bool
    detectors_found: List[str] = field(default_factory=list)
    expected_detectors: List[str] = field(default_factory=list)
    correct: bool = False
    time_taken: float = 0.0
    error: str = ""
    raw_output: str = ""


@dataclass
class CompilationResult:
    success: bool
    version: str = ""
    error: str = ""
    warnings: List[str] = field(default_factory=list)


# =============================================================================
# UTILITY FUNCTIONS
# =============================================================================

def get_expected_slither_detectors(vuln_type: str) -> List[str]:
    return SLITHER_DETECTORS_BY_NAME.get(vuln_type.lower(), [])


def get_expected_swc_ids(vuln_type: str) -> List[str]:
    return SWC_MAPPING_BY_NAME.get(vuln_type.lower(), [])


def is_detection_correct(
    vuln_type: str,
    detected_items: List[str],
    tool: str = "slither"
) -> bool:
    vuln_type = vuln_type.lower()
    
    if tool.lower() == "slither":
        expected = get_expected_slither_detectors(vuln_type)
        
        # For overflow/underflow, Slither doesn't detect, so any result is "correct"
        if vuln_type in ["overflow", "underflow"]:
            return True
        
        # Filter out ignored detectors
        relevant = [d for d in detected_items if d not in SLITHER_IGNORE_DETECTORS]
        
        # Check if any expected detector was found
        if not expected:
            return True  # No expected detectors means we accept any result
        
        return any(exp in relevant for exp in expected)
    
    elif tool.lower() == "mythril":
        expected = get_expected_swc_ids(vuln_type)
        return any(exp in detected_items for exp in expected)
    
    return False


def filter_relevant_detectors(detectors: List[str]) -> List[str]:
    return [d for d in detectors if d not in SLITHER_IGNORE_DETECTORS]


# =============================================================================
# COMPILATION FUNCTIONS
# =============================================================================

def compile_contract(filepath: str, version: str = None) -> CompilationResult:
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            source_code = f.read()
        
        # Auto-detect version if not provided
        if not version:
            from services.version_detector import get_best_version
            version = get_best_version(source_code, "solcx")
        
        # Ensure version is installed
        try:
            solcx.install_solc(version)
        except Exception:
            pass  # May already be installed
        
        solcx.set_solc_version(version)
        
        # Compile
        solcx.compile_source(
            source_code,
            output_values=["abi", "bin"],
            solc_version=version
        )
        
        return CompilationResult(success=True, version=version)
        
    except Exception as e:
        return CompilationResult(
            success=False,
            version=version or "unknown",
            error=str(e)
        )


def compile_contract_string(source_code: str, version: str) -> CompilationResult:
    try:
        try:
            solcx.install_solc(version)
        except Exception:
            pass
        
        solcx.set_solc_version(version)
        solcx.compile_source(
            source_code,
            output_values=["abi", "bin"],
            solc_version=version
        )
        
        return CompilationResult(success=True, version=version)
        
    except Exception as e:
        return CompilationResult(
            success=False,
            version=version,
            error=str(e)
        )


# =============================================================================
# SLITHER ANALYSIS
# =============================================================================

def run_slither(
    filepath: str,
    version: str,
    timeout: int = 60
) -> SlitherResult:
    start_time = time.time()
    
    try:
        # Install and select solc version using solc-select
        subprocess.run(
            ["solc-select", "install", version],
            capture_output=True,
            timeout=60
        )
        subprocess.run(
            ["solc-select", "use", version],
            capture_output=True,
            timeout=10
        )
        
        # Run Slither
        cmd = ["slither", filepath, "--json", "-"]
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        
        time_taken = time.time() - start_time
        
        # Parse JSON output
        detectors_found = []
        try:
            output = json.loads(result.stdout) if result.stdout else {}
            results = output.get("results", {}).get("detectors", [])
            
            for finding in results:
                check = finding.get("check", "")
                if check and check not in detectors_found:
                    detectors_found.append(check)
                    
        except json.JSONDecodeError:
            pass
        
        # Filter relevant detectors
        relevant = filter_relevant_detectors(detectors_found)
        
        return SlitherResult(
            success=True,
            detected=len(relevant) > 0,
            detectors_found=detectors_found,
            time_taken=time_taken,
            raw_output=result.stdout[:5000] if result.stdout else ""
        )
        
    except subprocess.TimeoutExpired:
        return SlitherResult(
            success=False,
            detected=False,
            error="Timeout",
            time_taken=timeout
        )
    except Exception as e:
        return SlitherResult(
            success=False,
            detected=False,
            error=str(e),
            time_taken=time.time() - start_time
        )


def analyze_with_slither(
    filepath: str,
    vuln_type: str,
    version: str = None,
    timeout: int = 60
) -> SlitherResult:
    # Auto-detect version if needed
    if not version:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                from services.version_detector import get_best_version
                version = get_best_version(f.read(), "slither")
        except Exception:
            version = "0.4.24"
    
    result = run_slither(filepath, version, timeout)
    
    # Set expected detectors and check correctness
    result.expected_detectors = get_expected_slither_detectors(vuln_type)
    result.correct = is_detection_correct(
        vuln_type,
        result.detectors_found,
        tool="slither"
    )
    
    return result


# =============================================================================
# BATCH ANALYSIS HELPERS
# =============================================================================

def analyze_injected_contract(
    filepath: str,
    vuln_type: str,
    version: str = None,
    compile_first: bool = True,
    timeout: int = 60
) -> Tuple[CompilationResult, SlitherResult]:
    comp_result = CompilationResult(success=True)
    
    # Auto-detect version
    if not version:
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                from services.version_detector import get_best_version
                version = get_best_version(f.read(), "slither")
        except Exception:
            version = "0.4.24"
    
    # Compile first if requested
    if compile_first:
        comp_result = compile_contract(filepath, version)
        if not comp_result.success:
            return comp_result, SlitherResult(
                success=False,
                detected=False,
                error="Compilation failed"
            )
    
    # Run Slither
    slither_result = analyze_with_slither(filepath, vuln_type, version, timeout)
    
    return comp_result, slither_result


# For backward compatibility - import these
import json

import random
from typing import List, Tuple


def parse_src_location(src: str) -> Tuple[int, int, int]:
    parts = src.split(':')
    return int(parts[0]), int(parts[1]), int(parts[2])


def is_version_compatible(version: str, min_version: str, max_version: str) -> bool:
    def parse_version(v: str) -> Tuple[int, ...]:
        # Remove common prefixes
        v = v.replace('^', '').replace('>=', '').replace('>', '').replace('<', '').strip()
        parts = v.split('.')[:3]
        return tuple(int(p) for p in parts if p.isdigit())
    
    try:
        ver = parse_version(version)
        min_v = parse_version(min_version)
        max_v = parse_version(max_version)
        return min_v <= ver <= max_v
    except (ValueError, IndexError):
        return True  # Default to compatible if parsing fails


def detect_indentation(content: bytes, offset: int) -> str:
    # Find the start of the next line after offset
    next_line_start = offset
    while next_line_start < len(content) and content[next_line_start:next_line_start + 1] != b'\n':
        next_line_start += 1
    next_line_start += 1  # Skip the newline
    
    in_multiline_comment = False
    
    # Skip empty lines, comments, and lines with only whitespace
    while next_line_start < len(content):
        # Find end of this line
        line_end = next_line_start
        while line_end < len(content) and content[line_end:line_end + 1] != b'\n':
            line_end += 1
        
        # Extract the line
        line = content[next_line_start:line_end]
        
        # Check if line has non-whitespace content
        stripped = line.strip()
        
        # Track multiline comments
        if b'/*' in stripped:
            in_multiline_comment = True
        if b'*/' in stripped:
            in_multiline_comment = False
            next_line_start = line_end + 1
            continue
        
        # Skip comments and empty lines
        if (stripped and 
            not in_multiline_comment and
            not stripped.startswith(b'//') and 
            not stripped.startswith(b'/*') and
            not stripped.startswith(b'*')):  # Skip lines that are part of multiline comment (starting with *)
            
            # This line has code - extract its indentation
            indent_bytes = b''
            pos = 0
            while pos < len(line) and line[pos:pos + 1] in (b' ', b'\t'):
                indent_bytes += line[pos:pos + 1]
                pos += 1
            
            if indent_bytes:
                return indent_bytes.decode('utf-8')
        
        # Move to next line
        next_line_start = line_end + 1
    
    # Default to 2 spaces if no indentation detected (common Solidity style)
    return "  "


def find_brace_offset(content: bytes, start_offset: int, length: int) -> int:
    search_range = content[start_offset:start_offset + length]
    brace_pos = search_range.find(b'{')
    
    if brace_pos == -1:
        return -1
    
    return start_offset + brace_pos + 1


def generate_unique_id() -> str:
    return str(random.randint(1, 99))


def sample_items(items: List, count: int, randomize: bool = True) -> List:
    count = min(count, len(items))
    if randomize:
        return random.sample(items, count)
    return items[:count]


def select_one(items: List, randomize: bool = True):
    if not items:
        return None
    if randomize:
        return random.choice(items)
    return items[0]

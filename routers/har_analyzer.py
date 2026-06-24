from fastapi import APIRouter, UploadFile, File, HTTPException
import json
import base64
from typing import Dict, Any, List
from datetime import datetime

router = APIRouter()

def is_binary_mime_type(mime_type: str) -> bool:
    """Check if mime type is binary"""
    binary_prefixes = ['image/', 'video/', 'audio/', 'font/', 'application/octet-stream',
                       'application/pdf', 'application/zip', 'application/x-']
    return any(mime_type.startswith(prefix) for prefix in binary_prefixes)

def process_response_content(text: str, mime_type: str, size: int, encoding: str = '') -> Dict[str, Any]:
    """
    Smart content processing:
    - Include small text responses (<100KB)
    - Truncate large text responses  
    - Preview binary content (first 1KB as base64)
    - Store metadata
    """
    MAX_TEXT_SIZE = 100 * 1024  # 100KB
    PREVIEW_SIZE = 1024  # 1KB preview for binary
    
    is_binary = is_binary_mime_type(mime_type)
    
    result = {
        'mimeType': mime_type,
        'size': size,
        'encoding': encoding,
        'isBinary': is_binary,
        'truncated': False,
        'text': None
    }
    
    if not text:
        return result
    
    if is_binary:
        # For binary content, include a small preview
        if encoding == 'base64':
            # Already base64, take first N characters
            result['text'] = text[:PREVIEW_SIZE] if len(text) > PREVIEW_SIZE else text
            result['truncated'] = len(text) > PREVIEW_SIZE
            result['preview'] = True
        else:
            # Not base64, truncate
            result['text'] = text[:PREVIEW_SIZE] if len(text) > PREVIEW_SIZE else text
            result['truncated'] = len(text) > PREVIEW_SIZE
            result['preview'] = True
    else:
        # For text content, include up to MAX_TEXT_SIZE
        if len(text) > MAX_TEXT_SIZE:
            result['text'] = text[:MAX_TEXT_SIZE] + '\n\n... (truncated)'
            result['truncated'] = True
        else:
            result['text'] = text
    
    return result

def parse_har_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced HAR entry parser with smart content handling.
    Preserves response content with appropriate size limits.
    """
    req = entry.get('request', {})
    res = entry.get('response', {})
    
    # Process response content smartly
    content = res.get('content', {})
    mime_type = content.get('mimeType', 'unknown')
    size = content.get('size', 0)
    text = content.get('text', '')
    encoding = content.get('encoding', '')
    
    processed_content = process_response_content(text, mime_type, size, encoding)
    
    # Process request content if present
    req_content = None
    if 'postData' in req:
        post_data = req['postData']
        req_text = post_data.get('text', '')
        req_mime = post_data.get('mimeType', 'text/plain')
        
        # Truncate large request bodies
        if len(req_text) > 50000:  # 50KB limit for requests
            req_content = {
                'text': req_text[:50000] + '\n\n... (truncated)',
                'mimeType': req_mime,
                'truncated': True
            }
        else:
            req_content = {
                'text': req_text,
                'mimeType': req_mime,
                'truncated': False
            }
    
    return {
        'startedDateTime': entry.get('startedDateTime'),
        'time': entry.get('time'),
        'method': req.get('method'),
        'url': req.get('url'),
        'status': res.get('status'),
        'statusText': res.get('statusText'),
        'headers': {
            'request': req.get('headers', []),
            'response': res.get('headers', [])
        },
        'cookies': {
            'request': req.get('cookies', []),
            'response': res.get('cookies', [])
        },
        'queryString': req.get('queryString', []),
        'requestContent': req_content,
        'responseContent': processed_content,
        'timings': entry.get('timings', {}),
        'serverIPAddress': entry.get('serverIPAddress'),
        'connection': entry.get('connection'),
        '_securityState': entry.get('_securityState'),
        'cache': entry.get('cache', {})
    }

@router.post("/api/tools/har/analyze")
async def analyze_har(file: UploadFile = File(...)):
    """
    Analyze HAR file with comprehensive content extraction.
    Includes smart content handling for both text and binary responses.
    """
    if not file.filename.endswith('.har') and not file.filename.endswith('.json'):
        raise HTTPException(status_code=400, detail="Invalid file type. Please upload a .har or .json file.")
    
    try:
        contents = await file.read()
        data = json.loads(contents)
        
        log = data.get('log', {})
        entries = log.get('entries', [])
        
        # Summary Stats
        total_requests = len(entries)
        total_size = sum(e.get('response', {}).get('content', {}).get('size', 0) for e in entries)
        total_time = sum(e.get('time', 0) for e in entries)
        
        status_counts = {}
        mime_counts = {}
        method_counts = {}
        
        parsed_entries = []
        
        for entry in entries:
            # Status Counts
            status = entry.get('response', {}).get('status')
            if status:
                status_counts[status] = status_counts.get(status, 0) + 1
                
            # Mime Counts
            mime = entry.get('response', {}).get('content', {}).get('mimeType', 'unknown')
            base_mime = mime.split(';')[0] if mime else 'unknown'
            mime_counts[base_mime] = mime_counts.get(base_mime, 0) + 1
            
            # Method Counts
            method = entry.get('request', {}).get('method', 'GET')
            method_counts[method] = method_counts.get(method, 0) + 1

            parsed_entries.append(parse_har_entry(entry))
            
        return {
            "summary": {
                "total_requests": total_requests,
                "total_size_bytes": total_size,
                "total_time_ms": total_time,
                "status_counts": status_counts,
                "mime_counts": mime_counts,
                "method_counts": method_counts,
                "pages": log.get('pages', []),
                "browser": log.get('browser', {}),
                "creator": log.get('creator', {})
            },
            "entries": parsed_entries
        }

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON format. The file might be corrupted.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to analyze HAR file: {str(e)}")

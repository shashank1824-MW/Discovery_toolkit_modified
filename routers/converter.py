from fastapi import APIRouter, UploadFile, File, HTTPException, Form, Request
from fastapi.responses import StreamingResponse, JSONResponse
import pandas as pd
import io
import json
import chardet
import clevercsv
import re
from typing import Optional, Dict, List, Any, Union
from dataclasses import dataclass, asdict

router = APIRouter(prefix="/api/convert", tags=["converter"])

# Configuration
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB default limit
MAX_ROWS_PREVIEW = 1000


class ConversionError(Exception):
    """Custom exception with detailed error information"""

    def __init__(
        self,
        message: str,
        line: int = None,
        column: int = None,
        suggestion: str = None,
        error_type: str = "parse_error",
    ):
        self.message = message
        self.line = line
        self.column = column
        self.suggestion = suggestion
        self.error_type = error_type
        super().__init__(self.format_message())

    def format_message(self) -> str:
        parts = [self.message]
        if self.line:
            loc = f"at line {self.line}"
            if self.column:
                loc += f", column {self.column}"
            parts.append(loc)
        return " | ".join(parts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "error_type": self.error_type,
            "message": self.message,
            "line": self.line,
            "column": self.column,
            "suggestion": self.suggestion,
        }


def extract_nested_data(data: Any) -> tuple[Any, Optional[str]]:
    """
    Auto-extract nested data from common wrapper patterns.
    Returns (extracted_data, extraction_message) where extraction_message
    describes what was extracted (or None if no extraction happened).
    """
    if not isinstance(data, dict):
        return data, None

    # Common patterns for data wrappers
    wrapper_patterns = [
        # Pattern: {"data": [...], "meta": {...}}
        ("data", ["meta", "pagination", "links", "included"]),
        # Pattern: {"results": [...], ...}
        ("results", ["count", "total", "page", "per_page"]),
        # Pattern: {"items": [...], ...}
        ("items", ["total", "skip", "limit"]),
        # Pattern: {"records": [...], ...}
        ("records", ["total", "page"]),
        # Pattern: {"rows": [...], ...}
        ("rows", ["total", "count"]),
        # Pattern: {"hits": [...], ...} (Elasticsearch style)
        ("hits", ["total", "max_score"]),
        # Pattern: {"docs": [...], ...} (CouchDB style)
        ("docs", ["total_rows", "offset"]),
    ]

    for data_key, metadata_keys in wrapper_patterns:
        if data_key in data:
            inner_data = data[data_key]
            # Check if it's a list (array of records)
            if isinstance(inner_data, list):
                return (
                    inner_data,
                    f"Extracted {len(inner_data)} records from '{data_key}' field",
                )
            # Check for nested patterns like {"hits": {"hits": [...]}}
            elif isinstance(inner_data, dict) and "hits" in inner_data:
                nested_hits = inner_data.get("hits")
                if isinstance(nested_hits, list):
                    return (
                        nested_hits,
                        f"Extracted {len(nested_hits)} records from nested structure",
                    )

    return data, None


def extract_json_structure_info(data: Any) -> dict:
    """
    Detect JSON structure and return information about it.
    Used for pre-conversion analysis.
    """
    info = {
        "is_wrapper": False,
        "wrapper_type": None,
        "record_count": None,
        "extraction_message": None,
        "has_metadata": False,
    }

    if isinstance(data, dict):
        wrapper_keys = ["data", "results", "items", "records", "rows", "hits", "docs"]
        found_wrappers = [
            k for k in wrapper_keys if k in data and isinstance(data.get(k), list)
        ]

        if found_wrappers:
            info["is_wrapper"] = True
            info["wrapper_type"] = found_wrappers[0]
            info["record_count"] = len(data[found_wrappers[0]])

            # Check for common metadata fields
            metadata_fields = [
                "meta",
                "pagination",
                "total",
                "page",
                "links",
                "included",
            ]
            info["has_metadata"] = any(k in data for k in metadata_fields)

    return info


def parse_json_safe(data: Union[str, bytes]) -> Any:
    """Parse JSON with detailed error reporting and suggestions"""
    try:
        if isinstance(data, bytes):
            # Try UTF-8 first, fallback to detected encoding
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                detected = chardet.detect(data)
                text = data.decode(detected.get("encoding", "utf-8"))
        else:
            text = data

        # Try standard JSON first
        try:
            return json.loads(text)
        except json.JSONDecodeError as e:
            # Provide helpful suggestions based on common errors
            lines = text.split("\n")
            error_line = lines[e.lineno - 1] if e.lineno <= len(lines) else ""

            suggestion = None
            error_msg = str(e).lower()

            if "expecting property name" in error_msg:
                if "'" in error_line and '"' not in error_line.replace("'", ""):
                    suggestion = (
                        "JSON requires double quotes for strings, not single quotes"
                    )
                elif error_line.strip().endswith(","):
                    suggestion = "Remove the trailing comma before the closing bracket"
            elif "expecting ',' delimiter" in error_msg:
                suggestion = "Check for missing comma between properties or extra comma before closing bracket"
            elif "expecting ':' delimiter" in error_msg:
                suggestion = (
                    'Object properties must be in format "key": value with a colon'
                )
            elif "extra data" in error_msg:
                suggestion = "JSON can only have one root element. Wrap multiple objects in an array []"
            elif "invalid escape" in error_msg:
                suggestion = "Check for unescaped backslashes. Use double backslash for literal backslash"

            raise ConversionError(
                message=f"Invalid JSON: {e.msg}",
                line=e.lineno,
                column=e.colno,
                suggestion=suggestion,
                error_type="json_parse_error",
            )
    except ConversionError:
        raise
    except Exception as e:
        raise ConversionError(
            message=f"Failed to parse JSON: {str(e)}",
            suggestion="Ensure the input is valid JSON format",
            error_type="json_parse_error",
        )


def robust_flatten_json(
    y: Any, separator: str = ".", max_depth: Optional[int] = None
) -> Dict[str, Any]:
    """
    Enhanced JSON flattener with options for handling edge cases

    Args:
        y: The JSON data to flatten
        separator: Delimiter for nested keys (default: '.')
        max_depth: Maximum depth to flatten (None for unlimited)
    """
    out = {}

    def flatten(x: Any, name: str = "", depth: int = 0):
        # Check max depth
        if max_depth is not None and depth > max_depth:
            out[name[:-1]] = x
            return

        if type(x) is dict:
            if len(x) == 0:
                # Handle empty objects
                out[name[:-1]] = {}
            else:
                for a in x:
                    # Escape separator in keys
                    safe_key = str(a).replace(separator, f"\\{separator}")
                    flatten(x[a], name + safe_key + separator, depth + 1)
        elif type(x) is list:
            if len(x) == 0:
                # Handle empty arrays
                out[name[:-1]] = []
            else:
                for i, a in enumerate(x):
                    flatten(a, name + str(i) + separator, depth + 1)
        else:
            # Handle None/null values
            if x is None:
                out[name[:-1]] = None
            else:
                out[name[:-1]] = x

    flatten(y)
    return out


def detect_csv_dialect(data: Union[str, bytes]) -> tuple:
    """
    Detect CSV encoding and dialect automatically

    Returns:
        tuple: (decoded_text, delimiter, detected_encoding)
    """
    # Detect encoding
    if isinstance(data, str):
        return data, None, "utf-8"

    detected = chardet.detect(data)
    encoding = detected.get("encoding", "utf-8")
    confidence = detected.get("confidence", 0)

    # Fallback to utf-8 if confidence is low
    if confidence < 0.5:
        encoding = "utf-8"

    try:
        text = data.decode(encoding)
    except (UnicodeDecodeError, LookupError):
        # Try common encodings
        for enc in ["utf-8", "latin-1", "cp1252", "iso-8859-1"]:
            try:
                text = data.decode(enc)
                encoding = enc
                break
            except UnicodeDecodeError:
                continue
        else:
            raise ConversionError(
                message="Could not detect file encoding",
                suggestion="Try saving the file as UTF-8 encoded",
                error_type="encoding_error",
            )

    # Detect delimiter using clevercsv
    try:
        dialect = clevercsv.Sniffer().sniff(text[:10000])  # Sample first 10KB
        delimiter = dialect.delimiter
    except:
        # Default to comma if detection fails
        delimiter = ","

    return text, delimiter, encoding


def read_csv_robust(
    file_or_text: Union[str, bytes, Any], delimiter: Optional[str] = None
) -> pd.DataFrame:
    """Read CSV with automatic encoding and delimiter detection"""
    try:
        if hasattr(file_or_text, "read"):
            # It's a file-like object
            content = file_or_text.read()
            if hasattr(content, "decode"):
                # Binary mode
                text, detected_delimiter, encoding = detect_csv_dialect(content)
            else:
                # Text mode
                text = content
                detected_delimiter = ","
        elif isinstance(file_or_text, bytes):
            text, detected_delimiter, encoding = detect_csv_dialect(file_or_text)
        else:
            text = file_or_text
            detected_delimiter = ","

        # Use detected delimiter or provided one
        final_delimiter = delimiter or detected_delimiter or ","

        # Read with pandas
        df = pd.read_csv(
            io.StringIO(text),
            delimiter=final_delimiter,
            dtype=str,  # Read all as strings initially, let user decide types
            keep_default_na=True,
            na_values=["", "NA", "N/A", "null", "NULL", "None"],
            engine="python",  # More flexible parser
        )

        return df

    except pd.errors.EmptyDataError:
        raise ConversionError(
            message="The CSV file is empty",
            suggestion="Ensure the file contains data with headers",
            error_type="empty_file_error",
        )
    except pd.errors.ParserError as e:
        raise ConversionError(
            message=f"CSV parsing error: {str(e)}",
            suggestion="Check for mismatched quotes or inconsistent column counts",
            error_type="csv_parse_error",
        )
    except Exception as e:
        raise ConversionError(
            message=f"Failed to read CSV: {str(e)}",
            suggestion="Ensure the file is a valid CSV format",
            error_type="csv_read_error",
        )


def validate_file_size(file: UploadFile, max_size: int = MAX_FILE_SIZE):
    """Validate file size before processing"""
    # Read content to check size
    content = file.file.read()
    file.file.seek(0)  # Reset for later reading

    if len(content) > max_size:
        raise ConversionError(
            message=f"File size ({len(content) / 1024 / 1024:.1f}MB) exceeds maximum allowed ({max_size / 1024 / 1024:.0f}MB)",
            suggestion="Try splitting the file into smaller chunks or use streaming mode",
            error_type="file_too_large",
        )

    return content


@dataclass
class ConversionResult:
    """Standard result structure for conversions"""

    data: Any
    format: str
    metadata: Dict[str, Any]
    warnings: List[str]


# =============================================================================
# API Endpoints
# =============================================================================


@router.post("/json-to-csv")
async def json_to_csv(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_data: Optional[str] = Form(None),
    separator: str = Form("."),
    max_depth: Optional[int] = Form(None),
):
    """
    Convert JSON to CSV with robust error handling and options

    Args:
        separator: Delimiter for flattened keys (default: '.')
        max_depth: Maximum nesting depth to flatten (null for unlimited)
    """
    try:
        if file:
            content = await file.read()
            validate_file_size(file)
            data = parse_json_safe(content)
        elif raw_data:
            data = parse_json_safe(raw_data)
        else:
            # Try to read raw JSON body (for large data sent as raw body)
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type or "text/plain" in content_type:
                body = await request.body()
                data = parse_json_safe(body)
            else:
                raise ConversionError(
                    message="No data provided",
                    suggestion="Upload a file, paste JSON data, or send raw JSON body",
                    error_type="missing_input",
                )

        # Auto-extract nested data from wrapper objects like {"data": [...], "meta": {...}}
        extraction_msg = None
        if isinstance(data, dict):
            data, extraction_msg = extract_nested_data(data)

        # Handle list of objects or single object
        if isinstance(data, list):
            flattened_data = [
                robust_flatten_json(item, separator, max_depth) for item in data
            ]
        else:
            flattened_data = [robust_flatten_json(data, separator, max_depth)]

        if len(flattened_data) == 0:
            raise ConversionError(
                message="No data to convert",
                suggestion="The JSON array appears to be empty",
                error_type="empty_data",
            )

        df = pd.DataFrame(flattened_data)

        # Ensure all columns from flattened data are present (fix for missing enrichment columns)
        if flattened_data:
            all_keys = set()
            for item in flattened_data:
                all_keys.update(item.keys())
            for col in all_keys:
                if col not in df.columns:
                    df[col] = ""

        # Auto-rename columns to human-readable format
        from utils.enrichment import EnrichmentSuggester

        column_renames = {}
        for col in df.columns:
            new_name = EnrichmentSuggester.suggest_column_rename(col)
            if new_name and new_name != col:
                column_renames[col] = new_name
        if column_renames:
            df = df.rename(columns=column_renames)

        # Convert null values to empty strings for better CSV compatibility
        df = df.fillna("")

        stream = io.StringIO()
        df.to_csv(stream, index=False, encoding="utf-8", lineterminator="\n")

        response = StreamingResponse(
            iter([stream.getvalue()]), media_type="text/csv; charset=utf-8"
        )
        response.headers["Content-Disposition"] = "attachment; filename=converted.csv"
        if extraction_msg:
            response.headers["X-Extraction-Message"] = extraction_msg
        return response

    except ConversionError as e:
        raise HTTPException(status_code=400, detail=e.to_dict())
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={
                "error_type": "unknown_error",
                "message": str(e),
                "suggestion": "Please try again or contact support",
            },
        )


@router.post("/json-to-xlsx")
async def json_to_xlsx(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_data: Optional[str] = Form(None),
    separator: str = Form("."),
    max_depth: Optional[int] = Form(None),
):
    """Convert JSON to Excel XLSX with robust error handling"""
    try:
        if file:
            content = await file.read()
            validate_file_size(file)
            data = parse_json_safe(content)
        elif raw_data:
            data = parse_json_safe(raw_data)
        else:
            # Try to read raw JSON body (for large data sent as raw body)
            content_type = request.headers.get("content-type", "")
            if "application/json" in content_type or "text/plain" in content_type:
                body = await request.body()
                data = parse_json_safe(body)
            else:
                raise ConversionError(
                    message="No data provided",
                    suggestion="Upload a file, paste JSON data, or send raw JSON body",
                    error_type="missing_input",
                )

        # Auto-extract nested data from wrapper objects like {"data": [...], "meta": {...}}
        extraction_msg = None
        if isinstance(data, dict):
            data, extraction_msg = extract_nested_data(data)

        # Handle list of objects or single object
        if isinstance(data, list):
            flattened_data = [
                robust_flatten_json(item, separator, max_depth) for item in data
            ]
        else:
            flattened_data = [robust_flatten_json(data, separator, max_depth)]

        df = pd.DataFrame(flattened_data)

        # Auto-rename columns to human-readable format
        from utils.enrichment import EnrichmentSuggester

        column_renames = {}
        for col in df.columns:
            new_name = EnrichmentSuggester.suggest_column_rename(col)
            if new_name and new_name != col:
                column_renames[col] = new_name
        if column_renames:
            df = df.rename(columns=column_renames)

        df = df.fillna("")

        stream = io.BytesIO()

        # Use xlsxwriter for better formatting options
        with pd.ExcelWriter(stream, engine="openpyxl") as writer:
            df.to_excel(writer, index=False, sheet_name="Data")

            # Auto-adjust column widths
            worksheet = writer.sheets["Data"]
            for column in worksheet.columns:
                max_length = 0
                column_letter = column[0].column_letter
                for cell in column:
                    try:
                        if len(str(cell.value)) > max_length:
                            max_length = len(str(cell.value))
                    except:
                        pass
                adjusted_width = min(max_length + 2, 50)  # Cap at 50
                worksheet.column_dimensions[column_letter].width = adjusted_width

        stream.seek(0)

        response = StreamingResponse(
            iter([stream.getvalue()]),
            media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        response.headers["Content-Disposition"] = "attachment; filename=converted.xlsx"
        if extraction_msg:
            response.headers["X-Extraction-Message"] = extraction_msg
        return response

    except ConversionError as e:
        raise HTTPException(status_code=400, detail=e.to_dict())
    except Exception as e:
        raise HTTPException(
            status_code=500, detail={"error_type": "unknown_error", "message": str(e)}
        )


@router.post("/csv-to-json")
async def csv_to_json(
    request: Request,
    file: Optional[UploadFile] = File(None),
    raw_data: Optional[str] = Form(None),
    delimiter: Optional[str] = Form(None),
):
    """
    Convert CSV to JSON with automatic encoding/delimiter detection

    Args:
        delimiter: Optional delimiter override (auto-detected if not provided)
    """
    try:
        if file:
            content = await file.read()
            validate_file_size(file)
            df = read_csv_robust(content, delimiter)
        elif raw_data:
            df = read_csv_robust(raw_data, delimiter)
        else:
            # Try to read raw body (for large data sent as raw body)
            content_type = request.headers.get("content-type", "")
            if (
                "text/plain" in content_type
                or "application/octet-stream" in content_type
            ):
                body = await request.body()
                df = read_csv_robust(body, delimiter)
            else:
                raise ConversionError(
                    message="No data provided",
                    suggestion="Upload a file, paste CSV data, or send raw body",
                    error_type="missing_input",
                )

        if len(df) == 0:
            raise ConversionError(
                message="CSV file contains no data rows",
                suggestion="Ensure the file has headers and at least one data row",
                error_type="empty_data",
            )

        # Convert to JSON with type inference
        result = json.loads(df.to_json(orient="records"))

        # Try to convert numeric strings back to numbers
        for row in result:
            for key, value in row.items():
                if isinstance(value, str):
                    # Try int
                    if value.isdigit() or (
                        value.startswith("-") and value[1:].isdigit()
                    ):
                        row[key] = int(value)
                    # Try float
                    else:
                        try:
                            row[key] = float(value)
                        except ValueError:
                            pass
                    # Handle booleans
                    if value.lower() in ("true", "false"):
                        row[key] = value.lower() == "true"

        return JSONResponse(content=result)

    except ConversionError as e:
        raise HTTPException(status_code=400, detail=e.to_dict())
    except Exception as e:
        raise HTTPException(
            status_code=500, detail={"error_type": "unknown_error", "message": str(e)}
        )


@router.post("/xlsx-to-json")
async def xlsx_to_json(
    file: UploadFile = File(...),
    sheet_name: Optional[str] = Form(None),
    include_all_sheets: bool = Form(False),
):
    """
    Convert Excel XLSX to JSON

    Args:
        sheet_name: Specific sheet to convert (default: first sheet)
        include_all_sheets: If true, return all sheets as dict
    """
    try:
        content = await file.read()
        validate_file_size(file)

        try:
            xls = pd.ExcelFile(io.BytesIO(content))
        except Exception as e:
            raise ConversionError(
                message=f"Invalid Excel file: {str(e)}",
                suggestion="Ensure the file is a valid .xlsx or .xls file",
                error_type="invalid_excel",
            )

        if include_all_sheets:
            # Return all sheets
            result = {}
            for sheet in xls.sheet_names:
                df = pd.read_excel(xls, sheet_name=sheet, dtype=str)
                df = df.fillna("")
                result[sheet] = json.loads(df.to_json(orient="records"))
            return JSONResponse(content=result)
        else:
            # Return single sheet
            sheet = sheet_name or xls.sheet_names[0]
            if sheet not in xls.sheet_names:
                raise ConversionError(
                    message=f"Sheet '{sheet}' not found",
                    suggestion=f"Available sheets: {', '.join(xls.sheet_names)}",
                    error_type="sheet_not_found",
                )

            df = pd.read_excel(xls, sheet_name=sheet, dtype=str)
            df = df.fillna("")
            result = json.loads(df.to_json(orient="records"))
            return JSONResponse(content=result)

    except ConversionError as e:
        raise HTTPException(status_code=400, detail=e.to_dict())
    except Exception as e:
        raise HTTPException(
            status_code=500, detail={"error_type": "unknown_error", "message": str(e)}
        )


# =============================================================================
# Data Quality and Analysis Endpoints
# =============================================================================

from utils.data_quality import DataQualityAnalyzer


@router.post("/analyze")
async def analyze_data(
    file: Optional[UploadFile] = File(None),
    raw_data: Optional[str] = Form(None),
    format_type: str = Form("auto"),  # auto, json, csv, xlsx
):
    """
    Analyze data quality without converting
    Returns quality score, column types, and issues
    """
    try:
        df = None

        if file:
            content = await file.read()
            validate_file_size(file)

            # Detect format if auto
            if format_type == "auto":
                if file.filename.endswith(".json"):
                    format_type = "json"
                elif file.filename.endswith(".csv"):
                    format_type = "csv"
                elif file.filename.endswith((".xlsx", ".xls")):
                    format_type = "xlsx"

            # Parse based on format
            if format_type == "json":
                data = parse_json_safe(content)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
            elif format_type in ["csv", "auto"]:
                df = read_csv_robust(content)
            elif format_type == "xlsx":
                df = pd.read_excel(io.BytesIO(content))
            else:
                raise ConversionError(
                    message=f"Unsupported format: {format_type}",
                    suggestion="Supported formats: json, csv, xlsx",
                    error_type="unsupported_format",
                )

        elif raw_data:
            # Try to detect format from content
            trimmed = raw_data.strip()
            if trimmed.startswith(("{", "[")):
                # Likely JSON
                data = parse_json_safe(raw_data)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
            else:
                # Try CSV
                df = read_csv_robust(raw_data)
        else:
            raise ConversionError(
                message="No data provided",
                suggestion="Upload a file or paste data to analyze",
                error_type="missing_input",
            )

        if df is None or df.empty:
            raise ConversionError(
                message="No data to analyze",
                suggestion="Ensure the file contains valid data",
                error_type="empty_data",
            )

        # Run quality analysis
        analyzer = DataQualityAnalyzer(df)
        report = analyzer.analyze()

        return JSONResponse(content=report.to_dict())

    except ConversionError as e:
        raise HTTPException(status_code=400, detail=e.to_dict())
    except Exception as e:
        raise HTTPException(
            status_code=500, detail={"error_type": "analysis_error", "message": str(e)}
        )


from utils.enrichment import EnrichmentSuggester, suggest_enrichments


@router.post("/detect-types")
async def detect_column_types(
    file: Optional[UploadFile] = File(None),
    raw_data: Optional[str] = Form(None),
    format_type: str = Form("auto"),
):
    """
    Detect semantic types of columns and suggest enrichments
    Returns enrichment suggestions that users can opt-in to apply
    """
    try:
        df = None

        if file:
            content = await file.read()
            validate_file_size(file)

            if format_type == "auto":
                if file.filename.endswith(".json"):
                    format_type = "json"
                elif file.filename.endswith(".csv"):
                    format_type = "csv"
                elif file.filename.endswith((".xlsx", ".xls")):
                    format_type = "xlsx"

            if format_type == "json":
                data = parse_json_safe(content)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
            elif format_type in ["csv", "auto"]:
                df = read_csv_robust(content)
            elif format_type == "xlsx":
                df = pd.read_excel(io.BytesIO(content))
            else:
                raise ConversionError(
                    message=f"Unsupported format: {format_type}",
                    error_type="unsupported_format",
                )

        elif raw_data:
            trimmed = raw_data.strip()
            if trimmed.startswith(("{", "[")):
                data = parse_json_safe(raw_data)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
            else:
                df = read_csv_robust(raw_data)
        else:
            raise ConversionError(
                message="No data provided", error_type="missing_input"
            )

        if df is None or df.empty:
            raise ConversionError(message="No data to analyze", error_type="empty_data")

        # Get column types from DataQualityAnalyzer
        from utils.data_quality import DataQualityAnalyzer

        analyzer = DataQualityAnalyzer(df)
        report = analyzer.analyze()
        column_types = {col.name: col.inferred_type for col in report.columns}

        # Get enrichment suggestions
        suggestions = suggest_enrichments(df, column_types)

        return JSONResponse(
            content={
                "column_types": column_types,
                "enrichment_suggestions": suggestions,
                "total_columns": len(df.columns),
                "suggestion_count": len(suggestions),
            }
        )

    except ConversionError as e:
        raise HTTPException(status_code=400, detail=e.to_dict())
    except Exception as e:
        raise HTTPException(
            status_code=500, detail={"error_type": "detection_error", "message": str(e)}
        )


@router.post("/apply-enrichment")
async def apply_enrichment(
    file: Optional[UploadFile] = File(None),
    raw_data: Optional[str] = Form(None),
    format_type: str = Form("auto"),
    column: str = Form(...),
    enrichment_type: str = Form(...),
    output_format: str = Form("json"),  # json, csv, xlsx
    enrichments: Optional[str] = Form(
        None
    ),  # JSON string of batch enrichments: [{"column": "...", "enrichment_type": "..."}, ...]
):
    """
    Apply enrichment(s) to column(s) and return the enriched data
    Supports both single enrichment (backward compatible) and batch enrichments
    This is the opt-in endpoint - user must explicitly request enrichment
    """
    try:
        df = None

        if file:
            content = await file.read()
            validate_file_size(file)

            if format_type == "auto":
                if file.filename.endswith(".json"):
                    format_type = "json"
                elif file.filename.endswith(".csv"):
                    format_type = "csv"
                elif file.filename.endswith((".xlsx", ".xls")):
                    format_type = "xlsx"

            if format_type == "json":
                data = parse_json_safe(content)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
            elif format_type in ["csv", "auto"]:
                df = read_csv_robust(content)
            elif format_type == "xlsx":
                df = pd.read_excel(io.BytesIO(content))
            else:
                raise ConversionError(
                    message=f"Unsupported format: {format_type}",
                    error_type="unsupported_format",
                )

        elif raw_data:
            trimmed = raw_data.strip()
            if trimmed.startswith(("{", "[")):
                data = parse_json_safe(raw_data)
                if isinstance(data, list):
                    df = pd.DataFrame(data)
                else:
                    df = pd.DataFrame([data])
            else:
                df = read_csv_robust(raw_data)
        else:
            raise ConversionError(
                message="No data provided", error_type="missing_input"
            )

        if df is None or df.empty:
            raise ConversionError(message="No data to enrich", error_type="empty_data")

        # Get column types
        from utils.data_quality import DataQualityAnalyzer

        analyzer = DataQualityAnalyzer(df)
        report = analyzer.analyze()
        column_types = {col.name: col.inferred_type for col in report.columns}

        suggester = EnrichmentSuggester(df, column_types)

        # Determine which enrichments to apply
        enrichment_list = []
        if enrichments:
            # Batch mode: apply multiple enrichments
            enrichment_list = json.loads(enrichments)
        else:
            # Single enrichment mode (backward compatible)
            enrichment_list = [{"column": column, "enrichment_type": enrichment_type}]

        all_new_columns = []
        renamed_columns = []  # Track renames separately
        total_applied = 0
        total_errors = 0

        # Apply each enrichment sequentially to the same dataframe
        for enrich_spec in enrichment_list:
            col = enrich_spec.get("column")
            enrich_type = enrich_spec.get("enrichment_type")

            if not col or not enrich_type:
                continue

            result = suggester.apply_enrichment(col, enrich_type)

            # Handle column rename specially
            if enrich_type == "rename_column":
                old_name = result.values["old_name"]
                new_name = result.values["new_name"]
                if old_name != new_name:
                    df = df.rename(columns={old_name: new_name})
                    renamed_columns.append({"from": old_name, "to": new_name})
                    # Update column name in suggester for subsequent enrichments
                    if col in column_types:
                        column_types[new_name] = column_types.pop(col)
                # Update suggester's reference to the dataframe
                suggester.df = df
            elif isinstance(result.values, dict):
                # Multiple columns (e.g., date components)
                for col_name, values in result.values.items():
                    df[col_name] = values
                    all_new_columns.append(col_name)
            else:
                # Single column
                df[result.new_column_name] = result.values
                all_new_columns.append(result.new_column_name)

            total_applied += result.applied_count
            total_errors += result.error_count

        # Auto-rename any remaining columns that need cleanup
        column_renames = {}
        for col in df.columns:
            new_name = suggester.suggest_column_rename(col)
            if new_name and new_name != col:
                column_renames[col] = new_name
        if column_renames:
            df = df.rename(columns=column_renames)

        # Return in requested format
        if output_format == "csv":
            stream = io.StringIO()
            df.to_csv(stream, index=False, encoding="utf-8", lineterminator="\n")
            response = StreamingResponse(
                iter([stream.getvalue()]), media_type="text/csv; charset=utf-8"
            )
            response.headers["Content-Disposition"] = (
                f"attachment; filename=enriched_data.csv"
            )
            return response

        elif output_format == "xlsx":
            stream = io.BytesIO()
            with pd.ExcelWriter(stream, engine="openpyxl") as writer:
                df.to_excel(writer, index=False, sheet_name="Enriched Data")
            stream.seek(0)
            response = StreamingResponse(
                iter([stream.getvalue()]),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )
            response.headers["Content-Disposition"] = (
                f"attachment; filename=enriched_data.xlsx"
            )
            return response

        else:  # json
            # Calculate total changes
            total_changes = len(all_new_columns) + len(renamed_columns)
            return JSONResponse(
                content={
                    "enriched_data": json.loads(df.to_json(orient="records")),
                    "new_columns": all_new_columns,
                    "renamed_columns": renamed_columns,
                    "total_changes": total_changes,
                    "applied_count": total_applied,
                    "error_count": total_errors,
                }
            )

    except ConversionError as e:
        raise HTTPException(status_code=400, detail=e.to_dict())
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail={"error_type": "enrichment_error", "message": str(e)},
        )

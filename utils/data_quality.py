"""
Data Quality Analysis Module
Provides comprehensive data quality scoring and analysis for tabular data
"""

import pandas as pd
import numpy as np
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class ColumnQuality:
    """Quality metrics for a single column"""
    name: str
    dtype: str
    null_count: int
    null_percentage: float
    unique_count: int
    unique_percentage: float
    inferred_type: str  # semantic type: 'email', 'phone', 'url', 'date', 'text', 'numeric', 'id'
    sample_values: List[Any] = field(default_factory=list)
    issues: List[str] = field(default_factory=list)
    
    # Additional metrics
    min_value: Optional[Any] = None
    max_value: Optional[Any] = None
    avg_length: Optional[float] = None  # For text columns
    pattern_examples: List[str] = field(default_factory=list)  # Common patterns found


@dataclass
class DataQualityReport:
    """Complete quality report for a dataset"""
    row_count: int
    column_count: int
    overall_score: float
    completeness_score: float
    uniqueness_score: float
    validity_score: float
    columns: List[ColumnQuality]
    dataset_issues: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'summary': {
                'row_count': self.row_count,
                'column_count': self.column_count,
                'overall_score': round(self.overall_score, 2),
                'scores': {
                    'completeness': round(self.completeness_score, 2),
                    'uniqueness': round(self.uniqueness_score, 2),
                    'validity': round(self.validity_score, 2)
                }
            },
            'dataset_issues': self.dataset_issues,
            'recommendations': self.recommendations,
            'columns': [
                {
                    'name': c.name,
                    'type': c.inferred_type,
                    'dtype': c.dtype,
                    'nulls': {'count': c.null_count, 'percentage': round(c.null_percentage, 2)},
                    'uniques': {'count': c.unique_count, 'percentage': round(c.unique_percentage, 2)},
                    'sample_values': c.sample_values,
                    'issues': c.issues,
                    'min_value': c.min_value,
                    'max_value': c.max_value,
                    'avg_length': round(c.avg_length, 2) if c.avg_length else None
                }
                for c in self.columns
            ],
            'generated_at': self.generated_at
        }


class DataQualityAnalyzer:
    """Analyze data quality and generate comprehensive reports"""
    
    # Patterns for semantic type detection
    PATTERNS = {
        'email': {
            'regex': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'description': 'Email addresses'
        },
        'phone': {
            'regex': r'^[\+]?[(]?[0-9]{1,4}[)]?[-\s\.]?[0-9]{1,4}[-\s\.]?[0-9]{1,9}$',
            'description': 'Phone numbers'
        },
        'url': {
            'regex': r'^https?://[^\s/$.?#].[^\s]*$',
            'description': 'URLs/Links'
        },
        'ip_address': {
            'regex': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'description': 'IP addresses'
        }
    }
    
    def __init__(self, df: pd.DataFrame):
        self.df = df.copy()
        self.row_count = len(df)
        self.column_count = len(df.columns)
        
    def analyze(self) -> DataQualityReport:
        """Run complete analysis and generate report"""
        columns = []
        
        for col_name in self.df.columns:
            col_data = self.df[col_name]
            column_quality = self._analyze_column(col_name, col_data)
            columns.append(column_quality)
        
        # Calculate overall scores
        completeness_score = self._calculate_completeness_score(columns)
        uniqueness_score = self._calculate_uniqueness_score(columns)
        validity_score = self._calculate_validity_score(columns)
        overall_score = (completeness_score + uniqueness_score + validity_score) / 3
        
        # Detect dataset-level issues
        dataset_issues = self._detect_dataset_issues(columns)
        recommendations = self._generate_recommendations(columns, dataset_issues)
        
        return DataQualityReport(
            row_count=self.row_count,
            column_count=self.column_count,
            overall_score=overall_score,
            completeness_score=completeness_score,
            uniqueness_score=uniqueness_score,
            validity_score=validity_score,
            columns=columns,
            dataset_issues=dataset_issues,
            recommendations=recommendations
        )
    
    def _analyze_column(self, name: str, series: pd.Series) -> ColumnQuality:
        """Analyze a single column"""
        # Basic stats
        null_count = int(series.isnull().sum())
        null_percentage = (null_count / self.row_count * 100) if self.row_count > 0 else 0
        
        # Handle unique count for columns with unhashable types (lists, dicts)
        try:
            unique_count = int(series.nunique())
        except TypeError:
            # Column contains unhashable types, convert to string for counting
            unique_count = int(series.astype(str).nunique())
        
        unique_percentage = (unique_count / self.row_count * 100) if self.row_count > 0 else 0
        
        # Detect issues
        issues = self._detect_column_issues(series, null_percentage, unique_percentage)
        
        # Infer semantic type
        inferred_type = self._infer_type(series)
        
        # Get sample values (non-null) - convert to string for unhashable types
        def safe_convert(val):
            if val is None:
                return None
            if isinstance(val, (list, dict)):
                return str(val)[:100]  # Truncate long structures
            return val
        
        sample_values = [safe_convert(v) for v in series.dropna().head(5).tolist()]
        
        # Calculate additional metrics
        min_val, max_val, avg_len = None, None, None
        if pd.api.types.is_numeric_dtype(series):
            min_val = series.min() if not series.empty else None
            max_val = series.max() if not series.empty else None
        elif series.dtype == 'object':
            str_lengths = series.dropna().astype(str).str.len()
            avg_len = float(str_lengths.mean()) if not str_lengths.empty else None
        
        return ColumnQuality(
            name=name,
            dtype=str(series.dtype),
            null_count=null_count,
            null_percentage=null_percentage,
            unique_count=unique_count,
            unique_percentage=unique_percentage,
            inferred_type=inferred_type,
            sample_values=sample_values,
            issues=issues,
            min_value=min_val,
            max_value=max_val,
            avg_length=avg_len
        )
    
    def _detect_column_issues(self, series: pd.Series, null_pct: float, unique_pct: float) -> List[str]:
        """Detect issues in a column"""
        issues = []
        
        # Missing data issues
        if null_pct == 100:
            issues.append("completely_empty")
        elif null_pct > 50:
            issues.append("mostly_empty")
        elif null_pct > 10:
            issues.append("moderate_missing")
        
        # Uniqueness issues
        if unique_pct == 0 and len(series) > 0:
            issues.append("constant_value")
        elif unique_pct == 100 and len(series) > 10:
            issues.append("likely_unique_id")
        
        # Check for mixed types in object columns
        if series.dtype == 'object':
            non_null = series.dropna()
            if len(non_null) > 0:
                # Convert types to string names, handling unhashable types like lists/dicts
                type_names = []
                for v in non_null.head(100):  # Sample first 100 for performance
                    try:
                        type_names.append(type(v).__name__)
                    except:
                        type_names.append("unhashable")
                types = set(type_names)
                if len(types) > 1:
                    issues.append("mixed_types")
        
        # Check for whitespace issues
        if series.dtype == 'object':
            str_vals = series.dropna().astype(str)
            if (str_vals.str.startswith(' ').any() or str_vals.str.endswith(' ').any()):
                issues.append("extra_whitespace")
        
        return issues
    
    def _infer_type(self, series: pd.Series) -> str:
        """Infer semantic type of column"""
        if series.empty or series.isnull().all():
            return 'empty'
        
        # Get non-null sample for analysis
        sample = series.dropna().astype(str).head(100)
        
        if len(sample) == 0:
            return 'unknown'
        
        # Check for datetime
        if pd.api.types.is_datetime64_any_dtype(series):
            return 'date'
        
        # Try to parse as datetime if object type
        if series.dtype == 'object':
            try:
                # Check if majority can be parsed as dates
                parsed = pd.to_datetime(sample, errors='coerce')
                if parsed.notna().sum() / len(sample) > 0.8:
                    return 'date'
            except:
                pass
        
        # Check for numeric
        if pd.api.types.is_numeric_dtype(series):
            # Check if it looks like an ID (all integers, high uniqueness)
            if series.dtype in ['int64', 'int32']:
                unique_ratio = series.nunique() / len(series.dropna())
                if unique_ratio > 0.95 and len(series) > 10:
                    return 'id'
            return 'numeric'
        
        # Check patterns for semantic types
        for type_name, pattern in self.PATTERNS.items():
            matches = sample.str.match(pattern['regex'], na=False).sum()
            if matches / len(sample) > 0.8:  # 80% match threshold
                return type_name
        
        # Check for boolean-like values
        bool_values = {'true', 'false', 'yes', 'no', '1', '0', 't', 'f', 'y', 'n'}
        lower_sample = sample.str.lower()
        if all(v in bool_values for v in lower_sample):
            return 'boolean'
        
        # Check for categorical (low cardinality)
        # Handle unhashable types by converting to string for counting
        try:
            unique_count = series.nunique()
        except TypeError:
            unique_count = series.astype(str).nunique()
        
        non_null_count = len(series.dropna())
        if non_null_count > 0:
            unique_ratio = unique_count / non_null_count
            if unique_ratio < 0.1 and unique_count < 50:
                return 'categorical'
        
        return 'text'
    
    def _calculate_completeness_score(self, columns: List[ColumnQuality]) -> float:
        """Calculate overall completeness score (0-100)"""
        if not columns:
            return 100.0
        avg_null = sum(c.null_percentage for c in columns) / len(columns)
        return max(0, 100 - avg_null)
    
    def _calculate_uniqueness_score(self, columns: List[ColumnQuality]) -> float:
        """Calculate uniqueness/consistency score (0-100)"""
        if not columns:
            return 100.0
        
        score = 100.0
        for col in columns:
            # Penalize completely constant columns
            if 'constant_value' in col.issues:
                score -= 10
            # Penalize likely ID columns (not necessarily bad, but flag it)
            if 'likely_unique_id' in col.issues:
                score -= 5
        
        return max(0, score)
    
    def _calculate_validity_score(self, columns: List[ColumnQuality]) -> float:
        """Calculate data validity score (0-100)"""
        if not columns:
            return 100.0
        
        score = 100.0
        for col in columns:
            # Penalize mixed types
            if 'mixed_types' in col.issues:
                score -= 15
            # Penalize whitespace issues
            if 'extra_whitespace' in col.issues:
                score -= 5
        
        return max(0, score)
    
    def _detect_dataset_issues(self, columns: List[ColumnQuality]) -> List[str]:
        """Detect dataset-level issues"""
        issues = []
        
        # Check for duplicate rows (skip if columns contain unhashable types)
        if len(self.df) > 1:
            try:
                duplicates = self.df.duplicated().sum()
                if duplicates > 0:
                    issues.append(f"Found {duplicates} duplicate row(s)")
            except TypeError:
                # DataFrame contains unhashable types (lists, dicts), skip duplicate check
                pass
        
        # Check for columns with very high missing rates
        high_missing = [c.name for c in columns if c.null_percentage > 50]
        if high_missing:
            issues.append(f"Columns with >50% missing data: {', '.join(high_missing)}")
        
        # Check for potential primary key columns
        id_columns = [c.name for c in columns if c.inferred_type == 'id']
        if not id_columns and self.row_count > 0:
            issues.append("No clear primary key/ID column detected")
        
        return issues
    
    def _generate_recommendations(self, columns: List[ColumnQuality], dataset_issues: List[str]) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Completeness recommendations
        for col in columns:
            if col.null_percentage > 20:
                recommendations.append(f"Consider imputing or removing column '{col.name}' ({col.null_percentage:.1f}% missing)")
        
        # Type conversion recommendations
        date_like = [c.name for c in columns if c.inferred_type == 'date' and c.dtype == 'object']
        if date_like:
            recommendations.append(f"Parse date columns as datetime: {', '.join(date_like)}")
        
        # Categorical encoding recommendations
        categorical_cols = [c for c in columns if c.inferred_type == 'categorical']
        for col in categorical_cols:
            if col.unique_count <= 10:
                recommendations.append(f"Column '{col.name}' has only {col.unique_count} values - consider one-hot encoding")
        
        # Data cleaning recommendations
        whitespace_cols = [c.name for c in columns if 'extra_whitespace' in c.issues]
        if whitespace_cols:
            recommendations.append(f"Trim whitespace from: {', '.join(whitespace_cols)}")
        
        return recommendations


def analyze_dataframe(df: pd.DataFrame) -> Dict[str, Any]:
    """Convenience function to analyze a dataframe and return dict"""
    analyzer = DataQualityAnalyzer(df)
    report = analyzer.analyze()
    return report.to_dict()

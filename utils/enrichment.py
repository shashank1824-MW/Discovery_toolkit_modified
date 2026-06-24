"""
Data Enrichment Module
Detects column types and suggests enrichments that users can opt-in to apply
"""

import pandas as pd
import numpy as np
import re
from typing import Dict, Any, List, Optional, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse


@dataclass
class EnrichmentSuggestion:
    """A suggested enrichment for a column"""
    column: str
    enrichment_type: str
    description: str
    preview: Any  # Sample of what the enrichment would produce
    confidence: float  # 0-1 confidence score
    applies_to: str  # description of what rows this applies to
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'column': self.column,
            'enrichment_type': self.enrichment_type,
            'description': self.description,
            'preview': self.preview,
            'confidence': round(self.confidence, 2),
            'applies_to': self.applies_to
        }


@dataclass
class EnrichmentResult:
    """Result of applying an enrichment"""
    new_column_name: str
    values: List[Any]
    applied_count: int
    error_count: int


class ColumnEnricher:
    """Enrich columns with derived data"""
    
    @staticmethod
    def extract_email_domain(email: str) -> Optional[str]:
        """Extract domain from email address"""
        if pd.isna(email) or not isinstance(email, str):
            return None
        try:
            return email.split('@')[1].lower() if '@' in email else None
        except:
            return None
    
    @staticmethod
    def extract_email_username(email: str) -> Optional[str]:
        """Extract username from email address"""
        if pd.isna(email) or not isinstance(email, str):
            return None
        try:
            return email.split('@')[0] if '@' in email else None
        except:
            return None
    
    @staticmethod
    def is_corporate_email(email: str) -> Optional[bool]:
        """Check if email is from a corporate domain"""
        if pd.isna(email) or not isinstance(email, str):
            return None
        try:
            domain = email.split('@')[1].lower() if '@' in email else ''
            personal_domains = {'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 
                              'aol.com', 'icloud.com', 'protonmail.com', 'mail.com'}
            return domain not in personal_domains and '.' in domain
        except:
            return None
    
    @staticmethod
    def normalize_phone(phone: str) -> Optional[str]:
        """Normalize phone number to E.164 format (basic)"""
        if pd.isna(phone) or not isinstance(phone, (str, int, float)):
            return None
        try:
            # Extract only digits
            digits = re.sub(r'\D', '', str(phone))
            # Add + if it looks like it might need it
            if len(digits) == 10:
                return f"+1{digits}"  # Assume US
            elif len(digits) > 10:
                return f"+{digits}"
            return digits if digits else None
        except:
            return None
    
    @staticmethod
    def extract_phone_country(phone: str) -> Optional[str]:
        """Extract country code from phone (very basic)"""
        if pd.isna(phone) or not isinstance(phone, str):
            return None
        normalized = ColumnEnricher.normalize_phone(phone)
        if normalized and normalized.startswith('+'):
            # Very basic country detection
            if normalized.startswith('+1'):
                return 'US/CA'
            elif normalized.startswith('+44'):
                return 'UK'
            elif normalized.startswith('+91'):
                return 'IN'
            elif normalized.startswith('+86'):
                return 'CN'
            elif normalized.startswith('+49'):
                return 'DE'
            elif normalized.startswith('+33'):
                return 'FR'
        return 'Unknown'
    
    @staticmethod
    def extract_url_domain(url: str) -> Optional[str]:
        """Extract domain from URL"""
        if pd.isna(url) or not isinstance(url, str):
            return None
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            return parsed.netloc.lower() if parsed.netloc else None
        except:
            return None
    
    @staticmethod
    def extract_url_path(url: str) -> Optional[str]:
        """Extract path from URL"""
        if pd.isna(url) or not isinstance(url, str):
            return None
        try:
            parsed = urlparse(url if url.startswith('http') else f'http://{url}')
            return parsed.path if parsed.path else '/'
        except:
            return None
    
    @staticmethod
    def parse_date_components(date_val) -> Dict[str, Any]:
        """Extract date components"""
        if pd.isna(date_val):
            return {'year': None, 'month': None, 'day': None, 'weekday': None}
        try:
            dt = pd.to_datetime(date_val)
            return {
                'year': dt.year,
                'month': dt.month,
                'day': dt.day,
                'weekday': dt.strftime('%A'),
                'month_name': dt.strftime('%B'),
                'quarter': (dt.month - 1) // 3 + 1
            }
        except:
            return {'year': None, 'month': None, 'day': None, 'weekday': None}
    
    @staticmethod
    def categorize_text(text: str, categories: Dict[str, List[str]]) -> Optional[str]:
        """Categorize text based on keyword matching"""
        if pd.isna(text) or not isinstance(text, str):
            return None
        text_lower = text.lower()
        for category, keywords in categories.items():
            if any(kw in text_lower for kw in keywords):
                return category
        return 'Other'


class EnrichmentSuggester:
    """Suggests enrichments based on column types"""
    
    # Common patterns for column name cleanup - order matters (more specific first)
    COLUMN_NAME_PATTERNS = [
        (r'^(?:.*\.)?id$', 'ID'),
        (r'^(?:.*\.)?uuid$', 'UUID'),
        (r'^(?:.*\.)?url$', 'URL'),
        # Handle flattened JSON paths with dots - convert dots to spaces (handles 2+ levels)
        (r'^([a-zA-Z_][a-zA-Z0-9_]*\.)+[a-zA-Z_][a-zA-Z0-9_]*$', lambda m: EnrichmentSuggester._flattened_path_to_title(m.group(0))),
        # Handle snake_case first (before camelCase patterns)
        (r'^(?:.*\.)?([a-z]+_[a-z]+(?:_[a-z]+)*)$', lambda m: ' '.join(word.capitalize() for word in m.group(1).split('_'))),  # snake_case
        # camelCase with common suffixes
        (r'^(?:.*\.)?([a-z]+[a-zA-Z]*)(Id|ID)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1)) + ' ID'),
        (r'^(?:.*\.)?([a-z]+[a-zA-Z]*)(Name)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1)) + ' Name'),
        (r'^(?:.*\.)?([a-z]+[a-zA-Z]*)(Email)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1)) + ' Email'),
        (r'^(?:.*\.)?([a-z]+[a-zA-Z]*)(Phone)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1)) + ' Phone'),
        (r'^(?:.*\.)?([a-z]+[a-zA-Z]*)(Date)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1)) + ' Date'),
        (r'^(?:.*\.)?([a-z]+[a-zA-Z]*)(At)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1)) + ' Date'),
        (r'^(?:.*\.)?([a-z]+[a-zA-Z]*)(Url|URL|Link)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1)) + ' URL'),
        # General camelCase
        (r'^(?:.*\.)?([a-z][a-zA-Z]*[A-Z][a-zA-Z]*)$', lambda m: EnrichmentSuggester._camel_to_title(m.group(1))),
        # single word
        (r'^(?:.*\.)?([a-z]+)$', lambda m: m.group(1).capitalize()),
        # Fallback
        (r'^(?:.*\.)?(.+)$', lambda m: m.group(1).capitalize()),
    ]
    
    @staticmethod
    def _camel_to_title(text: str) -> str:
        """Convert camelCase to Title Case"""
        # Insert space before capital letters (but not at start)
        s1 = re.sub('([a-z0-9])([A-Z])', r'\1 \2', text)
        # Handle consecutive caps like "URL" or "ID"
        s2 = re.sub('([A-Z]+)([A-Z][a-z])', r'\1 \2', s1)
        return s2.title().strip()
    
    @staticmethod
    def _flattened_path_to_title(path: str) -> str:
        """Convert flattened JSON path like 'providerSpecific.url' to 'Provider Specific URL'"""
        # Split by dot and process each part
        parts = path.split('.')
        processed_parts = []
        
        for part in parts:
            # Convert each part from camelCase/snake_case to Title Case
            if '_' in part:
                # Handle snake_case
                words = part.split('_')
                processed_parts.append(' '.join(word.capitalize() for word in words))
            else:
                # Handle camelCase
                # Insert space before capital letters
                s1 = re.sub('([a-z0-9])([A-Z])', r'\1 \2', part)
                # Handle consecutive caps
                s2 = re.sub('([A-Z]+)([A-Z][a-z])', r'\1 \2', s1)
                processed_parts.append(s2.title())
        
        return ' '.join(processed_parts)
    
    @staticmethod
    def suggest_column_rename(column_name: str) -> Optional[str]:
        """Suggest a human-readable column name"""
        # Check if it's already clean (no dots, no underscores, no camelCase)
        is_flattened_path = '.' in column_name
        has_underscore = '_' in column_name
        has_camel_case = re.search(r'[a-z][A-Z]', column_name) is not None
        
        # If it's a flattened path (has dots), we should process it
        if not is_flattened_path and not has_underscore and not has_camel_case:
            return None  # Already clean
        
        for pattern, replacement in EnrichmentSuggester.COLUMN_NAME_PATTERNS:
            match = re.match(pattern, column_name, re.IGNORECASE)
            if match:
                if callable(replacement):
                    try:
                        return replacement(match)
                    except:
                        continue
                return replacement
        
        return None
    
    # Available enrichments by type
    ENRICHMENTS = {
        'email': [
            {
                'type': 'extract_domain',
                'name': 'Extract Domain',
                'description': 'Extract the domain part (e.g., @company.com) from email addresses',
                'new_column_suffix': '_domain',
                'applies_to': 'Valid email addresses'
            },
            {
                'type': 'extract_username',
                'name': 'Extract Username',
                'description': 'Extract the username part (e.g., john.doe) from email addresses',
                'new_column_suffix': '_username',
                'applies_to': 'Valid email addresses'
            },
            {
                'type': 'is_corporate',
                'name': 'Is Corporate Email',
                'description': 'Flag emails as corporate (true) or personal (false)',
                'new_column_suffix': '_is_corporate',
                'applies_to': 'All email addresses'
            }
        ],
        'phone': [
            {
                'type': 'normalize_e164',
                'name': 'Normalize to E.164',
                'description': 'Standardize phone numbers to E.164 format (+1234567890)',
                'new_column_suffix': '_normalized',
                'applies_to': 'Phone numbers with sufficient digits'
            },
            {
                'type': 'extract_country',
                'name': 'Detect Country',
                'description': 'Attempt to detect country from phone number prefix',
                'new_column_suffix': '_country',
                'applies_to': 'International phone numbers'
            }
        ],
        'url': [
            {
                'type': 'extract_domain',
                'name': 'Extract Domain',
                'description': 'Extract the domain name from URLs',
                'new_column_suffix': '_domain',
                'applies_to': 'Valid URLs'
            },
            {
                'type': 'extract_path',
                'name': 'Extract Path',
                'description': 'Extract the URL path component',
                'new_column_suffix': '_path',
                'applies_to': 'URLs with paths'
            }
        ],
        'date': [
            {
                'type': 'extract_year',
                'name': 'Extract Year',
                'description': 'Extract the year component',
                'new_column_suffix': '_year',
                'applies_to': 'Valid dates'
            },
            {
                'type': 'extract_month',
                'name': 'Extract Month',
                'description': 'Extract the month as number (1-12)',
                'new_column_suffix': '_month',
                'applies_to': 'Valid dates'
            },
            {
                'type': 'extract_weekday',
                'name': 'Extract Weekday',
                'description': 'Extract the day of week (Monday, Tuesday, etc.)',
                'new_column_suffix': '_weekday',
                'applies_to': 'Valid dates'
            },
            {
                'type': 'extract_quarter',
                'name': 'Extract Quarter',
                'description': 'Extract the quarter (1-4)',
                'new_column_suffix': '_quarter',
                'applies_to': 'Valid dates'
            }
        ]
    }
    
    def __init__(self, df: pd.DataFrame, column_types: Dict[str, str]):
        self.df = df
        self.column_types = column_types
        self.enricher = ColumnEnricher()
    
    def get_suggestions(self) -> List[EnrichmentSuggestion]:
        """Get all enrichment suggestions for the dataset"""
        suggestions = []
        
        # Check for column name cleanup opportunities
        for column in self.df.columns:
            suggested_name = self.suggest_column_rename(column)
            if suggested_name and suggested_name != column:
                suggestions.append(EnrichmentSuggestion(
                    column=column,
                    enrichment_type='rename_column',
                    description=f"Rename column to '{suggested_name}'",
                    preview={'new_name': suggested_name},
                    confidence=1.0,
                    applies_to='Column name cleanup'
                ))
        
        for column, col_type in self.column_types.items():
            if col_type in self.ENRICHMENTS:
                col_suggestions = self._suggest_for_column(column, col_type)
                suggestions.extend(col_suggestions)
        
        # Sort by confidence
        suggestions.sort(key=lambda x: x.confidence, reverse=True)
        return suggestions
    
    def _suggest_for_column(self, column: str, col_type: str) -> List[EnrichmentSuggestion]:
        """Generate suggestions for a specific column"""
        suggestions = []
        series = self.df[column]
        non_null = series.dropna()
        
        if col_type == 'email':
            # Check for valid emails
            email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
            valid_emails = non_null[non_null.astype(str).str.match(email_pattern, na=False)]
            confidence = len(valid_emails) / len(non_null) if len(non_null) > 0 else 0
            
            if confidence > 0.5:
                # Domain extraction suggestion
                sample_domains = valid_emails.head(3).apply(
                    self.enricher.extract_email_domain
                ).tolist()
                suggestions.append(EnrichmentSuggestion(
                    column=column,
                    enrichment_type='email_extract_domain',
                    description=f"Extract email domains (e.g., {', '.join(filter(None, sample_domains[:2]))})",
                    preview={'new_columns': [f'{column}_domain']},
                    confidence=confidence,
                    applies_to=f'{len(valid_emails)} valid email addresses'
                ))
                
                # Corporate email detection
                sample_corporate = valid_emails.head(10).apply(
                    self.enricher.is_corporate_email
                )
                corporate_count = sample_corporate.sum()
                if corporate_count > 0:
                    suggestions.append(EnrichmentSuggestion(
                        column=column,
                        enrichment_type='email_is_corporate',
                        description=f"Flag corporate vs personal emails ({corporate_count} corporate detected in sample)",
                        preview={'new_columns': [f'{column}_is_corporate']},
                        confidence=confidence,
                        applies_to=f'All {len(valid_emails)} emails'
                    ))
        
        elif col_type == 'phone':
            # Check for normalizable phones
            normalized = non_null.apply(self.enricher.normalize_phone)
            successful = normalized.dropna()
            confidence = len(successful) / len(non_null) if len(non_null) > 0 else 0
            
            if confidence > 0.5:
                suggestions.append(EnrichmentSuggestion(
                    column=column,
                    enrichment_type='phone_normalize',
                    description="Standardize phone numbers to E.164 format",
                    preview={'new_columns': [f'{column}_normalized']},
                    confidence=confidence,
                    applies_to=f'{len(successful)} phone numbers'
                ))
        
        elif col_type == 'url':
            # Check for valid URLs
            url_pattern = r'^https?://[^\s/$.?#].[^\s]*$'
            valid_urls = non_null[non_null.astype(str).str.match(url_pattern, na=False)]
            confidence = len(valid_urls) / len(non_null) if len(non_null) > 0 else 0
            
            if confidence > 0.5:
                sample_domains = valid_urls.head(3).apply(
                    self.enricher.extract_url_domain
                ).tolist()
                suggestions.append(EnrichmentSuggestion(
                    column=column,
                    enrichment_type='url_extract_domain',
                    description=f"Extract domains (e.g., {', '.join(filter(None, sample_domains[:2]))})",
                    preview={'new_columns': [f'{column}_domain']},
                    confidence=confidence,
                    applies_to=f'{len(valid_urls)} valid URLs'
                ))
        
        elif col_type == 'date':
            # Check for parsable dates
            parsed = pd.to_datetime(non_null, errors='coerce')
            valid_dates = parsed.dropna()
            confidence = len(valid_dates) / len(non_null) if len(non_null) > 0 else 0
            
            if confidence > 0.5:
                suggestions.append(EnrichmentSuggestion(
                    column=column,
                    enrichment_type='date_extract_components',
                    description="Extract year, month, weekday, and quarter from dates",
                    preview={'new_columns': [f'{column}_year', f'{column}_month', f'{column}_weekday', f'{column}_quarter']},
                    confidence=confidence,
                    applies_to=f'{len(valid_dates)} valid dates'
                ))
        
        return suggestions
    
    def apply_enrichment(self, column: str, enrichment_type: str) -> EnrichmentResult:
        """Apply a specific enrichment to a column"""
        series = self.df[column]
        
        if enrichment_type == 'email_extract_domain':
            values = series.apply(self.enricher.extract_email_domain).tolist()
            return EnrichmentResult(
                new_column_name=f'{column}_domain',
                values=values,
                applied_count=len([v for v in values if v is not None]),
                error_count=len([v for v in values if v is None]) - series.isna().sum()
            )
        
        elif enrichment_type == 'email_extract_username':
            values = series.apply(self.enricher.extract_email_username).tolist()
            return EnrichmentResult(
                new_column_name=f'{column}_username',
                values=values,
                applied_count=len([v for v in values if v is not None]),
                error_count=0
            )
        
        elif enrichment_type == 'email_is_corporate':
            values = series.apply(self.enricher.is_corporate_email).tolist()
            return EnrichmentResult(
                new_column_name=f'{column}_is_corporate',
                values=values,
                applied_count=len([v for v in values if v is not None]),
                error_count=0
            )
        
        elif enrichment_type == 'phone_normalize':
            values = series.apply(self.enricher.normalize_phone).tolist()
            return EnrichmentResult(
                new_column_name=f'{column}_normalized',
                values=values,
                applied_count=len([v for v in values if v is not None]),
                error_count=0
            )
        
        elif enrichment_type == 'phone_extract_country':
            values = series.apply(self.enricher.extract_phone_country).tolist()
            return EnrichmentResult(
                new_column_name=f'{column}_country',
                values=values,
                applied_count=len([v for v in values if v is not None]),
                error_count=0
            )
        
        elif enrichment_type == 'url_extract_domain':
            values = series.apply(self.enricher.extract_url_domain).tolist()
            return EnrichmentResult(
                new_column_name=f'{column}_domain',
                values=values,
                applied_count=len([v for v in values if v is not None]),
                error_count=0
            )
        
        elif enrichment_type == 'url_extract_path':
            values = series.apply(self.enricher.extract_url_path).tolist()
            return EnrichmentResult(
                new_column_name=f'{column}_path',
                values=values,
                applied_count=len([v for v in values if v is not None]),
                error_count=0
            )
        
        elif enrichment_type == 'date_extract_components':
            components = series.apply(self.enricher.parse_date_components)
            # Return as dict of column names to values
            years = [c['year'] for c in components]
            months = [c['month'] for c in components]
            weekdays = [c['weekday'] for c in components]
            quarters = [c['quarter'] for c in components]
            
            return EnrichmentResult(
                new_column_name=f'{column}_components',  # Special case: multiple columns
                values={
                    f'{column}_year': years,
                    f'{column}_month': months,
                    f'{column}_weekday': weekdays,
                    f'{column}_quarter': quarters
                },
                applied_count=len([y for y in years if y is not None]),
                error_count=0
            )
        
        elif enrichment_type == 'rename_column':
            # Get the suggested new name
            new_name = self.suggest_column_rename(column)
            if not new_name:
                new_name = column  # Fallback to original
            
            return EnrichmentResult(
                new_column_name=new_name,
                values={'old_name': column, 'new_name': new_name},
                applied_count=1,
                error_count=0
            )
        
        else:
            raise ValueError(f"Unknown enrichment type: {enrichment_type}")


def suggest_enrichments(df: pd.DataFrame, column_types: Dict[str, str]) -> List[Dict[str, Any]]:
    """Convenience function to get enrichment suggestions"""
    suggester = EnrichmentSuggester(df, column_types)
    suggestions = suggester.get_suggestions()
    return [s.to_dict() for s in suggestions]

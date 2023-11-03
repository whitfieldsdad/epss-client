import fnmatch
from typing import Iterable

CASE_SENSITIVE = False


def string_matches_pattern(string: str, pattern: str, case_sensitive: bool = CASE_SENSITIVE) -> bool:
  """
  Determine whether the provided string matches the provided pattern.
  """
  if not case_sensitive:
    string = string.lower()
    pattern = pattern.lower()
  return fnmatch.fnmatch(string, pattern)


def string_matches_any_pattern(string: str, patterns: Iterable[str], case_sensitive: bool = CASE_SENSITIVE) -> bool:
  """
  Determine whether the provided string matches the provided pattern.
  """
  if not case_sensitive:
    string = string.lower()
    patterns = [p.lower() for p in patterns]
  return any(fnmatch.fnmatch(string, pattern) for pattern in patterns)

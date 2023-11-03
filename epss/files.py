import os
from typing import Optional
from epss.constants import SCORES_BY_CVE_ID_DIR, SCORES_BY_DATE_DIR
from epss.dates import DATE

import epss.dates as dates


def get_path_to_epss_scores_indexed_by_date(date: DATE) -> str:
    """
    Get the path for storing EPSS scores by date.

    Example output:

    /tmp/epss-scores/by/date/2021-07-15.csv.gz
    """
    date = dates.parse_date(date)
    return os.path.join(SCORES_BY_DATE_DIR, f"{date.isoformat()}.csv.gz")


def get_path_to_epss_scores_indexed_by_cve_id(cve_id: Optional[str] = None) -> str:
    """
    Get the path for storing EPSS scores by CVE ID.

    - If a CVE ID is provided, the path to the file containing EPSS scores for that CVE ID is returned.
    - If no CVE ID is provided, the path to the directory containing all EPSS scores indexed by CVE ID is returned.

    Example outputs:

    - /tmp/epss-scores/by/cve_id/
    - /tmp/epss-scores/by/cve_id/CVE-2021-3456.csv.gz
    """
    return os.path.join(SCORES_BY_CVE_ID_DIR, f"{cve_id}.csv.gz")

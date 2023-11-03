import datetime
import io
import logging
import os
import re
import tempfile
import pandas as pd
import requests
from epss import cli
import epss.pattern_matching
from typing import Iterable, Iterator, Optional, Tuple, Union
from dataclasses import dataclass
import concurrent.futures

logger = logging.getLogger(__name__)

DATE = Union[str, datetime.date, datetime.datetime]

WORKDIR = os.path.join(tempfile.gettempdir(), "epss-scores")
MIN_DATE = "2022-07-15"


@dataclass()
class Client:
    workdir: str = WORKDIR
    enable_progress_bar: bool = True

    @property
    def min_date(self) -> datetime.date:
        return get_min_date()

    @property
    def max_date(self) -> datetime.date:
        return get_max_date()

    def get_min_date(self) -> datetime.date:
        return self.min_date

    def get_max_date(self) -> datetime.date:
        return self.max_date

    @property
    def scores_by_date_dir(self) -> str:
        return os.path.join(self.workdir, "by", "date")

    def iter_cve_ids(
        self, date: Optional[DATE] = None, cve_ids: Optional[Iterable[str]] = None
    ) -> Iterator[str]:
        """
        List all known CVE IDs on a particular date.
        """
        df = self.get_scores_by_date(date=date, cve_ids=cve_ids)
        return df["cve"].sort_values(ascending=False).unique()

    def get_score(self, cve_id: str, date: Optional[DATE] = None) -> Optional[dict]:
        """
        Get the EPSS score for a given CVE ID on a particular date.
        """
        df = self.get_scores_by_date(date=date, cve_ids=[cve_id])
        if not df.empty:
            return df.iloc[0].to_dict()

    def get_scores_by_date_range(
        self,
        min_date: Optional[DATE] = None,
        max_date: Optional[DATE] = None,
        cve_ids: Optional[Iterable[str]] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
    ):
        """
        Get EPSS scores observed over a given date range.
        """
        dfs = []
        for _, df in self.iter_scores_grouped_by_date(
            min_date=min_date,
            max_date=max_date,
            cve_ids=cve_ids,
            min_score=min_score,
            max_score=max_score,
            min_percentile=min_percentile,
            max_percentile=max_percentile,
        ):
            dfs.append(df)
        return pd.concat(dfs)

    def iter_scores_grouped_by_date(
        self,
        min_date: Optional[DATE] = None,
        max_date: Optional[DATE] = None,
        cve_ids: Optional[Iterable[str]] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
    ) -> Iterator[Tuple[datetime.date, pd.DataFrame]]:
        """
        Iterate over EPSS scores observed over a given date range.
        """
        self.download_scores_by_date_range(
            min_date=min_date,
            max_date=max_date,
        )
        with concurrent.futures.ThreadPoolExecutor() as executor:
            futures = {}
            for date in iter_dates(min_date=min_date, max_date=max_date):
                future = executor.submit(
                    self.get_scores_by_date,
                    date=date,
                    cve_ids=cve_ids,
                    min_score=min_score,
                    max_score=max_score,
                    min_percentile=min_percentile,
                    max_percentile=max_percentile,
                )
                futures[future] = date

            for future in concurrent.futures.as_completed(futures):
                date = futures[future]
                df = future.result()
                if not df.empty:
                    yield date, df

        for date in iter_dates(min_date=min_date, max_date=max_date):
            df = self.get_scores_by_date(
                date=date,
                cve_ids=cve_ids,
                min_score=min_score,
                max_score=max_score,
                min_percentile=min_percentile,
                max_percentile=max_percentile,
            )
            if not df.empty:
                yield date, df

    def get_scores_by_date(
        self,
        date: Optional[DATE] = None,
        cve_ids: Optional[Iterable[str]] = None,
        min_score: Optional[float] = None,
        max_score: Optional[float] = None,
        min_percentile: Optional[float] = None,
        max_percentile: Optional[float] = None,
    ) -> pd.DataFrame:
        """
        Get EPSS scores for a given date.
        """
        date = parse_date(date) if date else get_max_date()
        path = self.get_path_to_scores_by_date(date)
        if not os.path.exists(path):
            download_scores_by_date(path=path, date=date)

        df = pd.read_csv(path)
        if any(
            (
                cve_ids,
                min_score,
                max_score,
                min_percentile,
                max_percentile,
            )
        ):
            df = filter_scores(
                df=df,
                cve_ids=cve_ids,
                min_score=min_score,
                max_score=max_score,
                min_percentile=min_percentile,
                max_percentile=max_percentile,
            )
        return df

    def download_scores_by_date_range(
        self,
        min_date: Optional[DATE] = None,
        max_date: Optional[DATE] = None,
    ):
        """
        Download EPSS scores for a given date range.
        """
        min_date, max_date = parse_date_range(min_date, max_date)
        downloads = []
        for date in iter_dates(min_date=min_date, max_date=max_date):
            path = self.get_path_to_scores_by_date(date)
            if os.path.exists(path):
                logger.debug(f"Skipping {path} (already exists)")
            else:
                downloads.append((path, date))

        if downloads:
            total = len(downloads)
            logger.info(
                f"Downloading {total} {'files' if total > 1 else 'file'} containing EPSS scores from {min_date.isoformat()} to {max_date.isoformat()}"
            )
            with concurrent.futures.ThreadPoolExecutor() as executor:
                futures = []
                for path, date in downloads:
                    future = executor.submit(
                        download_scores_by_date, path=path, date=date
                    )
                    futures.append(future)
                concurrent.futures.wait(futures)

    def download_scores_by_date(
        self,
        date: DATE,
    ):
        path = self.get_path_to_scores_by_date(date)
        if not (os.path.exists(path) and os.path.getsize(path) > 0):
            download_scores_by_date(
                path=path,
                date=date,
            )

    def get_path_to_scores_by_date(self, date: DATE) -> str:
        """
        Get the path to the CSV file containing EPSS scores for a given date.
        """
        date = parse_date(date)
        return os.path.join(self.scores_by_date_dir, f"{date.isoformat()}.csv.gz")


# TODO: add integrity check to detect failed downloads
def download_scores_by_date(
    path: str,
    date: DATE,
    cve_ids: Optional[Iterable[str]] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    min_percentile: Optional[float] = None,
    max_percentile: Optional[float] = None,
):
    """
    Download EPSS scores for a given date and save them to a CSV file.
    """
    url = get_download_url(date)
    df = get_scores_by_date(
        date=date,
        cve_ids=cve_ids,
        min_score=min_score,
        max_score=max_score,
        min_percentile=min_percentile,
        max_percentile=max_percentile,
    )
    os.makedirs(os.path.dirname(path), exist_ok=True)
    df.to_csv(path, index=False)
    logger.info(f"Downloaded {url} to {path}")


def get_scores_by_date(
    date: DATE,
    cve_ids: Optional[Iterable[str]] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    min_percentile: Optional[float] = None,
    max_percentile: Optional[float] = None,
):
    url = get_download_url(date)
    logger.info(f"Downloading {url}")
    response = requests.get(url, stream=True)
    if response.status_code != 200:
        logger.info(f"Failed to download {url} (status code: {response.status_code})")
    response.raise_for_status()

    df = pd.read_csv(io.BytesIO(response.content), skiprows=1, compression="gzip")
    df["date"] = date.isoformat()

    if any((cve_ids, min_score, max_score, min_percentile, max_percentile)):
        df = filter_scores(
            df=df,
            cve_ids=cve_ids,
            min_score=min_score,
            max_score=max_score,
            min_percentile=min_percentile,
            max_percentile=max_percentile,
        )
    return df


def filter_scores(
    df: pd.DataFrame,
    cve_ids: Optional[Iterable[str]] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    min_percentile: Optional[float] = None,
    max_percentile: Optional[float] = None,
) -> pd.DataFrame:
    """
    Filter a dataframe of EPSS scores.
    """
    df = df.copy()

    if cve_ids:
        f = lambda cve_id: epss.pattern_matching.string_matches_any_pattern(
            cve_id, cve_ids
        )
        df = df[df["cve"].apply(f)]

    if min_score is not None:
        df = df[df["epss"] >= min_score]

    if max_score is not None:
        df = df[df["epss"] <= max_score]

    if min_percentile is not None:
        df = df[df["percentile"] >= min_percentile]

    if max_percentile is not None:
        df = df[df["percentile"] <= max_percentile]

    return df


def parse_date(date: DATE) -> datetime.date:
    """
    Convert the provided date to a datetime.date object.

    If a date is provided as a string, it must be in ISO format (YYYY-MM-DD).
    """
    if isinstance(date, str):
        date = datetime.date.fromisoformat(date)
    elif isinstance(date, datetime.datetime):
        date = date.date()
    elif isinstance(date, datetime.date):
        pass
    else:
        raise TypeError(f"Invalid date: {date}")
    return date


def iter_dates(
    min_date: Optional[DATE] = None, max_date: Optional[DATE] = None
) -> Iterator[datetime.date]:
    """
    Iterate over the dates in the provided range (inclusive).
    """
    min_date = min_date or MIN_DATE
    max_date = max_date or get_max_date()
    min_date, max_date = parse_date_range(min_date, max_date)
    for date in pd.date_range(min_date, max_date, freq="D"):
        yield date.date()


def parse_date_range(
    min_date: Optional[DATE] = MIN_DATE, max_date: Optional[DATE] = None
) -> Tuple[datetime.date, datetime.date]:
    """
    Parse the provided start and end dates and ensure that they fall within the range of available EPSS scores.
    """
    min_date = parse_date(min_date) if min_date else get_min_date()
    max_date = parse_date(max_date) if max_date else get_max_date()
    if min_date > max_date:
        raise ValueError("min_date must be less than or equal to max_date")
    return min_date, max_date


def get_min_date(check: bool = False) -> datetime.datetime:
    """
    Returns the earliest date for which EPSS scores are available (i.e. 2022-07-15).
    """
    if check is False:
        return datetime.date.fromisoformat(MIN_DATE)

    # TODO: improve upon brute force search
    max_date = get_max_date()
    date = max_date
    while True:
        url = get_download_url(date)
        response = requests.head(url)
        if response.status_code != 200:
            return date
        date -= datetime.timedelta(days=1)


def get_max_date() -> datetime.date:
    """
    Determine the latest date for which EPSS scores are available.
    """
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    response = requests.head(url)
    response.raise_for_status()
    location = response.headers["location"]

    regex = r"(\d{4}-\d{2}-\d{2})"
    match = re.search(regex, location)
    assert match is not None, f"No date found in {location}"
    return datetime.date.fromisoformat(match.group(1))


def get_download_url(date: Optional[DATE] = None) -> str:
    date = parse_date(date) if date else get_max_date()
    return f"https://epss.cyentia.com/epss_scores-{date.isoformat()}.csv.gz"


if __name__ == "__main__":
    cli()

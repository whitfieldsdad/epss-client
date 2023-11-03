import json
import logging
from typing import Iterable, Optional
import click
import epss.epss
from epss.epss import MIN_DATE, Client

PLAIN = "plain"
JSON = "json"
CSV = "csv"


@click.group()
def cli():
    """
    Exploit Prediction Scoring System (EPSS)
    """
    pass


@cli.command("cve-ids")
@click.argument("date", required=False)
@click.option(
    "--output-format",
    type=click.Choice([PLAIN, JSON]),
    default=PLAIN,
    show_default=True,
)
def list_cve_ids(date: Optional[str], output_format: str):
    """
    List known CVE IDs (latest first)
    """
    client = Client()
    cve_ids = sorted(client.iter_cve_ids(date=date), reverse=True)
    if output_format == PLAIN:
        for cve_id in cve_ids:
            print(cve_id)
    elif output_format == JSON:
        print(json.dumps(cve_ids))
    else:
        raise ValueError(f"Invalid output format: {output_format}")


@cli.command("get-score")
@click.argument("cve-id", required=True)
@click.option("--date", required=False)
@click.option(
    "--output-format",
    type=click.Choice([JSON, PLAIN]),
    default=PLAIN,
    show_default=True,
)
def get_score(cve_id: str, date: Optional[str], output_format: str):
    """
    Get the EPSS score for a CVE ID
    """
    client = Client()
    score = client.get_score(cve_id=cve_id, date=date)
    if score is not None:
        if output_format == PLAIN:
            print(score["epss"])
        elif output_format == JSON:
            print(json.dumps(score))
        else:
            raise ValueError(f"Invalid output format: {output_format}")


@cli.command("list-scores")
@click.argument("cve_ids", nargs=-1)
@click.option("--date")
@click.option("--min-date")
@click.option("--max-date")
@click.option(
    "--output-format",
    type=click.Choice([JSON, CSV]),
    default=JSON,
    show_default=True,
)
@click.option("--min-score", "min_score", type=float)
@click.option("--max-score", "max_score", type=float)
@click.option("--min-percentile", type=float)
@click.option("--max-percentile", type=float)
@click.option("--latest/--all", "download_latest", default=True, show_default=True)
def list_scores(
    cve_ids: Optional[Iterable[str]],
    date: Optional[str],
    min_date: Optional[str],
    max_date: Optional[str],
    output_format: str,
    min_score: Optional[float],
    max_score: Optional[float],
    min_percentile: Optional[float],
    max_percentile: Optional[float],
    download_latest: bool,
):
    """
    List EPSS scores.
    """
    client = Client()
    if date:
        min_date = max_date = date
    elif download_latest:
        min_date = max_date = client.get_max_date()
    else:
        min_date = min_date or client.get_min_date()
        max_date = max_date or client.get_max_date()

    scores = client.iter_scores_grouped_by_date(
        min_date=min_date,
        max_date=max_date,
        cve_ids=cve_ids,
        min_score=min_score,
        max_score=max_score,
        min_percentile=min_percentile,
        max_percentile=max_percentile,
    )
    for _, df in scores:
        if output_format == JSON:
            print(df.to_json(orient="records"))
        elif output_format == CSV:
            print(df.to_csv(index=False))
        else:
            raise ValueError(f"Invalid output format: {output_format}")


@cli.command("count-scores")
@click.argument("cve_ids", nargs=-1)
@click.option("--date")
@click.option("--min-date")
@click.option("--max-date")
@click.option(
    "--output-format",
    type=click.Choice([JSON, CSV]),
    default=JSON,
    show_default=True,
)
@click.option("--min-score", "min_score", type=float)
@click.option("--max-score", "max_score", type=float)
@click.option("--min-percentile", type=float)
@click.option("--max-percentile", type=float)
@click.option("--latest/--all", "download_latest", default=True, show_default=True)
def count_scores(
    cve_ids: Optional[Iterable[str]],
    date: Optional[str],
    min_date: Optional[str],
    max_date: Optional[str],
    output_format: str,
    min_score: Optional[float],
    max_score: Optional[float],
    min_percentile: Optional[float],
    max_percentile: Optional[float],
    download_latest: bool,
):
    """
    Count EPSS scores.
    """
    client = Client()
    if date:
        min_date = max_date = date
    elif download_latest:
        min_date = max_date = client.get_max_date()
    else:
        min_date = min_date or client.get_min_date()
        max_date = max_date or client.get_max_date()

    scores = client.iter_scores_grouped_by_date(
        min_date=min_date,
        max_date=max_date,
        cve_ids=cve_ids,
        min_score=min_score,
        max_score=max_score,
        min_percentile=min_percentile,
        max_percentile=max_percentile,
    )
    total = 0
    for _, df in scores:
        total += len(df)
    print(total)


@cli.command("download-scores")
@click.option("--date")
@click.option("--min-date")
@click.option("--max-date")
@click.option("--latest/--all", "download_latest", default=True, show_default=True)
def download_scores(
    date: Optional[str],
    min_date: Optional[str],
    max_date: Optional[str],
    download_latest: bool,
):
    """
    Download EPSS scores.
    """
    client = Client()
    if date:
        min_date = max_date = date
    elif download_latest:
        min_date = max_date = client.get_max_date()
    else:
        min_date = min_date or client.get_min_date()
        max_date = max_date or client.get_max_date()

    client.download_scores_by_date_range(
        min_date=min_date,
        max_date=max_date,
    )


@cli.command("min-date")
@click.option("--check", is_flag=True)
def get_min_date(check: bool):
    """
    Get the earliest date for which EPSS scores are available.
    """
    print(epss.epss.get_min_date(check=check))


@cli.command("max-date")
def get_max_date():
    """
    Get the latest date for which EPSS scores are available.
    """
    print(epss.epss.get_max_date())


@cli.command("date-range")
def get_date_range():
    """
    Get the range of dates for which EPSS scores are available.
    """
    min_date = epss.epss.get_min_date()
    max_date = epss.epss.get_max_date()
    print(min_date, max_date)


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    cli()

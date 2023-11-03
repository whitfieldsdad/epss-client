# Exploit Prediction Scoring System (EPSS) client

The following Python 3 module can be used to:

- Download historical EPSS scores
- Identify anomalous changes in EPSS scores using % change (e.g. a 5% change)

## Installation

To install this repository, clone the repository and run the following command:

```shell
poetry install
```

## Usage

### Command line interface

#### Get the EPSS score for one CVE ID

To retrieve the latest EPSS score for a particular vulnerability:

```shell
poetry run epss score CVE-2014-0160 --output-format=json | jq
```

```json
{
  "cve": "CVE-2014-0160",
  "epss": 0.97588,
  "percentile": 1
}
```

To retrieve the EPSS score for a particular vulnerability on a particular date:

```shell
poetry run epss score CVE-2014-0160 --output-format=json --date=2023-01-01 | jq
```

```json
{
  "cve": "CVE-2014-0160",
  "epss": 0.96076,
  "percentile": 0.9999
}
```

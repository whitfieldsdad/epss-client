import json
import math
import os
from typing import Iterator, Optional
import logging
import requests
from threading import Event

logger = logging.getLogger(__name__)

API_KEY = os.environ.get('NIST_NVD_API_KEY')

PRODUCTS_URL = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'


def iter_products() -> Iterator[dict]:
  yield from query(PRODUCTS_URL, subkey='products')


def query(url: str, subkey: str, api_key: Optional[str] = API_KEY):
  api_key = api_key or API_KEY
  if not api_key:
    logger.warning('NIST_NVD_API_KEY not set, queries will be rate limited to 1 every 6 seconds')

  page_number = 0
  total_results = None
  total_pages = None

  event = Event()
  while not event.is_set():
    response = requests.get(url, params={'startIndex': page_number})
    if response.status_code == 403:
      logger.warning(f'Rate limit exceeded - sleeping for 6 seconds')
      event.wait(timeout=6)
      continue
      
    reply = response.json()
    yield from reply[subkey]

    # Determing how many pages of results there are.
    if total_pages is None:      
      total_results = reply['totalResults']
      page_size = reply['resultsPerPage']
      total_pages = math.ceil(total_results / page_size)
      if total_pages != 1:
        logger.info(f'Found {total_results} spanning {total_pages} pages with a page size of {page_size}')
      else:
        logger.debug(f'Response contains {total_results} results, no pagination required')
        break
    
    page_number += 1
    logger.info(f'Read page {page_number}/{total_pages}')
    if page_number >= total_pages:
      break

    event.wait(timeout=6)


if __name__ == "__main__":
  def cli():
    import click
    
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    @click.group()
    def _cli():
      pass
      
    @_cli.command('products')
    def _get_products():
      products = iter_products()
      for product in products:
        print(json.dumps(product))

    _cli()

  cli()

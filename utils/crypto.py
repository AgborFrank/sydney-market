import requests
import logging

logger = logging.getLogger(__name__)

def get_exchange_rates():
    """Fetch BTC and XMR exchange rates for USD, CAD, EUR, AUD, GBP."""
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {
        "ids": "bitcoin,monero",
        "vs_currencies": "usd,cad,eur,aud,gbp"
    }
    proxies = {
        "http": "socks5h://127.0.0.1:9050",
        "https": "socks5h://127.0.0.1:9050"
    }
    try:
        response = requests.get(url, params=params, timeout=15, proxies=proxies)
        response.raise_for_status()
        data = response.json()
        rates = {
            "bitcoin": {
                "USD": data["bitcoin"]["usd"],
                "CAD": data["bitcoin"]["cad"],
                "EUR": data["bitcoin"]["eur"],
                "AUD": data["bitcoin"]["aud"],
                "GBP": data["bitcoin"]["gbp"]
            },
            "monero": {
                "USD": data["monero"]["usd"],
                "CAD": data["monero"]["cad"],
                "EUR": data["monero"]["eur"],
                "AUD": data["monero"]["aud"],
                "GBP": data["monero"]["gbp"]
            }
        }
        logger.debug("Fetched exchange rates: %s", rates)
        return rates
    except Exception as e:
        logger.error("Failed to fetch exchange rates: %s", str(e))
        return {"bitcoin": {}, "monero": {}}
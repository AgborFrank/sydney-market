import requests
import logging

logger = logging.getLogger(__name__)

def get_exchange_rates():
    """Fetch BTC and XMR exchange rates for USD, CAD, EUR, AUD, GBP, and return as flat dict."""
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
        rates = {}
        # BTC
        for code in ["USD", "CAD", "EUR", "AUD", "GBP"]:
            key = f"BTC/{code}"
            value = data.get("bitcoin", {}).get(code.lower(), 0)
            rates[key] = {"rate": value}
        # XMR
        for code in ["USD", "CAD", "EUR", "AUD", "GBP"]:
            key = f"XMR/{code}"
            value = data.get("monero", {}).get(code.lower(), 0)
            rates[key] = {"rate": value}
        logger.debug("Fetched exchange rates (flat): %s", rates)
        return rates
    except Exception as e:
        logger.error("Failed to fetch exchange rates: %s", str(e))
        # Return empty rates in expected flat format
        return {f"BTC/{code}": {"rate": 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]} | {f"XMR/{code}": {"rate": 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]}
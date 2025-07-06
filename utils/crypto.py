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
    # Comment out Tor proxy for development - uncomment for production
    # proxies = {
    #     "http": "socks5h://127.0.0.1:9050",
    #     "https": "socks5h://127.0.0.1:9050"
    # }
    try:
        response = requests.get(url, params=params, timeout=15)  # Removed proxies
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
    except requests.exceptions.ConnectTimeout:
        logger.error("Connection timeout to CoinGecko API - check network/proxy settings")
        # Return fallback rates
        return {f"BTC/{code}": {"rate": 45000 if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]} | {f"XMR/{code}": {"rate": 150 if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]}
    except requests.exceptions.RequestException as e:
        logger.error("Network error fetching exchange rates: %s", str(e))
        # Return fallback rates
        return {f"BTC/{code}": {"rate": 45000 if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]} | {f"XMR/{code}": {"rate": 150 if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]}
    except Exception as e:
        logger.error("Unexpected error fetching exchange rates: %s", str(e))
        # Return fallback rates
        return {f"BTC/{code}": {"rate": 45000 if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]} | {f"XMR/{code}": {"rate": 150 if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]}

def get_btc_price():
    """Get current Bitcoin price in USD"""
    try:
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {"ids": "bitcoin", "vs_currencies": "usd"}
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("bitcoin", {}).get("usd", 45000)  # Default fallback price
    except Exception as e:
        logger.error("Failed to fetch BTC price: %s", str(e))
        return 45000  # Default fallback price

def get_xmr_price():
    """Get current Monero price in USD"""
    try:
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {"ids": "monero", "vs_currencies": "usd"}
        response = requests.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()
        return data.get("monero", {}).get("usd", 150)  # Default fallback price
    except Exception as e:
        logger.error("Failed to fetch XMR price: %s", str(e))
        return 150  # Default fallback price
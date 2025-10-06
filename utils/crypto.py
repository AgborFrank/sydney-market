import requests
import logging
import os
from config import Config

logger = logging.getLogger(__name__)

# Tor proxy configuration
TOR_ENABLED = os.getenv('TOR_ENABLED', 'false').lower() == 'true'
TOR_PROXY = {
    "http": f"socks5h://127.0.0.1:{Config.TOR_PROXY_PORT}",
    "https": f"socks5h://127.0.0.1:{Config.TOR_PROXY_PORT}"
}

def get_exchange_rates():
    """Fetch BTC and XMR exchange rates for USD, CAD, EUR, AUD, GBP, and return as flat dict."""
    
    # Check if offline mode is enabled
    if Config.OFFLINE_MODE:
        logger.info("Offline mode enabled, using fallback exchange rates")
        fallback_rates = {}
        for code in ["USD", "CAD", "EUR", "AUD", "GBP"]:
            fallback_rates[f"BTC/{code}"] = {"rate": Config.FALLBACK_BTC_PRICE if code == "USD" else 0}
            fallback_rates[f"XMR/{code}"] = {"rate": Config.FALLBACK_XMR_PRICE if code == "USD" else 0}
        return fallback_rates
    
    url = "https://api.coingecko.com/api/v3/simple/price"
    params = {
        "ids": "bitcoin,monero",
        "vs_currencies": "usd,cad,eur,aud,gbp"
    }
    
    # Use Tor proxy if enabled
    proxies = TOR_PROXY if TOR_ENABLED else None
    
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
    except requests.exceptions.ConnectTimeout:
        logger.error("Connection timeout to CoinGecko API - check network/proxy settings")
        # Return fallback rates
        return {f"BTC/{code}": {"rate": Config.FALLBACK_BTC_PRICE if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]} | {f"XMR/{code}": {"rate": Config.FALLBACK_XMR_PRICE if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]}
    except requests.exceptions.RequestException as e:
        logger.error("Network error fetching exchange rates: %s", str(e))
        # Return fallback rates
        return {f"BTC/{code}": {"rate": Config.FALLBACK_BTC_PRICE if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]} | {f"XMR/{code}": {"rate": Config.FALLBACK_XMR_PRICE if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]}
    except Exception as e:
        logger.error("Unexpected error fetching exchange rates: %s", str(e))
        # Return fallback rates
        return {f"BTC/{code}": {"rate": Config.FALLBACK_BTC_PRICE if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]} | {f"XMR/{code}": {"rate": Config.FALLBACK_XMR_PRICE if code == "USD" else 0} for code in ["USD", "CAD", "EUR", "AUD", "GBP"]}

def get_btc_price():
    """Get current Bitcoin price in USD"""
    
    # Check if offline mode is enabled
    if Config.OFFLINE_MODE:
        logger.info("Offline mode enabled, using fallback BTC price")
        return Config.FALLBACK_BTC_PRICE
    
    try:
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {"ids": "bitcoin", "vs_currencies": "usd"}
        proxies = TOR_PROXY if TOR_ENABLED else None
        response = requests.get(url, params=params, timeout=10, proxies=proxies)
        response.raise_for_status()
        data = response.json()
        return data.get("bitcoin", {}).get("usd", Config.FALLBACK_BTC_PRICE)  # Use config fallback
    except Exception as e:
        logger.error("Failed to fetch BTC price: %s", str(e))
        return Config.FALLBACK_BTC_PRICE  # Use config fallback

def get_xmr_price():
    """Get current Monero price in USD"""
    
    # Check if offline mode is enabled
    if Config.OFFLINE_MODE:
        logger.info("Offline mode enabled, using fallback XMR price")
        return Config.FALLBACK_XMR_PRICE
    
    try:
        url = "https://api.coingecko.com/api/v3/simple/price"
        params = {"ids": "monero", "vs_currencies": "usd"}
        proxies = TOR_PROXY if TOR_ENABLED else None
        response = requests.get(url, params=params, timeout=10, proxies=proxies)
        response.raise_for_status()
        data = response.json()
        return data.get("monero", {}).get("usd", Config.FALLBACK_XMR_PRICE)  # Use config fallback
    except Exception as e:
        logger.error("Failed to fetch XMR price: %s", str(e))
        return Config.FALLBACK_XMR_PRICE  # Use config fallback
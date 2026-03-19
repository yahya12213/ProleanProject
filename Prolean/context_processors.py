# context_processors.py
import ipaddress
import requests
from django.utils import timezone
from django.conf import settings
from django.core.cache import cache
from .models import CurrencyRate

def get_client_ip(request):
    """Get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR', '')
    candidates = [p.strip() for p in x_forwarded_for.split(',') if p.strip()]
    remote = str(request.META.get('REMOTE_ADDR', '') or '').strip()
    if remote:
        candidates.append(remote)
    for raw in candidates:
        try:
            ip_obj = ipaddress.ip_address(raw)
        except ValueError:
            continue
        # Keep first global/public address first, otherwise fallback later.
        if ip_obj.is_global:
            return str(ip_obj)
    return remote or '127.0.0.1'


def _normalize_city(city: str, district: str, region: str) -> str:
    city_clean = str(city or '').strip()
    district_clean = str(district or '').strip()
    region_clean = str(region or '').strip()
    if city_clean and district_clean and district_clean.lower() not in city_clean.lower():
        return f"{city_clean} ({district_clean})"
    if city_clean and region_clean and region_clean.lower() not in city_clean.lower():
        return f"{city_clean}, {region_clean}"
    if city_clean:
        return city_clean
    if district_clean:
        return district_clean
    if region_clean:
        return region_clean
    return "Casablanca"


def _provider_ipwho(ip_address: str):
    response = requests.get(f'https://ipwho.is/{ip_address}', timeout=3)
    if response.status_code != 200:
        return None
    data = response.json()
    if not data.get('success'):
        return None
    city = str(data.get('city') or '').strip()
    region = str(data.get('region') or '').strip()
    country = str(data.get('country') or 'Maroc').strip()
    country_code = str(data.get('country_code') or 'MA').strip()
    district = str(data.get('district') or '').strip()
    return {
        'city': _normalize_city(city, district, region),
        'exact_city': city or _normalize_city(city, district, region),
        'region': region,
        'country': country,
        'countryCode': country_code,
        'latitude': data.get('latitude'),
        'longitude': data.get('longitude'),
        'timezone': str(data.get('timezone', {}).get('id') or ''),
        'source': 'ipwho.is',
    }


def _provider_ipapi(ip_address: str):
    response = requests.get(f'https://ipapi.co/{ip_address}/json/', timeout=3)
    if response.status_code != 200:
        return None
    data = response.json()
    if data.get('error'):
        return None
    city = str(data.get('city') or '').strip()
    region = str(data.get('region') or '').strip()
    country = str(data.get('country_name') or 'Maroc').strip()
    country_code = str(data.get('country_code') or 'MA').strip()
    return {
        'city': _normalize_city(city, '', region),
        'exact_city': city or _normalize_city(city, '', region),
        'region': region,
        'country': country,
        'countryCode': country_code,
        'latitude': data.get('latitude'),
        'longitude': data.get('longitude'),
        'timezone': str(data.get('timezone') or ''),
        'source': 'ipapi.co',
    }


def _provider_ip_api(ip_address: str):
    response = requests.get(
        f'http://ip-api.com/json/{ip_address}?fields=status,country,countryCode,regionName,city,district,lat,lon,timezone',
        timeout=3,
    )
    if response.status_code != 200:
        return None
    data = response.json()
    if data.get('status') != 'success':
        return None
    city = str(data.get('city') or '').strip()
    region = str(data.get('regionName') or '').strip()
    district = str(data.get('district') or '').strip()
    return {
        'city': _normalize_city(city, district, region),
        'exact_city': city or _normalize_city(city, district, region),
        'region': region,
        'country': str(data.get('country') or 'Maroc').strip(),
        'countryCode': str(data.get('countryCode') or 'MA').strip(),
        'latitude': data.get('lat'),
        'longitude': data.get('lon'),
        'timezone': str(data.get('timezone') or ''),
        'source': 'ip-api.com',
    }

def get_location_from_ip(ip_address):
    """Get location from IP with multi-provider fallback and caching."""
    # Default fallback
    default_location = {
        'city': 'Casablanca',
        'exact_city': 'Casablanca',
        'region': 'Casablanca-Settat',
        'country': 'Maroc',
        'countryCode': 'MA',
        'latitude': None,
        'longitude': None,
        'timezone': 'Africa/Casablanca',
        'source': 'fallback',
    }
    
    # Localhost check
    if ip_address in ['127.0.0.1', 'localhost', '::1']:
        return default_location

    cache_key = f'geoip:{ip_address}'
    cached = cache.get(cache_key)
    if isinstance(cached, dict):
        return cached

    providers = (_provider_ipwho, _provider_ipapi, _provider_ip_api)
    for provider in providers:
        try:
            resolved = provider(ip_address)
            if resolved:
                cache.set(cache_key, resolved, timeout=int(getattr(settings, 'PROLEAN_GEOIP_CACHE_SECONDS', 21600)))
                return resolved
        except Exception:
            continue

    cache.set(cache_key, default_location, timeout=300)
    return default_location


def get_location_from_request(request):
    """Prefer browser GPS+OSM location stored in session, fallback to IP-based lookup."""
    try:
        session_location = request.session.get('browser_geo_location')
        if isinstance(session_location, dict):
            city = str(session_location.get('city') or '').strip()
            country = str(session_location.get('country') or '').strip()
            if city and country:
                return session_location
    except Exception:
        pass
    ip_address = get_client_ip(request)
    return get_location_from_ip(ip_address)

def currency_rates(request):
    """Add currency rates to context"""
    rates = {}
    try:
        db_rates = CurrencyRate.objects.all()
        for rate in db_rates:
            rates[rate.currency_code] = float(rate.rate_to_mad)
    except:
        rates = {
            'MAD': 1.0,
            'EUR': 0.093,
            'USD': 0.100,
            'GBP': 0.079,
            'CAD': 0.136,
            'AED': 0.367
        }
    
    preferred_currency = request.session.get('preferred_currency', 'MAD')
    
    return {
        'currency_rates': rates,
        'preferred_currency': preferred_currency,
    }

def user_location(request):
    """Add user location to context"""
    location = get_location_from_request(request)
    
    return {
        'user_location': location,
    }

def site_settings(request):
    """Add site settings to context"""
    return {
        'SITE_NAME': 'Prolean Centre',
        'SITE_URL': getattr(settings, 'SITE_URL', 'http://127.0.0.1:8000'),
        'CONTACT_PHONE': '+212 779 25 99 42',
        'CONTACT_EMAIL': 'contact@prolean.com',
        'CURRENT_YEAR': timezone.now().year,
    }

# Alias for backward compatibility
site_context = site_settings

def notifications(request):
    """Add user notifications to context"""
    if request.user.is_authenticated:
        unread_notifications = request.user.notifications.filter(is_read=False).order_by('-created_at')[:5]
        unread_count = request.user.notifications.filter(is_read=False).count()
        return {
            'global_notifications': unread_notifications,
            'unread_notifications_count': unread_count,
        }
    return {
        'global_notifications': [],
        'unread_notifications_count': 0,
    }

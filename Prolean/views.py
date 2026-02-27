# views.py - UPDATED with rate limiting, threat detection, and optimized queries
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.db.models import Q, Count, F, Prefetch
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
from django.db.utils import OperationalError, ProgrammingError
import json
import re
import requests
import time
import secrets
import hmac
import hashlib
from datetime import datetime, timedelta
from time import sleep
import logging
from django.conf import settings
from django.db.models import Avg, Count, Sum  # Add this line
from .models import (
    Training, City, ContactRequest, CurrencyRate,
    PageView, ClickEvent, PhoneCall, WhatsAppClick,
    FormSubmission, VisitorSession, DailyStat,
    TrainingWaitlist, TrainingReview, ThreatIP, RateLimitLog,
    Profile, StudentProfile, ProfessorProfile, AssistantProfile, Session,
    RecordedVideo, LiveRecording, AttendanceLog, VideoProgress, Question,
    TrainingPreSubscription, Notification, Live, Seance,
    ExternalLiveStudentStat, ExternalLiveSessionBan, ExternalLiveSecurityEvent,
    ExternalLiveJoinInvite, ExternalLiveJoinAttempt
)
from .forms import ContactRequestForm, TrainingReviewForm, WaitlistForm, TrainingInquiryForm, MigrationInquiryForm, StudentRegistrationForm, ExternalAuthorityLoginForm
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import translation
from django.utils.http import url_has_allowed_host_and_scheme
from .context_processors import get_client_ip, get_location_from_ip
from .presence import touch_user_presence, get_online_students
import uuid

from Prolean import models
from functools import wraps

def assistant_required(view_func):
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if request.user.is_authenticated and hasattr(request.user, 'profile') and request.user.profile.role in ['ASSISTANT', 'ADMIN']:
            return view_func(request, *args, **kwargs)
        messages.error(request, "Accès réservé aux assistants.")
        return redirect('Prolean:home')
    return _wrapped_view

def student_active_required(view_func):
    """Decorator to enforce ACTIVE status for students"""
    @wraps(view_func)
    def _wrapped_view(request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect('login') 
            
        if not hasattr(request.user, 'profile'):
            messages.error(request, "Profil introuvable.")
            return redirect('Prolean:home')
            
        profile = request.user.profile
        
        # If not a student (e.g. Professor/Admin), allow access (or let other decorators handle it)
        if profile.role != 'STUDENT':
            return view_func(request, *args, **kwargs)
            
        # Check Account Status
        if profile.status == 'SUSPENDED':
            return redirect('Prolean:account_status')
            
        return view_func(request, *args, **kwargs)
    return _wrapped_view

def professor_required(view_func):
    @wraps(view_func)
    @login_required
    def _wrapped_view(request, *args, **kwargs):
        if hasattr(request.user, 'profile') and request.user.profile.role == 'PROFESSOR':
            return view_func(request, *args, **kwargs)
        messages.error(request, "Accès réservé aux professeurs.")
        return redirect('Prolean:home')
    return _wrapped_view

logger = logging.getLogger(__name__)


def _is_user_banned_from_external_session(session_id: str, user: User) -> tuple[bool, str]:
    try:
        row = ExternalLiveSessionBan.objects.filter(session_id=str(session_id), user=user, active=True).first()
    except Exception:
        row = None
    if not row:
        return False, ""
    return True, str(row.reason or "")

# External authority (Barka) integration
from Prolean.integration.client import ManagementContractClient
from Prolean.integration.exceptions import ContractError, UpstreamUnavailable
from Prolean.integration.trainings import to_external_training
from agora_token_builder import RtcTokenBuilder


def _is_barka_token_expired(exc: Exception) -> bool:
    msg = str(exc or "").lower()
    return ("token expired" in msg) or ("token_expired" in msg) or ("code\":\"token_expired" in msg)


def _norm_identifier(value) -> str:
    return str(value or "").strip().lower()


def _extract_external_student_identifiers(student_row: dict) -> set[str]:
    if not isinstance(student_row, dict):
        return set()
    identifiers = set()
    for key in (
        "student_email", "email", "username",
        "student_phone", "phone",
        "student_name", "full_name", "name",
        "cin", "cin_or_passport",
    ):
        normalized = _norm_identifier(student_row.get(key))
        if normalized:
            identifiers.add(normalized)
    return identifiers


def _norm_cin(value: str) -> str:
    cin = str(value or "").strip().upper()
    cin = "".join(ch for ch in cin if ch.isalnum())
    if not cin:
        return ""
    if cin in {"NA", "NAN", "N_A"}:
        return ""
    return cin


def _external_live_one_click_ttl_seconds() -> int:
    ttl_seconds = int(getattr(settings, "EXTERNAL_LIVE_ONE_CLICK_TTL_SECONDS", 8 * 60 * 60) or (8 * 60 * 60))
    return max(60, min(ttl_seconds, 72 * 60 * 60))


def _hash_external_live_join_token(raw: str) -> str:
    raw = str(raw or "").strip()
    key = str(getattr(settings, "SECRET_KEY", "") or "").encode("utf-8")
    return hmac.new(key, raw.encode("utf-8"), hashlib.sha256).hexdigest()


def _device_label_from_request(request) -> tuple[str, str, str, str]:
    ua = str(request.META.get("HTTP_USER_AGENT", "") or "")[:800]
    platform = str(request.headers.get("Sec-CH-UA-Platform", "") or "").strip().strip('"')[:60]
    mobile = str(request.headers.get("Sec-CH-UA-Mobile", "") or "").strip()[:20]
    label = ""
    if platform:
        label = platform
    if mobile:
        label = (f"{label} Mobile" if mobile == "?1" else f"{label} Desktop").strip()
    return label[:120], ua, platform, mobile


def _parse_device_from_ua(user_agent: str) -> tuple[str, str, str]:
    ua = str(user_agent or "").lower()
    device_type = "desktop"
    if "mobile" in ua or "android" in ua or "iphone" in ua:
        device_type = "mobile"
    if "ipad" in ua or "tablet" in ua:
        device_type = "tablet"

    os_name = ""
    if "windows" in ua:
        os_name = "Windows"
    elif "android" in ua:
        os_name = "Android"
    elif "iphone" in ua or "ipad" in ua or "ios" in ua:
        os_name = "iOS"
    elif "mac os" in ua or "macintosh" in ua:
        os_name = "macOS"
    elif "linux" in ua:
        os_name = "Linux"

    browser = ""
    if "edg/" in ua or "edge" in ua:
        browser = "Edge"
    elif "chrome/" in ua and "chromium" not in ua and "edg/" not in ua:
        browser = "Chrome"
    elif "firefox/" in ua:
        browser = "Firefox"
    elif "safari/" in ua and "chrome/" not in ua and "chromium" not in ua:
        browser = "Safari"

    return browser[:60], os_name[:60], device_type[:20]


def _is_probably_link_preview(request) -> bool:
    try:
        method = str(getattr(request, "method", "") or "").upper()
        if method not in {"GET", "HEAD"}:
            return False
        ua = str(request.META.get("HTTP_USER_AGENT", "") or "").lower()
        accept = str(request.META.get("HTTP_ACCEPT", "") or "").lower()
        purpose = str(request.META.get("HTTP_PURPOSE", "") or "").lower()
        sec_purpose = str(request.META.get("HTTP_SEC_PURPOSE", "") or "").lower()
        if "prefetch" in purpose or "prefetch" in sec_purpose:
            return True
        bot_tokens = (
            "whatsapp",
            "facebookexternalhit",
            "facebot",
            "twitterbot",
            "slackbot",
            "discordbot",
            "telegrambot",
            "skypeuripreview",
            "linkedinbot",
            "pinterest",
            "embedly",
            "crawler",
            "spider",
            "bot/",
        )
        if any(tok in ua for tok in bot_tokens):
            return True
        if accept and ("text/html" not in accept and "application/xhtml+xml" not in accept):
            return True
    except Exception:
        return False
    return False


def _external_live_service_access_key() -> str:
    return "prolean:external_live_service_access"


def _external_live_join_fallback_key(token_hash: str) -> str:
    return f"prolean:external_live_join_fallback:{token_hash}"


def _grant_external_live_service_access(request, session_id: str, *, cin: str, expires_at) -> None:
    try:
        store = request.session.get(_external_live_service_access_key()) or {}
        if not isinstance(store, dict):
            store = {}
        store[str(session_id)] = {
            "cin": _norm_cin(cin),
            "expires_at": expires_at.isoformat() if hasattr(expires_at, "isoformat") else str(expires_at),
        }
        request.session[_external_live_service_access_key()] = store
    except Exception:
        return


def _get_external_live_service_access(request, session_id: str) -> tuple[str, str]:
    try:
        store = request.session.get(_external_live_service_access_key()) or {}
        if not isinstance(store, dict):
            return "", ""
        entry = store.get(str(session_id))
        if not isinstance(entry, dict):
            return "", ""
        cin = _norm_cin(entry.get("cin") or "")
        exp_raw = str(entry.get("expires_at") or "").strip()
        if not cin or not exp_raw:
            return "", ""
        exp = None
        try:
            exp = timezone.datetime.fromisoformat(exp_raw)
            if timezone.is_naive(exp):
                exp = timezone.make_aware(exp, timezone.get_current_timezone())
        except Exception:
            exp = None
        if exp and exp <= timezone.now():
            return "", ""
        return cin, exp_raw
    except Exception:
        return "", ""


def _build_online_student_lookup() -> dict[str, dict]:
    online_by_user_id = get_online_students()
    if not online_by_user_id:
        return {}
    try:
        users = User.objects.filter(id__in=list(online_by_user_id.keys())).select_related("profile", "profile__student_profile")
    except Exception:
        return {}
    lookup: dict[str, dict] = {}
    for user in users:
        profile = getattr(user, "profile", None)
        if not profile or str(getattr(profile, "role", "")).upper() != "STUDENT":
            continue
        payload = online_by_user_id.get(user.id, {})
        values = [
            user.username,
            user.email,
            getattr(profile, "full_name", ""),
            getattr(profile, "phone_number", ""),
            getattr(profile, "cin_or_passport", ""),
        ]
        for value in values:
            normalized = _norm_identifier(value)
            if normalized:
                lookup[normalized] = payload
    return lookup


def _enrich_external_students_with_presence(external_students: list[dict]) -> tuple[list[dict], int]:
    online_lookup = _build_online_student_lookup()
    online_count = 0
    enriched: list[dict] = []
    for row in external_students if isinstance(external_students, list) else []:
        entry = dict(row) if isinstance(row, dict) else {"student_name": str(row)}

        # Precompute safe display fields so templates don't crash on missing dict keys.
        first_name = str(entry.get("student_first_name") or entry.get("first_name") or "").strip()
        last_name = str(entry.get("student_last_name") or entry.get("last_name") or "").strip()
        combined_name = " ".join([part for part in (first_name, last_name) if part]).strip()
        entry["display_name"] = (
            str(entry.get("student_name") or "").strip()
            or str(entry.get("full_name") or "").strip()
            or str(entry.get("name") or "").strip()
            or combined_name
            or "Student"
        )
        entry["display_email"] = str(entry.get("student_email") or entry.get("email") or "").strip()
        entry["display_phone"] = str(entry.get("student_phone") or entry.get("phone") or "").strip()
        entry["display_cin"] = _norm_cin(entry.get("student_cin") or entry.get("cin") or entry.get("cin_or_passport") or "")

        identifiers = _extract_external_student_identifiers(entry)
        online_payload = None
        for ident in identifiers:
            if ident in online_lookup:
                online_payload = online_lookup[ident]
                break
        is_online = isinstance(online_payload, dict)
        entry["is_online_web"] = is_online
        entry["online_age_seconds"] = int(online_payload.get("age_seconds", 0)) if is_online else None
        if is_online:
            online_count += 1
        enriched.append(entry)
    return enriched, online_count

# ========== RATE LIMITING & THREAT DETECTION ==========

class RateLimiter:
    """Simple rate limiter with threat detection"""
    
    @staticmethod
    def check_rate_limit(ip_address, endpoint, limit=5, period_minutes=1):
        """
        Check if IP has exceeded rate limit
        Returns: (is_allowed, remaining_seconds)
        """
        one_minute_ago = timezone.now() - timedelta(minutes=period_minutes)
        
        # Count requests in the last minute
        request_count = RateLimitLog.objects.filter(
            ip_address=ip_address,
            endpoint=endpoint,
            last_request__gte=one_minute_ago
        ).count()
        
        # Log the request
        RateLimitLog.objects.create(
            ip_address=ip_address,
            endpoint=endpoint,
            period_minutes=period_minutes
        )
        
        # Check if limit exceeded
        if request_count >= limit:
            # Mark as potential threat
            threat_ip, created = ThreatIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': f'Rate limit exceeded on {endpoint}: {request_count+1} requests in {period_minutes} minute(s)',
                    'threat_level': 'high',
                }
            )
            
            if not created:
                threat_ip.increment_request_count()
                threat_ip.reason = f'Rate limit exceeded on {endpoint}: {threat_ip.request_count} total violations'
                threat_ip.save()
            
            return False, 60  # Wait 60 seconds
        
        return True, 0
    
    @staticmethod
    def is_ip_blocked(ip_address):
        """Check if IP is blocked"""
        return ThreatIP.objects.filter(
            ip_address=ip_address,
            is_blocked=True
        ).exists()







# Additional functionality
import uuid


@csrf_exempt
@require_POST
def mark_review_helpful(request):
    """Mark review as helpful or not helpful"""
    try:
        data = json.loads(request.body)
        review_id = data.get('review_id')
        is_helpful = data.get('is_helpful', True)
        
        review = TrainingReview.objects.get(id=review_id)
        
        if is_helpful:
            review.helpful_count += 1
        else:
            review.not_helpful_count += 1
        
        review.save()
        
        return JsonResponse({
            'success': True,
            'helpful_count': review.helpful_count,
            'not_helpful_count': review.not_helpful_count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })

# Helper function to get client IP
def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip












@csrf_exempt
@require_POST
def subscribe_promotion(request):
    """Subscribe to promotion"""
    try:
        data = json.loads(request.body)
        
        # Create a demo subscription for promotion
        transaction_id = str(uuid.uuid4())
        
        return JsonResponse({
            'success': True,
            'message': 'Inscription à la promotion réussie',
            'subscription': {
                'transaction_id': transaction_id,
                'full_name': data.get('full_name', 'Client'),
                'paid_price': '3500',
                'currency_used': 'MAD',
                'receipt_url': f'/media/receipts/{transaction_id}.pdf'
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Erreur: {str(e)}'
        })



# Helper function to get average rating
def get_training_avg_rating(training_id):
    """Calculate average rating for a training"""
    from django.db.models import Avg
    result = TrainingReview.objects.filter(
        training_id=training_id,
        is_approved=True
    ).aggregate(Avg('rating'))
    
    return result['rating__avg'] or 0


# views.py - UPDATED with avatar support for reviews
from django.shortcuts import render, get_object_or_404, redirect
from django.http import JsonResponse, HttpResponse
from django.contrib import messages
from django.db.models import Q, Count, F, Prefetch
from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone
from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import transaction
import json
import requests
from datetime import datetime, timedelta
import logging
from django.db.models import Avg, Count, Sum
from .models import (
    Training, City, ContactRequest, CurrencyRate,
    PageView, ClickEvent, PhoneCall, WhatsAppClick,
    FormSubmission, VisitorSession, DailyStat,
    TrainingWaitlist, TrainingReview, ThreatIP, RateLimitLog,
    CompanyBankAccount, TrainingPreSubscription
)
from .forms import ContactRequestForm, TrainingReviewForm, WaitlistForm, TrainingInquiryForm, MigrationInquiryForm
from .context_processors import get_client_ip, get_location_from_ip
import uuid

logger = logging.getLogger(__name__)

# ========== RATE LIMITING & THREAT DETECTION ==========

class RateLimiter:
    """Simple rate limiter with threat detection"""
    
    @staticmethod
    def check_rate_limit(ip_address, endpoint, limit=5, period_minutes=1):
        """
        Check if IP has exceeded rate limit
        Returns: (is_allowed, remaining_seconds)
        """
        one_minute_ago = timezone.now() - timedelta(minutes=period_minutes)
        
        # Count requests in the last minute
        request_count = RateLimitLog.objects.filter(
            ip_address=ip_address,
            endpoint=endpoint,
            last_request__gte=one_minute_ago
        ).count()
        
        # Log the request
        RateLimitLog.objects.create(
            ip_address=ip_address,
            endpoint=endpoint,
            period_minutes=period_minutes
        )
        
        # Check if limit exceeded
        if request_count >= limit:
            # Mark as potential threat
            threat_ip, created = ThreatIP.objects.get_or_create(
                ip_address=ip_address,
                defaults={
                    'reason': f'Rate limit exceeded on {endpoint}: {request_count+1} requests in {period_minutes} minute(s)',
                    'threat_level': 'high',
                }
            )
            
            if not created:
                threat_ip.increment_request_count()
                threat_ip.reason = f'Rate limit exceeded on {endpoint}: {threat_ip.request_count} total violations'
                threat_ip.save()
            
            return False, 60  # Wait 60 seconds
        
        return True, 0
    
    @staticmethod
    def is_ip_blocked(ip_address):
        """Check if IP is blocked"""
        return ThreatIP.objects.filter(
            ip_address=ip_address,
            is_blocked=True
        ).exists()

# ========== CACHING FUNCTIONS ==========

def get_cached_featured_trainings():
    """Get featured trainings from cache or database"""
    cache_key = 'featured_trainings'
    featured_trainings = cache.get(cache_key)
    
    if featured_trainings is None:
        featured_trainings = Training.objects.filter(
            is_active=True,
            is_featured=True
        ).select_related(None).only(
            'id', 'title', 'slug', 'short_description', 'price_mad',
            'duration_days', 'success_rate', 'max_students', 'badge',
            'thumbnail', 'category_caces', 'category_electricite',
            'category_soudage', 'category_securite', 'category_management'
        ).order_by('-created_at')[:4]
        
        # Convert to list to cache properly
        featured_trainings = list(featured_trainings)
        cache.set(cache_key, featured_trainings, 1800)  # 30 minutes
    
    return featured_trainings

def get_cached_currency_rates():
    """Get currency rates from cache or database"""
    cache_key = 'currency_rates'
    rates = cache.get(cache_key)
    
    if rates is None:
        rates = {}
        db_rates = CurrencyRate.objects.all()
        for rate in db_rates:
            rates[rate.currency_code] = float(rate.rate_to_mad)
        
        if not rates:
            rates = {
                'MAD': 1.0,
                'EUR': 0.093,
                'USD': 0.100,
                'GBP': 0.079,
                'CAD': 0.136,
                'AED': 0.367,
            }
        
        cache.set(cache_key, rates, 3600)  # 1 hour
    
    return rates

def get_cached_categories(trainings):
    """Get categories from cache or calculate"""
    cache_key = f'categories_{hash(str([t.id for t in trainings]))}'
    categories = cache.get(cache_key)
    
    if categories is None:
        categories = []
        category_data = {
            'caces': {'id': 'caces', 'name': 'CACES Engins', 'icon': 'construction', 'active_count': 0},
            'electricite': {'id': 'electricite', 'name': 'Électricité', 'icon': 'bolt', 'active_count': 0},
            'soudage': {'id': 'soudage', 'name': 'Soudage', 'icon': 'whatshot', 'active_count': 0},
            'securite': {'id': 'securite', 'name': 'Sécurité', 'icon': 'security', 'active_count': 0},
            'management': {'id': 'management', 'name': 'Management', 'icon': 'groups', 'active_count': 0},
            'autre': {'id': 'autre', 'name': 'Autre', 'icon': 'category', 'active_count': 0},
        }
        
        for training in trainings:
            if training.category_caces: category_data['caces']['active_count'] += 1
            if training.category_electricite: category_data['electricite']['active_count'] += 1
            if training.category_soudage: category_data['soudage']['active_count'] += 1
            if training.category_securite: category_data['securite']['active_count'] += 1
            if training.category_management: category_data['management']['active_count'] += 1
            if training.category_autre: category_data['autre']['active_count'] += 1
        
        for cat_id, cat_data in category_data.items():
            if cat_data['active_count'] > 0:
                categories.append(cat_data)
        
        cache.set(cache_key, categories, 900)  # 15 minutes
    
    return categories

# ========== ANALYTICS TRACKING ==========

def track_page_view(request, page_title=''):
    """Track page view for analytics"""
    try:
        session_id = request.session.session_key
        if not session_id:
            request.session.create()
            session_id = request.session.session_key
        
        ip_address = get_client_ip(request)
        user_location = get_location_from_ip(ip_address)
        
        # Check if IP is blocked
        if RateLimiter.is_ip_blocked(ip_address):
            logger.warning(f"Blocked IP tried to access page: {ip_address}")
            return
        
        # Track visitor session
        visitor_session, created = VisitorSession.objects.get_or_create(
            session_id=session_id,
            defaults={
                'ip_address': ip_address,
                'user_agent': request.META.get('HTTP_USER_AGENT', ''),
                'city': user_location.get('city', ''),
                'country': user_location.get('country', ''),
                'device_type': 'desktop',
                'landing_page': request.path,
                'referrer': request.META.get('HTTP_REFERER', '')
            }
        )
        
        if not created:
            visitor_session.page_views += 1
            visitor_session.last_activity = timezone.now()
            visitor_session.save()
        
        # Track page view
        PageView.objects.create(
            url=request.path,
            page_title=page_title,
            referrer=request.META.get('HTTP_REFERER', ''),
            session_id=session_id,
            ip_address=ip_address,
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            city=user_location.get('city', ''),
            country=user_location.get('country', ''),
            device_type='desktop'
        )
        
    except Exception as e:
        logger.error(f"Error tracking page view: {e}")

def home(request):
    """Home page view with optimized queries"""
    track_page_view(request, "Accueil - Prolean Centre")
    featured_trainings = []

    # 1) Prefer external authority (Barka) if configured.
    mgmt = ManagementContractClient()
    if mgmt.is_configured():
        try:
            cache_key = "external:featured_formations:v1"
            cached = cache.get(cache_key)
            if cached is None:
                formations = mgmt.list_formations()
                trainings = [to_external_training(f) for f in formations if isinstance(f, dict)]
                featured_trainings = trainings[:4]
                cache.set(cache_key, featured_trainings, 300)  # 5 min
            else:
                featured_trainings = cached
        except (UpstreamUnavailable, ContractError) as exc:
            logger.warning("External formations unavailable, falling back to local DB: %s", exc)

    # 2) Fallback to local DB (legacy mode).
    if not featured_trainings:
        try:
            featured_trainings = cache.get('featured_trainings')

            if featured_trainings is None:
                featured_trainings = Training.objects.filter(
                    is_active=True,
                    is_featured=True
                ).only(
                    'id', 'title', 'slug', 'short_description', 'price_mad',
                    'duration_days', 'success_rate', 'max_students', 'badge',
                    'thumbnail'
                ).order_by('-created_at')[:4]

                if not featured_trainings:
                    featured_trainings = Training.objects.filter(
                        is_active=True
                    ).only(
                        'id', 'title', 'slug', 'short_description', 'price_mad',
                        'duration_days', 'success_rate', 'max_students', 'badge',
                        'thumbnail'
                    ).order_by('-created_at')[:4]

                cache.set('featured_trainings', featured_trainings, 1800)  # 30 minutes
        except (OperationalError, ProgrammingError):
            logger.exception("Home page fallback: database tables not ready yet.")
            featured_trainings = []
    
    # Get user location
    ip_address = get_client_ip(request)
    user_location = get_location_from_ip(ip_address)
    
    # Get currency rates from cache
    currency_rates = cache.get('currency_rates')
    if currency_rates is None:
        currency_rates = {}
        try:
            db_rates = CurrencyRate.objects.all()
            for rate in db_rates:
                currency_rates[rate.currency_code] = float(rate.rate_to_mad)
        except:
            currency_rates = {'MAD': 1.0, 'EUR': 0.093, 'USD': 0.100, 'GBP': 0.079}
        cache.set('currency_rates', currency_rates, 3600)
    
    # Get preferred currency
    preferred_currency = request.session.get('preferred_currency', 'MAD')
    
    # Prepare training data
    for training in featured_trainings:
        try:
            training.price_mad_float = float(getattr(training, "price_mad", 0))
        except Exception:
            # Some external projection objects may be slots-based; keep existing default.
            pass

        if hasattr(training, "get_price_in_currency"):
            try:
                training.price_in_preferred = float(training.get_price_in_currency(preferred_currency))
            except Exception:
                pass
        else:
            try:
                training.price_in_preferred = float(getattr(training, "price_mad_float", getattr(training, "price_mad", 0)))
            except Exception:
                pass
    
    context = {
        'featured_trainings': featured_trainings,
        'user_location': user_location,
        'currency_rates': currency_rates,
        'preferred_currency': preferred_currency,
    }
    
    return render(request, "Prolean/home.html", context)

def training_catalog(request):
    """Training catalog view with optimized queries"""
    track_page_view(request, "Catalogue des formations")
    
    # Check rate limit
    ip_address = get_client_ip(request)
    allowed, wait_time = RateLimiter.check_rate_limit(ip_address, 'training_catalog')
    
    if not allowed:
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'wait_time': wait_time
        }, status=429)
    
    mgmt = ManagementContractClient()
    trainings = None
    external_mode = False

    if mgmt.is_configured():
        try:
            cache_key = "external:formations:all:v1"
            cached = cache.get(cache_key)
            if cached is None:
                formations = mgmt.list_formations()
                cached = [to_external_training(f) for f in formations if isinstance(f, dict)]
                cache.set(cache_key, cached, 300)  # 5 min
            trainings = list(cached)
            external_mode = True
        except (UpstreamUnavailable, ContractError) as exc:
            logger.warning("External formations unavailable, using local DB: %s", exc)
            trainings = None

    if trainings is None:
        trainings = Training.objects.filter(is_active=True).only(
            'id', 'title', 'slug', 'short_description', 'price_mad',
            'duration_days', 'success_rate', 'max_students', 'badge',
            'thumbnail', 'next_session', 'is_featured',
            'category_caces', 'category_electricite', 'category_soudage',
            'category_securite', 'category_management', 'category_autre'
        ).order_by('-created_at')
    
    # Get search query
    search_query = request.GET.get('q', '')
    if search_query:
        if external_mode:
            q = search_query.lower()
            trainings = [t for t in trainings if q in (t.title or "").lower() or q in (t.short_description or "").lower()]
        else:
            trainings = trainings.filter(
                Q(title__icontains=search_query) |
                Q(short_description__icontains=search_query)
            )
    
    # Get category filter
    category_filter = request.GET.get('category', 'all')
    if category_filter != 'all' and not external_mode:
        category_map = {
            'caces': 'category_caces',
            'electricite': 'category_electricite',
            'soudage': 'category_soudage',
            'securite': 'category_securite',
            'management': 'category_management',
            'autre': 'category_autre',
        }
        if category_filter in category_map:
            filter_kwargs = {category_map[category_filter]: True}
            trainings = trainings.filter(**filter_kwargs)
    
    # Get categories from cache
    categories = [] if external_mode else get_cached_categories(trainings)
    total_count = len(trainings) if external_mode else trainings.count()
    
    # Get preferred currency
    preferred_currency = request.session.get('preferred_currency', 'MAD')
    
    # Prepare training data
    trainings_list = list(trainings)
    for training in trainings_list:
        try:
            training.price_mad_float = float(getattr(training, "price_mad", 0))
        except Exception:
            pass
        if hasattr(training, "get_price_in_currency"):
            try:
                training.price_in_preferred = float(training.get_price_in_currency(preferred_currency))
            except Exception:
                pass
        else:
            try:
                training.price_in_preferred = float(getattr(training, "price_mad_float", getattr(training, "price_mad", 0)))
            except Exception:
                pass
    
    # Pagination
    page = request.GET.get('page', 1)
    paginator = Paginator(trainings_list, 12)
    
    try:
        trainings_page = paginator.page(page)
    except PageNotAnInteger:
        trainings_page = paginator.page(1)
    except EmptyPage:
        trainings_page = paginator.page(paginator.num_pages)
    
    context = {
        'trainings': trainings_page,
        'categories': categories,
        'selected_category': category_filter,
        'search_query': search_query,
        'total_count': total_count,
        'preferred_currency': preferred_currency,
    }
    
    return render(request, "Prolean/training_catalog.html", context)



# Update the training_detail function in views.py
def training_detail(request, slug):
    """Training detail view with reviews and optimized queries"""
    training = get_object_or_404(
        Training.objects.select_related(None),
        slug=slug,
        is_active=True
    )
    
    # Increment view count
    training.increment_view_count()
    track_page_view(request, f"{training.title} - Prolean Centre")
    
    # Get active bank account
    active_bank_account = CompanyBankAccount.get_active_account()
    
    # Check rate limit
    ip_address = get_client_ip(request)
    allowed, wait_time = RateLimiter.check_rate_limit(ip_address, f'training_detail_{slug}')
    
    if not allowed:
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'wait_time': wait_time
        }, status=429)
    
    # Get preferred currency
    preferred_currency = request.session.get('preferred_currency', 'MAD')
    
    # Prepare training data
    training.price_mad_float = float(training.price_mad)
    training.price_in_preferred = float(training.get_price_in_currency(preferred_currency))
    
    # Get available cities (only names, no phones)
    available_cities = []
    city_fields = [
        ('available_casablanca', 'Casablanca'),
        ('available_rabat', 'Rabat'),
        ('available_tanger', 'Tanger'),
        ('available_marrakech', 'Marrakech'),
        ('available_agadir', 'Agadir'),
        ('available_fes', 'Fès'),
        ('available_meknes', 'Meknès'),
        ('available_oujda', 'Oujda'),
        ('available_laayoune', 'Laâyoune'),
        ('available_dakhla', 'Dakhla'),
        ('available_other', 'Autre ville'),
    ]
    
    for field, name in city_fields:
        if getattr(training, field):
            available_cities.append({'name': name})
    
    # Get reviews
    reviews = TrainingReview.objects.filter(
        training=training,
        is_approved=True
    ).order_by('-created_at')
    
    # Add avatar path to each review (compatible with old and new reviews)
    for review in reviews:
        if not review.avatar or review.avatar == '':
            # Assign a default avatar based on review ID or name
            avatar_number = (review.id % 4) + 1 if review.id else (hash(review.full_name) % 4) + 1
            review.avatar = f'images/avatars/avatar{avatar_number}.png'
        # Ensure the avatar path is complete
        elif not review.avatar.startswith('images/avatars/'):
            # If it's just a filename, prepend the path
            if '.' in review.avatar:
                review.avatar = f'images/avatars/{review.avatar}'
            else:
                review.avatar = f'images/avatars/avatar1.png'
    
    avg_rating = get_training_avg_rating(training.id)
    
    # Get waitlist count
    waitlist_count = TrainingWaitlist.objects.filter(training=training).count()
    
    # Get gallery images, certificates, testimonials, FAQs, and features
    gallery_images = training.get_gallery_images()
    certificates = training.get_certificates()
    testimonials = training.get_testimonials()
    faqs = training.get_faqs()
    features = training.get_features()
    categories = training.get_categories()
    
    context = {
        'training': training,
        'available_cities': available_cities,
        'reviews': reviews,
        'review_count': reviews.count(),
        'waitlist_count': waitlist_count,
        'preferred_currency': preferred_currency,
        'gallery_images': gallery_images,
        'certificates': certificates,
        'testimonials': testimonials,
        'faqs': faqs,
        'features': features,
        'categories': categories,
        'avg_rating': avg_rating or 0,
        'preferred_currency': request.session.get('currency', 'MAD'),
        'bank_account': active_bank_account,
    }
    
    return render(request, "Prolean/training_detail.html", context)







def migration_services(request):
    """Migration services page"""
    track_page_view(request, "Services de migration")
    
    # Check rate limit
    ip_address = get_client_ip(request)
    allowed, wait_time = RateLimiter.check_rate_limit(ip_address, 'migration_services')
    
    if not allowed:
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'wait_time': wait_time
        }, status=429)
    
    cities = City.objects.filter(is_active=True).order_by('name')
    ip_address = get_client_ip(request)
    user_location = get_location_from_ip(ip_address)
    
    context = {
        'all_cities': cities,
        'user_location': user_location,
    }
    
    return render(request, "Prolean/migration_services.html", context)

def contact_centers(request):
    """Contact centers page"""
    track_page_view(request, "Centres de contact")
    
    # Check rate limit
    ip_address = get_client_ip(request)
    allowed, wait_time = RateLimiter.check_rate_limit(ip_address, 'contact_centers')
    
    if not allowed:
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'wait_time': wait_time
        }, status=429)
    
    cities = City.objects.filter(is_active=True).order_by('name')
    ip_address = get_client_ip(request)
    user_location = get_location_from_ip(ip_address)
    
    context = {
        'all_cities': cities,
        'user_location': user_location,
    }
    
    return render(request, "Prolean/contact_centers.html", context)

# ========== API VIEWS ==========


@require_POST
@csrf_exempt
def submit_contact_request(request):
    """Handle contact form submission with rate limiting"""
    try:
        # Check rate limit
        ip_address = get_client_ip(request)
        allowed, wait_time = RateLimiter.check_rate_limit(ip_address, 'submit_contact', limit=5)
        
        data = json.loads(request.body)
        
        # Get user location
        user_location = get_location_from_ip(ip_address)
        
        # Determine request type
        request_type = data.get('request_type', 'information')
        
        # Create contact request
        contact_data = {
            'full_name': data.get('full_name', '').strip(),
            'email': data.get('email', '').strip().lower(),
            'phone': data.get('phone', '').strip(),
            'city': data.get('city', user_location.get('city', '')),
            'country': data.get('country', user_location.get('country', 'Maroc')),
            'request_type': request_type,
            'message': data.get('message', '').strip(),
            'training_title': data.get('training_title', ''),
            'payment_method': data.get('payment_method', ''),
            'ip_address': ip_address,
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'session_id': request.session.session_key or '',
        }
        
        # Add payment details if present
        if data.get('payment_method'):
            contact_data['payment_status'] = 'pending' if data['payment_method'] == 'bank_transfer' else 'completed'
            contact_data['card_last_four'] = data.get('card_last_four', '')
            contact_data['card_expiry'] = data.get('card_expiry', '')
            contact_data['transfer_reference'] = data.get('transfer_reference', '')
        
        # Create contact request
        contact_request = ContactRequest.objects.create(**contact_data)
        
        # If training specified, increment inquiry count
        training_id = data.get('training_id')
        if training_id:
            try:
                training = Training.objects.get(id=training_id)
                training.increment_inquiry_count()
                contact_request.training = training
                contact_request.save()
            except Training.DoesNotExist:
                pass
        
        # Track form submission
        if request.session.session_key:
            FormSubmission.objects.create(
                form_type='contact',
                training_title=data.get('training_title', ''),
                session_id=request.session.session_key,
                ip_address=ip_address,
                city=user_location.get('city', ''),
                country=user_location.get('country', ''),
                time_spent=data.get('time_spent', 0)
            )
        
        return JsonResponse({
            'success': True,
            'message': 'Votre demande a été envoyée avec succès.',
            'request_id': contact_request.id
        })
        
    except Exception as e:
        logger.error(f"Error submitting contact request: {e}")
        return JsonResponse({
            'success': False,
            'message': f'Une erreur est survenue: {str(e)}'
        }, status=500)


@csrf_exempt
@require_POST
def create_pre_subscription(request):
    """Create a pre-subscription with bank transfer support"""
    try:
        data = json.loads(request.body)
        
        # Validate required fields
        required_fields = ['training_id', 'full_name', 'email', 'phone', 'city', 'payment_method']
        for field in required_fields:
            if not data.get(field):
                return JsonResponse({
                    'success': False,
                    'message': f'Le champ {field} est obligatoire'
                })
        
        # Get training
        try:
            training = Training.objects.get(id=data['training_id'])
        except Training.DoesNotExist:
            return JsonResponse({
                'success': False,
                'message': 'Formation non trouvée'
            })
        
        # Create subscription data
        subscription_data = {
            'training': training,
            'full_name': data['full_name'],
            'email': data['email'],
            'phone': data['phone'],
            'city': data['city'],
            'payment_method': data['payment_method'],
            'original_price_mad': data.get('original_price_mad', training.price_mad),
            'paid_price_mad': data.get('paid_price_mad', training.price_mad),
            'currency_used': data.get('currency_used', 'MAD'),
            'payment_status': 'pending' if data['payment_method'] == 'bank_transfer' else 'completed',
            'ip_address': get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'session_id': request.session.session_key or str(uuid.uuid4())
        }
        
        # Add card details if applicable
        if data['payment_method'] == 'card':
            subscription_data['card_last_four'] = data.get('card_last_four', '')[-4:] if data.get('card_last_four') else ''
            subscription_data['card_expiry'] = data.get('card_expiry', '')
        
        # Add bank transfer details if applicable
        if data['payment_method'] == 'bank_transfer':
            subscription_data['transfer_confirmation'] = data.get('transfer_confirmation', '')
            subscription_data['transfer_reference'] = f"TRF-{str(uuid.uuid4())[:8].upper()}"
        
        # Create subscription
        subscription = TrainingPreSubscription.objects.create(**subscription_data)
        
        # Generate PDF receipt
        receipt_url = subscription.generate_receipt_pdf()
        
        return JsonResponse({
            'success': True,
            'message': 'Inscription créée avec succès' if data['payment_method'] != 'bank_transfer' 
                      else 'Pré-inscription enregistrée. Veuillez effectuer le virement.',
            'subscription': {
                'id': subscription.id,
                'transaction_id': str(subscription.transaction_id),
                'full_name': subscription.full_name,
                'paid_price': str(subscription.paid_price_mad),
                'currency_used': subscription.currency_used,
                'receipt_url': receipt_url or '',
                'payment_method': subscription.payment_method,
                'payment_status': subscription.payment_status,
                'transfer_reference': subscription.transfer_reference if data['payment_method'] == 'bank_transfer' else None
            }
        })
        
    except Exception as e:
        logger.error(f"Error creating pre-subscription: {str(e)}")
        return JsonResponse({
            'success': False,
            'message': f'Erreur: {str(e)}'
        })



@csrf_exempt
@require_POST
def submit_review(request):
    """Submit a training review with avatar support"""
    try:
        data = json.loads(request.body)
        training_id = data.get('training_id')
        
        training = Training.objects.get(id=training_id)
        
        # Create review
        review = TrainingReview.objects.create(
            training=training,
            full_name=data.get('full_name'),
            email=data.get('email'),
            rating=int(data.get('rating', 5)),
            title=data.get('title'),
            comment=data.get('comment'),
            avatar=data.get('avatar', 'images/avatars/avatar1.png'),
            is_approved=False,  # Needs admin approval
            created_at=timezone.now()
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Votre avis a été soumis et sera examiné par notre équipe.',
            'review_id': review.id
        })
        
    except Training.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Formation non trouvée'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Erreur: {str(e)}'
        })

@csrf_exempt
@require_POST
def join_waitlist(request):
    """Join training waitlist"""
    try:
        data = json.loads(request.body)
        training_id = data.get('training_id')
        email = data.get('email')
        
        training = Training.objects.get(id=training_id)
        
        # Check if already in waitlist
        existing = TrainingWaitlist.objects.filter(
            training=training, 
            email=email
        ).first()
        
        if existing:
            return JsonResponse({
                'success': False,
                'message': 'Vous êtes déjà sur la liste d\'attente pour cette formation.'
            })
        
        # Count current waitlist position
        position = TrainingWaitlist.objects.filter(training=training).count() + 1
        
        # Create waitlist entry
        TrainingWaitlist.objects.create(
            training=training,
            email=email,
            full_name=data.get('full_name', ''),
            phone=data.get('phone', ''),
            city=data.get('city', ''),
            created_at=timezone.now()
        )
        
        return JsonResponse({
            'success': True,
            'message': 'Ajouté à la liste d\'attente',
            'position': position
        })
        
    except Training.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Formation non trouvée'
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Erreur: {str(e)}'
        })

# Helper function to get average rating
def get_training_avg_rating(training_id):
    """Calculate average rating for a training"""
    from django.db.models import Avg
    result = TrainingReview.objects.filter(
        training_id=training_id,
        is_approved=True
    ).aggregate(Avg('rating'))
    
    return result['rating__avg'] or 0

@require_POST
@csrf_exempt
def update_currency(request):
    """Update user's preferred currency"""
    try:
        # Check rate limit
        ip_address = get_client_ip(request)
        allowed, wait_time = RateLimiter.check_rate_limit(ip_address, 'update_currency', limit=10)
        
        if not allowed:
            return JsonResponse({
                'success': False,
                'wait_time': wait_time
            }, status=429)
        
        data = json.loads(request.body)
        currency = data.get('currency', 'MAD')
        
        valid_currencies = ['MAD', 'EUR', 'USD', 'GBP', 'CAD', 'AED', 'CHF']
        
        if currency in valid_currencies:
            request.session['preferred_currency'] = currency
            return JsonResponse({'success': True})
        else:
            return JsonResponse({'success': False, 'message': 'Devise non supportée.'})
            
    except Exception as e:
        return JsonResponse({'success': False, 'message': str(e)})

@csrf_exempt
def get_currency_rates_api(request):
    """API endpoint to get currency rates"""
    try:
        rates = get_cached_currency_rates()
        return JsonResponse({
            'success': True,
            'rates': rates,
            'last_updated': datetime.now().isoformat()
        })
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })

@require_POST
@csrf_exempt
def track_click_event(request):
    """Track button/link clicks for analytics"""
    try:
        data = json.loads(request.body)
        
        session_id = request.session.session_key
        if not session_id:
            return JsonResponse({'success': False})
        
        ip_address = get_client_ip(request)
        user_location = get_location_from_ip(ip_address)
        
        ClickEvent.objects.create(
            element_type=data.get('element_type', 'button'),
            element_text=data.get('element_text', ''),
            element_id=data.get('element_id', ''),
            url=data.get('url', request.path),
            session_id=session_id,
            ip_address=ip_address,
            city=user_location.get('city', '')
        )
        
        return JsonResponse({'success': True})
        
    except:
        return JsonResponse({'success': False})

@require_POST
@csrf_exempt
def track_phone_call(request):
    """Track phone call clicks"""
    try:
        data = json.loads(request.body)
        
        session_id = request.session.session_key
        if not session_id:
            return JsonResponse({'success': False})
        
        ip_address = get_client_ip(request)
        user_location = get_location_from_ip(ip_address)
        
        PhoneCall.objects.create(
            phone_number=data.get('phone_number', ''),
            caller_city=user_location.get('city', ''),
            caller_country=user_location.get('country', ''),
            url=data.get('url', request.path),
            session_id=session_id,
            ip_address=ip_address
        )
        
        return JsonResponse({'success': True})
        
    except:
        return JsonResponse({'success': False})

@require_POST
@csrf_exempt
def track_whatsapp_click(request):
    """Track WhatsApp button clicks"""
    try:
        data = json.loads(request.body)
        
        session_id = request.session.session_key
        if not session_id:
            return JsonResponse({'success': False})
        
        ip_address = get_client_ip(request)
        user_location = get_location_from_ip(ip_address)
        
        WhatsAppClick.objects.create(
            phone_number=data.get('phone_number', '+212779259942'),
            message_prefill=data.get('message', ''),
            url=data.get('url', request.path),
            session_id=session_id,
            ip_address=ip_address,
            city=user_location.get('city', '')
        )
        
        return JsonResponse({'success': True})
        
    except:
        return JsonResponse({'success': False})

@csrf_exempt
def get_training_reviews(request, training_id):
    """Get reviews for a training"""
    try:
        training = get_object_or_404(Training, id=training_id)
        reviews = TrainingReview.objects.filter(
            training=training,
            is_approved=True
        ).order_by('-created_at')
        
        reviews_data = []
        for review in reviews:
            reviews_data.append({
                'id': review.id,
                'full_name': review.full_name,
                'avatar': review.avatar or f'images/avatars/avatar{(review.id % 4) + 1}.png',
                'rating': review.rating,
                'title': review.title,
                'comment': review.comment,
                'is_verified': review.is_verified,
                'created_at': review.created_at.strftime('%d/%m/%Y'),
                'helpful_count': review.helpful_count,
                'not_helpful_count': review.not_helpful_count,
            })
        
        avg_rating = reviews.aggregate(Avg('rating'))['rating__avg'] or 0
        
        return JsonResponse({
            'success': True,
            'reviews': reviews_data,
            'avg_rating': round(avg_rating, 1),
            'total_reviews': reviews.count()
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })

@require_POST
@csrf_exempt
def mark_review_helpful(request):
    """Mark review as helpful"""
    try:
        data = json.loads(request.body)
        review_id = data.get('review_id')
        is_helpful = data.get('is_helpful', True)
        
        review = get_object_or_404(TrainingReview, id=review_id)
        
        if is_helpful:
            review.helpful_count = F('helpful_count') + 1
        else:
            review.not_helpful_count = F('not_helpful_count') + 1
        
        review.save(update_fields=['helpful_count', 'not_helpful_count'])
        
        return JsonResponse({
            'success': True,
            'helpful_count': review.helpful_count,
            'not_helpful_count': review.not_helpful_count
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': str(e)
        })

# ==========================================
# AUTHENTICATION VIEWS
# ==========================================

from django.contrib.auth.forms import AuthenticationForm
from django.contrib import messages
import json


def _extract_contract_error_message(exc: Exception) -> str:
    """
    ContractError embeds upstream JSON in the exception string.
    Try to extract a clean message for end users.
    """
    raw = str(exc)
    idx = raw.find("{")
    if idx != -1:
        try:
            payload = json.loads(raw[idx:])
            if isinstance(payload, dict):
                if payload.get("error"):
                    return str(payload["error"])
                if payload.get("message"):
                    return str(payload["message"])
        except Exception:
            pass
    return raw

def register(request):
    """Handle student registration"""
    # Keep city list in sync with Barka authority (projection-only).
    mgmt = ManagementContractClient()
    if mgmt.is_configured():
        try:
            from .models import City
            remote_cities = mgmt.list_cities()
            for c in remote_cities:
                if not isinstance(c, dict):
                    continue
                name = str(c.get("name", "")).strip()
                if not name:
                    continue
                City.objects.get_or_create(name=name)
        except Exception as exc:
            logger.warning("Could not sync cities from authority: %s", exc)

    if request.method == 'POST':
        form = StudentRegistrationForm(request.POST, external_authority=mgmt.is_configured())
        if form.is_valid():
            # 1) Create student in Barka (source of truth) if configured.
            if mgmt.is_configured():
                full_name = str(form.cleaned_data.get('full_name') or '').strip()
                cin = str(form.cleaned_data.get('cin_or_passport') or '').strip().upper()
                if not cin:
                    form.add_error('cin_or_passport', "CIN is required for registration.")
                    return render(request, 'registration/signup.html', {'form': form, 'external_authority': True})
                phone = str(form.cleaned_data.get('phone_number') or '').strip()
                email = str(form.cleaned_data.get('email') or '').strip()
                birth_date = form.cleaned_data.get('birth_date')
                birth_place = str(form.cleaned_data.get('birth_place') or '').strip()
                address = str(form.cleaned_data.get('address') or '').strip()

                if not birth_date:
                    form.add_error('birth_date', "Date of birth is required.")
                if not birth_place:
                    form.add_error('birth_place', "Place of birth is required.")
                if not address:
                    form.add_error('address', "Address is required.")
                if form.errors:
                    return render(request, 'registration/signup.html', {'form': form, 'external_authority': True})

                parts = [p for p in full_name.split(" ") if p]
                prenom = parts[0] if parts else full_name
                nom = " ".join(parts[1:]) if len(parts) > 1 else (parts[0] if parts else full_name)

                try:
                    mgmt.create_student({
                        "nom": nom,
                        "prenom": prenom,
                        "cin": cin,
                        "email": email,
                        "phone": phone,
                        "date_naissance": birth_date.isoformat() if hasattr(birth_date, "isoformat") else str(birth_date),
                        "lieu_naissance": birth_place,
                        "adresse": address,
                        "statut_compte": "actif",
                    })
                except (UpstreamUnavailable, ContractError) as exc:
                    messages.error(request, f"Registration is temporarily unavailable: {exc}")
                    return render(request, 'registration/signup.html', {'form': form, 'external_authority': True})

                # Auto-login after successful registration (requested UX).
                try:
                    login_payload = mgmt.login(username=cin, password=str(form.cleaned_data.get('password') or ''))
                    if not login_payload.get("success"):
                        messages.success(request, "Registration successful. Please login to access your space.")
                        return redirect('Prolean:login')

                    token = login_payload.get("token")
                    user_data = login_payload.get("user") if isinstance(login_payload.get("user"), dict) else {}
                    permissions = login_payload.get("permissions") if isinstance(login_payload.get("permissions"), list) else []

                    local_username = str(user_data.get("username") or cin).strip()
                    django_user, _created = User.objects.get_or_create(username=local_username)
                    django_user.set_unusable_password()
                    django_user.save()

                    try:
                        profile = django_user.profile
                    except Exception:
                        from .models import Profile as ProleanProfile
                        profile, _ = ProleanProfile.objects.get_or_create(user=django_user)

                    profile.role = "STUDENT"
                    if user_data.get("full_name"):
                        profile.full_name = str(user_data.get("full_name"))
                    profile.status = "ACTIVE"
                    profile.save()

                    if token:
                        request.session["barka_token"] = token
                    request.session["barka_permissions"] = permissions

                    login(request, django_user)
                    messages.success(request, "Welcome to your space.")
                    return redirect('Prolean:dashboard')
                except (UpstreamUnavailable, ContractError) as exc:
                    messages.success(request, "Registration successful. Please login to access your space.")
                    messages.error(request, f"Login temporarily unavailable: {exc}")
                    return redirect('Prolean:login')

            # 2) Legacy local registration fallback (when external authority is not configured).
            user = User.objects.create_user(
                username=form.cleaned_data['cin_or_passport'],
                email=form.cleaned_data['email'],
                password=form.cleaned_data['password'],
                first_name=form.cleaned_data['full_name'].split(' ')[0],
                last_name=' '.join(form.cleaned_data['full_name'].split(' ')[1:])
            )
            
            # Profile is created by signal, but we update it here
            try:
                profile = user.profile
                profile.role = 'STUDENT'
                profile.full_name = form.cleaned_data['full_name']
                profile.cin_or_passport = form.cleaned_data['cin_or_passport']
                profile.phone_number = form.cleaned_data['phone_number']
                profile.city = form.cleaned_data['city']
                profile.save()
            except Exception as e:
                logger.error(f"Error updating profile: {e}")
            
            # Authenticate and login (optional, or redirect to login)
            login(request, user)
            messages.success(request, "Compte créé avec succès! En attente de validation.")
            return redirect('Prolean:home')
    else:
        form = StudentRegistrationForm(external_authority=mgmt.is_configured())

    # Ensure form gets latest city queryset after sync.
    try:
        from .models import City
        form.fields['city'].queryset = City.objects.filter(is_active=True).order_by('name')
    except Exception:
        pass
    
    return render(request, 'registration/signup.html', {'form': form, 'external_authority': mgmt.is_configured()})

def login_view(request):
    """Custom login view"""
    mgmt = ManagementContractClient()
    use_external = mgmt.is_configured()

    if request.method == 'POST':
        if use_external:
            form = ExternalAuthorityLoginForm(request.POST)
            if form.is_valid():
                raw_identifier = str(form.cleaned_data.get('username') or '').strip()
                cin_pattern = re.compile(r'^[A-Za-z]{1,2}\s*\d{6}$')
                if cin_pattern.match(raw_identifier):
                    username = raw_identifier.replace(" ", "").upper()
                else:
                    username = raw_identifier
                password = form.cleaned_data.get('password') or ''
                try:
                    payload = mgmt.login(username=username, password=password)
                    if not payload.get("success"):
                        messages.error(request, payload.get("error") or "Invalid credentials.")
                        return redirect('Prolean:login')

                    token = payload.get("token")
                    user_data = payload.get("user") if isinstance(payload.get("user"), dict) else {}
                    permissions = payload.get("permissions") if isinstance(payload.get("permissions"), list) else []

                    local_username = str(user_data.get("username") or username).strip()
                    if not local_username:
                        messages.error(request, "Identifiant invalide.")
                        return redirect('Prolean:login')

                    django_user, _created = User.objects.get_or_create(username=local_username)
                    django_user.set_unusable_password()
                    django_user.save()

                    # Mirror role in Prolean profile (projection only).
                    try:
                        profile = django_user.profile
                    except Exception:
                        from .models import Profile as ProleanProfile
                        profile, _ = ProleanProfile.objects.get_or_create(user=django_user)

                    raw_role = str(user_data.get("role", "")).strip().upper()
                    if raw_role == "STUDENT" or raw_role == "student":
                        profile.role = "STUDENT"
                    elif raw_role == "PROFESSOR" or raw_role == "professor":
                        profile.role = "PROFESSOR"
                    elif raw_role == "ADMIN" or raw_role == "GERANT":
                        profile.role = "ADMIN"
                    else:
                        # Default safe role.
                        profile.role = "STUDENT"

                    if user_data.get("full_name"):
                        profile.full_name = str(user_data.get("full_name"))
                    profile.status = "ACTIVE"
                    profile.save()

                    if token:
                        request.session["barka_token"] = token
                    request.session["barka_permissions"] = permissions

                    login(request, django_user)
                    return redirect('Prolean:home')
                except UpstreamUnavailable as exc:
                    messages.error(request, f"Login temporarily unavailable: {exc}")
                    return redirect('Prolean:login')
                except ContractError as exc:
                    messages.error(request, _extract_contract_error_message(exc))
                    return redirect('Prolean:login')
            else:
                messages.error(request, "Invalid credentials.")
        else:
            form = AuthenticationForm(request, data=request.POST)
            if form.is_valid():
                username = form.cleaned_data.get('username')
                password = form.cleaned_data.get('password')

                user = authenticate(username=username, password=password)
                if user is not None:
                    login(request, user)
                    return redirect('Prolean:home')
                messages.error(request, "Identifiants invalides.")
            else:
                messages.error(request, "Identifiants invalides.")
    
    form = ExternalAuthorityLoginForm() if use_external else AuthenticationForm()
    return render(request, 'registration/login.html', {'form': form})

def logout_view(request):
    logout(request)
    return redirect('Prolean:home')


@require_POST
def set_language_preference(request):
    """
    Force language switch in session+cookie (fr/en/ar) and redirect back.
    This avoids relying on JS-only flows and ensures deterministic behavior.
    """
    # Language switching disabled: keep endpoint as no-op for backwards compatibility.
    return redirect(request.META.get("HTTP_REFERER") or reverse("Prolean:home"))
    lang = str(request.POST.get("language", "") or "").strip().lower()
    if lang not in {"fr", "en", "ar"}:
        lang = "fr"
    next_url = str(request.POST.get("next", "") or "").strip()
    if not next_url or not url_has_allowed_host_and_scheme(
        url=next_url,
        allowed_hosts={request.get_host()},
        require_https=request.is_secure(),
    ):
        next_url = request.META.get("HTTP_REFERER") or reverse("Prolean:home")
    translation.activate(lang)
    request.LANGUAGE_CODE = lang
    messages.success(
        request,
        "Language updated." if lang == "en" else ("تم تغيير اللغة." if lang == "ar" else "Langue mise à jour."),
    )
    response = redirect(next_url)
    response.set_cookie("django_language", lang, max_age=31536000, samesite="Lax")
    return response

# ==========================================
# STUDENT DASHBOARD VIEWS
# ==========================================

def dashboard(request):
    """Student dashboard view - Enhanced with stats and schedule"""
    # 🧠 Behavior to Implement: Simulate logged-in experience
    if not request.user.is_authenticated:
        return render(request, 'Prolean/dashboard/restricted_access.html')
    if not hasattr(request.user, 'profile'):
        messages.error(request, "Votre profil n'est pas encore configuré.")
        return redirect('Prolean:home')
        
    profile = request.user.profile
    
    # Check role and redirect accordingly
    if profile.role == 'PROFESSOR':
        return redirect('Prolean:professor_dashboard')
    elif profile.role in ['ADMIN', 'ASSISTANT']:
        return redirect('/admin/')
    
    # Check if student
    if profile.role != 'STUDENT':
         messages.warning(request, "Accès restreint aux étudiants.")
         return redirect('Prolean:home')
         
    try:
        student_profile = profile.student_profile
    except StudentProfile.DoesNotExist:
        student_profile = StudentProfile.objects.create(profile=profile)
    
    # Get active formations
    my_formations = student_profile.authorized_formations.all()
    
    # Calculate watch percentage
    total_videos = RecordedVideo.objects.filter(training__in=my_formations).count()
    watched_videos = VideoProgress.objects.filter(student=profile, video__training__in=my_formations, completed=True).count()
    watch_percentage = int((watched_videos / total_videos) * 100) if total_videos > 0 else 0
    
    # Get next seance
    next_seance = None
    if student_profile.session:
        next_seance = Seance.objects.filter(
            session=student_profile.session,
            date__gte=timezone.now().date()
        ).order_by('date', 'time').first()
    
    # Notifications
    student_session = student_profile.session
    notifications = Notification.objects.filter(
        user=request.user,
        is_read=False
    ).filter(
        Q(session=student_session) | Q(session__isnull=True)
    )[:10]

    # Active streams
    active_streams = Live.objects.filter(
        session=student_session,
        is_active=True
    ).select_related('session', 'session__professor__profile').prefetch_related('session__formations') if student_session else []

    # External authority (Barka) snapshot for assignments.
    external_profile_payload = None
    external_pending_assignment = False
    external_formations = []
    external_schedule = []
    external_authority_mode = False
    external_live_states = {}
    external_active_live_sessions = []
    try:
        token = request.session.get("barka_token")
        mgmt = ManagementContractClient()
        external_authority_mode = mgmt.is_configured()
        if external_authority_mode and isinstance(token, str) and token.strip():
            external_profile_payload = mgmt.get_student_me_profile(bearer_token=token.strip())
            external_formations = external_profile_payload.get("formations") or []
            external_schedule = external_profile_payload.get("schedule") or []
            if isinstance(external_formations, list):
                external_pending_assignment = len(external_formations) == 0
            else:
                external_formations = []
                external_pending_assignment = True
    except Exception as exc:
        if _is_barka_token_expired(exc):
            try:
                request.session.pop("barka_token", None)
                request.session.pop("barka_permissions", None)
            except Exception:
                pass
            messages.warning(request, "Session expired. Please login again.")
        logger.warning("Could not load external student profile: %s", exc)

    # Fallback mapping by CIN using service credentials (UI adaptation resilience).
    if external_authority_mode and not external_formations:
        try:
            mgmt = ManagementContractClient()
            cin = _norm_cin(getattr(request.user, "username", "") or "")
            if cin:
                rows = mgmt.list_students_with_sessions()
                matched = [
                    r for r in rows
                    if isinstance(r, dict) and _norm_cin(r.get("cin", "")) == cin
                ]
                mapped = []
                for row in matched:
                    if not row.get("session_id"):
                        continue
                    mapped.append({
                        "formation_name": row.get("formation_titre"),
                        "session_id": row.get("session_id"),
                        "session_name": row.get("session_titre"),
                        "session_type": row.get("session_type"),
                        "session_status": row.get("session_statut"),
                        "ville": row.get("ville"),
                        "professor_name": row.get("professor_name"),
                        "montant_total": row.get("montant_total"),
                        "montant_paye": row.get("montant_paye"),
                        "montant_du": row.get("montant_du"),
                        "student_status": "actif",
                    })
                if mapped:
                    external_formations = mapped
                external_pending_assignment = len(external_formations) == 0
        except Exception as exc:
            logger.warning("Could not load fallback assignments by CIN: %s", exc)

    # Prefer payment values from external authority when available.
    if isinstance(external_formations, list) and external_formations:
        def _to_float(v):
            try:
                return float(v)
            except Exception:
                return 0.0

        amount_paid_ext = sum(_to_float(f.get("montant_paye")) for f in external_formations if isinstance(f, dict))
        amount_remaining_ext = sum(_to_float(f.get("montant_du")) for f in external_formations if isinstance(f, dict))
        context_amount_paid = amount_paid_ext
        context_amount_remaining = amount_remaining_ext
    else:
        context_amount_paid = student_profile.amount_paid
        context_amount_remaining = student_profile.amount_remaining

    # Resolve live state per external session for dashboard badges/actions.
    if external_authority_mode and isinstance(external_formations, list) and external_formations:
        try:
            token = request.session.get("barka_token")
            mgmt = ManagementContractClient()
            session_ids = {
                str(row.get("session_id") or row.get("id") or "").strip()
                for row in external_formations
                if isinstance(row, dict) and (row.get("session_id") or row.get("id"))
            }
            if isinstance(token, str) and token.strip():
                for session_id in session_ids:
                    try:
                        state = mgmt.get_session_live_state(session_id, bearer_token=token.strip())
                        if isinstance(state, dict):
                            external_live_states[session_id] = state
                        else:
                            logger.info("External live state for session %s is empty/not live", session_id)
                    except Exception as exc:
                        logger.warning("Failed to resolve live state for session %s: %s", session_id, exc)
                        continue
            else:
                service_token = str(mgmt.get_service_bearer_token() or "").strip()
                cin_default = str(getattr(request.user, "username", "") or "").strip().upper()
                if service_token and cin_default:
                    for session_id in session_ids:
                        try:
                            cin_hint, _exp = _get_external_live_service_access(request, session_id)
                            cin = str(cin_hint or cin_default).strip().upper()
                            state = mgmt.get_session_live_state_for_student(
                                session_id,
                                student_cin=cin,
                                bearer_token=service_token,
                            )
                            if isinstance(state, dict):
                                external_live_states[session_id] = state
                            else:
                                logger.info("External live state for session %s is empty/not live (service mode)", session_id)
                        except Exception as exc:
                            logger.warning("Failed to resolve live state for session %s (service mode): %s", session_id, exc)
                            continue
        except Exception as exc:
            logger.error("Could not resolve external live states for student dashboard: %s", exc)

    if isinstance(external_formations, list) and external_formations and isinstance(external_live_states, dict):
        session_preview = {}
        for row in external_formations:
            if not isinstance(row, dict):
                continue
            session_id = str(row.get("session_id") or "").strip()
            if not session_id or session_id in session_preview:
                continue
            session_preview[session_id] = {
                "session_id": session_id,
                "session_name": row.get("session_name") or "Session",
                "professor_name": row.get("professor_name") or "Professor",
                "ville": row.get("ville") or "-",
            }
        external_active_live_sessions = [
            session_preview[sid]
            for sid, state in external_live_states.items()
            if sid in session_preview and isinstance(state, dict) and str(state.get("status", "")).lower() == "live"
        ]

    context = {
        'profile': profile,
        'student_profile': student_profile,
        'my_formations': my_formations,
        'next_seance': next_seance,
        'watch_percentage': watch_percentage,
        'active_streams': active_streams,
        'notifications': notifications,
        'active_count': my_formations.count(),
        'amount_paid': context_amount_paid,
        'amount_remaining': context_amount_remaining,
        'external_profile': external_profile_payload,
        'external_formations': external_formations if isinstance(external_formations, list) else [],
        'external_schedule': external_schedule if isinstance(external_schedule, list) else [],
        'external_pending_assignment': external_pending_assignment,
        'external_authority_mode': external_authority_mode,
        'external_live_states': external_live_states,
        'external_active_live_sessions': external_active_live_sessions,
    }
    
    return render(request, 'Prolean/dashboard/dashboard.html', context)

@login_required
@student_active_required
def student_schedule(request):
    """View to display student's schedule (seances)"""
    profile = request.user.profile
    try:
        student_profile = profile.student_profile
    except:
        return redirect('Prolean:dashboard')
        
    session = student_profile.session
    seances = []
    if session:
        seances = Seance.objects.filter(session=session).order_by('date', 'time')
        
    return render(request, 'Prolean/dashboard/schedule.html', {
        'profile': profile,
        'session': session,
        'seances': seances
    })

@login_required
@student_active_required
def student_profile(request):
    """View to update student profile"""
    profile = request.user.profile
    
    if request.method == 'POST':
        # Update logic here
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone = request.POST.get('phone_number', '')
        city_name = request.POST.get('city')
        
        user = request.user
        user.first_name = first_name
        user.last_name = last_name
        user.save()
        
        profile.full_name = f"{first_name} {last_name}"
        profile.phone_number = phone
        
        # Fix: Get or create City object instead of assigning string
        if city_name:
            city_obj, created = City.objects.get_or_create(name=city_name)
            profile.city = city_obj
        
        profile.save()
        
        messages.success(request, "Profil mis à jour avec succès.")
        return redirect('Prolean:student_profile')
        
    return render(request, 'Prolean/dashboard/profile.html', {'profile': profile})

@login_required
@student_active_required
def student_certificates(request):
    profile = request.user.profile
    return render(request, "Prolean/dashboard/certificates.html", {"profile": profile})


@login_required
@require_POST
def upload_profile_picture(request):
    """Secure profile picture upload via ImgBB API"""
    import mimetypes
    import os
    from django.core.files.uploadedfile import InMemoryUploadedFile
    
    try:
        profile = request.user.profile
    except:
        return JsonResponse({'success': False, 'error': 'Profil introuvable.'}, status=400)
    
    # Security: Rate Limiting (3 uploads per hour)
    cache_key = f'profile_upload_{request.user.id}'
    attempts = cache.get(cache_key, 0)
    if attempts >= 3:
        return JsonResponse({
            'success': False, 
            'error': 'Trop de tentatives. Veuillez réessayer dans 1 heure.'
        }, status=429)
    
    # Get uploaded file
    if 'profile_picture' not in request.FILES:
        return JsonResponse({'success': False, 'error': 'Aucun fichier sélectionné.'}, status=400)
    
    uploaded_file = request.FILES['profile_picture']
    
    # Security: File Size Validation (Max 5MB)
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    if uploaded_file.size > MAX_FILE_SIZE:
        return JsonResponse({
            'success': False, 
            'error': 'L\'image doit faire moins de 5MB.'
        }, status=400)
    
    # Security: File Type Validation
    ALLOWED_EXTENSIONS = ['jpg', 'jpeg', 'png', 'webp']
    ALLOWED_MIMES = ['image/jpeg', 'image/png', 'image/webp']
    
    # Check extension
    file_ext = uploaded_file.name.split('.')[-1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return JsonResponse({
            'success': False, 
            'error': 'Format non supporté. Utilisez JPG, PNG ou WebP.'
        }, status=400)
    
    # Security: MIME Type Validation (server-side)
    mime_type, _ = mimetypes.guess_type(uploaded_file.name)
    if mime_type not in ALLOWED_MIMES:
        return JsonResponse({
            'success': False, 
            'error': 'Type de fichier invalide.'
        }, status=400)
    
    # Security: Filename Sanitization
    import re
    safe_filename = re.sub(r'[^a-zA-Z0-9._-]', '', uploaded_file.name)
    
    # Get session info for folder organization
    try:
        student_profile = profile.student_profile
        session_folder = student_profile.session.city.name if student_profile.session and student_profile.session.city else 'default'
    except:
        session_folder = 'default'
    
    # Sanitize folder name
    session_folder = re.sub(r'[^a-zA-Z0-9_-]', '', session_folder)
    
    # Prepare ImgBB upload
    IMGBB_API_KEY = '4f4a4f813037f0bdf500c95d898ede08'
    IMGBB_URL = 'https://api.imgbb.com/1/upload'
    
    try:
        # Read file content
        file_content = uploaded_file.read()
        
        # Prepare request
        import base64
        encoded_image = base64.b64encode(file_content).decode('utf-8')
        
        # Create album/folder name with session
        album_name = f"Prolean_{session_folder}_{profile.user.username}"
        
        payload = {
            'key': IMGBB_API_KEY,
            'image': encoded_image,
            'name': f"{profile.user.username}_{safe_filename}",
        }
        
        # Upload to ImgBB
        response = requests.post(IMGBB_URL, data=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if data.get('success'):
                # Get direct image URL
                image_url = data['data']['display_url']
                
                # Save to profile
                profile.profile_picture = image_url
                profile.save(update_fields=['profile_picture'])
                
                # Increment rate limit counter
                cache.set(cache_key, attempts + 1, 3600)  # 1 hour
                
                return JsonResponse({
                    'success': True, 
                    'image_url': image_url,
                    'message': 'Photo de profil mise à jour avec succès!'
                })
            else:
                return JsonResponse({
                    'success': False, 
                    'error': 'Erreur lors du téléchargement. Veuillez réessayer.'
                }, status=500)
        else:
            return JsonResponse({
                'success': False, 
                'error': 'Erreur de connexion au serveur. Veuillez réessayer.'
            }, status=500)
            
    except requests.exceptions.Timeout:
        return JsonResponse({
            'success': False, 
            'error': 'Délai d\'attente dépassé. Veuillez réessayer.'
        }, status=504)
    except requests.exceptions.RequestException as e:
        return JsonResponse({
            'success': False, 
            'error': 'Erreur de connexion. Veuillez réessayer.'
        }, status=500)
    except Exception as e:
        logging.error(f"Profile upload error: {str(e)}")
        return JsonResponse({
            'success': False, 
            'error': 'Une erreur est survenue. Veuillez réessayer.'
        }, status=500)

# Classroom
@login_required
def classroom(request, training_slug, video_id=None):
    """Classroom view for VOD"""
    try:
        profile = request.user.profile
        student_profile = profile.student_profile
    except:
         return redirect('Prolean:home')

    # Get Training and check access
    training = get_object_or_404(Training, slug=training_slug)
    if not student_profile.authorized_formations.filter(id=training.id).exists():
        messages.error(request, "Vous n'avez pas accès à cette formation.")
        return redirect('Prolean:dashboard')
        
    # Get Videos
    videos = RecordedVideo.objects.filter(training=training, is_active=True).order_by('created_at')
    
    if not videos.exists():
        messages.warning(request, "Aucune vidéo disponible pour cette formation.")
        return redirect('Prolean:dashboard')
        
    # Select current video
    if video_id:
        current_video = get_object_or_404(RecordedVideo, id=video_id, training=training)
    else:
        current_video = videos.first()
        
    # Find the session this student is currently in for this training
    student_session = student_profile.session
    
    # Validating session pertains to this training (optional but good)
    if student_session and not student_session.formations.filter(id=training.id).exists():
        student_session = None

    # Get Questions (filtered by session if available)
    if student_session:
        questions = Question.objects.filter(video=current_video, student__session=student_session, is_deleted=False).order_by('-created_at')
    else:
        questions = Question.objects.filter(video=current_video, is_deleted=False).order_by('-created_at')
    
    # Handle Question Submission
    if request.method == 'POST':
        content = request.POST.get('content')
        if content:
            # Create the question
            question = Question.objects.create(
                video=current_video,
                student=student_profile,
                content=content
            )
            
            # Notify Professor(s)
            professors_to_notify = []
            if student_session:
                professors_to_notify.append(student_session.professor.profile.user)
            else:
                # Notify all professors associated with this training via past or ongoing sessions
                prof_users = User.objects.filter(
                    profile__professor_profile__sessions__formations=training
                ).distinct()
                professors_to_notify.extend(list(prof_users))

            notifications = []
            for prof_user in professors_to_notify:
                notifications.append(Notification(
                    user=prof_user,
                    session=student_session,
                    title=f"Nouvelle question - {training.title}",
                    message=f"{profile.full_name} a posé une question sur la vidéo: {current_video.title}",
                    notification_type='info',
                    link=f"/professor/comments/{'?session_id=' + str(student_session.id) if student_session else ''}"
                ))
            
            if notifications:
                Notification.objects.bulk_create(notifications)

            messages.success(request, "Votre question a été ajoutée.")
            return redirect('Prolean:classroom_video', training_slug=training.slug, video_id=current_video.id)
            
    context = {
        'training': training,
        'videos': videos,
        'current_video': current_video,
        'comments': questions,
    }
    
    return render(request, 'Prolean/classroom/classroom.html', context)

@login_required
def check_updates_ajax(request):
    """API endpoint for long-polling/updates (notifications and live status)"""
    profile = request.user.profile
    touch_user_presence(request.user, path=request.path)
    now = timezone.now()
    
    # 1. Notifications
    notifications = Notification.objects.filter(
        user=request.user, 
        is_read=False
    ).select_related('session').order_by('-created_at')[:5]
    
    notif_data = [{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.notification_type,
        'created_at': n.created_at.strftime('%H:%M'),
        'link': n.link
    } for n in notifications]

    # 2. Live Streams (Context-Specific)
    active_streams_data = []
    
    if profile.role == 'STUDENT':
        student_profile = profile.student_profile
        active_streams = Live.objects.filter(
            session=student_profile.session,
            is_active=True
        ).select_related('session').prefetch_related('session__formations') if student_profile.session else []
        
    elif profile.role == 'PROFESSOR':
        prof_profile = profile.professor_profile
        active_streams = Live.objects.filter(
            session__professor=prof_profile,
            is_active=True
        ).select_related('session').prefetch_related('session__formations')
    else:
        active_streams = []

    for stream in active_streams:
        formations = ", ".join([t.title for t in stream.session.formations.all()])
        active_streams_data.append({
            'id': stream.id,
            'session_id': stream.session.id,
            'trainings': formations,
            'professor': stream.session.professor.profile.full_name,
            'join_url': f"/live/{stream.id}/" # Hardcoded path or use reverse
        })

    # 3. External/Barka live streams (available on all pages for floating live button)
    try:
        token = request.session.get("barka_token")
        mgmt = ManagementContractClient()
        if mgmt.is_configured() and isinstance(token, str) and token.strip():
            external_candidates: set[str] = set()
            if profile.role == 'STUDENT':
                payload = mgmt.get_student_me_profile(bearer_token=token.strip())
                formations = payload.get("formations") if isinstance(payload, dict) else []
                if isinstance(formations, list):
                    for row in formations:
                        if isinstance(row, dict) and row.get("session_id"):
                            external_candidates.add(str(row.get("session_id")))
            elif profile.role == 'PROFESSOR':
                sessions = mgmt.list_my_professor_sessions(bearer_token=token.strip())
                if isinstance(sessions, list):
                    for row in sessions:
                        if isinstance(row, dict) and row.get("id"):
                            external_candidates.add(str(row.get("id")))

            for sid in external_candidates:
                try:
                    state = mgmt.get_session_live_state(sid, bearer_token=token.strip())
                    if isinstance(state, dict) and str(state.get("status", "")).lower() == "live":
                        active_streams_data.append({
                            'id': state.get('id') or sid,
                            'session_id': sid,
                            'trainings': state.get('room_name') or 'External live',
                            'professor': '',
                            'join_url': reverse('Prolean:external_live_room', kwargs={'session_id': sid}),
                        })
                except Exception:
                    continue
    except Exception as exc:
        logger.warning("External live polling skipped: %s", exc)

    return JsonResponse({
        'status': 'success',
        'notifications': notif_data,
        'unread_count': Notification.objects.filter(user=request.user, is_read=False).count(),
        'active_streams': active_streams_data,
        'server_time': now.isoformat()
    })

# ==========================================
# LIVE SESSION VIEW
# ==========================================

@professor_required
def start_live_stream(request, session_id):
    """Professor starts a new live stream event for a session"""
    session = get_object_or_404(Session, id=session_id, professor__profile=request.user.profile)
    
    if session.status == 'COMPLETED':
        messages.error(request, "Cette session est terminée. Vous ne pouvez plus lancer de live.")
        return redirect('Prolean:professor_dashboard')
        
    if session.status != 'ONGOING':
        messages.error(request, "La session doit être 'En cours' pour démarrer un live.")
        return redirect('Prolean:professor_dashboard')
    
    # Check if there's already an active stream
    active_stream = Live.objects.filter(session=session, is_active=True).first()
    if active_stream:
        messages.info(request, "Un live est déjà en cours pour cette session.")
        return redirect('Prolean:live_session', stream_id=active_stream.id)
    
    # Create new stream event
    stream = Live.objects.create(
        session=session,
        agora_channel=f"session_{session.id}_live_{timezone.now().strftime('%Y%H%M%S')}",
        is_active=True
    )
    
    messages.success(request, "Live démarré ! Les étudiants peuvent maintenant rejoindre.")
    return redirect('Prolean:live_session', stream_id=stream.id)

@professor_required
def end_live_stream(request, stream_id):
    """Professor ends an active live stream"""
    stream = get_object_or_404(Live, id=stream_id, session__professor__profile=request.user.profile)
    stream.is_active = False
    stream.ended_at = timezone.now()
    stream.save()
    
    messages.success(request, "Le live a été terminé. La session reste active.")
    return redirect('Prolean:professor_dashboard')

@professor_required
def update_session_status(request, session_id):
    """Professor transitions the session (CREATED -> ONGOING -> COMPLETED)"""
    session = get_object_or_404(Session, id=session_id, professor__profile=request.user.profile)
    new_status = request.POST.get('status')
    
    if new_status in ['ONGOING', 'COMPLETED']:
        session.status = new_status
        session.save()
        messages.success(request, f"Statut de la session mis à jour : {session.get_status_display()}")
        
        # If completing, end all lives
        if new_status == 'COMPLETED':
            Live.objects.filter(session=session, is_active=True).update(
                is_active=False, 
                ended_at=timezone.now()
            )
            
    return redirect('Prolean:professor_dashboard')

@login_required
def live_session(request, stream_id):
    """Live session view for a specific stream event"""
    stream = get_object_or_404(Live, id=stream_id)
    session = stream.session
    profile = request.user.profile
    
    user_is_host = False
    
    if profile.role == 'PROFESSOR':
        try:
            professor_profile = profile.professor_profile
            if session.professor == professor_profile:
                user_is_host = True
            else:
                messages.error(request, "Vous n'êtes pas le professeur assigné à cette session.")
                return redirect('Prolean:professor_dashboard')
        except ProfessorProfile.DoesNotExist:
            return redirect('Prolean:home')
    else:
        # Student check
        try:
            student_profile = profile.student_profile
            if student_profile.session != session:
                messages.error(request, "Vous n'avez pas accès à cette session.")
                return redirect('Prolean:dashboard')
            
            # Record attendance (joining now)
            AttendanceLog.objects.create(
                student=profile,
                live_stream=stream,
                session=session,
                join_time=timezone.now()
            )
        except StudentProfile.DoesNotExist:
            return redirect('Prolean:home')
    
    # Agora credentials
    agora_app_id = "YOUR_AGORA_APP_ID" 
    agora_channel = stream.agora_channel
    agora_token = None
    
    context = {
        'stream': stream,
        'session': session,
        'is_currently_live': stream.is_active,
        'now': timezone.now(),
        'user_is_host': user_is_host,
        'agora_app_id': agora_app_id,
        'agora_channel': agora_channel,
        'agora_token': agora_token,
    }
    
    return render(request, 'Prolean/live/live_session.html', context)


@login_required
def live_stream_status(request, stream_id):
    """
    Lightweight status endpoint for live sessions.
    Used by clients to auto-exit when the professor ends the live.
    """
    stream = get_object_or_404(Live, id=stream_id)
    session = stream.session

    if not hasattr(request.user, "profile"):
        return JsonResponse({"ok": False, "error": "missing_profile"}, status=403)

    profile = request.user.profile
    if profile.role == "PROFESSOR":
        try:
            professor_profile = profile.professor_profile
        except ProfessorProfile.DoesNotExist:
            return JsonResponse({"ok": False, "error": "not_allowed"}, status=403)
        if session.professor != professor_profile:
            return JsonResponse({"ok": False, "error": "not_allowed"}, status=403)
    else:
        try:
            student_profile = profile.student_profile
        except StudentProfile.DoesNotExist:
            return JsonResponse({"ok": False, "error": "not_allowed"}, status=403)
        if student_profile.session != session:
            return JsonResponse({"ok": False, "error": "not_allowed"}, status=403)

    return JsonResponse(
        {
            "ok": True,
            "stream_id": int(stream.id),
            "is_active": bool(stream.is_active),
            "ended_at": stream.ended_at.isoformat() if stream.ended_at else None,
        }
    )


@login_required
@student_active_required
def recorded_videos_list(request, training_slug):
    """List all recorded videos for a training"""
    try:
        profile = request.user.profile
        student_profile = profile.student_profile
    except:
        return redirect('Prolean:home')
    
    # Get Training and check access
    training = get_object_or_404(Training, slug=training_slug)
    if not student_profile.authorized_formations.filter(id=training.id).exists():
        messages.error(request, "Vous n'avez pas accès à cette formation.")
        return redirect('Prolean:dashboard')
    
    # Get all videos
    videos = RecordedVideo.objects.filter(training=training, is_active=True).order_by('created_at')
    
    # Get progress for each video
    video_progress = {}
    for video in videos:
        try:
            progress = VideoProgress.objects.get(student=profile, video=video)
            video_progress[video.id] = {
                'watched_seconds': progress.watched_seconds,
                'completed': progress.completed,
                'percentage': int((progress.watched_seconds / video.duration_seconds) * 100) if video.duration_seconds > 0 else 0
            }
        except VideoProgress.DoesNotExist:
            video_progress[video.id] = {
                'watched_seconds': 0,
                'completed': False,
                'percentage': 0
            }
    
    context = {
        'training': training,
        'videos': videos,
        'video_progress': video_progress,
    }
    
    return render(request, 'Prolean/videos/videos_list.html', context)

# ==========================================
# PROFESSOR DASHBOARD & MANAGEMENT
# ==========================================

@professor_required
def professor_dashboard(request):
    """Professor dashboard main view - Session-Centric"""
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if mgmt.is_configured() and isinstance(token, str) and token.strip():
        def _is_transient_external_error(exc: Exception) -> bool:
            msg = str(exc).lower()
            transient_tokens = (
                "502", "503", "504", "595",
                "bad gateway", "temporarily unavailable", "upstream",
                "timeout", "timed out", "connection reset",
            )
            return any(tok in msg for tok in transient_tokens)

        def _retry_external_call(callable_fn, attempts: int = 5):
            last_exc = None
            for attempt in range(attempts):
                try:
                    return callable_fn()
                except UpstreamUnavailable as exc:
                    last_exc = exc
                    if attempt >= attempts - 1:
                        raise
                    sleep(0.5 * (attempt + 1))
                except ContractError as exc:
                    if (not _is_transient_external_error(exc)) or attempt >= attempts - 1:
                        raise
                    last_exc = exc
                    sleep(0.5 * (attempt + 1))
            if last_exc:
                raise last_exc
            return None

        def _is_live_like_session(sess: dict) -> bool:
            if not isinstance(sess, dict):
                return False
            status = str(sess.get("status") or sess.get("statut") or "").strip().lower()
            return status in {"ongoing", "en_cours", "active", "live", "started"}

        def _norm(value) -> str:
            return str(value or "").strip().lower()

        def _extract_session_professor_candidates(sess: dict) -> set[str]:
            values: set[str] = set()
            if not isinstance(sess, dict):
                return values
            direct_keys = (
                "professor_id", "professeur_id", "teacher_id", "instructor_id",
                "professor_name", "professeur_name", "teacher_name", "instructor_name",
                "professor_username", "professeur_username", "teacher_username", "instructor_username",
                "professor_cin", "professeur_cin", "teacher_cin", "instructor_cin",
            )
            for key in direct_keys:
                val = _norm(sess.get(key))
                if val:
                    values.add(val)
            nested_keys = ("professor", "professeur", "teacher", "instructor", "user")
            for key in nested_keys:
                obj = sess.get(key)
                if isinstance(obj, dict):
                    for nkey in ("id", "name", "full_name", "username", "cin", "cin_or_passport", "email"):
                        val = _norm(obj.get(nkey))
                        if val:
                            values.add(val)
            for list_key in ("professors", "professeurs", "teachers", "instructors", "assigned_professors"):
                arr = sess.get(list_key)
                if isinstance(arr, list):
                    for item in arr:
                        if isinstance(item, dict):
                            for nkey in ("id", "name", "full_name", "username", "cin", "cin_or_passport", "email"):
                                val = _norm(item.get(nkey))
                                if val:
                                    values.add(val)
                        else:
                            val = _norm(item)
                            if val:
                                values.add(val)
            return values

        def _resolve_sessions_without_relogin(initial_sessions: list[dict]) -> list[dict]:
            sessions = initial_sessions if isinstance(initial_sessions, list) else []
            if sessions:
                return sessions
            try:
                me = _retry_external_call(lambda: mgmt.get_current_user(token.strip()), attempts=2)
            except Exception:
                me = {}
            candidate_ids = {
                _norm(getattr(request.user, "username", "")),
                _norm(getattr(request.user, "email", "")),
                _norm(getattr(request.user, "get_full_name", lambda: "")()),
            }
            profile = getattr(request.user, "profile", None)
            if profile:
                candidate_ids.add(_norm(getattr(profile, "full_name", "")))
                candidate_ids.add(_norm(getattr(profile, "cin_or_passport", "")))
            if isinstance(me, dict):
                for key in ("id", "username", "cin", "cin_or_passport", "full_name", "name", "email"):
                    candidate_ids.add(_norm(me.get(key)))
                nested_user = me.get("user")
                if isinstance(nested_user, dict):
                    for key in ("id", "username", "cin", "cin_or_passport", "full_name", "name", "email"):
                        candidate_ids.add(_norm(nested_user.get(key)))
            candidate_ids.discard("")
            if not candidate_ids:
                return sessions
            all_sessions = _retry_external_call(lambda: mgmt.list_sessions_formation(), attempts=3)
            if not isinstance(all_sessions, list):
                return sessions
            matched = []
            for sess in all_sessions:
                prof_values = _extract_session_professor_candidates(sess)
                if prof_values.intersection(candidate_ids):
                    matched.append(sess)
            return matched

        try:
            sessions = _retry_external_call(lambda: mgmt.list_my_professor_sessions(bearer_token=token.strip()))
            if not isinstance(sessions, list):
                sessions = []
            sessions = _resolve_sessions_without_relogin(sessions)
            selected_session_id = request.GET.get('session_id')
            selected_session = None
            if selected_session_id:
                selected_session = next((s for s in sessions if str(s.get("id")) == str(selected_session_id)), None)
            if not selected_session and sessions:
                selected_session = next((s for s in sessions if _is_live_like_session(s)), None) or sessions[0]

            selected_students = []
            if selected_session and selected_session.get("id"):
                details = _retry_external_call(
                    lambda: mgmt.get_my_professor_session_detail(str(selected_session.get("id")), bearer_token=token.strip()),
                    attempts=4,
                )
                selected_students = details.get("etudiants") if isinstance(details, dict) else []
                if not isinstance(selected_students, list):
                    selected_students = []
            selected_students, online_students_count = _enrich_external_students_with_presence(selected_students)

            external_live_state = None
            if selected_session and selected_session.get("id"):
                try:
                    external_live_state = mgmt.get_session_live_state(str(selected_session.get("id")), bearer_token=token.strip())
                except Exception as exc:
                    logger.warning("Could not load live state for professor dashboard: %s", exc)

            bans = []
            if selected_session and selected_session.get("id"):
                try:
                    bans = list(
                        ExternalLiveSessionBan.objects.filter(session_id=str(selected_session.get("id")), active=True)
                        .select_related("user", "created_by")
                        .order_by("-updated_at")[:200]
                    )
                except Exception:
                    bans = []

            context = {
                'external_professor_mode': True,
                'external_sessions': sessions if isinstance(sessions, list) else [],
                'external_selected_session': selected_session,
                'external_students': selected_students,
                'external_bans': bans,
                'online_students_count': online_students_count,
                'external_live_state': external_live_state if isinstance(external_live_state, dict) else None,
                'students_count': len(selected_students),
                'all_sessions': [],
                'selected_session': None,
                'recent_comments': [],
                'active_streams': [],
                'notifications': [],
                'upcoming_sessions': [],
                'active_sessions': [],
            }
            return render(request, 'Prolean/professor/dashboard.html', context)
        except Exception as exc:
            if _is_barka_token_expired(exc):
                try:
                    request.session.pop("barka_token", None)
                    request.session.pop("barka_permissions", None)
                except Exception:
                    pass
                logout(request)
                messages.warning(request, "Session expired. Please login again.")
                return redirect("Prolean:login")
            logger.warning("External professor dashboard unavailable: %s", exc)
            context = {
                'external_professor_mode': True,
                'external_sessions': [],
                'external_selected_session': None,
                'external_students': [],
                'external_bans': [],
                'online_students_count': 0,
                'external_live_state': None,
                'external_error': str(exc),
                'students_count': 0,
                'all_sessions': [],
                'selected_session': None,
                'recent_comments': [],
                'active_streams': [],
                'notifications': [],
                'upcoming_sessions': [],
                'active_sessions': [],
            }
            return render(request, 'Prolean/professor/dashboard.html', context)

    prof_profile = get_object_or_404(ProfessorProfile, profile=request.user.profile)
    
    # Get all potential sessions for this professor
    all_sessions = Session.objects.filter(
        professor=prof_profile,
        is_active=True
    ).prefetch_related('formations').order_by('-start_date')
    
    # Identify the current/selected session
    selected_session_id = request.GET.get('session_id')
    selected_session = None
    
    if selected_session_id:
        selected_session = all_sessions.filter(id=selected_session_id).first()
    
    if not selected_session:
        # Default to the most recent/active session
        now = timezone.now().date()
        selected_session = all_sessions.filter(start_date__lte=now, end_date__gte=now).first()
        if not selected_session:
            selected_session = all_sessions.first()
            
    # Scoped Data
    students_count = 0
    online_students_count = 0
    recent_questions = []
    active_streams = []
    upcoming_sessions = all_sessions.filter(start_date__gt=timezone.now().date())
    active_sessions = all_sessions.filter(status='ONGOING')
    
    if selected_session:
        # Students in THIS session
        students_count = selected_session.students.count()
        online_now = get_online_students()
        if online_now:
            selected_user_ids = selected_session.students.values_list("profile__user_id", flat=True)
            online_students_count = sum(1 for user_id in selected_user_ids if int(user_id) in online_now)
        
        # Comments on THIS session's topics (scoped to session)
        recent_questions = Question.objects.filter(
            student__session=selected_session,
            is_deleted=False
        ).order_by('-created_at')[:5]
        
        # Active streams for THIS session
        active_streams = Live.objects.filter(
            session=selected_session,
            is_active=True
        ).prefetch_related('session__formations')

    # notifications filtering
    notifications = Notification.objects.filter(
        user=request.user, 
        is_read=False
    ).filter(
        Q(session=selected_session) | Q(session__isnull=True)
    )[:5]

    context = {
        'prof_profile': prof_profile,
        'all_sessions': all_sessions,
        'selected_session': selected_session,
        'students_count': students_count,
        'online_students_count': online_students_count,
        'recent_comments': recent_questions,
        'active_streams': active_streams,
        'trainings': Training.objects.filter(sessions__professor=prof_profile).distinct(),
        'notifications': notifications,
        'upcoming_sessions': upcoming_sessions,
        'active_sessions': active_sessions,
        'current_time': timezone.now(),
    }
    return render(request, 'Prolean/professor/dashboard.html', context)


@professor_required
@require_POST
def external_professor_live_start(request, session_id):
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if not (mgmt.is_configured() and isinstance(token, str) and token.strip()):
        messages.error(request, "Live controls are unavailable: external authority token is missing.")
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")

    try:
        mgmt.start_session_live(str(session_id), bearer_token=token.strip())
        try:
            cache.delete(f"prolean:external_live_ended_at:{session_id}")
            cache.delete(f"prolean:external_live_stats:{session_id}")
        except Exception:
            pass
        messages.success(request, "Live started successfully.")
        return redirect('Prolean:external_live_room', session_id=str(session_id))
    except Exception as exc:
        messages.error(request, f"Unable to start live: {exc}")
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_professor_live_pause(request, session_id):
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if not (mgmt.is_configured() and isinstance(token, str) and token.strip()):
        messages.error(request, "Live controls are unavailable: external authority token is missing.")
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")

    try:
        mgmt.pause_session_live(str(session_id), bearer_token=token.strip())
        messages.success(request, "Live paused successfully.")
    except Exception as exc:
        messages.error(request, f"Unable to pause live: {exc}")
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_professor_live_end(request, session_id):
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if not (mgmt.is_configured() and isinstance(token, str) and token.strip()):
        messages.error(request, "Live controls are unavailable: external authority token is missing.")
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")

    recording_url = str(request.POST.get("recording_url", "") or "").strip() or None
    try:
        mgmt.end_session_live(str(session_id), bearer_token=token.strip(), recording_url=recording_url)
        try:
            cache.set(
                f"prolean:external_live_ended_at:{session_id}",
                timezone.now().isoformat(),
                timeout=60 * 60 * 24,
            )
        except Exception:
            pass
        messages.success(request, "Live ended successfully.")
    except Exception as exc:
        messages.error(request, f"Unable to end live: {exc}")
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_send_session_notification(request, session_id):
    """
    Professor broadcast to students of an external (Barka) session.
    Creates local Notification rows for all matched local student accounts.
    """
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if not (mgmt.is_configured() and isinstance(token, str) and token.strip()):
        messages.error(request, "Broadcast unavailable: external authority token is missing.")
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")

    title = str(request.POST.get("title", "") or "").strip()
    body = str(request.POST.get("message", "") or "").strip()
    notif_type = str(request.POST.get("type", "info") or "info").strip().lower()
    if notif_type not in {"info", "success", "warning", "error"}:
        notif_type = "info"

    if not title or not body:
        messages.error(request, "Title and message are required.")
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")

    try:
        details = mgmt.get_my_professor_session_detail(str(session_id), bearer_token=token.strip())
        external_students = details.get("etudiants") if isinstance(details, dict) else []
        if not isinstance(external_students, list):
            external_students = []
    except Exception as exc:
        messages.error(request, f"Unable to load session students: {exc}")
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")

    all_students = Profile.objects.filter(role="STUDENT").select_related("user")
    local_lookup: dict[str, User] = {}
    for profile in all_students:
        values = [
            profile.user.username,
            profile.user.email,
            profile.full_name,
            profile.phone_number,
            profile.cin_or_passport,
        ]
        for value in values:
            normalized = _norm_identifier(value)
            if normalized and normalized not in local_lookup:
                local_lookup[normalized] = profile.user

    target_user_ids: set[int] = set()
    unmatched_count = 0
    for ext_student in external_students:
        found = False
        for ident in _extract_external_student_identifiers(ext_student):
            user = local_lookup.get(ident)
            if user:
                target_user_ids.add(int(user.id))
                found = True
                break
        if not found:
            unmatched_count += 1

    if not target_user_ids:
        messages.warning(request, "No local student accounts matched this external session.")
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")

    link = reverse('Prolean:external_live_room', kwargs={'session_id': str(session_id)})
    notifications = [
        Notification(
            user_id=user_id,
            session=None,
            title=title,
            message=body,
            notification_type=notif_type,
            link=link,
        )
        for user_id in sorted(target_user_ids)
    ]
    Notification.objects.bulk_create(notifications)

    if unmatched_count:
        messages.warning(
            request,
            f"Broadcast sent to {len(notifications)} students. {unmatched_count} students could not be matched to local accounts.",
        )
    else:
        messages.success(request, f"Broadcast sent to {len(notifications)} students.")
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@login_required
@require_POST
def presence_heartbeat(request):
    """Keep user's online presence fresh for professor dashboards."""
    payload = {}
    try:
        payload = json.loads(request.body or "{}")
    except Exception:
        payload = {}
    touch_user_presence(
        request.user,
        path=str(payload.get("path") or request.path or "")[:255],
        session_id=str(payload.get("session_id") or "")[:64],
    )
    return JsonResponse({"status": "success"})


@professor_required
@require_POST
def external_live_join_invite_regen(request, session_id):
    """Professor generates/regenerates a one-time join link for a student (by CIN)."""
    session_id = str(session_id or "").strip()
    if not session_id:
        return JsonResponse({"ok": False, "error": "Missing session_id."}, status=400)

    payload = {}
    try:
        payload = json.loads(request.body or "{}")
    except Exception:
        payload = {}

    cin = _norm_cin(payload.get("cin") or payload.get("student_cin") or payload.get("username") or "")
    if not cin:
        return JsonResponse({"ok": False, "error": "Missing student CIN."}, status=400)

    student_name = str(payload.get("name") or payload.get("full_name") or payload.get("student_name") or "").strip()[:120]
    student_email = str(payload.get("email") or payload.get("student_email") or "").strip()[:254]
    student_phone = str(payload.get("phone") or payload.get("student_phone") or "").strip()[:50]

    now = timezone.now()
    ttl_seconds = _external_live_one_click_ttl_seconds()
    expires_at = now + timedelta(seconds=ttl_seconds)
    try:
        ExternalLiveJoinInvite.objects.filter(
            session_id=session_id,
            student_cin=cin,
            revoked_at__isnull=True,
            used_at__isnull=True,
            expires_at__gt=now,
        ).update(revoked_at=now)
    except Exception:
        pass

    raw = secrets.token_urlsafe(32)
    token_hash = _hash_external_live_join_token(raw)
    inv = None
    tracking_mode = "db"
    try:
        inv = ExternalLiveJoinInvite.objects.create(
            session_id=session_id,
            student_cin=cin,
            student_name=student_name,
            student_email=student_email,
            student_phone=student_phone,
            token_hash=token_hash,
            created_by=request.user,
            expires_at=expires_at,
        )
    except Exception as exc:
        logger.exception("Join invite DB create failed, using cache fallback: %s", exc)
        tracking_mode = "cache"
        cache.set(
            _external_live_join_fallback_key(token_hash),
            {
                "session_id": session_id,
                "student_cin": cin,
                "student_name": student_name,
                "student_email": student_email,
                "student_phone": student_phone,
                "expires_at": expires_at.isoformat(),
            },
            timeout=ttl_seconds,
        )
    join_url = request.build_absolute_uri(reverse("Prolean:external_live_join_with_token", kwargs={"token": raw}))
    return JsonResponse(
        {
            "ok": True,
            "join_url": join_url,
            "expires_at": (inv.expires_at.isoformat() if inv else expires_at.isoformat()),
            "session_id": session_id,
            "student_cin": cin,
            "tracking_mode": tracking_mode,
        }
    )


@professor_required
def external_live_join_invite_list(request, session_id):
    """List join invites for a session (raw tokens are never returned)."""
    session_id = str(session_id or "").strip()
    if not session_id:
        return JsonResponse({"ok": False, "error": "Missing session_id."}, status=400)
    now = timezone.now()
    rows = []
    for inv in ExternalLiveJoinInvite.objects.filter(session_id=session_id).order_by("-created_at")[:1000]:
        status = "unused"
        if inv.revoked_at:
            status = "revoked"
        elif inv.used_at:
            status = "used"
        elif inv.expires_at and inv.expires_at <= now:
            status = "expired"
        rows.append(
            {
                "id": int(inv.id),
                "student_cin": inv.student_cin,
                "student_name": inv.student_name,
                "status": status,
                "created_at": inv.created_at.isoformat() if inv.created_at else None,
                "expires_at": inv.expires_at.isoformat() if inv.expires_at else None,
                "used_at": inv.used_at.isoformat() if inv.used_at else None,
                "device": inv.used_device_label,
                "browser": inv.used_browser,
                "os": inv.used_os,
                "device_type": inv.used_device_type,
                "ip": inv.used_ip,
                "location": inv.used_location,
            }
        )
    return JsonResponse(
        {
            "ok": True,
            "session_id": session_id,
            "rows": rows,
            "server_time": now.isoformat(),
        }
    )


def external_live_join_with_token(request, token):
    """Consume a one-time token and redirect to external live room."""
    raw = str(token or "").strip()
    ip_address = get_client_ip(request)
    location_payload = get_location_from_ip(ip_address)
    city = str((location_payload or {}).get("city") or "").strip()
    country = str((location_payload or {}).get("country") or "").strip()
    location_label = ", ".join([p for p in (city, country) if p])[:160]
    if _is_probably_link_preview(request):
        try:
            ExternalLiveJoinAttempt.objects.create(
                status="preview_bot",
                ip_address=ip_address,
                location=location_label,
                user_agent=str(request.META.get("HTTP_USER_AGENT", "") or "")[:800],
                detail="preview/prefetch",
            )
        except Exception:
            pass
        if str(getattr(request, "method", "") or "").upper() == "HEAD":
            return HttpResponse("")
        return HttpResponse(
            "<!doctype html><html><head><meta charset='utf-8'/>"
            "<meta name='robots' content='noindex,nofollow'/>"
            "<title>Join live</title></head><body>Join live session</body></html>",
            content_type="text/html; charset=utf-8",
            status=200,
        )

    allowed, remaining = RateLimiter.check_rate_limit(ip_address, "external_live_join_with_token", limit=20, period_minutes=1)
    if not allowed:
        try:
            ExternalLiveJoinAttempt.objects.create(
                status="rate_limited",
                ip_address=ip_address,
                location=location_label,
                user_agent=str(request.META.get("HTTP_USER_AGENT", "") or "")[:800],
                detail=f"retry_after={remaining}",
            )
        except Exception:
            pass
        return render(
            request,
            "Prolean/live/join_link_message.html",
            {
                "title": "Too many attempts",
                "message": "Please wait a moment and try again.",
                "cta_label": "Go to home",
                "cta_url": reverse("Prolean:home"),
            },
            status=429,
        )

    if not raw or len(raw) < 10:
        try:
            ExternalLiveJoinAttempt.objects.create(
                status="invalid",
                ip_address=ip_address,
                location=location_label,
                user_agent=str(request.META.get("HTTP_USER_AGENT", "") or "")[:800],
                detail="missing_or_short",
            )
        except Exception:
            pass
        return render(
            request,
            "Prolean/live/join_link_message.html",
            {
                "title": "Invalid link",
                "message": "This join link is invalid. Ask your professor to regenerate it.",
                "cta_label": "Go to home",
                "cta_url": reverse("Prolean:home"),
            },
            status=400,
        )

    token_hash = _hash_external_live_join_token(raw)
    now = timezone.now()
    device_label, user_agent, ch_platform, ch_mobile = _device_label_from_request(request)
    browser, os_name, device_type = _parse_device_from_ua(user_agent)

    inv = None
    fallback_mode = False
    user = None
    cin = ""
    session_id = ""
    expires_at = None
    fallback_entry = cache.get(_external_live_join_fallback_key(token_hash))
    with transaction.atomic():
        inv = ExternalLiveJoinInvite.objects.select_for_update().filter(token_hash=token_hash).first()
        if not inv and isinstance(fallback_entry, dict):
            used_key = f"{_external_live_join_fallback_key(token_hash)}:used"
            first_use = cache.add(used_key, "1", timeout=max(60, _external_live_one_click_ttl_seconds()))
            if not first_use:
                return render(
                    request,
                    "Prolean/live/join_link_message.html",
                    {
                        "title": "Link already used",
                        "message": "This join link was already used. Ask your professor to regenerate it.",
                        "cta_label": "Go to home",
                        "cta_url": reverse("Prolean:home"),
                    },
                    status=400,
                )
            fallback_mode = True
            cin = _norm_cin(fallback_entry.get("student_cin"))
            session_id = str(fallback_entry.get("session_id") or "").strip()
            exp_raw = str(fallback_entry.get("expires_at") or "").strip()
            if exp_raw:
                try:
                    expires_at = timezone.datetime.fromisoformat(exp_raw)
                    if timezone.is_naive(expires_at):
                        expires_at = timezone.make_aware(expires_at, timezone.get_current_timezone())
                except Exception:
                    expires_at = now + timedelta(seconds=_external_live_one_click_ttl_seconds())
            else:
                expires_at = now + timedelta(seconds=_external_live_one_click_ttl_seconds())
            if not cin or not session_id or (expires_at and expires_at <= now):
                return render(
                    request,
                    "Prolean/live/join_link_message.html",
                    {
                        "title": "Invalid or expired link",
                        "message": "This join link is invalid or expired. Ask your professor to regenerate it.",
                        "cta_label": "Go to home",
                        "cta_url": reverse("Prolean:home"),
                    },
                    status=400,
                )
            user, _ = User.objects.get_or_create(username=cin)
            fb_name = str(fallback_entry.get("student_name") or "").strip()[:120]
            fb_email = str(fallback_entry.get("student_email") or "").strip()[:254]
            fb_phone = str(fallback_entry.get("student_phone") or "").strip()[:50]
            if fb_email and not user.email:
                user.email = fb_email
                user.save(update_fields=["email"])
            try:
                profile = user.profile
                profile.role = "STUDENT"
                profile.status = "ACTIVE"
                if fb_name:
                    profile.full_name = fb_name
                if not profile.cin_or_passport:
                    profile.cin_or_passport = cin
                if fb_phone and not profile.phone_number:
                    profile.phone_number = fb_phone
                profile.save()
            except Exception:
                pass
            cache.delete(_external_live_join_fallback_key(token_hash))
        elif not inv:
            try:
                ExternalLiveJoinAttempt.objects.create(
                    status="invalid",
                    token_hash=token_hash,
                    ip_address=ip_address,
                    location=location_label,
                    user_agent=user_agent,
                    detail="not_found",
                )
            except Exception:
                pass
            return render(
                request,
                "Prolean/live/join_link_message.html",
                {
                    "title": "Invalid or expired link",
                    "message": "This join link is invalid or expired. Ask your professor to regenerate it.",
                    "cta_label": "Go to home",
                    "cta_url": reverse("Prolean:home"),
                },
                status=400,
            )

        if inv:
            cin = _norm_cin(inv.student_cin)
            session_id = str(inv.session_id or "").strip()
            expires_at = inv.expires_at
        if inv and inv.revoked_at:
            status = "revoked"
            message = "This join link was revoked. Ask your professor to regenerate it."
            title = "Link revoked"
        elif inv and inv.expires_at and inv.expires_at <= now:
            status = "expired"
            message = "This join link is expired. Ask your professor to regenerate it."
            title = "Link expired"
        elif inv and inv.used_at:
            status = "used"
            message = "This join link was already used. Ask your professor to regenerate it."
            title = "Link already used"
        elif not cin:
            status = "error"
            message = "This join link is invalid. Ask your professor to regenerate it."
            title = "Invalid link"
        else:
            status = ""

        if status:
            try:
                ExternalLiveJoinAttempt.objects.create(
                    invite=inv,
                    status=status,
                    session_id=session_id,
                    student_cin=(inv.student_cin if inv else cin),
                    user=(inv.user if inv else user),
                    token_hash=token_hash,
                    ip_address=ip_address,
                    location=location_label,
                    user_agent=user_agent,
                )
            except Exception:
                pass
            return render(
                request,
                "Prolean/live/join_link_message.html",
                {
                    "title": title,
                    "message": message,
                    "cta_label": "Go to home",
                    "cta_url": reverse("Prolean:home"),
                },
                status=400,
            )

        if inv:
            user = inv.user
        if inv and not user:
            user, _ = User.objects.get_or_create(username=cin)
            if inv.student_email and not user.email:
                user.email = inv.student_email
                user.save(update_fields=["email"])
            try:
                profile = user.profile
                profile.role = "STUDENT"
                profile.status = "ACTIVE"
                if inv.student_name:
                    profile.full_name = inv.student_name
                if not profile.cin_or_passport:
                    profile.cin_or_passport = cin
                if inv.student_phone and not profile.phone_number:
                    profile.phone_number = inv.student_phone
                profile.save()
            except Exception:
                pass
            inv.user = user
            inv.save(update_fields=["user"])

    # Access check before consuming token to avoid burning link on denied access.
    mgmt = ManagementContractClient()
    if mgmt.is_configured():
        service_token = str(mgmt.get_service_bearer_token() or "").strip()
        if service_token:
            try:
                live_state = mgmt.get_session_live_state_for_student(
                    str(session_id),
                    student_cin=cin,
                    bearer_token=service_token,
                )
                if live_state is None:
                    return render(
                        request,
                        "Prolean/live/join_link_message.html",
                        {
                            "title": "Live not started",
                            "message": "No live stream is active for this session yet. Ask your professor to start the live, then try again.",
                            "cta_label": "Go to home",
                            "cta_url": reverse("Prolean:home"),
                        },
                        status=404,
                    )
            except UpstreamUnavailable:
                return render(
                    request,
                    "Prolean/live/join_link_message.html",
                    {
                        "title": "Live temporarily unavailable",
                        "message": "The live authority service is temporarily unavailable. Please try again in a moment.",
                        "cta_label": "Go to home",
                        "cta_url": reverse("Prolean:home"),
                    },
                    status=503,
                )
            except ContractError as exc:
                detail = str(exc or "")
                lowered = detail.lower()
                # If the contract does not support /live/access yet, fail with a clear message.
                if " 404" in lowered or "not found" in lowered or "cannot post" in lowered:
                    return render(
                        request,
                        "Prolean/live/join_link_message.html",
                        {
                            "title": "Live service update required",
                            "message": "The live access endpoint is unavailable right now. Ask admin to redeploy Barka API, then try your join link again.",
                            "cta_label": "Go to home",
                            "cta_url": reverse("Prolean:home"),
                        },
                        status=503,
                    )
                else:
                    msg = "Access denied for this session. Verify your enrollment (CIN) with your professor."
                    if "access denied" in lowered or "not enrolled" in lowered or "enrolled" in lowered:
                        msg = "You are not enrolled in this session (CIN mismatch or not assigned). Ask your professor to verify your enrollment."
                    return render(
                        request,
                        "Prolean/live/join_link_message.html",
                        {
                            "title": "Unable to join live",
                            "message": msg,
                            "cta_label": "Go to home",
                            "cta_url": reverse("Prolean:home"),
                        },
                        status=403,
                    )
            except Exception:
                return render(
                    request,
                    "Prolean/live/join_link_message.html",
                    {
                        "title": "Unable to join live",
                        "message": "Access denied for this session. Ask your professor to regenerate the link or verify your enrollment.",
                        "cta_label": "Go to home",
                        "cta_url": reverse("Prolean:home"),
                    },
                    status=403,
                )

    if inv and not fallback_mode:
        with transaction.atomic():
            locked = ExternalLiveJoinInvite.objects.select_for_update().filter(id=getattr(inv, "id", None)).first()
            if not locked or locked.revoked_at or locked.used_at or (locked.expires_at and locked.expires_at <= timezone.now()):
                try:
                    ExternalLiveJoinAttempt.objects.create(
                        invite=locked or inv,
                        status="used",
                        session_id=session_id,
                        student_cin=str(getattr(locked or inv, "student_cin", "") or ""),
                        user=user,
                        token_hash=token_hash,
                        ip_address=ip_address,
                        location=location_label,
                        user_agent=user_agent,
                        detail="race_or_reuse",
                    )
                except Exception:
                    pass
                return render(
                    request,
                    "Prolean/live/join_link_message.html",
                    {
                        "title": "Link already used",
                        "message": "This join link was already used. Ask your professor to regenerate it.",
                        "cta_label": "Go to home",
                        "cta_url": reverse("Prolean:home"),
                    },
                    status=400,
                )

            locked.used_at = now
            locked.used_user_agent = user_agent
            locked.used_device_label = device_label
            locked.used_sec_ch_platform = ch_platform
            locked.used_sec_ch_mobile = ch_mobile
            locked.used_ip = str(ip_address or "")[:64]
            locked.used_location = location_label
            locked.used_browser = browser
            locked.used_os = os_name
            locked.used_device_type = device_type
            locked.user = user
            locked.save()
            try:
                ExternalLiveJoinAttempt.objects.create(
                    invite=locked,
                    status="success",
                    session_id=locked.session_id,
                    student_cin=locked.student_cin,
                    user=user,
                    token_hash=token_hash,
                    ip_address=ip_address,
                    location=location_label,
                    user_agent=user_agent,
                )
            except Exception:
                pass
    elif fallback_mode:
        try:
            ExternalLiveJoinAttempt.objects.create(
                status="success",
                session_id=session_id,
                student_cin=cin,
                user=user,
                token_hash=token_hash,
                ip_address=ip_address,
                location=location_label,
                user_agent=user_agent,
                detail="cache_fallback",
            )
        except Exception:
            pass

    # Switch to the correct student account.
    try:
        if request.user.is_authenticated and request.user.id != user.id:
            logout(request)
        login(request, user)
    except Exception:
        return redirect("Prolean:login")

    _grant_external_live_service_access(request, session_id, cin=cin, expires_at=expires_at)
    return redirect("Prolean:external_live_room", session_id=str(session_id))


@login_required
def external_live_room(request, session_id):
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if not mgmt.is_configured():
        messages.error(request, "Live is unavailable: external authority is not configured.")
        return redirect("Prolean:dashboard")

    bearer_token = token.strip() if isinstance(token, str) and token.strip() else ""
    service_cin, _exp = _get_external_live_service_access(request, str(session_id))
    service_mode = bool((not bearer_token) and service_cin)
    service_token = ""
    if service_mode:
        service_token = str(mgmt.get_service_bearer_token() or "").strip()
        if not service_token:
            messages.error(request, "Live is unavailable: please login again.")
            return redirect("Prolean:login")

    if not bearer_token and not service_mode:
        messages.error(request, "Live is unavailable: please login first or use a join link.")
        return redirect("Prolean:dashboard")

    if hasattr(request.user, "profile") and request.user.profile.role != "PROFESSOR":
        banned, reason = _is_user_banned_from_external_session(str(session_id), request.user)
        if banned:
            msg = "You are banned from this live session."
            if reason:
                msg = f"{msg} ({reason})"
            messages.error(request, msg)
            return redirect('Prolean:dashboard')

    try:
        def _is_transient_external_error(exc: Exception) -> bool:
            msg = str(exc).lower()
            transient_tokens = (
                "502", "503", "504", "595",
                "bad gateway", "temporarily unavailable", "upstream",
                "timeout", "timed out", "connection reset",
            )
            return any(tok in msg for tok in transient_tokens)

        def _norm(value) -> str:
            return str(value or "").strip()

        def _extract_professor_hints(source: dict) -> tuple[str, str]:
            if not isinstance(source, dict):
                return "", ""
            identity = ""
            name = ""
            identity_keys = (
                "professor_identity", "presenter_identity", "host_identity", "owner_identity",
                "professor_username", "presenter_username", "host_username", "owner_username",
                "professor_cin", "presenter_cin", "host_cin", "owner_cin",
            )
            name_keys = ("professor_name", "presenter_name", "host_name", "owner_name")
            for key in identity_keys:
                value = _norm(source.get(key))
                if value:
                    identity = value
                    break
            for key in name_keys:
                value = _norm(source.get(key))
                if value:
                    name = value
                    break
            nested = source.get("professor") or source.get("presenter") or source.get("host") or source.get("owner")
            if isinstance(nested, dict):
                if not identity:
                    for key in ("username", "cin", "cin_or_passport", "id"):
                        value = _norm(nested.get(key))
                        if value:
                            identity = value
                            break
                if not name:
                    name = _norm(nested.get("full_name") or nested.get("name"))
            return identity, name

        payload = None
        last_exc = None
        if service_mode:
            try:
                live_state = mgmt.get_session_live_state_for_student(
                    str(session_id),
                    student_cin=service_cin,
                    bearer_token=service_token,
                )
            except ContractError as exc:
                detail = str(exc or "")
                lowered = detail.lower()
                if " 404" in lowered or "not found" in lowered or "cannot post" in lowered:
                    raise ContractError("Live access endpoint is unavailable. Ask admin to redeploy Barka API.")
                raise
            if not isinstance(live_state, dict):
                raise ContractError("Live is not available for this session yet.")
            payload = {"live": live_state, "role": "student"}
        else:
            for attempt in range(6):
                try:
                    payload = mgmt.join_session_live(str(session_id), bearer_token=bearer_token)
                    break
                except UpstreamUnavailable as exc:
                    last_exc = exc
                    if attempt >= 5:
                        raise
                    sleep(0.6 * (attempt + 1))
                except ContractError as exc:
                    is_transient = _is_transient_external_error(exc)
                    if not is_transient or attempt >= 5:
                        raise
                    last_exc = exc
                    sleep(0.6 * (attempt + 1))

            if payload is None and last_exc is not None:
                raise last_exc

        live = payload.get("live") if isinstance(payload, dict) else None
        role = payload.get("role") if isinstance(payload, dict) else "student"
        if not isinstance(live, dict):
            raise ContractError("Invalid live join payload.")
        room_name = str(live.get("room_name") or f"session_{session_id}").strip()
        if not room_name:
            room_name = f"session_{session_id}"

        app_id = str(getattr(settings, "AGORA_APP_ID", "") or "").strip()
        app_certificate = str(getattr(settings, "AGORA_APP_CERTIFICATE", "") or "").strip()
        missing = []
        if not app_id:
            missing.append("AGORA_APP_ID")
        if not app_certificate:
            missing.append("AGORA_APP_CERTIFICATE")
        if missing:
            raise ContractError(f"Agora configuration is missing on backend ({', '.join(missing)}).")

        role_text = str(role or "").strip().lower()
        is_professor = role_text == "professor"
        # Fixed UID strategy to make role detection deterministic in the client:
        # professor camera uid = 1, professor screen-share uid = 1001.
        if is_professor:
            agora_uid = 1
        else:
            base_uid = int(getattr(request.user, "id", 0) or 0)
            agora_uid = 10000 + base_uid
            if agora_uid in (1, 1001):
                agora_uid += 10000

        expiry = int(time.time()) + int(getattr(settings, "AGORA_TOKEN_EXPIRY_SECONDS", 3600) or 3600)
        agora_token = RtcTokenBuilder.buildTokenWithUid(
            app_id,
            app_certificate,
            room_name,
            int(agora_uid),
            1,  # publisher (host) for both professor and students (students can share camera)
            expiry,
        )
        agora_screen_token = ""
        if is_professor:
            agora_screen_token = RtcTokenBuilder.buildTokenWithUid(
                app_id,
                app_certificate,
                room_name,
                1001,
                1,
                expiry,
            )

        professor_identity_hint, professor_name_hint = _extract_professor_hints(payload if isinstance(payload, dict) else {})
        if (not professor_identity_hint or not professor_name_hint) and isinstance(live, dict):
            p2, n2 = _extract_professor_hints(live)
            if not professor_identity_hint:
                professor_identity_hint = p2
            if not professor_name_hint:
                professor_name_hint = n2
        if not professor_identity_hint or not professor_name_hint:
            try:
                detail = mgmt.get_session_formation_detail(str(session_id), bearer_token=token.strip())
                p3, n3 = _extract_professor_hints(detail if isinstance(detail, dict) else {})
                if not professor_identity_hint:
                    professor_identity_hint = p3
                if not professor_name_hint:
                    professor_name_hint = n3
            except Exception:
                pass

        touch_user_presence(request.user, path=request.path, session_id=str(session_id))
        try:
            # If the live is joinable, clear any stale "ended" flag so clients don't auto-exit.
            cache.delete(f"prolean:external_live_ended_at:{session_id}")
        except Exception:
            pass
        return render(request, 'Prolean/live/external_live_room.html', {
            "session_id": str(session_id),
            "live_state": live,
            "agora_app_id": app_id,
            "agora_channel": room_name,
            "agora_token": agora_token,
            "agora_screen_token": agora_screen_token,
            "agora_uid": int(agora_uid),
            "professor_uid_hint": 1,
            "live_role": str(role),
            "professor_identity_hint": professor_identity_hint,
            "professor_name_hint": professor_name_hint,
        })
    except Exception as exc:
        if _is_barka_token_expired(exc):
            try:
                request.session.pop("barka_token", None)
                request.session.pop("barka_permissions", None)
            except Exception:
                pass
            messages.warning(request, "Session expired. Please login again.")
            return redirect("Prolean:login")
        text = str(exc or "")
        if "/live/access" in text.lower() and ("cannot post" in text.lower() or "404" in text.lower()):
            text = "Live access endpoint is unavailable. Ask admin to redeploy Barka API."
        messages.error(request, f"Unable to join live: {text}")
        if hasattr(request.user, "profile") and request.user.profile.role == "PROFESSOR":
            return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")
        return redirect('Prolean:dashboard')


@login_required
@require_POST
def external_live_leave(request, session_id):
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if mgmt.is_configured() and isinstance(token, str) and token.strip():
        try:
            mgmt.leave_session_live(str(session_id), bearer_token=token.strip())
        except Exception as exc:
            logger.warning("External live leave failed for session %s: %s", session_id, exc)

    if hasattr(request.user, "profile") and request.user.profile.role == "PROFESSOR":
        return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")
    return redirect('Prolean:dashboard')


@login_required
def external_live_status(request, session_id):
    ended_at = None
    try:
        ended_at = cache.get(f"prolean:external_live_ended_at:{session_id}")
    except Exception:
        ended_at = None

    # Confirm live state with the external authority to avoid stale cache forcing exits.
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    live_state = None
    if mgmt.is_configured():
        bearer = token.strip() if isinstance(token, str) and token.strip() else ""
        if bearer:
            try:
                live_state = mgmt.get_session_live_state(str(session_id), bearer_token=bearer)
            except Exception:
                live_state = None
        else:
            cin, _exp = _get_external_live_service_access(request, str(session_id))
            if cin:
                try:
                    service_token = str(mgmt.get_service_bearer_token() or "").strip()
                    if service_token:
                        live_state = mgmt.get_session_live_state_for_student(
                            str(session_id),
                            student_cin=cin,
                            bearer_token=service_token,
                        )
                except Exception:
                    live_state = None

    status = str((live_state or {}).get("status") or "").strip().lower() if isinstance(live_state, dict) else ""
    externally_ended = status == "ended"

    if ended_at and not externally_ended and status in {"live", "paused"}:
        try:
            cache.delete(f"prolean:external_live_ended_at:{session_id}")
        except Exception:
            pass
        ended_at = None

    banned = False
    ban_reason = ""
    if hasattr(request.user, "profile") and request.user.profile.role != "PROFESSOR":
        banned, ban_reason = _is_user_banned_from_external_session(str(session_id), request.user)

    mic_locked = False
    if hasattr(request.user, "profile") and request.user.profile.role != "PROFESSOR":
        try:
            key_all = f"prolean:external_live_mic_lock_all:{session_id}"
            key_user = f"prolean:external_live_mic_lock_user:{session_id}:{request.user.id}"
            mic_locked = bool(cache.get(key_all) or cache.get(key_user))
        except Exception:
            mic_locked = False

    return JsonResponse(
        {
            "session_id": str(session_id),
            "ended": bool(ended_at) or externally_ended,
            "ended_at": ended_at,
            "status": status or None,
            "banned": bool(banned),
            "ban_reason": ban_reason or None,
            "mic_locked": bool(mic_locked),
            "server_time": timezone.now().isoformat(),
        }
    )


@professor_required
def external_live_stats_get(request, session_id):
    payload = None
    try:
        payload = cache.get(f"prolean:external_live_stats:{session_id}")
    except Exception:
        payload = None

    if not isinstance(payload, dict):
        rows = ExternalLiveStudentStat.objects.filter(session_id=str(session_id)).select_related("user").order_by("-updated_at")[:300]
        students = []
        for row in rows:
            students.append(
                {
                    "uid": row.agora_uid,
                    "name": row.display_name or (row.user.get_full_name() if row.user else f"Student {row.agora_uid}"),
                    "watch_ms": int(row.watch_seconds) * 1000,
                    "speaking_ms": int(getattr(row, "speaking_seconds", 0) or 0) * 1000,
                    "hand_raised_ms": int(getattr(row, "hand_raised_seconds", 0) or 0) * 1000,
                    "speaks": int(row.speaks),
                    "hands": int(row.hands),
                    "engagement": float(row.engagement),
                }
            )
        payload = {"session_id": str(session_id), "updated_at": None, "students": students}

    payload.setdefault("session_id", str(session_id))
    payload.setdefault("updated_at", None)
    payload.setdefault("students", [])
    return JsonResponse(payload)


@professor_required
@require_POST
def external_live_stats_push(request, session_id):
    incoming = {}
    try:
        incoming = json.loads(request.body or "{}")
    except Exception:
        incoming = {}

    students = incoming.get("students") if isinstance(incoming, dict) else None
    if not isinstance(students, list):
        return JsonResponse({"ok": False, "error": "Invalid stats payload."}, status=400)

    cleaned = []
    for row in students[:300]:
        if not isinstance(row, dict):
            continue
        uid = str(row.get("uid") or "").strip()
        if not uid:
            continue
        cleaned.append(
            {
                "uid": uid,
                "name": str(row.get("name") or f"Student {uid}")[:80],
                "watch_ms": int(row.get("watch_ms") or 0),
                "speaking_ms": int(row.get("speaking_ms") or 0),
                "hand_raised_ms": int(row.get("hand_raised_ms") or 0),
                "speaks": int(row.get("speaks") or 0),
                "hands": int(row.get("hands") or 0),
                "engagement": float(row.get("engagement") or 0),
            }
        )

    payload = {
        "session_id": str(session_id),
        "updated_at": timezone.now().isoformat(),
        "students": cleaned,
    }

    try:
        cache.set(f"prolean:external_live_stats:{session_id}", payload, timeout=60 * 60 * 24)
    except Exception:
        return JsonResponse({"ok": False, "error": "Unable to store stats."}, status=500)

    try:
        ended_at = cache.get(f"prolean:external_live_ended_at:{session_id}")
    except Exception:
        ended_at = None

    if ended_at:
        return JsonResponse({"ok": True, "ended": True})

    # Persist stats in DB for per-student history and professor/students view.
    session_id_str = str(session_id)
    uids = [str(r.get("uid") or "").strip() for r in cleaned]
    existing = ExternalLiveStudentStat.objects.filter(session_id=session_id_str, agora_uid__in=[u for u in uids if u]).select_related("user")
    existing_by_uid = {str(r.agora_uid): r for r in existing}

    users_by_id = {}
    needed_user_ids = set()
    for uid in uids:
        try:
            n = int(uid)
        except Exception:
            continue
        if n >= 10000:
            needed_user_ids.add(n - 10000)
    if needed_user_ids:
        for u in User.objects.filter(id__in=sorted(needed_user_ids)):
            users_by_id[int(u.id)] = u

    for row in cleaned:
        uid = str(row.get("uid") or "").strip()
        if not uid:
            continue
        obj = existing_by_uid.get(uid) or ExternalLiveStudentStat(session_id=session_id_str, agora_uid=uid)

        linked_user = None
        try:
            n = int(uid)
            if n >= 10000:
                linked_user = users_by_id.get(n - 10000)
        except Exception:
            linked_user = None

        if linked_user:
            obj.user = linked_user
            obj.display_name = linked_user.get_full_name() or (linked_user.username or obj.display_name)
        else:
            obj.display_name = str(row.get("name") or obj.display_name or f"Student {uid}")[:80]

        watch_ms = int(row.get("watch_ms") or 0)
        obj.watch_seconds = max(0, int(round(watch_ms / 1000)))
        speaking_ms = int(row.get("speaking_ms") or 0)
        obj.speaking_seconds = max(0, int(round(speaking_ms / 1000)))
        hand_ms = int(row.get("hand_raised_ms") or 0)
        obj.hand_raised_seconds = max(0, int(round(hand_ms / 1000)))
        obj.speaks = max(0, int(row.get("speaks") or 0))
        obj.hands = max(0, int(row.get("hands") or 0))
        obj.engagement = float(row.get("engagement") or 0)
        obj.save()

    return JsonResponse({"ok": True})


def _accepts_json(request) -> bool:
    accept = str(request.headers.get("accept", "") or "").lower()
    return "application/json" in accept


@professor_required
@require_POST
def external_live_mute_user(request, session_id):
    user_id = str(request.POST.get("user_id", "") or "").strip()
    if not user_id:
        return JsonResponse({"ok": False, "error": "Missing user_id."}, status=400)
    try:
        target = User.objects.get(id=int(user_id))
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid user_id."}, status=400)

    try:
        cache.set(f"prolean:external_live_mic_lock_user:{session_id}:{target.id}", True, timeout=60 * 60 * 8)
    except Exception:
        pass

    try:
        ExternalLiveSecurityEvent.objects.create(session_id=str(session_id), actor=request.user, target=target, event_type="mute_user", payload={})
    except Exception:
        pass

    if _accepts_json(request):
        return JsonResponse({"ok": True})
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_live_unmute_user(request, session_id):
    user_id = str(request.POST.get("user_id", "") or "").strip()
    if not user_id:
        return JsonResponse({"ok": False, "error": "Missing user_id."}, status=400)
    try:
        target = User.objects.get(id=int(user_id))
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid user_id."}, status=400)

    try:
        cache.delete(f"prolean:external_live_mic_lock_user:{session_id}:{target.id}")
    except Exception:
        pass

    try:
        ExternalLiveSecurityEvent.objects.create(session_id=str(session_id), actor=request.user, target=target, event_type="unmute_user", payload={})
    except Exception:
        pass

    if _accepts_json(request):
        return JsonResponse({"ok": True})
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_live_mute_all(request, session_id):
    try:
        cache.set(f"prolean:external_live_mic_lock_all:{session_id}", True, timeout=60 * 60 * 8)
    except Exception:
        pass
    try:
        ExternalLiveSecurityEvent.objects.create(session_id=str(session_id), actor=request.user, target=None, event_type="mute_all", payload={})
    except Exception:
        pass
    if _accepts_json(request):
        return JsonResponse({"ok": True})
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_live_unmute_all(request, session_id):
    try:
        cache.delete(f"prolean:external_live_mic_lock_all:{session_id}")
    except Exception:
        pass
    try:
        ExternalLiveSecurityEvent.objects.create(session_id=str(session_id), actor=request.user, target=None, event_type="unmute_all", payload={})
    except Exception:
        pass
    if _accepts_json(request):
        return JsonResponse({"ok": True})
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_live_ban_user(request, session_id):
    user_id = str(request.POST.get("user_id", "") or "").strip()
    reason = str(request.POST.get("reason", "") or "").strip()[:200]
    if not user_id:
        return JsonResponse({"ok": False, "error": "Missing user_id."}, status=400)
    try:
        target = User.objects.get(id=int(user_id))
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid user_id."}, status=400)

    row, _created = ExternalLiveSessionBan.objects.get_or_create(
        session_id=str(session_id),
        user=target,
        defaults={"active": True, "reason": reason, "created_by": request.user},
    )
    if not row.active or (reason and row.reason != reason) or (row.created_by_id is None):
        row.active = True
        if reason:
            row.reason = reason
        if row.created_by_id is None:
            row.created_by = request.user
        row.save(update_fields=["active", "reason", "created_by", "updated_at"])

    try:
        ExternalLiveSecurityEvent.objects.create(
            session_id=str(session_id),
            actor=request.user,
            target=target,
            event_type="ban",
            payload={"reason": reason} if reason else {},
        )
    except Exception:
        pass

    accept = str(request.headers.get("accept", "") or "").lower()
    if "application/json" in accept:
        return JsonResponse({"ok": True})
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@professor_required
@require_POST
def external_live_unban_user(request, session_id):
    user_id = str(request.POST.get("user_id", "") or "").strip()
    if not user_id:
        return JsonResponse({"ok": False, "error": "Missing user_id."}, status=400)
    try:
        target = User.objects.get(id=int(user_id))
    except Exception:
        return JsonResponse({"ok": False, "error": "Invalid user_id."}, status=400)

    ExternalLiveSessionBan.objects.filter(session_id=str(session_id), user=target).update(active=False)
    try:
        ExternalLiveSecurityEvent.objects.create(session_id=str(session_id), actor=request.user, target=target, event_type="unban", payload={})
    except Exception:
        pass
    accept = str(request.headers.get("accept", "") or "").lower()
    if "application/json" in accept:
        return JsonResponse({"ok": True})
    return redirect(f"{reverse('Prolean:professor_dashboard')}?session_id={session_id}")


@login_required
@require_POST
def external_live_event_log(request, session_id):
    payload = {}
    try:
        payload = json.loads(request.body or "{}")
    except Exception:
        payload = {}

    event_type = str((payload or {}).get("event_type") or (payload or {}).get("type") or "").strip()[:60]
    if not event_type:
        return JsonResponse({"ok": False, "error": "Missing event_type."}, status=400)

    target_user_id = (payload or {}).get("target_user_id")
    target = None
    if target_user_id:
        try:
            target = User.objects.get(id=int(target_user_id))
        except Exception:
            target = None

    data = (payload or {}).get("payload")
    if not isinstance(data, dict):
        data = {}

    try:
        ExternalLiveSecurityEvent.objects.create(
            session_id=str(session_id),
            actor=request.user,
            target=target,
            event_type=event_type,
            payload=data,
        )
    except Exception:
        return JsonResponse({"ok": False, "error": "Unable to store event."}, status=500)

    return JsonResponse({"ok": True})

@login_required
def account_status(request):
    """View to display account status (Pending/Suspended)"""
    if not hasattr(request.user, 'profile'):
        return redirect('Prolean:home')
        
    profile = request.user.profile
    
    # If active, no need to be here
    if profile.status == 'ACTIVE':
        return redirect('Prolean:dashboard')
        
    return render(request, 'Prolean/dashboard/account_status.html', {'profile': profile})

@professor_required
def professor_students(request):
    """List students enrolled in professor's sessions - Session-Centric"""
    token = request.session.get("barka_token")
    mgmt = ManagementContractClient()
    if mgmt.is_configured() and isinstance(token, str) and token.strip():
        try:
            sessions = mgmt.list_my_professor_sessions(bearer_token=token.strip())
            session_id = request.GET.get('session_id')
            selected_session = None
            if session_id:
                selected_session = next((s for s in sessions if str(s.get("id")) == str(session_id)), None)
            if not selected_session and sessions:
                selected_session = sessions[0]

            students = []
            if selected_session and selected_session.get("id"):
                details = mgmt.get_my_professor_session_detail(str(selected_session.get("id")), bearer_token=token.strip())
                students = details.get("etudiants") if isinstance(details, dict) else []
                if not isinstance(students, list):
                    students = []
            students, _online = _enrich_external_students_with_presence(students)

            stats_rows = []
            selected_session_id = str(selected_session.get("id")) if isinstance(selected_session, dict) else ""
            if selected_session_id:
                stats_rows = list(
                    ExternalLiveStudentStat.objects.filter(session_id=selected_session_id)
                    .select_related("user")
                    .order_by("-updated_at")[:500]
                )

            stats_by_user_id = {}
            for row in stats_rows:
                if row.user_id:
                    stats_by_user_id[int(row.user_id)] = row

            all_students = Profile.objects.filter(role="STUDENT").select_related("user")
            local_lookup = {}
            for profile in all_students:
                values = [
                    profile.user.username,
                    profile.user.email,
                    profile.full_name,
                    profile.phone_number,
                    profile.cin_or_passport,
                ]
                for value in values:
                    normalized = _norm_identifier(value)
                    if normalized and normalized not in local_lookup:
                        local_lookup[normalized] = profile.user

            for ext_student in students:
                if not isinstance(ext_student, dict):
                    continue
                matched_user = None
                for ident in _extract_external_student_identifiers(ext_student):
                    matched_user = local_lookup.get(ident)
                    if matched_user:
                        break
                stat = stats_by_user_id.get(int(matched_user.id)) if matched_user else None
                watch_seconds = int(getattr(stat, "watch_seconds", 0) or 0)
                minutes = max(0, watch_seconds // 60)
                hours = minutes // 60
                mins = minutes % 60
                watch_label = f"{minutes}m" if hours <= 0 else f"{hours}h {mins}m"

                speaking_seconds = int(getattr(stat, "speaking_seconds", 0) or 0)
                sm = max(0, speaking_seconds // 60)
                sh = sm // 60
                smins = sm % 60
                speaking_label = f"{sm}m" if sh <= 0 else f"{sh}h {smins}m"

                hand_seconds = int(getattr(stat, "hand_raised_seconds", 0) or 0)
                hm = max(0, hand_seconds // 60)
                hh = hm // 60
                hmins = hm % 60
                hand_label = f"{hm}m" if hh <= 0 else f"{hh}h {hmins}m"

                ext_student["tracking_watch_seconds"] = watch_seconds
                ext_student["tracking_watch_label"] = watch_label
                ext_student["tracking_speaking_seconds"] = speaking_seconds
                ext_student["tracking_speaking_label"] = speaking_label
                ext_student["tracking_hand_seconds"] = hand_seconds
                ext_student["tracking_hand_label"] = hand_label
                ext_student["tracking_speaks"] = int(getattr(stat, "speaks", 0) or 0)
                ext_student["tracking_hands"] = int(getattr(stat, "hands", 0) or 0)
                ext_student["tracking_engagement"] = float(getattr(stat, "engagement", 0.0) or 0.0)
                ext_student["tracking_updated_at"] = getattr(stat, "updated_at", None)
                if matched_user:
                    ext_student["local_user_id"] = int(matched_user.id)
                    ext_student["local_full_name"] = matched_user.get_full_name() or matched_user.username
                else:
                    ext_student["local_user_id"] = None
                    ext_student["local_full_name"] = None

            latest_invite_by_cin = {}
            invite_rows = []
            if selected_session_id:
                now = timezone.now()
                try:
                    invites = (
                        ExternalLiveJoinInvite.objects.filter(session_id=selected_session_id)
                        .order_by("-created_at")[:5000]
                    )
                    invite_rows = list(invites[:300])
                    for inv in invites:
                        cin_key = _norm_cin(inv.student_cin)
                        if cin_key and cin_key not in latest_invite_by_cin:
                            status = "unused"
                            if inv.revoked_at:
                                status = "revoked"
                            elif inv.used_at:
                                status = "used"
                            elif inv.expires_at and inv.expires_at <= now:
                                status = "expired"
                            latest_invite_by_cin[cin_key] = {
                                "status": status,
                                "expires_at": inv.expires_at,
                                "used_at": inv.used_at,
                                "used_location": inv.used_location,
                                "used_device": inv.used_device_label,
                                "created_at": inv.created_at,
                            }
                except Exception:
                    latest_invite_by_cin = {}
                    invite_rows = []

            for ext_student in students:
                if not isinstance(ext_student, dict):
                    continue
                cin_key = _norm_cin(ext_student.get("display_cin") or ext_student.get("cin") or ext_student.get("cin_or_passport") or "")
                info = latest_invite_by_cin.get(cin_key, {})
                ext_student["join_invite_status"] = info.get("status", "none")
                ext_student["join_invite_expires_at"] = info.get("expires_at")
                ext_student["join_invite_used_at"] = info.get("used_at")
                ext_student["join_invite_used_location"] = info.get("used_location")
                ext_student["join_invite_used_device"] = info.get("used_device")
                ext_student["join_invite_created_at"] = info.get("created_at")

            attendance_timeline = []
            if selected_session_id:
                now = timezone.now()
                label_by_user_id: dict[int, str] = {}
                for ext_student in students:
                    if not isinstance(ext_student, dict):
                        continue
                    local_user_id = ext_student.get("local_user_id")
                    if local_user_id:
                        label_by_user_id[int(local_user_id)] = str(ext_student.get("display_name") or "Student")

                event_label_map = {
                    "mute_user": "Muted student mic",
                    "unmute_user": "Unmuted student mic",
                    "mute_all": "Muted all microphones",
                    "unmute_all": "Unmuted all microphones",
                    "ban": "Kicked student",
                    "unban": "Allowed student back",
                    "moderate_mute_user": "Muted student mic (studio)",
                    "moderate_unmute_user": "Unmuted student mic (studio)",
                    "moderate_ban": "Kicked student (studio)",
                    "moderate_mute_all": "Muted all mics (studio)",
                    "moderate_unmute_all": "Unmuted all mics (studio)",
                    "forced_mute": "Student mic forced to mute",
                    "forced_unmute": "Student mic forced to unmute",
                    "forced_mute_all": "All mics forced to mute",
                    "forced_unmute_all": "All mics forced to unmute",
                    "security_alert": "Security alert received",
                }
                try:
                    recent_events = list(
                        ExternalLiveSecurityEvent.objects.filter(session_id=selected_session_id)
                        .select_related("actor", "target")
                        .order_by("-created_at")[:200]
                    )
                except Exception:
                    recent_events = []

                for ev in recent_events:
                    actor_label = ""
                    if ev.actor_id:
                        actor_label = str(ev.actor.get_full_name() or ev.actor.username or "").strip()
                    target_label = ""
                    if ev.target_id:
                        target_label = label_by_user_id.get(int(ev.target_id)) or str(ev.target.get_full_name() or ev.target.username or "").strip()
                    event_label = event_label_map.get(str(ev.event_type or ""), str(ev.event_type or "event").replace("_", " ").strip().title())
                    meta_bits = []
                    if actor_label:
                        meta_bits.append(f"By {actor_label}")
                    if target_label:
                        meta_bits.append(f"Target: {target_label}")
                    attendance_timeline.append(
                        {
                            "happened_at": ev.created_at,
                            "event_label": event_label,
                            "student_name": target_label or "Session",
                            "meta_label": " · ".join(meta_bits),
                        }
                    )

                for inv in invite_rows:
                    invite_label = str(inv.student_name or inv.student_cin or "Student")
                    if inv.used_at:
                        attendance_timeline.append(
                            {
                                "happened_at": inv.used_at,
                                "event_label": "Join link opened",
                                "student_name": invite_label,
                                "meta_label": str(inv.used_location or inv.used_device_label or "").strip(),
                            }
                        )
                    elif inv.created_at and inv.created_at >= (now - timedelta(hours=12)):
                        attendance_timeline.append(
                            {
                                "happened_at": inv.created_at,
                                "event_label": "Join link generated",
                                "student_name": invite_label,
                                "meta_label": "",
                            }
                        )

                for stat in stats_rows[:250]:
                    if not getattr(stat, "updated_at", None):
                        continue
                    label = str(stat.display_name or "").strip()
                    if not label and stat.user_id:
                        label = label_by_user_id.get(int(stat.user_id), "")
                    if not label:
                        label = f"Student {stat.agora_uid}"
                    attendance_timeline.append(
                        {
                            "happened_at": stat.updated_at,
                            "event_label": "Attendance synced",
                            "student_name": label,
                            "meta_label": f"Watch {max(0, int(stat.watch_seconds or 0) // 60)}m · Engagement {int(stat.engagement or 0)}",
                        }
                    )

            attendance_timeline = sorted(
                [row for row in attendance_timeline if isinstance(row, dict) and row.get("happened_at")],
                key=lambda row: row["happened_at"],
                reverse=True,
            )[:120]

            context = {
                'external_professor_mode': True,
                'external_sessions': sessions if isinstance(sessions, list) else [],
                'external_selected_session': selected_session,
                'external_students': students,
                'attendance_timeline': attendance_timeline,
                'students': [],
                'all_sessions': [],
                'selected_session': None,
            }
            return render(request, 'Prolean/professor/students.html', context)
        except Exception as exc:
            logger.warning("External professor students fallback to local mode: %s", exc)

    prof_profile = get_object_or_404(ProfessorProfile, profile=request.user.profile)
    
    # Session filtering
    session_id = request.GET.get('session_id')
    selected_session = None
    if session_id:
        selected_session = Session.objects.filter(id=session_id, professor=prof_profile).first()
        
    if selected_session:
        students = selected_session.students.select_related('profile').all()
    else:
        students = StudentProfile.objects.filter(
            session__professor=prof_profile
        ).select_related('profile').distinct()
    
    all_sessions = Session.objects.filter(professor=prof_profile, is_active=True).order_by('-start_date')
    
    context = {
        'students': students,
        'all_sessions': all_sessions,
        'selected_session': selected_session,
        'prof_profile': prof_profile,
    }
    return render(request, 'Prolean/professor/students.html', context)

@professor_required
def professor_sessions(request):
    """Manage professor's sessions"""
    prof_profile = get_object_or_404(ProfessorProfile, profile=request.user.profile)
    
    if request.method == 'POST':
        if request.user.profile.role != 'ADMIN':
            messages.error(request, "Seuls les administrateurs peuvent créer des sessions.")
            return redirect('Prolean:professor_sessions')

        training_ids = request.POST.getlist('training_ids')
        start_date = request.POST.get('start_date')
        end_date = request.POST.get('end_date')
        city_id = request.POST.get('city_id')
        is_live = request.POST.get('is_live') == 'on'
        
        try:
            city_obj = City.objects.get(id=city_id)
            session = Session.objects.create(
                professor=prof_profile,
                start_date=start_date,
                end_date=end_date,
                city=city_obj,
                is_live=is_live,
                is_active=True
            )
            if training_ids:
                session.formations.set(Training.objects.filter(id__in=training_ids))
            
            messages.success(request, "Session créée avec succès.")
        except Exception as e:
            messages.error(request, f"Erreur lors de la création: {e}")
        
        return redirect('Prolean:professor_sessions')
        
    sessions = Session.objects.filter(professor=prof_profile).prefetch_related('formations').order_by('-start_date')
    trainings = Training.objects.all()
    cities = City.objects.all()
    
    # Get seances for sessions
    for sess in sessions:
        sess.theory_count = sess.seances.filter(type='THEORIQUE').count()
        sess.practice_count = sess.seances.filter(type='PRATIQUE').count()
    
    context = {
        'sessions': sessions,
        'all_sessions': sessions,
        'trainings': trainings,
        'cities': cities,
        'prof_profile': prof_profile,
    }
    return render(request, 'Prolean/professor/sessions.html', context)

@professor_required
@require_POST
def add_seance(request):
    """Add a seance to a session (UI-based)"""
    session_id = request.POST.get('session_id')
    session = get_object_or_404(Session, id=session_id, professor__profile=request.user.profile)
    
    if session.status == 'COMPLETED':
        messages.error(request, "Cette session est terminée. Vous ne pouvez plus ajouter de séances.")
        return redirect('Prolean:professor_sessions')
    
    title = request.POST.get('title')
    seance_type = request.POST.get('type')
    date = request.POST.get('date')
    time = request.POST.get('time')
    location = request.POST.get('location', '')
    
    try:
        # Check if we already have 2 of this type
        existing_count = session.seances.filter(type=seance_type).count()
        if existing_count >= 2:
            messages.warning(request, f"Vous avez déjà ajouté 2 séances de type {seance_type} pour cette session.")
            
        Seance.objects.create(
            session=session,
            title=title,
            type=seance_type,
            date=date,
            time=time,
            location=location
        )
        messages.success(request, "Séance ajoutée avec succès.")
    except Exception as e:
        messages.error(request, f"Erreur: {e}")
        
    return redirect('Prolean:professor_sessions')

@professor_required
def professor_comments(request):
    """View and reply to comments - Session-Centric"""
    prof_profile = get_object_or_404(ProfessorProfile, profile=request.user.profile)
    
    if request.method == 'POST':
        question_id = request.POST.get('comment_id')
        reply_content = request.POST.get('reply')
        
        if question_id and reply_content:
            question = get_object_or_404(Question, id=question_id)
            
            # Check if session is completed
            if question.student.session and question.student.session.status == 'COMPLETED':
                messages.error(request, "Cette session est terminée. Vous ne pouvez plus répondre aux questions.")
                return redirect('Prolean:professor_comments')
            
            # Update the question with the answer
            question.answer_content = f"REPONSE PROFESSEUR: {reply_content}"
            question.answered_by = prof_profile
            question.is_answered = True
            question.save()
            
            messages.success(request, "Réponse envoyée.")
            return redirect('Prolean:professor_comments')

    # Session filtering
    session_id = request.GET.get('session_id')
    selected_session = None
    if session_id:
        selected_session = Session.objects.filter(id=session_id, professor=prof_profile).first()
        
    if selected_session:
        questions = Question.objects.filter(student__session=selected_session, is_deleted=False).order_by('-created_at')
    else:
        # Get trainings where the professor is teaching (via sessions)
        trainings = Training.objects.filter(sessions__professor=prof_profile).distinct()
        questions = Question.objects.filter(
            video__training__in=trainings,
            is_deleted=False
        ).order_by('-created_at')
    
    all_sessions = Session.objects.filter(professor=prof_profile, is_active=True).order_by('-start_date')
    
    context = {
        'comments': questions,
        'all_sessions': all_sessions,
        'selected_session': selected_session,
        'prof_profile': prof_profile,
    }
    return render(request, 'Prolean/professor/comments.html', context)

@login_required
def mark_notification_read(request, notification_id):
    """Mark a notification as read and redirect to its link"""
    notification = get_object_or_404(Notification, id=notification_id, user=request.user)
    notification.is_read = True
    notification.save()
    
    if notification.link:
        return redirect(notification.link)
    return redirect(request.META.get('HTTP_REFERER', 'Prolean:home'))

@professor_required
def send_session_notification(request, session_id):
    """Professor sends a notification to all students in a session"""
    session = get_object_or_404(Session, id=session_id, professor__profile=request.user.profile)
    back_url = f"{reverse('Prolean:professor_dashboard')}?session_id={session.id}"
    
    if session.status == 'COMPLETED':
        messages.error(request, "Cette session est terminée. Vous ne pouvez plus envoyer de notifications.")
        return redirect(back_url)
    
    if request.method == 'POST':
        title = request.POST.get('title')
        message = request.POST.get('message')
        notif_type = request.POST.get('type', 'info')
        
        if title and message:
            students = session.students.all()
            notifications = []
            for student in students:
                notifications.append(Notification(
                    user=student.profile.user,
                    session=session,
                    title=title,
                    message=message,
                    notification_type=notif_type
                ))
            
            if notifications:
                Notification.objects.bulk_create(notifications)
                messages.success(request, f"Notification envoyée à {len(notifications)} étudiants.")
            else:
                messages.warning(request, "Aucun étudiant n'est inscrit dans cette session.")
                
        return redirect(back_url)
    
    return redirect(back_url)
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

@csrf_exempt
@login_required
def attendance_heartbeat(request, stream_id):
    """API endpoint to update student attendance duration via heartbeat"""
    if request.method == 'POST':
        stream = get_object_or_404(Live, id=stream_id)
        profile = request.user.profile
        
        # We find the most recent log for this student and stream
        log = AttendanceLog.objects.filter(student=profile, live_stream=stream).last()
        
        if log:
            # Update leave_time to now and increment duration
            now = timezone.now()
            log.leave_time = now
            delta = now - log.join_time
            log.duration_seconds = int(delta.total_seconds())
            log.save()
            
            return JsonResponse({'status': 'success', 'duration': log.duration_seconds})
            
    return JsonResponse({'status': 'error'}, status=400)
# ==========================================
# ASSISTANT & CALL CENTER MANAGEMENT
# ==========================================

@require_POST
@assistant_required
def create_entity_ajax(request):
    """Unified creation for Students by an Assistant. Extended for efficiency."""
    try:
        data = json.loads(request.body)
        role = data.get('role', 'STUDENT')
        email = data.get('email')
        full_name = data.get('full_name')
        password = data.get('password', 'Prolean2026!')
        phone = data.get('phone', '')
        city_id = data.get('city_id')
        
        # New fields for efficiency
        cin = data.get('cin', '')
        formation_ids = data.get('formation_ids', [])
        session_id = data.get('session_id', None)
        status = data.get('status', 'PENDING')
        
        if not all([email, full_name, city_id]):
            return JsonResponse({'status': 'error', 'message': 'Champs requis manquants: Email, Nom, Ville.'})
            
        # Permission check: Assistants can ONLY create STUDENTS
        if not request.user.is_superuser:
            if role != 'STUDENT':
                return JsonResponse({'status': 'error', 'message': 'Action non autorisée: Vous ne pouvez créer que des étudiants.'}, status=403)
            
        city = City.objects.get(id=city_id)
        
        # Check if assistant has access to this city
        if not request.user.is_superuser:
            assistant_profile = request.user.profile.assistant_profile
            if city not in assistant_profile.assigned_cities.all():
                return JsonResponse({'status': 'error', 'message': 'Accès refusé pour cette ville.'}, status=403)
        
        with transaction.atomic():
            # 1. Create/Get User
            user, created = User.objects.get_or_create(
                username=email,
                defaults={'email': email}
            )
            if created:
                user.set_password(password)
                user.save()
            
            # 2. Update Profile (Automatic creation managed by signals)
            profile = user.profile
            profile.role = role
            profile.full_name = full_name
            profile.phone_number = phone
            profile.city = city
            profile.status = status
            profile.cin_or_passport = cin
            profile.save()
            
            # 3. Handle Special Access (StudentProfile is auto-created via profile signal)
            if role == 'STUDENT':
                student_prof = profile.student_profile
                if formation_ids:
                    student_prof.authorized_formations.set(Training.objects.filter(id__in=formation_ids))
                if session_id:
                    session = Session.objects.get(id=session_id)
                    student_prof.session = session
                    student_prof.save()
                
            return JsonResponse({'status': 'success', 'message': f'{profile.get_role_display()} créé et configuré avec succès.'})
            
    except City.DoesNotExist:
        return JsonResponse({'status': 'error', 'message': 'Ville invalide.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)})

@require_POST
@assistant_required
def toggle_student_status(request, student_id):
    """Allow assistants to approve/suspend students in their cities"""
    try:
        student = get_object_or_404(StudentProfile, id=student_id)
        
        # Permission check: Assistant must be assigned to student's city
        if not request.user.is_superuser:
            assistant_profile = request.user.profile.assistant_profile
            if student.profile.city not in assistant_profile.assigned_cities.all():
                 return JsonResponse({'status': 'error', 'message': 'Accès refusé pour cette ville.'}, status=403)
        
        # Toggle status
        new_status = 'ACTIVE' if student.profile.status != 'ACTIVE' else 'PENDING'
        student.profile.status = new_status
        student.profile.save()
        
        return JsonResponse({
            'status': 'success', 
            'message': f'Statut mis à jour: {new_status}',
            'new_status': new_status
        })
    except Exception as e:
         return JsonResponse({'status': 'error', 'message': str(e)}, status=500)


@require_POST
@assistant_required
def assistant_assign_training(request):
    """Enroll a student in specific trainings"""
    try:
        data = json.loads(request.body)
        student_id = data.get('student_id')
        training_ids = data.get('training_ids', []) # List of IDs
        
        student = get_object_or_404(StudentProfile, id=student_id)
        
        # Permission check
        if not request.user.is_superuser:
            assistant_profile = request.user.profile.assistant_profile
            if student.profile.city not in assistant_profile.assigned_cities.all():
                return JsonResponse({'status': 'error', 'message': 'Accès refusé pour cet étudiant.'}, status=403)
        
        trainings = Training.objects.filter(id__in=training_ids)
        student.authorized_formations.add(*trainings)
        
        return JsonResponse({'status': 'success', 'message': f'Affectation réussie pour {trainings.count()} formations.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@require_POST
@assistant_required
def assistant_assign_session(request):
    """Assign a student to a specific session"""
    try:
        data = json.loads(request.body)
        student_id = data.get('student_id')
        session_id = data.get('session_id')
        
        student = get_object_or_404(StudentProfile, id=student_id)
        session = get_object_or_404(Session, id=session_id)
        
        # Permission check
        if not request.user.is_superuser:
            assistant_profile = request.user.profile.assistant_profile
            if student.profile.city not in assistant_profile.assigned_cities.all() or \
               session.city not in assistant_profile.assigned_cities.all():
                return JsonResponse({'status': 'error', 'message': 'Accès refusé pour cette session ou cet étudiant.'}, status=403)
        
        student.session = session
        student.save()
        
        return JsonResponse({'status': 'success', 'message': 'Étudiant ajouté à la session.'})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@require_POST
@assistant_required
def assistant_create_session(request):
    """Create a new session"""
    try:
        data = json.loads(request.body)
        training_ids = data.get('training_ids', [])
        professor_id = data.get('professor_id')
        city_id = data.get('city_id')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        is_live = data.get('is_live', False)
        
        city = get_object_or_404(City, id=city_id)
        
        # Permission check
        if not request.user.is_superuser:
            assistant_profile = request.user.profile.assistant_profile
            if city not in assistant_profile.assigned_cities.all():
                return JsonResponse({'status': 'error', 'message': 'Action non autorisée pour cette ville.'}, status=403)
        
        professor = get_object_or_404(ProfessorProfile, id=professor_id)
        
        with transaction.atomic():
            session = Session.objects.create(
                professor=professor,
                city=city,
                start_date=start_date,
                end_date=end_date,
                is_live=is_live,
                is_active=True
            )
            session.formations.add(*Training.objects.filter(id__in=training_ids))
            
        return JsonResponse({'status': 'success', 'message': 'Session créée avec succès.', 'session_id': session.id})
    except Exception as e:
        return JsonResponse({'status': 'error', 'message': str(e)}, status=500)

@assistant_required
def assistant_dashboard(request):
    """Redirect to Django Admin as per user request"""
    return redirect('/admin/')


from django.contrib.auth.decorators import user_passes_test
from django.db.models import Sum, Count
from django.utils import timezone
from datetime import timedelta

@user_passes_test(lambda u: u.is_superuser)
def director_dashboard(request):
    """Redirect to Django Admin as per user request"""
    return redirect('/admin/')

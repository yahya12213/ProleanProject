from __future__ import annotations

from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse

from .health import integration_health_snapshot


@staff_member_required
def integration_health(request):
    return JsonResponse(integration_health_snapshot())


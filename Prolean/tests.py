from __future__ import annotations

from urllib.parse import urlparse

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from .models import ExternalLiveJoinInvite, ExternalLiveJoinAttempt


class OneClickJoinInviteTests(TestCase):
    def setUp(self):
        self.prof = User.objects.create(username="prof_test")
        self.prof.set_unusable_password()
        self.prof.save()
        profile = self.prof.profile
        profile.role = "PROFESSOR"
        profile.status = "ACTIVE"
        profile.full_name = "Prof Test"
        profile.save()
        self.prof.refresh_from_db()

    def test_professor_can_generate_and_student_consume_once(self):
        self.client.force_login(self.prof)
        session_id = "sess_123"
        cin = "M123123X"

        regen_url = reverse("Prolean:external_live_join_invite_regen", kwargs={"session_id": session_id})
        resp = self.client.post(regen_url, data='{"cin":"M123123X","name":"Student A"}', content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data.get("ok"))
        self.assertIn("/external/live/join/", data.get("join_url", ""))
        inv = ExternalLiveJoinInvite.objects.get(session_id=session_id, student_cin=cin)
        self.assertTrue(inv.token_hash)
        self.assertGreater(inv.expires_at, timezone.now())

        token_path = urlparse(data["join_url"]).path
        student_client = self.client_class()
        join_resp = student_client.get(token_path, REMOTE_ADDR="127.0.0.1", follow=False)
        self.assertEqual(join_resp.status_code, 302)
        self.assertIn(f"/external/live/{session_id}/", join_resp["Location"])

        inv.refresh_from_db()
        self.assertIsNotNone(inv.used_at)
        self.assertEqual(inv.used_ip, "127.0.0.1")
        self.assertTrue(ExternalLiveJoinAttempt.objects.filter(invite=inv, status="success").exists())

        user = User.objects.get(username=cin)
        self.assertEqual(user.profile.role, "STUDENT")

        # Reuse should be blocked for one-time links.
        reuse_resp = student_client.get(token_path, REMOTE_ADDR="127.0.0.1", follow=False)
        self.assertEqual(reuse_resp.status_code, 400)
        self.assertTrue(ExternalLiveJoinAttempt.objects.filter(invite=inv, status="used").exists())

    def test_join_is_rate_limited_for_invalid_tokens(self):
        c = self.client_class()
        url = reverse("Prolean:external_live_join_with_token", kwargs={"token": "invalid_token_value_12345"})
        last = None
        for _ in range(25):
            last = c.get(url, REMOTE_ADDR="127.0.0.1")
        self.assertIsNotNone(last)
        self.assertEqual(last.status_code, 429)

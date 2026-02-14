# apps.py
from django.apps import AppConfig

class ProleanConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'Prolean'
    
    def ready(self):
        # Import signals if you have any
        try:
            import Prolean.signals
        except ImportError:
            pass
import os
from django.conf import settings
from celery import Celery

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings.base")
app = Celery("tasks", include=["tasks.tasks"])
app.config_from_object("django.conf:settings")

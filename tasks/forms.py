from django import forms
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm
from django.forms import ModelForm
from task_manager.users.models import User

from tasks.models import Report, Task


class StyleMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for visible in self.visible_fields():
            visible.field.widget.attrs["class"] = "p-2 bg-slate-100 rounded"
            visible.field.widget.attrs["style"] = "border-color: transparent"


class TaskForm(StyleMixin, ModelForm):
    class Meta:
        model = Task
        fields = ["title", "description", "status", "priority", "completed"]


class TaskUserCreationForm(StyleMixin, UserCreationForm):

    class Meta:
        model = User
        fields = ["username", "email"]


class TaskUserLoginForm(StyleMixin, AuthenticationForm):

    class Meta:
        model = User
        fields = ["username"]


class ScheduleReportForm(StyleMixin, ModelForm):

    time = forms.TimeField(
        widget=forms.TimeInput(
            attrs={"type": "time"}
        ),
        required=True,
        help_text="<small><em>Use UTC time</em></small>"
    )

    disabled = forms.BooleanField(
        widget=forms.CheckboxInput(),
        label="Disable daily reports",
        required=False
    )

    class Meta:
        model = Report
        fields = ["time", "disabled"]

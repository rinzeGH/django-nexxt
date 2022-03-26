from django.http import Http404


class HaveProfileMixin:
    def has_permission(self):
        if self.requsets.user.is_superuser:
            return True
        try:
            return bool(self.request.user.profile)
        except:
            raise Http404()

    def dispatch(self, request, *args, **kwargs):
        if not self.has_permission():
            raise Http404()
        return super().dispatch(request, *args, **kwargs)
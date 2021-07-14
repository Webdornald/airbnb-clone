from django.utils import timezone
from django.views.generic import ListView, DetailView

from . import models


# Create your views here.
class HomeView(ListView):
    """ HomeView Definition """

    model = models.Room
    paginate_by = 10
    paginate_orphans = 5
    ordering = 'created'
    context_object_name = 'rooms'

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super(HomeView, self).get_context_data(**kwargs)
        now = timezone.now()
        context['now'] = now
        return context


class RoomDetail(DetailView):
    """ RoomDetail Definition """

    model = models.Room
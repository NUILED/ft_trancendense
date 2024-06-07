from django.shortcuts import render
from django.http import HttpResponse

def index(request):
    return render(request,"ping_pong/logim.html")
# Create your views here.
def callback(request):
    print(request)
    print(request.session[0])
    return HttpResponse("OK")


def login(request):
    print(request)

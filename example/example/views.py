# -*- coding: utf-8 -*-
from django.shortcuts import render
from django.contrib.auth.forms import AuthenticationForm
from django_authopenid.forms import OpenidSigninForm


def home(request):
    form1 = OpenidSigninForm()
    form2 = AuthenticationForm()

    return render(request, "home.html", {
        'form1': form1,
        'form2': form2
    })
# main/views.py
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse, HttpResponseForbidden
from django.utils.timezone import localtime, now, timedelta, make_aware
from django.contrib import messages
# Models & Forms
from .models import (
    UserMembership,
)

# Decorators
def role_required(role):
    """
    A decorator restricting access to a particular role
    (e.g., operator, admin). If mismatch, returns 403.
    """
    def decorator(view_func):
        def _wrapped_view(request, *args, **kwargs):
            if request.user.is_authenticated and request.user.profile.has_minimum_role(role):
                return view_func(request, *args, **kwargs)
            return HttpResponseForbidden("You do not have permission to access this page.")
        return _wrapped_view
    return decorator


# ------------------------------------------
# HOME & AUTHENTICATION
# ------------------------------------------
def home_view(request):
    """
    Public home page (not password protected).
    Shows different dashboard options based on user roles.
    """
    user = request.user
    is_admin = False
    is_operator = False
    is_member = False

    if user.is_authenticated:
        profile = getattr(user, "profile", None)
        if profile:
            # Check for admin role
            is_admin = profile.has_minimum_role("admin")
            # Check for operator role
            is_operator = profile.has_minimum_role("operator")
            # Check for member role
            is_member = profile.has_minimum_role("member")

    context = {
        'is_logged_in': user.is_authenticated,
        'is_admin': is_admin,
        'is_operator': is_operator,
        'is_member': is_member,
        'current_time': now(),
    }
    return render(request, 'main/home.html', context)


def member_login_view(request):
    """
    Standard Django authentication (username/password).
    """
    error = None
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)

        if user:
            login(request, user)
            return redirect('home')
        else:
            error = "Invalid credentials. Please try again."

    return render(request, 'credential/member_login.html', {'error': error})

@login_required
def member_logout_view(request):
    logout(request)
    return redirect('home')

@login_required
def member_profile(request):
    """
    Display/Edit the member's profile.
    """
    if request.user.profile.role == "public":
        return HttpResponseForbidden("You are not authorized to access this page.")

    if request.method == "POST":
        # Update Django's built-in User fields
        user = request.user
        user.first_name = request.POST.get("first_name", user.first_name)
        user.last_name = request.POST.get("last_name", user.last_name)
        user.email = request.POST.get("email", user.email)
        user.save()

        # Update your Profile model fields
        user_profile = user.profile
        user_profile.phone = request.POST.get("phone", user_profile.phone)
        user_profile.save()

        messages.success(request, "Your profile has been updated.")
        return redirect("member_profile")

    # On GET, add user to context so template can fill in existing values
    try:
        membership = request.user.usermembership
        membership_status = "Paid" if membership.active else "Unpaid"
    except UserMembership.DoesNotExist:
        membership_status = "Unpaid"

    context = {
        "user": request.user,  # so template can do {{ user.first_name }}, etc.
        "membership_status": membership_status,
    }
    return render(request, "member/profile.html", context)

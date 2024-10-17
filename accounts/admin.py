from django.contrib import admin
from import_export.admin import ImportExportModelAdmin
from django.contrib import admin
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken

# Project Import
from .models import User,BlacklistedToken

class UserAdmin(ImportExportModelAdmin):
    list_display = ['id', 'email', 'user_type','created_at','modified_at','contact']

admin.site.register(User, UserAdmin)


class BlacklistedTokenAdmin(admin.ModelAdmin):
    list_display = ('id', 'token')

admin.site.register(BlacklistedToken, BlacklistedTokenAdmin)




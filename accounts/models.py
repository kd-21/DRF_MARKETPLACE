# Django Imports
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.contrib.auth.models import AbstractUser, AbstractBaseUser, PermissionsMixin, BaseUserManager
# from django.contrib.auth.base_user import BaseUserManager



class CustomUserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        """
        Create and save a User with the given email and password.
        """

        if not email:
            raise ValueError(_("The Email must be set"))
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        extra_fields.setdefault("is_active", True)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password=None, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """

        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("user_type", "SUPERADMIN")
        if extra_fields.get("is_staff") is not True:
            raise ValueError(_("Superuser must have is_staff=True."))
        if extra_fields.get("is_superuser") is not True:
            raise ValueError(_("Superuser must have is_superuser=True."))
        return self._create_user(email, password, **extra_fields)


class BaseModel(models.Model):
    """
    BaseModel:
    Containes DateTime for creation and updation'
    """

    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    modified_at = models.DateTimeField(auto_now=True, db_index=True)
    is_active = models.BooleanField(default=True)
    created_by = models.CharField(max_length=100, null=True, blank=True)
    modified_by = models.CharField(max_length=100, null=True, blank=True)

    class Meta:
        abstract = True





class User(AbstractBaseUser, PermissionsMixin, BaseModel):
    """
    User:
    Contains Information to store for user'
    """
    
    USERTYPE = (
    ("SUPERADMIN", "Super Admin"),
    ("BUYER", "Buyer"),
    ("SELLER", "Seller"),
)

    email = models.EmailField(max_length=255, unique=True)
    name = models.CharField(max_length=20, null=True, blank=True)
    is_staff = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    user_type = models.CharField(
        max_length=15,
        choices=USERTYPE,
        null=True,
        blank=True,
        default=None
    )
    contact = models.CharField(max_length=15, null=True, blank=True)
    designation = models.CharField(max_length=20, null=True, blank=True)
    profile_pic = models.ImageField(
        upload_to="profile_pic/",
        null=True,
        blank=True
    )
    username = None
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []
    objects = CustomUserManager()

    def __str__(self):
        return str(self.email)
    
    


class BlacklistedToken(models.Model):
    token = models.TextField()

    def __str__(self):
        return self.token
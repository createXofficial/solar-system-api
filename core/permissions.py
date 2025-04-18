from rest_framework import permissions

class IsCustomerOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        return obj.owner == request.user or request.user.role == 'admin'

class IsTechnicianOrAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role in ['technician', 'admin']
#
# Copyright 2026 Red Hat, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
"""Service layer for GroupV2."""

import logging
from typing import Optional, Sequence

from django.db import IntegrityError, transaction
from django.db.models import Count, F, ProtectedError, Q, QuerySet
from management.group.model import Group
from management.group.relation_api_dual_write_group_handler import RelationApiDualWriteGroupHandler
from management.group.v2_exceptions import GroupAlreadyExistsError, GroupHasRoleBindingsError, ProtectedGroupError
from management.principal.model import Principal
from management.relation_replicator.relation_replicator import ReplicationEventType
from management.role.model import Role
from management.v2_filters import v2_name_filter

from api.models import Tenant

logger = logging.getLogger(__name__)


class GroupV2Service:
    """Service for V2 group operations."""

    UNIQUE_NAME_CONSTRAINT = "unique group name per tenant"
    DEFAULT_ORDER_BY = "name"
    ORDER_BY_FIELD_MAPPING = {
        "name": "name",
        "modified": "modified",
        "principal_count": "principal_count_annotation",
        "role_count": "role_count_annotation",
    }
    PROTECTED_FLAGS_FOR_UPDATE = ("system",)
    PROTECTED_FLAGS_FOR_DELETE = ("system", "platform_default", "admin_default")
    ORG_ID_SCOPE = "org_id"
    PRINCIPAL_SCOPE = "principal"
    SCOPES = (ORG_ID_SCOPE, PRINCIPAL_SCOPE)
    ROLE_DISCRIMINATOR_ANY = "any"
    ROLE_DISCRIMINATOR_ALL = "all"
    ROLE_DISCRIMINATORS = (ROLE_DISCRIMINATOR_ANY, ROLE_DISCRIMINATOR_ALL)

    def __init__(self, tenant: Tenant):
        """Initialize service with tenant context."""
        self.tenant = tenant

    def queryset(self) -> QuerySet:
        """Return the tenant's groups annotated with principal and role counts."""
        return Group.objects.filter(tenant=self.tenant).annotate(
            principal_count_annotation=Count(
                "principals", filter=Q(principals__type=Principal.Types.USER), distinct=True
            ),
            role_count_annotation=Count(
                "role_binding_entries__binding__role",
                filter=Q(role_binding_entries__binding__tenant=F("tenant")),
                distinct=True,
            ),
        )

    def list(self, params: dict, requester_username: Optional[str] = None) -> QuerySet:
        """List groups with optional filtering and ordering.

        requester_username is required for scope=principal, which returns only the requester's groups.
        """
        queryset = self.queryset()

        name = params.get("name")
        if name:
            queryset = v2_name_filter(queryset, name, field="name")

        uuids = params.get("uuid")
        if uuids:
            queryset = queryset.filter(uuid__in=uuids)

        # Filters traversing principals or role bindings join multi-valued relations, so .distinct() prevents
        # duplicate groups. The count annotations use Count(distinct=True) and are unaffected by the extra joins.
        # All principal-based filters restrict to Principal.Types.USER to match principal_count_annotation --
        # service accounts share the username field but are excluded from that count.
        username = params.get("username")
        if username:
            queryset = v2_name_filter(
                queryset,
                username,
                field="principals__username",
                extra_filters={"principals__type": Principal.Types.USER},
            ).distinct()

        exclude_username = params.get("exclude_username")
        if exclude_username:
            # exclude() on a multi-valued relation ANDs conditions across independently-matched rows
            # rather than requiring a single row to satisfy both (unlike filter()), so the type and
            # username conditions are combined here via a Principal subquery instead.
            matching_principals = Principal.objects.filter(
                tenant=self.tenant, type=Principal.Types.USER, username__icontains=exclude_username
            ).values("pk")
            queryset = queryset.exclude(principals__in=matching_principals)

        role_names = params.get("role_names")
        if role_names:
            discriminator = params.get("role_discriminator", self.ROLE_DISCRIMINATOR_ANY)
            queryset = self._filter_by_role_names(queryset, role_names, discriminator)

        # Chain one filter per principal so a group must contain all of them.
        principals = params.get("principals") or ()
        for principal in principals:
            queryset = queryset.filter(principals__type=Principal.Types.USER, principals__username__iexact=principal)
        if principals:
            queryset = queryset.distinct()

        if params.get("scope") == self.PRINCIPAL_SCOPE:
            if not requester_username:
                return queryset.none()
            queryset = queryset.filter(
                principals__type=Principal.Types.USER, principals__username__iexact=requester_username
            ).distinct()

        for flag in ("system", "platform_default", "admin_default"):
            value = params.get(flag)
            if value is not None:
                queryset = queryset.filter(**{flag: value})

        return queryset.order_by(*self._ordering(params.get("order_by") or self.DEFAULT_ORDER_BY))

    def get(self, group: Group) -> Group:
        """Return the given group re-fetched with count annotations."""
        return self.queryset().get(pk=group.pk)

    def create(self, name: str, description: Optional[str] = None) -> Group:
        """Create a new group."""
        try:
            with transaction.atomic():
                group = Group.objects.create(name=name, description=description, tenant=self.tenant)
        except IntegrityError as e:
            if self._is_unique_name_violation(e):
                raise GroupAlreadyExistsError(name)
            raise
        return group

    def update(self, group: Group, name: str, description: Optional[str] = None) -> Group:
        """Update the name and description of a group."""
        self._check_not_protected(group, self.PROTECTED_FLAGS_FOR_UPDATE, "updated")

        group.name = name
        group.description = description
        try:
            with transaction.atomic():
                group.save()
        except IntegrityError as e:
            if self._is_unique_name_violation(e):
                raise GroupAlreadyExistsError(name)
            raise
        return group

    def delete(self, group: Group) -> None:
        """Delete a group and replicate the removal of its membership relations."""
        self._check_not_protected(group, self.PROTECTED_FLAGS_FOR_DELETE, "deleted")

        # Count both v2 role bindings (RoleBindingGroup) and legacy v1 role assignments
        # (Policy). role_binding_entries alone misses tenants still on v1-era Policy/
        # BindingMapping assignments, which would otherwise pass this guard and leave
        # orphaned SpiceDB tuples behind after the group is deleted.
        binding_count = group.role_binding_entries.count()
        legacy_role_count = Role.objects.filter(policies__group=group).count()
        if binding_count or legacy_role_count:
            raise GroupHasRoleBindingsError(binding_count + legacy_role_count)

        # Capture members before deletion; the M2M rows are removed along with the group.
        principals = list(group.principals.all())
        # Construct before delete(): Django clears the instance pk on delete(), and while
        # this handler currently only reads group.tenant_id/uuid (unaffected), constructing
        # it up front matches the V1 destroy() ordering and avoids relying on that detail.
        dual_write_handler = RelationApiDualWriteGroupHandler(group, ReplicationEventType.DELETE_GROUP)
        try:
            group.delete()
        except ProtectedError as e:
            raise GroupHasRoleBindingsError(len(e.protected_objects))

        dual_write_handler.replicate_removed_principals(principals)

    def _filter_by_role_names(self, queryset: QuerySet, role_names: Sequence[str], discriminator: str) -> QuerySet:
        """Filter groups bound to any (default) or all of the given role names, matched case-insensitively."""
        # Only count bindings in the group's own tenant, matching role_count_annotation.
        tenant_bindings = Q(role_binding_entries__binding__tenant=F("tenant"))
        if discriminator == self.ROLE_DISCRIMINATOR_ALL:
            # Each chained filter() joins the bindings anew, so every role name must match some binding.
            for role_name in role_names:
                queryset = queryset.filter(
                    tenant_bindings, role_binding_entries__binding__role__name__iexact=role_name
                )
            return queryset.distinct()

        any_role = Q()
        for role_name in role_names:
            any_role |= Q(role_binding_entries__binding__role__name__iexact=role_name)
        return queryset.filter(tenant_bindings, any_role).distinct()

    def _ordering(self, order_by: str) -> tuple[str, ...]:
        """Translate an API order_by value into ORM ordering, with a stable name/uuid tiebreaker."""
        descending = order_by.startswith("-")
        field = self.ORDER_BY_FIELD_MAPPING[order_by.lstrip("-")]
        primary = f"-{field}" if descending else field
        if field == "name":
            return (primary, "uuid")
        return (primary, "name", "uuid")

    @staticmethod
    def _check_not_protected(group: Group, flags: tuple[str, ...], action: str) -> None:
        for flag in flags:
            if getattr(group, flag):
                raise ProtectedGroupError(action, flag)

    @classmethod
    def _is_unique_name_violation(cls, error: IntegrityError) -> bool:
        """Check whether an IntegrityError was raised by the unique group name constraint.

        Inspects the underlying psycopg2 diagnostics (constraint_name) instead of matching the
        free-text error message, which is brittle across driver/locale differences.
        """
        diag = getattr(getattr(error, "__cause__", None), "diag", None)
        constraint_name = getattr(diag, "constraint_name", None)
        if constraint_name is not None:
            return constraint_name == cls.UNIQUE_NAME_CONSTRAINT
        return cls.UNIQUE_NAME_CONSTRAINT in str(error)

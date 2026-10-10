from collections import defaultdict

from .models import Resource, Relationship


class ResourceGraph:
    def __init__(self) -> None:
        self.resources: dict[str, Resource] = {}
        self.relationships: set[Relationship] = set()
        self._outgoing: dict[str, set[Relationship]] = defaultdict(set)

    def add_resource(self, resource: Resource) -> None:
        self.resources[resource.resource_id] = resource

    def add_relationship(self, relationship: Relationship) -> None:
        if relationship.source not in self.resources:
            raise ValueError(
                f"Unknown source resource: {relationship.source}"
            )

        if relationship.target not in self.resources:
            raise ValueError(
                f"Unknown target resource: {relationship.target}"
            )

        self.relationships.add(relationship)
        self._outgoing[relationship.source].add(relationship)

    def get_relationships(self, resource_id: str) -> set[Relationship]:
        return self._outgoing.get(resource_id, set())

    def get_resource(self, resource_id: str) -> Resource | None:
        return self.resources.get(resource_id)
from dataclasses import dataclass,field
from typing import Any


@dataclass(frozen=True)
class Resource:
    resource_id:str
    resource_type:str
    name:str | None=None
    properties:dict[str,Any]=field(default_factory=dict)
    
@dataclass(frozen=True)
class Relationship:
    source:str
    relation:str
    target:str
    
@dataclass(frozen=True)

class Finding:
    finding_id:str
    resource_id:str
    severity:str
    title:str
    properties: dict[str, Any] = field(default_factory=dict)
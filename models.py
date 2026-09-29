from datetime import datetime
from enum import Enum
from typing import Optional, Dict
from pydantic import BaseModel, Field


class SeverityLevel(str, Enum):
    baja = "baja"
    media = "media"
    alta = "alta"
    critica = "critica"


class IncidentCategory(str, Enum):
    malware = "malware"
    phishing = "phishing"
    ddos = "ddos"
    ransomware = "ransomware"
    acceso_no_autorizado = "acceso_no_autorizado"
    inyeccion_sql = "inyeccion_sql"
    fuga_de_datos = "fuga_de_datos"


class IncidentStatus(str, Enum):
    abierto = "abierto"
    en_investigacion = "en_investigacion"
    mitigado = "mitigado"
    cerrado = "cerrado"


class IncidentBase(BaseModel):
    title: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Título breve del incidente de seguridad",
        examples=["Intento de inyección SQL en API de pagos"]
    )
    description: str = Field(
        ...,
        min_length=10,
        description="Descripción detallada de la vulnerabilidad o anomalía detectada",
        examples=["Se detectaron payloads maliciosos 'OR 1=1-- en el parámetro de consulta auth."]
    )
    severity: SeverityLevel = Field(
        ...,
        description="Nivel de impacto y severidad",
        examples=["alta"]
    )
    category: IncidentCategory = Field(
        ...,
        description="Categoría o vector de ataque de ciberseguridad",
        examples=["inyeccion_sql"]
    )
    affected_system: str = Field(
        ...,
        min_length=2,
        max_length=80,
        description="Servidor, servicio o componente afectado",
        examples=["srv-payments-prod-01"]
    )
    reported_by: str = Field(
        ...,
        min_length=2,
        max_length=50,
        description="Nombre o alias del analista SOC / pentester",
        examples=["analista_alex"]
    )
    ip_origin: Optional[str] = Field(
        default=None,
        pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$",
        description="Dirección IPv4 pública de origen del atacante (opcional)",
        examples=["198.51.100.45"]
    )


class IncidentCreate(IncidentBase):
    pass


class IncidentUpdate(BaseModel):
    title: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = Field(None, min_length=10)
    severity: Optional[SeverityLevel] = None
    category: Optional[IncidentCategory] = None
    affected_system: Optional[str] = Field(None, min_length=2, max_length=80)
    status: Optional[IncidentStatus] = None
    ip_origin: Optional[str] = Field(None, pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    mitigation_notes: Optional[str] = Field(None, description="Pasos o notas de contención y mitigación")


class MitigateAction(BaseModel):
    mitigation_notes: str = Field(
        ...,
        min_length=5,
        description="Detalle de las acciones tomadas para mitigar el incidente (parche, bloqueo en firewall, etc.)",
        examples=["Se aplicó regla WAF bloqueando la IP y se sanitizó la entrada con prepared statements."]
    )


class IncidentResponse(IncidentBase):
    id: int
    status: IncidentStatus
    created_at: datetime
    mitigation_notes: Optional[str] = None

    class Config:
        from_attributes = True


class IncidentStats(BaseModel):
    total_incidentes: int
    por_severidad: Dict[str, int]
    por_estado: Dict[str, int]
    por_categoria: Dict[str, int]
    sistemas_criticos_afectados: list[str]
    porcentaje_mitigados: float

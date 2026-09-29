from datetime import datetime
from typing import List, Optional
from models import (
    IncidentResponse,
    IncidentCreate,
    IncidentUpdate,
    IncidentStatus,
    SeverityLevel,
    IncidentCategory,
)

# Base de datos en memoria para la gestión de incidentes del SOC
incidents_db: List[dict] = [
    {
        "id": 1,
        "title": "Campaña de Phishing dirigida al departamento de Finanzas",
        "description": "Correos fraudulentos suplantando al banco corporativo solicitando actualización urgente de credenciales token.",
        "severity": SeverityLevel.alta.value,
        "category": IncidentCategory.phishing.value,
        "affected_system": "Servidor de Correo Exchange & Endpoints Finanzas",
        "reported_by": "analista_valeria",
        "ip_origin": "185.220.101.5",
        "status": IncidentStatus.mitigado.value,
        "created_at": datetime(2026, 9, 20, 10, 15, 0),
        "mitigation_notes": "Se bloquearon dominios maliciosos en firewall DNS y se forzó restablecimiento de credenciales.",
    },
    {
        "id": 2,
        "title": "Ataque de fuerza bruta SSH contra servidor bastion",
        "description": "Más de 15,000 intentos fallidos de autenticación SSH utilizando diccionarios comunes de contraseñas.",
        "severity": SeverityLevel.media.value,
        "category": IncidentCategory.acceso_no_autorizado.value,
        "affected_system": "bastion-ssh-prod.cloud",
        "reported_by": "soc_bot_monitor",
        "ip_origin": "194.26.29.112",
        "status": IncidentStatus.cerrado.value,
        "created_at": datetime(2026, 9, 22, 3, 40, 0),
        "mitigation_notes": "Fail2Ban bloqueó la IP de origen permanentemente. Se deshabilitó login por password.",
    },
    {
        "id": 3,
        "title": "Detección de Ransomware LockBit en estación de ingeniería",
        "description": "Ejecutable sospechoso cifrando archivos locales y dejando nota de rescate en el escritorio del usuario.",
        "severity": SeverityLevel.critica.value,
        "category": IncidentCategory.ransomware.value,
        "affected_system": "WS-ENG-DEV-42",
        "reported_by": "analista_carlos",
        "ip_origin": "103.145.13.88",
        "status": IncidentStatus.en_investigacion.value,
        "created_at": datetime(2026, 9, 28, 8, 30, 0),
        "mitigation_notes": None,
    },
]

# Contador de IDs autoincrementales
_current_id = 3


def get_all_incidents() -> List[dict]:
    return incidents_db


def get_incident_by_id(incident_id: int) -> Optional[dict]:
    for inc in incidents_db:
        if inc["id"] == incident_id:
            return inc
    return None


def create_incident(data: IncidentCreate) -> dict:
    global _current_id
    _current_id += 1
    new_incident = {
        "id": _current_id,
        "title": data.title,
        "description": data.description,
        "severity": data.severity.value,
        "category": data.category.value,
        "affected_system": data.affected_system,
        "reported_by": data.reported_by,
        "ip_origin": data.ip_origin,
        "status": IncidentStatus.abierto.value,
        "created_at": datetime.now(),
        "mitigation_notes": None,
    }
    incidents_db.append(new_incident)
    return new_incident


def update_incident(incident_id: int, data: IncidentUpdate) -> Optional[dict]:
    incident = get_incident_by_id(incident_id)
    if not incident:
        return None

    update_dict = data.model_dump(exclude_unset=True)
    for key, value in update_dict.items():
        if value is not None:
            # Si es un Enum, guardamos su valor en string
            if hasattr(value, "value"):
                incident[key] = value.value
            else:
                incident[key] = value

    return incident


def delete_incident(incident_id: int) -> bool:
    incident = get_incident_by_id(incident_id)
    if not incident:
        return False
    incidents_db.remove(incident)
    return True

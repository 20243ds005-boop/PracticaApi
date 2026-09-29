from typing import List, Optional
from collections import Counter
from fastapi import FastAPI, HTTPException, status, Query
from fastapi.responses import JSONResponse

from models import (
    IncidentResponse,
    IncidentCreate,
    IncidentUpdate,
    IncidentStats,
    MitigateAction,
    SeverityLevel,
    IncidentStatus,
    IncidentCategory,
)
import database

# Creación de la aplicación FastAPI con metadata descriptiva
app = FastAPI(
    title="CyberGuard SOC - API de Gestión de Incidentes de Ciberseguridad",
    description=(
        "API REST para el registro, consulta, análisis y mitigación de incidentes de seguridad "
        "y vectores de ciberamenaza en tiempo real."
    ),
    version="1.0.0",
    contact={
        "name": "Equipo de Operaciones de Seguridad (SOC)",
        "email": "soc-alerts@cyberguard.local",
    },
)


@app.get("/", tags=["General"])
def root():
    """Ruta raíz que proporciona información general sobre el estado del SOC y endpoints disponibles."""
    return {
        "sistema": "CyberGuard Incident Management API",
        "estado": "ACTIVO",
        "version": "1.0.0",
        "docs_url": "/docs",
        "redoc_url": "/redoc",
        "total_incidentes_activos": len(database.get_all_incidents()),
    }


# ==========================================
# ENDPOINTS CREATIVOS EXTRA (MÉTRICAS Y BÚSQUEDA)
# ==========================================

@app.get(
    "/incidentes/estadisticas",
    response_model=IncidentStats,
    tags=["Métricas SOC"],
    summary="Estadísticas globales de ciberamenazas",
)
def get_soc_statistics():
    """Genera un reporte analítico del SOC con distribución por severidad, estado y sistemas comprometidos."""
    incidents = database.get_all_incidents()
    total = len(incidents)

    if total == 0:
        return {
            "total_incidentes": 0,
            "por_severidad": {},
            "por_estado": {},
            "por_categoria": {},
            "sistemas_criticos_afectados": [],
            "porcentaje_mitigados": 0.0,
        }

    severities = Counter(inc["severity"] for inc in incidents)
    statuses = Counter(inc["status"] for inc in incidents)
    categories = Counter(inc["category"] for inc in incidents)
    sistemas = list(set(inc["affected_system"] for inc in incidents))

    mitigados_o_cerrados = statuses.get("mitigado", 0) + statuses.get("cerrado", 0)
    porcentaje_mitigados = round((mitigados_o_cerrados / total) * 100, 2)

    return {
        "total_incidentes": total,
        "por_severidad": dict(severities),
        "por_estado": dict(statuses),
        "por_categoria": dict(categories),
        "sistemas_criticos_afectados": sistemas,
        "porcentaje_mitigados": porcentaje_mitigados,
    }


@app.get(
    "/incidentes/buscar",
    response_model=List[IncidentResponse],
    tags=["Búsqueda"],
    summary="Búsqueda avanzada de amenazas por palabra clave",
)
def search_incidents(
    q: str = Query(..., min_length=2, description="Término a buscar en título, descripción o sistema afectado")
):
    """Busca incidentes que coincidan con la palabra clave en el título, descripción o sistema afectado."""
    q_lower = q.lower()
    matches = [
        inc for inc in database.get_all_incidents()
        if q_lower in inc["title"].lower()
        or q_lower in inc["description"].lower()
        or q_lower in inc["affected_system"].lower()
    ]
    return matches


# ==========================================
# OPERACIONES CRUD PRINCIPALES
# ==========================================

@app.get(
    "/incidentes/",
    response_model=List[IncidentResponse],
    status_code=status.HTTP_200_OK,
    tags=["Incidentes"],
    summary="Listar todos los incidentes con filtros opcionales",
)
def get_all_incidents(
    severity: Optional[SeverityLevel] = Query(None, description="Filtrar por nivel de severidad"),
    status_filter: Optional[IncidentStatus] = Query(None, alias="status", description="Filtrar por estado del incidente"),
    category: Optional[IncidentCategory] = Query(None, description="Filtrar por vector de ataque"),
):
    """Obtiene la lista completa de incidentes con capacidad de filtrado por severidad, estado o categoría."""
    incidents = database.get_all_incidents()

    filtered = incidents
    if severity:
        filtered = [inc for inc in filtered if inc["severity"] == severity.value]
    if status_filter:
        filtered = [inc for inc in filtered if inc["status"] == status_filter.value]
    if category:
        filtered = [inc for inc in filtered if inc["category"] == category.value]

    return filtered


@app.get(
    "/incidentes/{incident_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    tags=["Incidentes"],
    summary="Consultar un incidente por su ID",
    responses={
        404: {"description": "El incidente solicitado no existe"},
        200: {"description": "Detalles completos del incidente recuperado"},
    },
)
def get_incident(incident_id: int):
    """Recupera los detalles de un incidente específico a partir de su identificador único."""
    incident = database.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incidente de seguridad con ID {incident_id} no encontrado en el sistema.",
        )
    return incident


@app.post(
    "/incidentes/",
    response_model=IncidentResponse,
    status_code=status.HTTP_201_CREATED,
    tags=["Incidentes"],
    summary="Registrar un nuevo incidente de seguridad",
    responses={
        201: {"description": "Incidente registrado exitosamente en el SOC"},
        422: {"description": "Error de validación en los datos enviados"},
    },
)
def create_incident(incident_data: IncidentCreate):
    """Registra y valida un nuevo incidente de seguridad utilizando el modelo Pydantic IncidentCreate."""
    new_incident = database.create_incident(incident_data)
    return new_incident


@app.put(
    "/incidentes/{incident_id}",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    tags=["Incidentes"],
    summary="Actualizar la información de un incidente existente",
    responses={
        404: {"description": "El incidente no fue encontrado para actualizar"},
        200: {"description": "Incidente actualizado exitosamente"},
    },
)
def update_incident(incident_id: int, update_data: IncidentUpdate):
    """Actualiza campos específicos o completos de un incidente existente en el sistema."""
    updated = database.update_incident(incident_id, update_data)
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se puede actualizar. Incidente con ID {incident_id} no existe.",
        )
    return updated


@app.delete(
    "/incidentes/{incident_id}",
    status_code=status.HTTP_200_OK,
    tags=["Incidentes"],
    summary="Eliminar un incidente del registro",
    responses={
        404: {"description": "El incidente no fue encontrado para eliminar"},
        200: {"description": "Confirmación de eliminación exitosa"},
    },
)
def delete_incident(incident_id: int):
    """Elimina permanentemente un incidente del registro de amenazas del SOC."""
    success = database.delete_incident(incident_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No se puede eliminar. Incidente con ID {incident_id} no existe.",
        )
    return {
        "status": "success",
        "message": f"Incidente de seguridad con ID {incident_id} eliminado exitosamente.",
        "deleted_id": incident_id,
    }


# ==========================================
# ENDPOINT ACCIÓN RÁPIDA: MITIGAR INCIDENTE
# ==========================================

@app.post(
    "/incidentes/{incident_id}/mitigar",
    response_model=IncidentResponse,
    status_code=status.HTTP_200_OK,
    tags=["Incidentes"],
    summary="Marcar un incidente como mitigado agregando notas de remediación",
)
def mitigate_incident(incident_id: int, action: MitigateAction):
    """Aplica notas de mitigación y cambia el estado del incidente automáticamente a 'mitigado'."""
    incident = database.get_incident_by_id(incident_id)
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incidente con ID {incident_id} no encontrado.",
        )

    incident["status"] = IncidentStatus.mitigado.value
    incident["mitigation_notes"] = action.mitigation_notes
    return incident

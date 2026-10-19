"""Typed API routes for catalogs, victim runs, persistence, and reports."""

from __future__ import annotations

from dataclasses import asdict, is_dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from time import perf_counter
from typing import Any, Literal
from uuid import uuid4

from fastapi import APIRouter, Depends, Query
from fastapi.responses import PlainTextResponse

from promptfirewall.api.dependencies import get_job_manager, get_repository, get_victim_service
from promptfirewall.api.errors import ApiError
from promptfirewall.api.job_manager import ExperimentJobManager
from promptfirewall.api.schemas import (
    ExperimentCreateResponse,
    ExperimentResponse,
    HealthResponse,
    ReportResponse,
    RunDetailResponse,
    RunSummaryResponse,
    TestRunRequest,
    TestRunResponse,
    VictimChatRequest,
    VictimChatResponse,
)
from promptfirewall.attacks.registry import (
    get_attack,
    get_attacks,
    get_benign_case,
    get_benign_cases,
)
from promptfirewall.contracts.attacks import AttackCategory, AttackDefinition, BenignCase, CaseKind
from promptfirewall.contracts.defenses import DefenseContext, DefenseProfile
from promptfirewall.contracts.experiments import ExperimentCreate, RunStatus
from promptfirewall.contracts.models import ModelResponse, TestIdentity
from promptfirewall.contracts.results import MetricsSnapshot
from promptfirewall.contracts.traces import TraceEvent
from promptfirewall.defenses.pipeline import DefensePipeline
from promptfirewall.defenses.registry import DEFAULT_REGISTRY
from promptfirewall.judges import (
    PromptDisclosureJudge,
    StateChangeJudge,
    ToolMisuseJudge,
    UtilityJudge,
    aggregate_judges,
)
from promptfirewall.judges.observable_canary_leak import ObservableCanaryLeakJudge
from promptfirewall.metrics import calculate_metrics
from promptfirewall.storage.repository import ExperimentCounts, StorageRepository
from promptfirewall.victim_app.service import VictimRunResult, VictimService


router = APIRouter(tags=["promptfirewall"])
_REPOSITORY = Depends(get_repository)
_VICTIM = Depends(get_victim_service)
_JOB_MANAGER = Depends(get_job_manager)


def _iso(value: datetime) -> str:
    if value.tzinfo is None:
        value = value.replace(tzinfo=UTC)
    return value.isoformat()


def _json(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        return _iso(value)
    if hasattr(value, "model_dump"):
        return _json(value.model_dump(mode="json"))
    if is_dataclass(value):
        return _json(asdict(value))
    if isinstance(value, dict):
        return {str(key): _json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json(item) for item in value]
    return value


def _default_identity() -> TestIdentity:
    return TestIdentity(user_id="demo-customer", role="customer", customer_id="cust-1001")


def _run_summary(record: Any) -> RunSummaryResponse:
    return RunSummaryResponse(
        id=record.id,
        experiment_id=record.experiment_id,
        case_id=record.case_id,
        case_kind=record.case_kind,
        defense_profile_id=record.defense_profile_id,
        status=record.status,
        outcome=record.outcome,
        latency_ms=record.latency_ms,
        created_at=_iso(record.created_at),
    )


def _experiment_response(record: Any, counts: ExperimentCounts) -> ExperimentResponse:
    return ExperimentResponse(
        id=record.id,
        name=record.name,
        status=record.status,
        total_runs=counts.total_runs,
        completed_runs=counts.completed_runs,
        failed_runs=counts.failed_runs,
        cancelled_runs=counts.cancelled_runs,
        remaining_runs=counts.remaining_runs,
        created_at=_iso(record.created_at),
        updated_at=_iso(record.updated_at),
        config=ExperimentCreate.model_validate(record.config),
        metadata=record.experiment_metadata,
        cancel_requested=record.cancel_requested,
    )


def _not_found(resource: str, identifier: str) -> ApiError:
    return ApiError(404, f"{resource}_not_found", f"Unknown {resource}: {identifier}")


async def _require_experiment(repository: StorageRepository, experiment_id: str) -> Any:
    experiment = await repository.get_experiment(experiment_id)
    if experiment is None:
        raise _not_found("experiment", experiment_id)
    return experiment


def _catalog_case(request: TestRunRequest) -> tuple[Any, str | None, str]:
    if request.case_kind is CaseKind.ATTACK:
        try:
            case = get_attack(request.case_id)
        except KeyError as error:
            raise _not_found("attack", request.case_id) from error
        return case, case.category.value, case.payload_template
    try:
        case = get_benign_case(request.case_id)
    except KeyError as error:
        raise _not_found("benign_case", request.case_id) from error
    return case, None, case.request


def _validate_profile(profile_id: str) -> str:
    try:
        return DEFAULT_REGISTRY.get_profile(profile_id).id
    except KeyError as error:
        raise ApiError(
            422,
            "unknown_defense_profile",
            f"Unknown defense profile: {profile_id}",
        ) from error


def _experiment_specs(request: ExperimentCreate, *, max_matrix_size: int) -> list[dict[str, Any]]:
    cases: list[tuple[str, str, str | None, dict[str, Any]]] = []
    for attack_id in request.attack_ids:
        try:
            attack = get_attack(attack_id)
        except KeyError as error:
            raise ApiError(422, "unknown_attack", f"Unknown attack: {attack_id}") from error
        cases.append((attack.id, CaseKind.ATTACK.value, attack.category.value, _json(attack)))
    for benign_id in request.benign_case_ids:
        try:
            benign = get_benign_case(benign_id)
        except KeyError as error:
            raise ApiError(
                422,
                "unknown_benign_case",
                f"Unknown benign case: {benign_id}",
            ) from error
        cases.append((benign.id, CaseKind.BENIGN.value, None, _json(benign)))
    profiles = [_validate_profile(profile_id) for profile_id in request.defense_profile_ids]
    total = len(cases) * len(profiles) * request.repetitions
    if total > max_matrix_size:
        raise ApiError(
            422,
            "matrix_too_large",
            "Experiment matrix exceeds the configured maximum",
            details={"requested": total, "maximum": max_matrix_size},
        )
    return [
        {
            "id": f"run-{uuid4().hex}",
            "case_id": case_id,
            "case_kind": case_kind,
            "category": category,
            "defense_profile_id": profile_id,
            "input_payload": {"case": case, "repetition_index": repetition_index},
        }
        for case_id, case_kind, category, case in cases
        for profile_id in profiles
        for repetition_index in range(request.repetitions)
    ]


@router.get("/health", response_model=HealthResponse, operation_id="apiHealth")
async def api_health() -> HealthResponse:
    return HealthResponse(status="ok", service="promptfirewall", database="configured")


@router.get("/catalogs/attacks", response_model=list[AttackDefinition], operation_id="listAttacks")
@router.get("/catalog/attacks", response_model=list[AttackDefinition], include_in_schema=False)
async def list_attacks(category: str | None = Query(default=None)) -> list[AttackDefinition]:
    if category is not None:
        try:
            AttackCategory(category)
        except ValueError as error:
            raise ApiError(
                422,
                "invalid_attack_category",
                f"Unknown attack category: {category}",
            ) from error
    return list(get_attacks(category))


@router.get("/catalogs/benign", response_model=list[BenignCase], operation_id="listBenignCases")
@router.get("/catalog/benign", response_model=list[BenignCase], include_in_schema=False)
async def list_benign_cases() -> list[BenignCase]:
    return list(get_benign_cases())


@router.get(
    "/catalogs/defense-profiles",
    response_model=list[DefenseProfile],
    operation_id="listDefenseProfiles",
)
@router.get(
    "/catalog/defense-profiles",
    response_model=list[DefenseProfile],
    include_in_schema=False,
)
async def list_defense_profiles() -> list[DefenseProfile]:
    return list(DEFAULT_REGISTRY.profiles())


@router.post("/victim/chat", response_model=VictimChatResponse, operation_id="victimChat")
async def victim_chat(
    request: VictimChatRequest,
    repository: StorageRepository = _REPOSITORY,
    victim: VictimService = _VICTIM,
) -> VictimChatResponse:
    run_id = request.run_id or f"run-{uuid4().hex}"
    identity = request.identity or _default_identity()
    try:
        result = victim.run(
            request.message,
            identity,
            session_id=request.session_id,
            run_id=run_id,
        )
    except ValueError as error:
        raise ApiError(422, "invalid_victim_request", str(error)) from error
    await repository.create_run(
        run_id=result.run_id,
        experiment_id=None,
        case_id="chat",
        case_kind="chat",
        defense_profile_id="none",
        input_payload={"message": request.message, "identity": _json(identity)},
    )
    await repository.save_run_result(
        result.run_id,
        status=RunStatus.COMPLETED,
        latency_ms=result.model_response.latency_ms,
        result=_victim_result_payload(result),
    )
    await repository.add_trace_events(result.run_id, result.trace_events)
    return VictimChatResponse(
        run_id=result.run_id,
        session_id=result.session_id,
        response=result.model_response,
        tool_results=list(result.tool_results),
        trace_events=list(result.trace_events),
        access_denials=list(result.access_denials),
    )


@router.post("/victim/test-run", response_model=TestRunResponse, operation_id="victimTestRun")
@router.post("/victim/test", response_model=TestRunResponse, include_in_schema=False)
async def victim_test_run(
    request: TestRunRequest,
    repository: StorageRepository = _REPOSITORY,
    victim: VictimService = _VICTIM,
) -> TestRunResponse:
    case, category, message = _catalog_case(request)
    profile_id = _validate_profile(request.defense_profile_id)
    run_id = request.run_id or f"run-{uuid4().hex}"
    identity = request.identity or _default_identity()
    await repository.create_run(
        run_id=run_id,
        experiment_id=None,
        case_id=request.case_id,
        case_kind=request.case_kind.value,
        defense_profile_id=profile_id,
        category=category,
        input_payload={"case": _json(case), "identity": _json(identity)},
    )
    started = perf_counter()
    context = DefenseContext(
        run_id=run_id,
        correlation_id=run_id,
        identity=_json(identity),
        metadata={"case_id": request.case_id, "case_kind": request.case_kind.value},
    )
    pipeline = DefensePipeline(profile_id)
    input_result = pipeline.process_input(message, context)
    decisions = list(input_result.decisions)
    response: ModelResponse | None = None
    tool_results: list[Any] = []
    trace_events: list[Any] = []
    blocked = input_result.blocked
    if blocked:
        observed: Any = {
            "text": "Request blocked by the selected defense profile.",
            "tool_results": [],
            "trace_events": [],
            "state_before": {},
            "state_after": {},
            "blocked": True,
        }
    else:
        try:
            result = victim.run(
                input_result.payload.content,
                identity,
                session_id=request.session_id,
                run_id=run_id,
            )
        except ValueError as error:
            await repository.save_run_result(
                run_id,
                status=RunStatus.FAILED,
                latency_ms=(perf_counter() - started) * 1000,
                error={"code": "victim_execution_error", "message": str(error)},
            )
            raise ApiError(422, "invalid_victim_request", str(error)) from error
        output_result = pipeline.scan_output(result.model_response, context)
        decisions.extend(output_result.decisions)
        response = output_result.payload.content
        if not isinstance(response, ModelResponse):
            response = result.model_response
        result = replace(result, model_response=response)
        tool_results = list(result.tool_results)
        trace_events = list(result.trace_events)
        observed = result
    judge_results = [
        ObservableCanaryLeakJudge().evaluate(observed),
        PromptDisclosureJudge().evaluate(observed),
        ToolMisuseJudge().evaluate(observed),
        StateChangeJudge().evaluate(observed),
    ]
    if request.case_kind is CaseKind.BENIGN:
        judge_results.append(UtilityJudge().evaluate(observed))
    aggregate = aggregate_judges(judge_results, case_kind=request.case_kind.value)
    outcome = aggregate.outcome
    latency_ms = response.latency_ms if response is not None else (perf_counter() - started) * 1000
    result_payload = {
        "case": _json(case),
        "response": _json(response),
        "tool_results": _json(tool_results),
        "defense_decisions": _json(decisions),
        "judge_results": _json(judge_results),
        "evidence": _json(aggregate.evidence),
        "blocked": blocked,
    }
    saved = await repository.save_run_result(
        run_id,
        status=RunStatus.COMPLETED,
        outcome=outcome,
        latency_ms=latency_ms,
        result=result_payload,
    )
    if saved is None:
        raise _not_found("run", run_id)
    await repository.add_trace_events(run_id, trace_events)
    return TestRunResponse(
        run=_run_summary(saved),
        response=response,
        tool_results=tool_results,
        trace_events=trace_events,
        defense_decisions=decisions,
        judge_results=judge_results,
        outcome=outcome,
        blocked=blocked,
    )


def _victim_result_payload(result: VictimRunResult) -> dict[str, Any]:
    return {
        "session_id": result.session_id,
        "response": _json(result.model_response),
        "tool_results": _json(result.tool_results),
        "retrieved": _json(result.retrieved),
        "memory": _json(result.memory),
        "access_denials": list(result.access_denials),
    }


@router.post(
    "/experiments",
    response_model=ExperimentCreateResponse,
    operation_id="createExperiment",
)
async def create_experiment(
    request: ExperimentCreate,
    repository: StorageRepository = _REPOSITORY,
    job_manager: ExperimentJobManager = _JOB_MANAGER,
) -> ExperimentCreateResponse:
    settings = repository.session.info.get("settings")
    max_matrix_size = getattr(settings, "max_matrix_size", 500)
    specs = _experiment_specs(request, max_matrix_size=max_matrix_size)
    record = await repository.create_experiment_with_runs(request, specs)
    submitted = True
    try:
        await job_manager.submit(record.id)
    except Exception:
        submitted = False
    counts = await repository.counts_for_experiment(record.id)
    return ExperimentCreateResponse(
        **_experiment_response(record, counts).model_dump(),
        submitted=submitted,
    )


@router.get("/experiments", response_model=list[ExperimentResponse], operation_id="listExperiments")
async def list_experiments(
    repository: StorageRepository = _REPOSITORY,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
) -> list[ExperimentResponse]:
    records = await repository.list_experiments(offset=offset, limit=limit)
    return [
        _experiment_response(record, await repository.counts_for_experiment(record.id))
        for record in records
    ]


@router.get(
    "/experiments/{experiment_id}",
    response_model=ExperimentResponse,
    operation_id="getExperiment",
)
async def get_experiment(
    experiment_id: str,
    repository: StorageRepository = _REPOSITORY,
) -> ExperimentResponse:
    record = await _require_experiment(repository, experiment_id)
    return _experiment_response(record, await repository.counts_for_experiment(record.id))


@router.post(
    "/experiments/{experiment_id}/cancel",
    response_model=ExperimentResponse,
    operation_id="cancelExperiment",
)
async def cancel_experiment(
    experiment_id: str,
    repository: StorageRepository = _REPOSITORY,
    job_manager: ExperimentJobManager = _JOB_MANAGER,
) -> ExperimentResponse:
    record = await repository.cancel_experiment(experiment_id)
    if record is None:
        raise _not_found("experiment", experiment_id)
    await job_manager.cancel(experiment_id)
    return _experiment_response(record, await repository.counts_for_experiment(record.id))


@router.get(
    "/experiments/{experiment_id}/runs",
    response_model=list[RunSummaryResponse],
    operation_id="listExperimentRuns",
)
async def list_experiment_runs(
    experiment_id: str,
    repository: StorageRepository = _REPOSITORY,
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[RunSummaryResponse]:
    await _require_experiment(repository, experiment_id)
    return [
        _run_summary(run)
        for run in await repository.list_runs(
            experiment_id=experiment_id,
            offset=offset,
            limit=limit,
        )
    ]


@router.get("/runs", response_model=list[RunSummaryResponse], operation_id="listRuns")
async def list_runs(
    repository: StorageRepository = _REPOSITORY,
    experiment_id: str | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=1000),
) -> list[RunSummaryResponse]:
    return [
        _run_summary(run)
        for run in await repository.list_runs(
            experiment_id=experiment_id,
            offset=offset,
            limit=limit,
        )
    ]


@router.get("/runs/{run_id}", response_model=RunDetailResponse, operation_id="getRun")
async def get_run(
    run_id: str,
    repository: StorageRepository = _REPOSITORY,
) -> RunDetailResponse:
    run = await repository.get_run(run_id)
    if run is None:
        raise _not_found("run", run_id)
    return RunDetailResponse(
        run=_run_summary(run),
        result=run.result,
        error=run.error,
        trace_events=[
            _trace_response(event) for event in await repository.list_trace_events(run_id)
        ],
    )


@router.get("/runs/{run_id}/traces", response_model=list[TraceEvent], operation_id="listRunTraces")
async def list_run_traces(
    run_id: str,
    repository: StorageRepository = _REPOSITORY,
) -> list[TraceEvent]:
    if await repository.get_run(run_id) is None:
        raise _not_found("run", run_id)
    return [_trace_response(event) for event in await repository.list_trace_events(run_id)]


def _trace_response(event: Any) -> TraceEvent:
    return TraceEvent(
        event_id=event.event_id,
        run_id=event.run_id,
        sequence=event.sequence,
        event_type=event.event_type,
        timestamp=event.timestamp,
        stage=event.stage,
        correlation_id=event.correlation_id,
        payload=event.payload,
        defense_id=event.defense_id,
        tool_name=event.tool_name,
        error=event.error,
    )


@router.get(
    "/experiments/{experiment_id}/metrics",
    response_model=MetricsSnapshot,
    operation_id="getExperimentMetrics",
)
async def get_experiment_metrics(
    experiment_id: str,
    repository: StorageRepository = _REPOSITORY,
) -> MetricsSnapshot:
    await _require_experiment(repository, experiment_id)
    return calculate_metrics(await repository.metric_records(experiment_id))


async def _build_report(
    experiment_id: str,
    repository: StorageRepository,
) -> ReportResponse:
    experiment = await _require_experiment(repository, experiment_id)
    counts = await repository.counts_for_experiment(experiment_id)
    runs = await repository.list_runs(experiment_id=experiment_id, limit=100_000)
    return ReportResponse(
        experiment=_experiment_response(experiment, counts),
        runs=[_run_summary(run) for run in runs],
        metrics=calculate_metrics(await repository.metric_records(experiment_id)),
        generated_at=datetime.now(UTC).isoformat(),
    )


def _markdown_report(report: ReportResponse) -> str:
    metrics = report.metrics
    lines = [
        f"# PromptFirewall report: {report.experiment.name}",
        "",
        f"- Experiment ID: `{report.experiment.id}`",
        f"- Status: `{report.experiment.status.value}`",
        f"- Runs: {report.experiment.total_runs}",
        "",
        "## Metrics",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Attack success rate | {_metric_value(metrics.attack_success_rate.value)} |",
        f"| Attack block rate | {_metric_value(metrics.attack_block_rate.value)} |",
        f"| False positive rate | {_metric_value(metrics.false_positive_rate.value)} |",
        f"| Utility retention | {_metric_value(metrics.utility_retention.value)} |",
        f"| Error rate | {_metric_value(metrics.error_rate.value)} |",
        f"| Median latency (ms) | {_metric_value(metrics.median_latency_ms)} |",
        "",
        "## Runs",
        "",
        "| ID | Case | Profile | Status | Outcome |",
        "| --- | --- | --- | --- | --- |",
    ]
    lines.extend(
        f"| `{run.id}` | `{run.case_id}` | `{run.defense_profile_id}` | `{run.status.value}` | "
        f"`{run.outcome or 'pending'}` |"
        for run in report.runs
    )
    return "\n".join(lines) + "\n"


def _metric_value(value: float | None) -> str:
    return "—" if value is None else f"{value:.4f}"


@router.get(
    "/experiments/{experiment_id}/report",
    response_model=ReportResponse,
    operation_id="exportExperimentReport",
)
async def export_experiment_report(
    experiment_id: str,
    format: Literal["json", "markdown"] = Query(default="json"),
    repository: StorageRepository = _REPOSITORY,
) -> ReportResponse | PlainTextResponse:
    report = await _build_report(experiment_id, repository)
    if format == "markdown":
        return PlainTextResponse(_markdown_report(report), media_type="text/markdown")
    return report


@router.get(
    "/experiments/{experiment_id}/report.json",
    response_model=ReportResponse,
    include_in_schema=False,
)
async def export_experiment_report_json(
    experiment_id: str,
    repository: StorageRepository = _REPOSITORY,
) -> ReportResponse:
    return await _build_report(experiment_id, repository)


@router.get(
    "/experiments/{experiment_id}/report.md",
    response_class=PlainTextResponse,
    include_in_schema=False,
)
async def export_experiment_report_markdown(
    experiment_id: str,
    repository: StorageRepository = _REPOSITORY,
) -> PlainTextResponse:
    return PlainTextResponse(
        _markdown_report(await _build_report(experiment_id, repository)),
        media_type="text/markdown",
    )


__all__ = ["router"]

export interface Health {
  status: 'ok';
  request_id: string;
}

export interface Capabilities {
  request_id: string;
  version: string;
  stage: 'M1' | 'M2' | 'M3' | 'M4' | 'M5';
  model_mode: 'fake' | 'real';
  model_aliases?: string[];
  analysis_available: boolean;
  repair_available: boolean;
  dynamic_validation_available: boolean;
  supported_input_types: string[];
  planned_input_types: string[];
  max_file_bytes: number;
  max_files: number;
  max_total_bytes: number;
}

export interface Finding {
  category: 'xss' | 'sqli' | 'cmdi'; cwe: string; severity: string;
  evidence: string; evidence_truncated: boolean; explanation: string; recommendation: string;
  sources: string[]; evidence_status: string;
  location: { kind: 'source'; artifact_id: string; start_line: number; end_line: number } | { kind: 'http'; artifact_id: string; field: string };
}

/** Public, redacted metadata for one HTTP field; raw positions refer to the submitted text. */
export interface FieldMeta {
  part: string; name: string; decode_passes: number; masked: boolean;
  line?: number; raw_start?: number; raw_end?: number; decode_limited?: boolean;
}

export interface InputFeature {
  kind: 'call' | 'string_expression' | 'input_source' | 'text_call_hint';
  line: number; name?: string; sink_candidate?: 'xss' | 'sqli' | 'cmdi';
}

export interface ArtifactPreview {
  id: string; input_type: 'source' | 'http'; display_name: string; sha256: string;
  size_bytes: number; parser_version: string; rule_version: string;
  content: string; fields: Record<string, string>; field_meta: Record<string, FieldMeta>;
  features: InputFeature[]; warnings: string[]; chunk_count: number;
  rule_findings: Finding[]; rule_findings_truncated: boolean;
}

export type Strategy = 'rules' | 'llm' | 'hybrid';
/** One analysed chunk: what rules and the model actually did there (never inferred). */
export interface CoverageEntry {
  artifact_id: string; display_name: string; input_type: string; chunk: number;
  start_line: number; end_line: number;
  rules: 'pending' | 'ran' | 'not_requested' | 'ast_unavailable';
  model: 'not_requested' | 'pending' | 'succeeded' | 'simulated' | 'failed';
  model_error: string | null; failure_category: string | null; llm_findings: number;
}
export interface ScanResult {
  warnings?: string[]; analysis_complete?: boolean; finding_count?: number;
  expected_chunks?: number; processed_chunks?: number; completed_chunks?: number; model_mode?: string;
  coverage?: CoverageEntry[];
}
export interface Scan {
  id: string; status: 'queued' | 'running' | 'completed' | 'partial' | 'failed' | 'cancelled';
  strategy: Strategy; model_alias: string; error_code: string | null;
  cancel_requested: boolean; retries: number; created_at: string; finished_at: string | null;
  call_count: number; artifacts: {id: string; display_name: string; input_type: string; sha256: string}[];
  budget?: { scan_used: number; scan_limit: number; daily_used: number; daily_limit: number } | null;
  attempt?: number;
  attempts?: { attempt: number; status: string; error_code: string | null; finished_at: string | null; summary: ScanResult }[];
  receipt?: AnalysisReceipt;
  result: ScanResult;
}
export interface AnalysisReceipt {
  schema_version: string; input_digest: string; plan_digest: string;
  configuration: { strategy: Strategy; model_alias: string; model: string | null;
    versions: Record<string, string>; system_prompt_sha256: string | null; options: Record<string, unknown> };
  artifacts: { artifact_id: string; input_type: string; sha256: string; normalized_sha256: string;
    fields_sha256: string; chunks: { chunk: number; start_line: number; end_line: number; sha256: string }[] }[];
  limits: Record<string, number>;
}
export interface StoredFinding extends Finding {
  id: string; contributors: Finding[]; severity_disagreement: boolean; severity_policy?: string | null;
}
export interface FindingFilters { cwe?: string; severity?: string; source?: string; evidence_status?: string }
export interface FindingFacets {
  cwe: Record<string, number>; severity: Record<string, number>;
  source: Record<string, number>; evidence_status: Record<string, number>;
}
export type ScanMode = 'rules' | 'simulated' | 'real';
export interface Overview {
  tasks: number; states: Record<string, number>; modes: Record<string, number>;
  real_outcomes: Record<string, number>; cwes: Record<string, number>; severities: Record<string, number>;
  repairs: { current?: number; archived?: number; verdict_sampled?: number; verdict_limit?: number; candidates_total?: number; total: number; by_status: Record<string, number>; simulated: number; dynamic: Record<string, number>;
    verdicts: Record<string, number>; verdicts_truncated: boolean };
  notice: string;
}
export interface HistoryRow {
  id: string; status: Scan['status']; strategy: Strategy; mode: ScanMode; attempt: number; error_code: string | null;
  created_at: string; finished_at: string | null; analysis_complete: boolean | null | undefined;
  expected_chunks?: number | null; completed_chunks?: number | null;
  artifacts: { display_name: string; input_type: string }[];
  findings: { total: number; severities: Record<string, number>; cwes: Record<string, number> };
  repairs: { current?: number; archived?: number; by_status?: Record<string, number>; total: number; simulated: number; verdicts: Record<string, number> };
}
export interface HistoryFilters { status?: string; q?: string; cwe?: string; severity?: string }
/** Redacted public text of one input, for evidence navigation (always rendered as plain text). */
export interface InputView {
  artifact_id: string; display_name: string; input_type: 'source' | 'http'; content: string;
  fields: Record<string, string>; field_meta: Record<string, FieldMeta>; chunk_count: number;
}
export interface LineRange { cwe: string; start_line: number; end_line: number; by_source?: Record<string, string> }
export interface CompareView {
  finding_attempt?: number; scan_attempt?: number; archived?: boolean; delta_status?: { rules: string; model: string };
  repair_id: string; scan_id: string; simulated: boolean; target: LineRange;
  original: { sha256: string; content: string }; candidate: { sha256: string; content: string };
  hunks: { old_start: number; old_end: number; new_start: number; new_end: number }[];
  baseline: LineRange[]; after: { persisting: LineRange[]; preexisting: LineRange[]; introduced: LineRange[] };
}
export type GateState = 'passed' | 'failed' | 'skipped' | 'pending' | 'error';
export interface Gate { id: string; label: string; state: GateState; detail: string }
export interface PatchImpact {
  total_lines: number; changed_lines: number; added_lines: number; change_ratio: number; hunks: number;
  distance: number; removed: string[]; signature_changed: string[]; decorator_changed: string[];
  forbidden_added: string[]; risky_added: string[]; imports_added: string[];
  violations: string[]; warnings: string[];
}
export interface Repair {
  id: string; scan_id: string; finding_id: string; source_id: string; source_sha256: string; anchor: string;
  candidate_id: string | null; model_alias: string; model: string; status: string; error_code: string | null;
  archived?: boolean; finding_attempt?: number; created_at?: string | null; diff: string; validation_status: 'passed' | 'failed' | 'unverified' | 'error'; call_count: number;
  simulated?: boolean; gates?: Gate[]; impact?: PatchImpact | null; dynamic_requested?: boolean;
  checks: {
    contract?: { digest: string; model_alias: string; model: string | null; versions: Record<string, string>; candidate_sha256?: string; source_sha256: string; diff_sha256?: string };
    mode?: string; explanation?: string; syntax?: string; static_passed?: boolean; target_remaining?: boolean;
    llm_complete?: boolean; review?: { status: string; error: string | null };
    preexisting?: { cwe: string; start_line: number; end_line: number }[];
  };
  dynamic: {
    status?: string; error_code?: string; run_id?: string | null; digest?: string; case_id?: string;
    tests?: { name: string; passed: boolean }[]; candidate_sha256?: string; harness_sha256?: string;
    requested_at?: string | null; finished_at?: string; elapsed_ms?: number; cancel_requested?: boolean;
  };
}

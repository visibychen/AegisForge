export interface Health {
  status: 'ok';
  request_id: string;
}

export interface Capabilities {
  request_id: string;
  version: string;
  stage: 'M1' | 'M2' | 'M3';
  model_mode: 'fake';
  analysis_available: false;
  repair_available: false;
  dynamic_validation_available: false;
  supported_input_types: string[];
  planned_input_types: string[];
  max_file_bytes: number;
  max_files: number;
  max_total_bytes: number;
}

export interface Finding {
  category: 'xss' | 'sqli' | 'cmdi'; cwe: string; severity: string;
  evidence: string; explanation: string; recommendation: string;
  sources: string[]; evidence_status: string;
  location: { kind: 'source'; artifact_id: string; start_line: number; end_line: number } | { kind: 'http'; artifact_id: string; field: string };
}
export interface ArtifactPreview {
  id: string; input_type: 'source' | 'http'; display_name: string; sha256: string;
  size_bytes: number; parser_version: string; rule_version: string;
  content: string; fields: Record<string, string>; features: unknown[];
  warnings: string[]; chunk_count: number; rule_findings: Finding[];
}

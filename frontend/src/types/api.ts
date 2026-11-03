export interface Health {
  status: 'ok';
  request_id: string;
}

export interface Capabilities {
  request_id: string;
  version: string;
  stage: 'M1';
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

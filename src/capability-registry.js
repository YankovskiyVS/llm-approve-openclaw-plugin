const PASSIVE_EXACT = new Set([
  'nango_list_connections',
  'nango_yandex_disk_info', 'nango_yandex_disk_list', 'nango_yandex_disk_get',
  'nango_yandex_disk_files', 'nango_yandex_disk_last_uploaded',
  'nango_yandex_disk_download_link', 'nango_yandex_disk_trash_list',
  'nango_yandex_mail_list', 'nango_yandex_mail_get',
  'nango_yandex_calendar_list_calendars', 'nango_yandex_calendar_list_events',
  'nango_yandex_calendar_get_event',
  'read', 'web_fetch', 'web_search', 'sessions_list', 'sessions_history',
  'session_status',
]);

const MUTATION_EXACT = new Set(['write', 'edit', 'apply_patch']);
const EXTERNAL_EXACT = new Set(['nango_yandex_mail_send', 'sessions_send']);
const RESOURCE_EXACT = new Set([
  'sessions_spawn', 'nango_yandex_disk_mkdir',
  'nango_yandex_calendar_create_calendar', 'nango_yandex_calendar_create_event',
]);
const DESTRUCTIVE_EXACT = new Set([
  'nango_yandex_disk_delete', 'nango_yandex_disk_trash_empty',
  'nango_yandex_calendar_delete_event',
]);
const NANGO_MUTATION_PATTERN = /_(?:upload|upload_link|copy|move|publish|unpublish|trash_restore|update_event)$/u;
const PASSIVE_NAME_PATTERN = /_(?:list|list_[a-z0-9_]+|get|get_[a-z0-9_]+|read|read_[a-z0-9_]+|search|search_[a-z0-9_]+|info|files|last_uploaded|download_link)$/u;

function genericNangoCall(toolName, params) {
  if (!toolName.startsWith('nango_') || !toolName.endsWith('_call')) return null;
  const method = typeof params?.method === 'string' ? params.method.trim().toUpperCase() : 'GET';
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') return 'passive';
  if (method === 'DELETE') return 'destructive';
  if (method === 'POST' || method === 'PUT' || method === 'PATCH') return 'mutation';
  return 'unknown';
}

function toolFamily(toolName) {
  if (toolName.startsWith('nango_yandex_mail_')) return 'nango_mail';
  if (toolName.startsWith('nango_yandex_disk_')) return 'nango_disk';
  if (toolName.startsWith('nango_yandex_calendar_')) return 'nango_calendar';
  if (toolName.startsWith('nango_')) return 'nango';
  if (toolName === 'web_fetch' || toolName === 'web_search') return 'web';
  if (toolName === 'write' || toolName === 'edit' || toolName === 'apply_patch' || toolName === 'read') return 'filesystem';
  if (toolName.startsWith('sessions_') || toolName === 'session_status') return 'session';
  if (toolName === 'exec' || toolName === 'bash') return 'shell';
  if (toolName === 'browser') return 'browser';
  if (toolName === 'message') return 'message';
  if (toolName === 'process') return 'process';
  if (toolName === 'cron') return 'cron';
  if (toolName === 'nodes') return 'node';
  if (toolName === 'image_generate' || toolName === 'music_generate'
    || toolName === 'video_generate') return 'generation';
  if (toolName === 'skill_workshop') return 'skill';
  if (toolName === 'image_query') return 'network';
  return 'unknown';
}

function result(kind, toolName, reason) {
  return Object.freeze({
    kind,
    tool_family: toolFamily(toolName),
    passive: kind === 'passive',
    mutation: kind === 'mutation' || kind === 'destructive'
      || kind === 'externalCommunication' || kind === 'resourceCreation',
    destructive: kind === 'destructive',
    external_communication: kind === 'externalCommunication',
    resource_creation: kind === 'resourceCreation',
    reason,
  });
}

export function classifyToolCapability(toolName, params = {}) {
  if (typeof toolName !== 'string' || !toolName.trim()) {
    return result('unknown', '', 'invalid_tool_name');
  }
  const name = toolName.trim();
  if (PASSIVE_EXACT.has(name) || (name.startsWith('nango_') && PASSIVE_NAME_PATTERN.test(name))) {
    return result('passive', name, 'known_read_only_tool');
  }
  const generic = genericNangoCall(name, params);
  if (generic) return result(generic, name, `nango_http_${generic}`);
  if (EXTERNAL_EXACT.has(name)) return result('externalCommunication', name, 'known_external_communication');
  if (RESOURCE_EXACT.has(name)) return result('resourceCreation', name, 'known_resource_creation');
  if (DESTRUCTIVE_EXACT.has(name) || /_(?:delete|remove|trash_empty)$/u.test(name)) {
    return result('destructive', name, 'known_destructive_tool');
  }
  if (MUTATION_EXACT.has(name) || NANGO_MUTATION_PATTERN.test(name)) {
    return result('mutation', name, 'known_mutation_tool');
  }
  return result('unknown', name, 'unknown_tool_semantics');
}

export function classifyToolFamily(toolName, params = {}) {
  if (typeof toolName !== 'string' || !toolName.trim()
    || toolName.length > 256 || Buffer.byteLength(toolName, 'utf8') > 512
    || /[\u0000-\u001f\u007f-\u009f]/u.test(toolName)) {
    throw new TypeError('invalid run decision store');
  }
  return classifyToolCapability(toolName, params).tool_family;
}

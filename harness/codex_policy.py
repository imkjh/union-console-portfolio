"""Fixed Codex options shared by offline verification and the pending live probe."""
FLAGS = (
    'shell_tool', 'unified_exec', 'shell_snapshot', 'view_image', 'apps',
    'browser_use', 'browser_use_external', 'computer_use', 'hooks', 'plugins',
    'remote_plugin', 'multi_agent', 'image_generation', 'skill_search',
    'skill_mcp_dependency_install', 'code_mode_host', 'workspace_dependencies',
    'in_app_local_automation', 'tool_suggest', 'enable_request_compression',
)
BASE_OPTIONS = (
    '--skip-git-repo-check', '--ephemeral', '--ignore-user-config', '--ignore-rules',
    '--strict-config', '--json', '-c', 'approval_policy="never"', '-m', 'gpt-6-astra',
    '-c', 'model_catalog_json="/work/catalog.json"', '-c', 'web_search="disabled"',
    '-c', 'agents.enabled=false', '-c', 'analytics.enabled=false', '-c', 'feedback.enabled=false',
    '-c', 'history.persistence="none"', '-c', 'otel.exporter="none"',
    '-c', 'otel.trace_exporter="none"', '-c', 'otel.metrics_exporter="none"',
    '-c', 'otel.log_user_prompt=false',
)
ROOT_DENY_OPTIONS = (
    '-c', 'default_permissions="union_probe"', '-c',
    'permissions.union_probe={extends=":read-only",filesystem={"/"="deny"}}',
)


def locked_options():
    options = [*BASE_OPTIONS, *ROOT_DENY_OPTIONS]
    for feature in FLAGS:
        options += ['--disable', feature]
    return options

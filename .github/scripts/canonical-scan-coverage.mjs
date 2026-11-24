import { pathToFileURL } from 'node:url';

const repositories = {
  'mark-siazon/Hackathon-HireProof': {
    canonical: 'Iron-Mark/Hackathon-HireProof',
    workflowPath: '.github/workflows/codeql.yml',
  },
  'mark-siazon/Hackathon-LexInsights': {
    canonical: 'Iron-Mark/Hackathon-LexInsights',
    workflowPath: 'dynamic/github-code-scanning/codeql',
  },
};
const maxScanAge = 10 * 24 * 60 * 60 * 1000; // Weekly scan plus three days of grace.
const metadataPaths = new Set([
  '.github/dependabot.yml',
  '.github/workflows/codeql.yml',
  '.github/workflows/weekly-repository-health.yml',
  '.github/scripts/canonical-scan-coverage.mjs',
  '.github/tests/canonical-scan-coverage.test.mjs',
  'AGENTS.md',
  'docs/README.md',
  'docs/security.md',
  'docs/operations/TESTING.md',
]);

// Cross-repository calls deliberately use public APIs, never a privileged PAT.
// The workflow token is used only for its own repository's Actions metadata.
export function createApi({ token, localRepository, fetchImpl = fetch }) {
  return async (repository, endpoint) => {
    const headers = {
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    };
    if (repository === localRepository && token) headers.Authorization = `Bearer ${token}`;
    const response = await fetchImpl(`https://api.github.com/repos/${repository}${endpoint}`, {
      headers,
      signal: AbortSignal.timeout(30_000),
    });
    if (!response.ok) throw new Error(`GitHub API ${response.status}: ${repository}${endpoint}`);
    return response.json();
  };
}

async function list(api, repository, endpoint, key) {
  const values = [];
  for (let page = 1; page <= 20; page++) {
    const data = await api(repository, `${endpoint}${endpoint.includes('?') ? '&' : '?'}per_page=100&page=${page}`);
    if (!Array.isArray(data[key]) || !Number.isInteger(data.total_count)) {
      throw new Error(`Incomplete ${key} response for ${repository}`);
    }
    values.push(...data[key]);
    if (values.length >= data.total_count) return values;
    if (data[key].length === 0) break;
  }
  throw new Error(`Could not completely enumerate ${key} for ${repository}`);
}

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

export async function auditCoverage({ repository, api, now = Date.now() }) {
  const summary = [];
  const problems = [];
  try {
    const policy = repositories[repository];
    invariant(policy, `No canonical scanning policy for ${repository}`);
    const local = await api(repository, '');
    invariant(local.fork === true && local.parent?.full_name === policy.canonical,
      'Fork parent does not match the approved canonical repository');
    const localWorkflows = await list(api, repository, '/actions/workflows', 'workflows');
    const localCodeQL = localWorkflows.find((workflow) => workflow.path === '.github/workflows/codeql.yml');
    invariant(localCodeQL?.state === 'disabled_manually',
      'Duplicate fork CodeQL must remain manually disabled; verify the scanning policy');
    summary.push('Duplicate fork CodeQL: intentionally disabled (disabled_manually); historical fork scans are not used as current coverage.');
    invariant(!localWorkflows.some((workflow) => workflow.state === 'active'
      && (/codeql/i.test(workflow.name) || workflow.path === 'dynamic/github-code-scanning/codeql')),
    'An additional active CodeQL workflow is running on the fork');

    const canonical = await api(policy.canonical, '');
    invariant(canonical.private === false && !canonical.archived,
      'Canonical scan evidence must come from an active public repository');
    const canonicalBranch = canonical.default_branch;
    invariant(typeof canonicalBranch === 'string' && canonicalBranch.length > 0, 'Canonical default branch is unavailable');
    const branch = await api(policy.canonical, `/branches/${encodeURIComponent(canonicalBranch)}`);
    const sha = branch.commit?.sha;
    invariant(/^[a-f0-9]{40}$/.test(sha), 'Canonical default-branch SHA is unavailable');
    const workflows = await list(api, policy.canonical, '/actions/workflows', 'workflows');
    const workflow = workflows.find((candidate) => candidate.path === policy.workflowPath);
    invariant(workflow?.state === 'active', 'Canonical CodeQL workflow is missing or disabled');
    summary.push(`Canonical scanner: ${policy.canonical} (${workflow.path}), active.`);
    const runs = await list(api, policy.canonical,
      `/actions/workflows/${workflow.id}/runs?branch=${encodeURIComponent(canonicalBranch)}&head_sha=${sha}`, 'workflow_runs');
    const run = runs.filter((candidate) => candidate.head_sha === sha
      && candidate.head_branch === canonicalBranch
      && candidate.repository?.full_name === policy.canonical
      && candidate.head_repository?.full_name === policy.canonical
      && ['push', 'schedule', 'dynamic', 'workflow_dispatch'].includes(candidate.event))
      .sort((left, right) => Date.parse(right.created_at) - Date.parse(left.created_at) || right.id - left.id)[0];
    invariant(run, `No canonical CodeQL run covers current ${canonicalBranch} (${sha})`);
    invariant(run.status === 'completed' && run.conclusion === 'success',
      `Latest canonical CodeQL run for current ${canonicalBranch} is ${run.status}/${run.conclusion}`);
    const scanTime = Date.parse(run.updated_at);
    invariant(Number.isFinite(scanTime) && scanTime <= now + 5 * 60 * 1000 && now - scanTime <= maxScanAge,
      'Canonical CodeQL run is stale (over 10 days old) or has an invalid timestamp');
    const jobs = await list(api, policy.canonical, `/actions/runs/${run.id}/jobs?filter=latest`, 'jobs');
    const analysisJobs = jobs.filter((job) => job.steps?.some((step) => step.name === 'Perform CodeQL Analysis'));
    invariant(jobs.length > 0 && jobs.every((job) => job.status === 'completed' && job.conclusion === 'success')
      && analysisJobs.length > 0 && analysisJobs.every((job) => job.steps.some((step) => step.name === 'Perform CodeQL Analysis'
        && step.status === 'completed' && step.conclusion === 'success')),
    'Canonical run lacks successful completed CodeQL analysis jobs/steps');
    const runUrl = `https://github.com/${policy.canonical}/actions/runs/${run.id}`;
    summary.push(`Canonical coverage: [successful CodeQL run](${runUrl}) for current ${canonicalBranch} \`${sha}\`; completed ${run.updated_at}; ${analysisJobs.length} analysis job(s).`);

    const localBranch = await api(repository, `/branches/${encodeURIComponent(local.default_branch)}`);
    const forkSha = localBranch.commit?.sha;
    invariant(/^[a-f0-9]{40}$/.test(forkSha), 'Fork default-branch SHA is unavailable');
    const comparison = await api(policy.canonical, `/compare/${sha}...${forkSha}?per_page=1`);
    invariant(comparison.base_commit?.sha === sha
      && Array.isArray(comparison.files) && Number.isInteger(comparison.ahead_by)
      && Number.isInteger(comparison.behind_by), 'Incomplete fork divergence evidence');
    // GitHub caps this field at 300 files; a full-looking page cannot prove coverage.
    invariant(comparison.files.length < 300, 'Fork comparison may be truncated at GitHub\'s 300-file limit');
    const uncovered = comparison.files.filter((file) => !metadataPaths.has(file.filename)
      || (file.previous_filename && !metadataPaths.has(file.previous_filename)));
    invariant(uncovered.length === 0,
      `Fork-only files need separate scan coverage: ${uncovered.map((file) => file.filename).join(', ')}`);
    summary.push(`Fork divergence: ${comparison.ahead_by} commit(s) ahead, ${comparison.behind_by} behind canonical main; ${comparison.files.length} fork-only metadata/documentation file(s), no fork-only application changes.`);
    summary.push('Coverage applies to canonical application code; fork-only metadata/workflows are outside that scan. Canonical alert contents are not available to this fork token; this is execution coverage, not a zero-alert assertion.');
    // A push during this audit must not make a previously verified SHA look current.
    const finalBranch = await api(policy.canonical, `/branches/${encodeURIComponent(canonicalBranch)}`);
    const finalLocalBranch = await api(repository, `/branches/${encodeURIComponent(local.default_branch)}`);
    invariant(finalBranch.commit?.sha === sha && finalLocalBranch.commit?.sha === forkSha,
      'A default branch changed during verification; rerun the audit');
  } catch (error) {
    problems.push(error.message);
  }
  return { summary, problems };
}

export function formatCoverage(result) {
  // Render API-derived text as one line per item, with no workflow commands.
  const clean = (value) => String(value).replace(/[\r\n\u0000-\u001f]/g, ' ');
  return [
    ...result.summary.map((line) => `- ℹ️ ${clean(line)}`),
    ...result.problems.map((line) => `- ❌ Canonical scan coverage: ${clean(line)}`),
  ].join('\n');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const repository = process.env.GH_REPO;
  const result = await auditCoverage({
    repository,
    api: createApi({ token: process.env.GH_TOKEN, localRepository: repository }),
  });
  console.log(formatCoverage(result));
  process.exitCode = result.problems.length > 0 ? 1 : 0;
}

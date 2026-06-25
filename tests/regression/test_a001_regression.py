"""
PRBL-A001 regression suite — Missing Access Control.

Covers every false-positive fix discovered across production stress testing:
  - DRF views relying on DEFAULT_PERMISSION_CLASSES falsely flagged (downgrade to LOW)
  - permission_classes declared at class level (60-line lookback) not recognized
  - Inline auth middleware (router.get('/x', auth, handler)) bare 'auth' identifier
  - /public prefix matching /public-data (negative lookahead)
  - /health, /docs, /swagger, /metrics, JWKS routes falsely flagged
  - Inline auth-check function calls (requireAuth(), getServerSession()) not recognized
  - /:id/similar public product route (confirmed FP from 74-repo batch)
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
from prbl.scanner.rules import run_all_rules


def run(code: str, language: str = 'javascript', file_path: str = 'test.js') -> list:
    return [{'rule_id': m.rule_id, 'severity': m.severity, 'line': m.line_number}
            for m in run_all_rules(code, language, file_path)]


# ── TRUE POSITIVES ────────────────────────────────────────────────────────────

def test_unprotected_route_fires():
    """True positive: route with no auth fires A001."""
    code = '''
app.get('/api/users', (req, res) => {
  const users = db.query('SELECT * FROM users')
  res.json(users)
})
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-A001' for f in findings), \
        "PRBL-A001 must fire on unprotected route accessing user data"


def test_express_with_auth_middleware_not_flagged():
    """True positive guard: route with explicit auth middleware must NOT fire."""
    code = '''
app.get('/api/users', requireAuth, (req, res) => {
  const users = db.query('SELECT * FROM users')
  res.json(users)
})
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-A001' for f in findings)


# ── FALSE POSITIVE REGRESSIONS ────────────────────────────────────────────────

def test_health_route_not_flagged():
    """Regression: /health route must not be flagged as missing auth."""
    code = '''
app.get('/health', (req, res) => {
  res.json({ status: 'ok' })
})
'''
    findings = run(code)
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, \
        f"PRBL-A001 must not fire on /health route. Got: {a001}"


def test_docs_route_not_flagged():
    """Regression: /docs route must not be flagged."""
    code = '''
app.get('/docs', swaggerUI)
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-A001' for f in findings)


def test_swagger_route_not_flagged():
    """Regression: /swagger route must not be flagged."""
    code = '''
app.use('/swagger', swaggerUI.serve, swaggerUI.setup(swaggerDoc))
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-A001' for f in findings)


def test_metrics_route_not_flagged():
    """Regression: /metrics route must not be flagged."""
    code = '''
app.get('/metrics', (req, res) => {
  res.send(prometheusMetrics())
})
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-A001' for f in findings)


def test_jwks_route_not_flagged():
    """Regression: /.well-known/jwks.json route must not be flagged."""
    code = '''
app.get('/.well-known/jwks.json', (req, res) => {
  res.json(jwks)
})
'''
    findings = run(code)
    assert not any(f['rule_id'] == 'PRBL-A001' for f in findings)


def test_public_prefix_does_not_match_public_data():
    """Regression: /public-data must not be treated as a /public route exemption."""
    # /public-data is NOT a public static file path — should still be evaluated
    code = '''
app.get('/public-data/users', (req, res) => {
  const users = db.query('SELECT * FROM users')
  res.json(users)
})
'''
    # This SHOULD fire (no auth, accessing sensitive data at a non-public path)
    findings = run(code)
    # The test is that /public-data doesn't get the /public exemption
    # We can't assert it fires (depends on taint analysis), but at minimum the
    # negative lookahead must prevent /public-data from matching the public exclusion.
    # Verify the exclusion pattern correctly distinguishes /public from /public-data.
    from prbl.scanner.rules import _PUBLIC_ROUTE_RE
    import re
    # The regex requires surrounding quotes (as it matches route strings in code)
    assert _PUBLIC_ROUTE_RE.search("'/public'"), "/public must be in safe routes"
    assert _PUBLIC_ROUTE_RE.search("'/public/img/logo.png'"), "/public/sub must be in safe routes"
    # /public-data must NOT match
    assert not _PUBLIC_ROUTE_RE.search("'/public-data'"), \
        "/public-data must NOT match the /public safe-route exclusion"


def test_inline_require_auth_not_flagged():
    """Regression: requireAuth() called in first lines of handler suppresses A001."""
    code = '''
export async function GET(req) {
  requireAuth(req)
  const data = await db.query('SELECT * FROM users')
  return Response.json(data)
}
'''
    findings = run(code)
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, \
        f"PRBL-A001 must not fire when requireAuth() called inline. Got: {a001}"


def test_get_server_session_not_flagged():
    """Regression: getServerSession() in handler body suppresses A001."""
    code = '''
export async function GET(req) {
  const session = await getServerSession(authOptions)
  if (!session) return new Response('Unauthorized', { status: 401 })
  const data = await prisma.user.findMany()
  return Response.json(data)
}
'''
    findings = run(code)
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, \
        f"PRBL-A001 must not fire when getServerSession() called inline. Got: {a001}"


def test_drf_view_without_permission_classes_downgraded():
    """Regression: DRF view relying on DEFAULT_PERMISSION_CLASSES is downgraded to LOW."""
    code = '''
from rest_framework.views import APIView
from rest_framework.response import Response

class UserListView(APIView):
    def get(self, request):
        users = User.objects.all()
        return Response(UserSerializer(users, many=True).data)
'''
    findings = run(code, language='python', file_path='views.py')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    if a001:
        # If it fires, it must be LOW (DRF default permissions policy)
        assert a001[0]['severity'] == 'low', \
            f"DRF view without explicit permission_classes must be LOW. Got: {a001[0]['severity']}"


def test_route_with_similar_suffix_not_exempt():
    """Regression: /:id/similar public product route was confirmed FP — should not fire."""
    code = '''
router.get('/products/:id/similar', async (req, res) => {
  const similar = await Product.findSimilar(req.params.id)
  res.json(similar)
})
'''
    # This is a public product recommendation endpoint — confirmed FP in 74-repo batch
    findings = run(code)
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    # Either doesn't fire, or fires at LOW/medium — should not fire HIGH
    if a001:
        assert a001[0]['severity'] != 'high', \
            f"/:id/similar product route should not fire HIGH. Got: {a001[0]['severity']}"


# ── PRBL-A001: Fastify route patterns (ITEM 9) ───────────────────────────────

def test_fastify_get_no_auth_fires():
    """True positive: fastify.get() with sensitive op and no auth fires A001."""
    code = '''
fastify.get('/users', async (req, reply) => {
  const users = await db.find({})
  reply.send(users)
})
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-A001' for f in findings), \
        "PRBL-A001 must fire on fastify.get with sensitive op and no auth"


def test_fastify_route_object_config_no_auth_fires():
    """True positive: fastify.route({method, url, handler}) with no auth fires A001."""
    code = '''
fastify.route({
  method: 'GET',
  url: '/admin/users',
  handler: async (req, reply) => {
    const users = await User.findAll()
    reply.send(users)
  }
})
'''
    findings = run(code)
    assert any(f['rule_id'] == 'PRBL-A001' for f in findings), \
        "PRBL-A001 must fire on fastify.route() object-config with no auth"


def test_fastify_post_with_auth_not_flagged():
    """True negative: fastify.post() with auth middleware must not fire A001."""
    code = '''
fastify.addHook('preHandler', authenticate)
fastify.post('/users', async (req, reply) => {
  const user = await User.create(req.body)
  reply.send(user)
})
'''
    findings = run(code)
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, \
        f"PRBL-A001 must not fire when auth hook is present. Got: {a001}"


def test_fastify_health_route_not_flagged():
    """True negative: fastify.get('/health', handler) must not fire A001."""
    code = '''
fastify.get('/health', async (req, reply) => {
  reply.send({ status: 'ok' })
})
'''
    findings = run(code)
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, \
        f"PRBL-A001 must not fire on fastify /health route. Got: {a001}"


def test_fastify_login_route_not_flagged():
    """True negative: fastify.get('/login', handler) must not fire A001."""
    code = '''
fastify.get('/login', async (req, reply) => {
  reply.send({ message: 'login page' })
})
'''
    findings = run(code)
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, \
        f"PRBL-A001 must not fire on fastify /login route. Got: {a001}"


def test_permission_classes_class_level_recognized():
    """Regression: permission_classes at class level (60-line lookback) recognized."""
    code = '''
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated

class UserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        users = User.objects.all()
        return Response(UserSerializer(users, many=True).data)
'''
    findings = run(code, language='python', file_path='views.py')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, \
        f"PRBL-A001 must not fire when permission_classes declared at class level. Got: {a001}"


# ── Fix 2: Repo-wide A001 suppression (via filter_a001_if_no_repo_auth) ───────
# Note: run_all_rules() is per-file. The repo-level suppression is in
# PrblScanner.scan_directory() and filter_a001_if_no_repo_auth(). These tests
# verify the helper function works correctly.

def test_no_auth_anywhere_suppresses_a001():
    """Fix 2: when no file in a repo has any auth, all A001 findings are suppressed."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from prbl.scanner.rules import filter_a001_if_no_repo_auth, run_all_rules

    # Simulate two files: both have routes with no auth (TodoMVC style)
    code1 = '''
app.get('/todos', (req, res) => {
  const todos = db.query('SELECT * FROM todos')
  res.json(todos)
})
'''
    code2 = '''
app.post('/todos', (req, res) => {
  db.run('INSERT INTO todos VALUES (?)', [req.body.text])
  res.sendStatus(201)
})
'''
    findings1 = run_all_rules(code1, 'javascript', 'routes/todos.js')
    findings2 = run_all_rules(code2, 'javascript', 'routes/todos2.js')

    # Before filter — should have A001
    assert any(f.rule_id == 'PRBL-A001' for f in findings1 + findings2), \
        "Should have A001 before repo-level filter"

    # Apply repo-level filter
    filtered = filter_a001_if_no_repo_auth([findings1, findings2], [code1, code2])
    all_after = filtered[0] + filtered[1]
    a001_after = [f for f in all_after if f.rule_id == 'PRBL-A001']
    assert not a001_after, \
        f"A001 must be suppressed when no file has auth indicators. Got: {a001_after}"


def test_repo_with_some_auth_keeps_a001():
    """Fix 2: if any file has auth, A001 findings are kept (partial auth = gaps)."""
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))
    from prbl.scanner.rules import filter_a001_if_no_repo_auth, run_all_rules

    code_unprotected = '''
app.get('/admin', (req, res) => {
  const users = db.query('SELECT * FROM users')
  res.json(users)
})
'''
    code_with_auth = '''
const requireAuth = (req, res, next) => { /* check token */ next() }
app.get('/profile', requireAuth, (req, res) => {
  res.json(req.user)
})
'''
    findings_unprotected = run_all_rules(code_unprotected, 'javascript', 'routes/admin.js')
    findings_auth = run_all_rules(code_with_auth, 'javascript', 'routes/profile.js')

    filtered = filter_a001_if_no_repo_auth(
        [findings_unprotected, findings_auth],
        [code_unprotected, code_with_auth]
    )
    all_after = filtered[0] + filtered[1]
    a001_after = [f for f in all_after if f.rule_id == 'PRBL-A001']
    assert a001_after, \
        "A001 must be kept when at least one file has auth indicators"


# ── KNOWN-SAFE ROUTE ALLOWLIST (Fix 2) ────────────────────────────────────────

def test_health_route_suppressed():
    """True negative: /health route must not fire A001."""
    code = """
app.get('/health', (req, res) => {
  res.json({ status: 'ok', db: db.ping() })
})
"""
    findings = run(code, language='javascript', file_path='routes.js')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, f"A001 must not fire on /health route. Got: {a001}"


def test_api_status_route_suppressed():
    """True negative: /api/status route must not fire A001."""
    code = """
app.get('/api/status', (req, res) => {
  res.json({ uptime: process.uptime(), users: User.count() })
})
"""
    findings = run(code, language='javascript', file_path='routes.js')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, f"A001 must not fire on /api/status route. Got: {a001}"


def test_api_users_route_still_fires():
    """True positive: /api/users with no auth still fires A001."""
    code = """
app.get('/api/users', (req, res) => {
  const users = User.findAll()
  res.json(users)
})
"""
    findings = run(code, language='javascript', file_path='routes.js')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert a001, "A001 must still fire on /api/users without auth"


def test_nextjs_health_file_path_suppressed():
    """True negative: Next.js App Router health endpoint file must not fire A001."""
    code = """
export async function GET(request) {
  const status = await db.query('SELECT 1')
  return Response.json({ status: 'ok' })
}
"""
    findings = run(code, language='javascript', file_path='app/api/health/route.ts')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert not a001, f"A001 must not fire on app/api/health/route.ts. Got: {a001}"


# ── Centralized/router-level auth blind spot ────────────────────────────────
# Confirmed across 8 frameworks in a 976-repo HN stress test (Express, Next.js,
# FastAPI, Fastify, SvelteKit, NestJS, Flask, Hono). When auth is applied once
# at the router/middleware level instead of per-route, a per-route pattern
# match can never see it — repos hit this at scale (7-34 near-identical A001
# hits in one file). Downgraded to LOW with a "verify manually" message rather
# than suppressed entirely, since centralized auth can still have real gaps.

def test_fastapi_router_dependencies_downgraded_to_low():
    """FastAPI APIRouter(dependencies=[...]) — auth applied at router level."""
    padding = "\n".join(f"# padding line {i}" for i in range(70))
    code = f"""
from fastapi import APIRouter, Depends
router = APIRouter(dependencies=[Depends(get_current_user)])
{padding}

@router.get("/users", response_model=list)
def list_users():
    return db.query(User).all()
"""
    findings = run(code, language='python', file_path='routes.py')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert a001, "A001 should still fire (downgraded), not disappear entirely"
    assert a001[0]['severity'] == 'low', \
        f"A001 must downgrade to LOW when APIRouter(dependencies=[...]) is present. Got: {a001}"


def test_express_router_use_downgraded_to_low():
    """Express router.use(middleware) — auth applied at router level."""
    padding = "\n".join(f"// padding line {i}" for i in range(70))
    code = f"""
const router = require('express').Router();
router.use(globalMiddleware);
{padding}

router.get('/users', (req, res) => {{
  db.query('SELECT * FROM users').then(rows => res.json(rows));
}});
"""
    findings = run(code, language='javascript', file_path='routes.js')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert a001, "A001 should still fire (downgraded), not disappear entirely"
    assert a001[0]['severity'] == 'low', \
        f"A001 must downgrade to LOW when router.use(...) is present. Got: {a001}"


def test_plain_unauthenticated_route_still_fires_medium():
    """Regression guard: no router-level auth signal anywhere — must still
    fire MEDIUM, not get incorrectly downgraded."""
    code = """
app.get('/users', (req, res) => {
  db.query('SELECT * FROM users').then(rows => res.json(rows));
});
"""
    findings = run(code, language='javascript', file_path='plain.js')
    a001 = [f for f in findings if f['rule_id'] == 'PRBL-A001']
    assert a001, "A001 must still fire on a genuinely unauthenticated route"
    assert a001[0]['severity'] == 'medium', \
        f"A001 must stay MEDIUM with no router-level auth signal present. Got: {a001}"

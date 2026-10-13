import { useEffect, useState } from "react";
import {
  Activity,
  AlertTriangle,
  CheckCircle2,
  Database,
  Edit3,
  LogOut,
  Moon,
  Plus,
  RefreshCw,
  Save,
  Server,
  Shield,
  Sun,
  Trash2,
  Undo2,
  X,
} from "lucide-react";
import { t, setLang, getLang, type Lang } from "./i18n";

type Principal = { username: string; role: string; csrf: string };
type Addr = { type: "any" | "cidr" | "ipset" | "alias"; value: string };
type Alias = { id: number; name: string; address: string };
type PortRange = { from: number; to: number };
type Rule = {
  id: string;
  table: string;
  chain: string;
  action: string;
  source: Addr;
  destination: Addr;
  protocol: string;
  source_ports: PortRange[];
  dest_ports: PortRange[];
  in_interface: string;
  out_interface: string;
  to_address: string;
  to_port: number;
  states: string[];
  comment: string;
  enabled: boolean;
  position: number;
  packets: number;
  bytes: number;
};
type RawRule = { table: string; chain: string; line: string; reason: string };
type Draft = {
  snapshot_id: string;
  policies: Record<string, string>;
  aliases?: Record<string, string>;
  rules: Rule[] | null;
  unsupported: RawRule[] | null;
  raw: string;
};
type IPSetMember = {
  value: string;
  comment: string;
};
type IPSet = {
  name: string;
  type: string;
  family: string;
  members: IPSetMember[] | null;
  references: number;
  comment: boolean;
};
type Rollback = { active: boolean; deadline: string };

let csrf = "";
async function api(path: string, init: RequestInit = {}) {
  const headers = new Headers(init.headers);
  headers.set("Content-Type", "application/json");
  if (csrf) headers.set("X-CSRF-Token", csrf);
  const response = await fetch("/api/v1" + path, { ...init, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || response.statusText);
  return data;
}
function normalize(d: Draft): Draft {
  return {
    ...d,
    policies: d?.policies || {},
    rules: d?.rules || [],
    unsupported: d?.unsupported || [],
  };
}
function ruleID() {
  const bytes = new Uint32Array(4);
  if (globalThis.crypto?.getRandomValues)
    globalThis.crypto.getRandomValues(bytes);
  else
    for (let i = 0; i < bytes.length; i++)
      bytes[i] = Math.floor(Math.random() * 0xffffffff);
  return `draft-${Date.now().toString(36)}-${Array.from(bytes, (n) => n.toString(36)).join("")}`;
}
function emptyRule(table: string, chain: string, position: number): Rule {
  return {
    id: ruleID(),
    table,
    chain,
    action: table === "nat" ? "DNAT" : "ACCEPT",
    source: { type: "any", value: "" },
    destination: { type: "any", value: "" },
    protocol: "tcp",
    source_ports: [],
    dest_ports: [],
    in_interface: "",
    out_interface: "",
    to_address: "",
    to_port: 0,
    states: [],
    comment: "",
    enabled: true,
    position,
    packets: 0,
    bytes: 0,
  };
}

function Auth({ done }: { done: (p: Principal) => void }) {
  const [setup, setSetup] = useState(false),
    [username, setUser] = useState("admin"),
    [password, setPass] = useState(""),
    [error, setError] = useState("");
  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    try {
      if (setup) {
        const r = await fetch("/api/v1/setup", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
        });
        if (!r.ok) throw new Error((await r.json()).error);
      }
      const p = await api("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username, password }),
      });
      csrf = p.csrf;
      done(p);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <main className="auth">
      <form className="login card" onSubmit={submit}>
        <div className="brand">
          <span className="logo">
            <Shield />
          </span>
          <div>
            <h1>Firewall UI</h1>
            <p>{t("Secure iptables management")}</p>
          </div>
        </div>
        <h2>{setup ? t("Create administrator") : t("Sign in")}</h2>
        {error && <div className="error">{error}</div>}
        <label>
          {t("Username")}
          <input
            value={username}
            onChange={(e) => setUser(e.target.value)}
            autoComplete="username"
          />
        </label>
        <label>
          {t("Password")}
          <input
            type="password"
            value={password}
            onChange={(e) => setPass(e.target.value)}
            autoComplete={setup ? "new-password" : "current-password"}
          />
        </label>
        <button className="primary">
          {setup ? t("Create and sign in") : t("Sign in")}
        </button>
        <button type="button" className="link" onClick={() => setSetup(!setup)}>
          {setup ? t("I already have an account") : t("First launch setup")}
        </button>
      </form>
    </main>
  );
}

export function App() {
  const [user, setUser] = useState<Principal | null>(null),
    [draft, setDraft] = useState<Draft | null>(null),
    [baseline, setBaseline] = useState(""),
    [sys, setSys] = useState<any>(null),
    [tab, setTab] = useState("Overview"),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [dark, setDark] = useState(false),
    [fontSize, setFontSize] = useState<"small" | "medium" | "large" | "x-large">(
      (localStorage.getItem("fwui_font_size") as any) || "medium",
    ),
    [safeMode, setSafeMode] = useState(false),
    [ipsets, setIPSets] = useState<IPSet[]>([]),
    [aliases, setAliases] = useState<Alias[]>([]),
    [initializing, setInitializing] = useState(false),
    [rollback, setRollback] = useState<Rollback>({
      active: false,
      deadline: "",
    }),
    [diff, setDiff] = useState<any | null>(null),
    [draft6, setDraft6] = useState<Draft | null>(null),
    [baseline6, setBaseline6] = useState(""),
    [rollback6, setRollback6] = useState<Rollback>({
      active: false,
      deadline: "",
    }),
    [diff6, setDiff6] = useState<any | null>(null);
  useEffect(() => {
    api("/auth/me")
      .then((p) => {
        csrf = p.csrf;
        setUser(p);
      })
      .catch(() => {});
  }, []);
  useEffect(() => {
    const zoom = { small: "0.95", medium: "1", large: "1.08", "x-large": "1.16" }[fontSize] || "1";
    document.documentElement.style.setProperty("--app-zoom", zoom);
  }, [fontSize]);
  useEffect(() => {
    if (!user) return;
    setInitializing(true);
    Promise.all([
      api("/system"),
      api("/draft"),
      api("/ipsets").catch(() => []),
      api("/aliases").catch(() => []),
      api("/firewall/rollback"),
      api("/ip6/draft").catch(() => null),
      api("/settings").catch(() => null),
    ])
      .then(async ([s, existing, sets, aliasList, rb, existing6, settings]) => {
        setSys(s);
        const loaded =
          existing || (await api("/draft/refresh", { method: "POST" }));
        const n = normalize(loaded);
        setDraft(n);
        setBaseline(JSON.stringify(n));
        setIPSets(sets || []);
        setAliases(aliasList || []);
        setRollback(rb);
        if (existing6) {
          const n6 = normalize(existing6);
          setDraft6(n6);
          setBaseline6(JSON.stringify(n6));
        }
        if (settings) {
          setSafeMode(!!settings.safe_mode);
        }
      })
      .catch((e) => setError(e.message))
      .finally(() => setInitializing(false));
  }, [user]);
  useEffect(() => {
    if (!rollback.active) return;
    const timer = setInterval(
      () =>
        api("/firewall/rollback")
          .then(setRollback)
          .catch(() => {}),
      1000,
    );
    return () => clearInterval(timer);
  }, [rollback.active]);
  const pending = draft ? Number(JSON.stringify(draft) !== baseline) : 0;
  const seconds = rollback.active
    ? Math.max(
        0,
        Math.ceil((new Date(rollback.deadline).getTime() - Date.now()) / 1000),
      )
    : 0;
  if (!user) return <Auth done={setUser} />;
  async function refresh() {
    try {
      const n = normalize(await api("/draft/refresh", { method: "POST" }));
      setDraft(n);
      setBaseline(JSON.stringify(n));
      setError("");
      setNotice("Live firewall loaded");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function save(next: Draft) {
    const hydrated = {
      ...next,
      aliases: Object.fromEntries(aliases.map((a) => [a.name, a.address])),
    };
    setDraft(hydrated);
    try {
      await api("/draft", { method: "PUT", body: JSON.stringify(hydrated) });
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function action(path: string) {
    try {
      const result = await api(path, { method: "POST" });
      setError("");
      if (path.endsWith("/apply")) {
        setRollback({ active: true, deadline: result.rollback_deadline });
        setBaseline(JSON.stringify(draft));
        setNotice(
          t("Firewall applied. Confirm changes before the timer expires."),
        );
      }
      if (path.endsWith("/confirm")) {
        setRollback({ active: false, deadline: "" });
        setNotice("Firewall changes confirmed");
      }
      if (path.endsWith("/rollback")) {
        setRollback({ active: false, deadline: "" });
        await refresh();
        setNotice("Previous firewall configuration restored");
      }
      if (path.endsWith("/validate")) setNotice("Draft validation successful");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function refresh6() {
    try {
      const n = normalize(await api("/ip6/draft/refresh", { method: "POST" }));
      setDraft6(n);
      setBaseline6(JSON.stringify(n));
      setNotice("Live IPv6 firewall loaded");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function save6(next: Draft) {
    const hydrated = {
      ...next,
      aliases: Object.fromEntries(aliases.map((a) => [a.name, a.address])),
    };
    setDraft6(hydrated);
    try {
      await api("/ip6/draft", {
        method: "PUT",
        body: JSON.stringify(hydrated),
      });
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function action6(path: string) {
    try {
      const result = await api(path, { method: "POST" });
      setError("");
      if (path.endsWith("/apply")) {
        setRollback6({ active: true, deadline: result.rollback_deadline });
        setBaseline6(JSON.stringify(draft6));
        setNotice(
          t("IPv6 firewall applied. Confirm changes before the timer expires."),
        );
      }
      if (path.endsWith("/confirm")) {
        setRollback6({ active: false, deadline: "" });
        setNotice("IPv6 changes confirmed");
      }
      if (path.endsWith("/rollback")) {
        setRollback6({ active: false, deadline: "" });
        await refresh6();
        setNotice("Previous IPv6 configuration restored");
      }
      if (path.endsWith("/validate"))
        setNotice("IPv6 draft validation successful");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  const rules = draft?.rules || [],
    filter = rules.filter((r) => r.table === "filter"),
    nat = rules.filter((r) => r.table === "nat");
  const backendOk = (sys?.Commands || []).some(
    (c: any) => c.Name === "iptables-save" && c.Available,
  );
  return (
    <div
      className={dark ? "app dark" : "app"}
      style={{ zoom: "var(--app-zoom, 1)" }}
    >
      <header>
        <div className="brand">
          <span className="logo">
            <Shield />
          </span>
          <div>
            <b>Firewall UI</b>
            <small>
              {sys?.Hostname || "server"} / {user.username}
            </small>
          </div>
          <i className={backendOk ? "status-ok" : "status-bad"}>
            {backendOk ? "Live mode" : "No backend"}
          </i>
          <i>{user.role}</i>
        </div>
        <div className="actions">
          <button onClick={refresh}>
            <RefreshCw /> {t("Refresh")}
          </button>
          <button onClick={() => action("/draft/validate")}>
            <CheckCircle2 /> {t("Validate")}
          </button>
          <button
            className="apply"
            disabled={!draft || !pending}
            onClick={() =>
              api("/draft/diff")
                .then(setDiff)
                .catch((e) => setError(e.message))
            }
          >
            <Save /> {t("Apply")}
          </button>
          <button
            disabled={!pending}
            onClick={async () => {
              const n = normalize(
                await api("/draft/discard", { method: "POST" }),
              );
              setDraft(n);
              setBaseline(JSON.stringify(n));
              setNotice("Draft discarded");
            }}
          >
            <X /> {t("Discard")}
          </button>
          <button
            disabled={!rollback.active}
            title={
              rollback.active
                ? "Restore the pre-Apply snapshot"
                : "No active rollback snapshot"
            }
            onClick={() => action("/firewall/rollback")}
          >
            <Undo2 /> {t("Rollback")}
          </button>
          <select
            className="langsel"
            value={getLang()}
            onChange={(e) => {
              setLang(e.target.value as Lang);
              location.reload();
            }}
          >
            <option value="en">EN</option>
            <option value="ru">RU</option>
            <option value="uk">UA</option>
          </select>
          <button title={t("Theme")} onClick={() => setDark(!dark)}>
            {dark ? <Sun /> : <Moon />}
          </button>
          <button
            title={t("Logout")}
            onClick={() =>
              api("/auth/logout", { method: "POST" }).finally(() =>
                location.reload(),
              )
            }
          >
            <LogOut />
          </button>
        </div>
      </header>
      <section className="stats">
        <Stat name={t("Listen address")} value={location.host} />
        <Stat
          name={t("Snapshot")}
          value={draft?.snapshot_id?.slice(0, 12) || "not loaded"}
        />
        <Stat name={t("Filter rules")} value={filter.length} />
        <Stat name={t("NAT rules")} value={nat.length} />
        <Stat name={t("Raw lines")} value={(draft?.unsupported || []).length} />
        <Stat name={t("Pending changes")} value={pending} />
      </section>
      {initializing && (
        <div className="notice bar">
          <RefreshCw /> Loading live firewall configuration…
        </div>
      )}
      {rollback.active && (
        <div className="rollback">
          <b>
            Automatic rollback in{" "}
            {String(Math.floor(seconds / 60)).padStart(2, "0")}:
            {String(seconds % 60).padStart(2, "0")}
          </b>
          <button onClick={() => action("/firewall/confirm")}>
            Confirm changes
          </button>
          <button onClick={() => action("/firewall/rollback")}>
            Rollback now
          </button>
        </div>
      )}
      {error && (
        <div className="error bar">
          <AlertTriangle /> {error}
          <button onClick={() => setError("")}>
            <X />
          </button>
        </div>
      )}
      {notice && (
        <div className="notice bar">
          <CheckCircle2 /> {notice}
          <button onClick={() => setNotice("")}>
            <X />
          </button>
        </div>
      )}
      <nav>
        {[
          "Overview",
          "Filter",
          "NAT",
          "IPv6",
          "IP Sets",
          "Aliases",
          "Raw",
          ...(user.role === "admin" ? ["Settings"] : []),
        ].map((x) => (
          <button
            key={x}
            className={tab === x ? "active" : ""}
            onClick={() => setTab(x)}
          >
            {t(x)}
          </button>
        ))}
      </nav>
      <main className="content">
        {tab === "Overview" && <Overview sys={sys} draft={draft} />}
        {tab === "Filter" && (
          <Rules
            title="Filter Rules"
            table="filter"
            rules={filter}
            draft={draft}
            ipsets={ipsets}
            aliases={aliases}
            save={save}
            safeMode={safeMode}
          />
        )}
        {tab === "NAT" && (
          <Rules
            title="NAT / Port Forward"
            table="nat"
            rules={nat}
            draft={draft}
            ipsets={ipsets}
            aliases={aliases}
            save={save}
            safeMode={safeMode}
          />
        )}
        {tab === "IPv6" && (
          <IPv6
            draft6={draft6}
            setDraft6={setDraft6}
            baseline6={baseline6}
            setBaseline6={setBaseline6}
            rollback6={rollback6}
            setRollback6={setRollback6}
            diff6={diff6}
            setDiff6={setDiff6}
            ipsets={ipsets}
            aliases={aliases}
            setError={setError}
            setNotice={setNotice}
            safeMode={safeMode}
          />
        )}
        {diff6 && (
          <DiffModal
            diff={diff6}
            close={() => setDiff6(null)}
            apply={() => {
              setDiff6(null);
              action6("/ip6/draft/apply");
            }}
          />
        )}
        {tab === "IP Sets" && (
          <IPSets
            sets={ipsets}
            reload={() => api("/ipsets").then((v) => setIPSets(v || []))}
          />
        )}
        {tab === "Aliases" && (
          <Aliases
            aliases={aliases}
            reload={() => api("/aliases").then((v) => setAliases(v || []))}
          />
        )}
        {tab === "Raw" && <Raw draft={draft} />}
        {tab === "Settings" && (
          <Settings
            fontSize={fontSize}
            setFontSize={setFontSize}
            ipsets={ipsets}
            setGlobalSafeMode={setSafeMode}
            me={user}
            sys={sys}
            draft={draft}
            refreshDraft={refresh}
          />
        )}
      </main>
      {diff && (
        <DiffModal
          diff={diff}
          close={() => setDiff(null)}
          apply={() => {
            setDiff(null);
            action("/draft/apply");
          }}
        />
      )}
    </div>
  );
}
function Stat({ name, value }: { name: string; value: any }) {
  return (
    <div className="stat">
      <small>{name}</small>
      <strong>{value}</strong>
    </div>
  );
}
function Overview({ sys, draft }: { sys: any; draft: Draft | null }) {
  return (
    <div className="grid">
      <section className="card">
        <h2>
          <Activity /> System status
        </h2>
        <div className="facts">
          <span>
            {t("Operating system")}<b>{sys?.OS}</b>
          </span>
          <span>
            {t("Hostname")}<b>{sys?.Hostname}</b>
          </span>
          <span>
            {t("iptables backend")}<b>{sys?.IPTablesBackend || t("Unavailable")}</b>
          </span>
          <span>
            {t("IPv4 forwarding")}<b>{sys?.IPv4Forwarding ? t("Enabled") : t("Disabled")}</b>
          </span>
        </div>
      </section>
      <section className="card">
        <h2>
          <Server /> Commands
        </h2>
        {(sys?.Commands || []).map((c: any) => (
          <div className="command" key={c.Name}>
            <span>
              {c.Name}
              <small>{c.Path || "Not found"}</small>
            </span>
            <i className={c.Available ? "ok" : "bad"}>
              {c.Available ? "available" : "missing"}
            </i>
          </div>
        ))}
      </section>
      <section className="card">
        <h2>
          <Database /> Draft
        </h2>
        <div className="facts">
          <span>
            Filter rules
            <b>
              {(draft?.rules || []).filter((r) => r.table === "filter").length}
            </b>
          </span>
          <span>
            Raw lines<b>{(draft?.unsupported || []).length}</b>
          </span>
        </div>
      </section>
    </div>
  );
}

function Rules({
  title,
  table,
  rules,
  draft,
  ipsets,
  aliases,
  save,
  safeMode,
}: {
  title: string;
  table: string;
  rules: Rule[];
  draft: Draft | null;
  ipsets: IPSet[];
  aliases: Alias[];
  save: (d: Draft) => void;
  safeMode: boolean;
}) {
  const builtins =
    table === "filter"
      ? ["INPUT", "FORWARD", "OUTPUT"]
      : ["PREROUTING", "INPUT", "OUTPUT", "POSTROUTING"];
  const custom = Object.keys(draft?.policies || {})
    .filter(
      (k) =>
        k.startsWith(table + "/") &&
        draft?.policies[k] === "-" &&
        !builtins.includes(k.slice(table.length + 1)),
    )
    .map((k) => k.slice(table.length + 1));
  const chains = [
    ...new Set([...builtins, ...custom, ...rules.map((r) => r.chain)]),
  ];
  const [editing, setEditing] = useState<Rule | null>(null),
    [newChain, setNewChain] = useState("FWUI_"),
    [selectedChain, setSelectedChain] = useState("ALL"),
    [dragged, setDragged] = useState<string | null>(null);
  const displayedChains =
    selectedChain === "ALL"
      ? chains
      : chains.filter((c) => c === selectedChain);
  function commit(rule: Rule) {
    if (!draft) return;
    const all = [...(draft.rules || [])],
      index = all.findIndex((r) => r.id === rule.id);
    if (index >= 0) all[index] = rule;
    else all.push(rule);
    save({ ...draft, rules: all });
    setEditing(null);
  }
  function remove(id: string) {
    if (draft && confirm(t("Delete this rule from the draft?")))
      save({ ...draft, rules: (draft.rules || []).filter((r) => r.id !== id) });
  }
  function policy(chain: string, value: string) {
    if (draft)
      save({
        ...draft,
        policies: { ...draft.policies, [table + "/" + chain]: value },
      });
  }
  function addChain(e: React.FormEvent) {
    e.preventDefault();
    if (!draft) return;
    const name = newChain.toUpperCase();
    if (!/^FWUI_[A-Z0-9_.+-]{1,26}$/.test(name))
      return alert("Chain name must start with FWUI_");
    if (chains.includes(name)) return alert("Chain already exists");
    save({
      ...draft,
      policies: { ...draft.policies, [table + "/" + name]: "-" },
    });
    setNewChain("FWUI_");
  }
  function deleteChain(name: string) {
    if (!draft) return;
    const refs = (draft.rules || []).filter(
      (r) => r.chain === name || r.action === name,
    ).length;
    if (refs)
      return alert(`Chain ${name} is used by ${refs} firewall rule(s).`);
    if (!confirm(`Delete custom chain ${name}?`)) return;
    const policies = { ...draft.policies };
    delete policies[table + "/" + name];
    save({ ...draft, policies });
  }
  function renameChain(old: string) {
    if (!draft) return;
    const name = prompt(`Rename chain ${old} (must start with FWUI_):`, old);
    if (!name || name === old) return;
    const upper = name.toUpperCase();
    if (!/^FWUI_[A-Z0-9_.+-]{1,26}$/.test(upper))
      return alert("Chain name must start with FWUI_");
    if (chains.includes(upper)) return alert("Chain already exists");
    const policies = { ...draft.policies };
    policies[table + "/" + upper] = policies[table + "/" + old];
    delete policies[table + "/" + old];
    save({
      ...draft,
      policies,
      rules: (draft.rules || []).map((r) => ({
        ...r,
        chain: r.chain === old ? upper : r.chain,
        action: r.action === old ? upper : r.action,
      })),
    });
  }
  function reorder(chain: string, targetID: string) {
    if (!draft || !dragged || dragged === targetID) return;
    const all = [...(draft.rules || [])],
      ordered = all
        .filter((r) => r.table === table && r.chain === chain)
        .sort((a, b) => a.position - b.position),
      from = ordered.findIndex((r) => r.id === dragged),
      to = ordered.findIndex((r) => r.id === targetID);
    if (from < 0 || to < 0) return;
    const [moved] = ordered.splice(from, 1);
    ordered.splice(to, 0, moved);
    const positions = new Map(ordered.map((r, i) => [r.id, i + 1]));
    save({
      ...draft,
      rules: all.map((r) =>
        positions.has(r.id) ? { ...r, position: positions.get(r.id)! } : r,
      ),
    });
    setDragged(null);
  }
  return (
    <div className="rules-layout">
      {safeMode && (
        <div className="notice" style={{ gridColumn: "1 / -1" }}>
          {t(
            "Safe Mode is ON: built-in chains and external chains are read-only. Only FWUI_* custom chains and jumps to them can be edited.",
          )}
        </div>
      )}
      <aside className="card directory">
        <h3>{t("Chain directory")}</h3>
        <p>{t("Browse rules by built-in and custom chain.")}</p>
        <button
          className={selectedChain === "ALL" ? "chain selected" : "chain"}
          onClick={() => setSelectedChain("ALL")}
        >
          <b>{t("All chains")}</b>
          <i>{rules.length}</i>
        </button>
        {chains.map((c) => (
          <button
            className={selectedChain === c ? "chain selected" : "chain"}
            key={c}
            onClick={() => setSelectedChain(c)}
          >
            <span>
              {c}
              <small>{builtins.includes(c) ? t("built-in") : t("custom")}</small>
            </span>
            <i>{rules.filter((r) => r.chain === c).length}</i>
          </button>
        ))}
      </aside>
      <section className="rulesmain">
        <div className="section-title">
          <div>
            <h2>{title}</h2>
            <p>Editable IPv4 {t(table)} {t("rules for built-in and custom chains")}.</p>
          </div>
          <button
            className="darkbtn"
            disabled={!draft}
            onClick={() =>
              setEditing(emptyRule(table, builtins[0], rules.length + 1))
            }
          >
            <Plus /> {t("Add rule")}
          </button>
        </div>
        {displayedChains.map((c) => (
          <div className="card chainbox" key={c}>
            <div className="chainhead">
              <h3>
                {c} <i>{builtins.includes(c) ? t("built-in") : t("custom")}</i>
                {builtins.includes(c) && (
                  <i>{t("Policy")}: {draft?.policies[table + "/" + c] || "ACCEPT"}</i>
                )}
              </h3>
              <button
                onClick={() =>
                  setEditing(
                    emptyRule(
                      table,
                      c,
                      rules.filter((r) => r.chain === c).length + 1,
                    ),
                  )
                }
              >
                <Plus /> {t("Add rule")}
              </button>
            </div>
            {rules.some((r) => r.chain === c) ? (
              <table>
                <thead>
                  <tr>
                    <th>{t("ORDER")}</th>
                    <th>{t("ON")}</th>
                    <th>{t("ACTION")}</th>
                    <th>{t("SOURCE")}</th>
                    <th>{t("DESTINATION")}</th>
                    <th>{t("PROTO")}</th>
                    <th>{t("D.PORT")}</th>
                    {table === "nat" && <th>{t("TRANSLATE TO")}</th>}
                    <th>{t("STATE")}</th>
                    <th>{t("PACKETS")}</th>
                    <th>{t("BYTES")}</th>
                    <th>{t("COMMENT")}</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rules
                    .filter((r) => r.chain === c)
                    .sort((a, b) => a.position - b.position)
                    .map((r) => {
                      const readOnly = safeMode && !c.startsWith("FWUI_");
                      return (
                      <tr
                        key={r.id}
                        draggable={!readOnly}
                        onDragStart={readOnly ? undefined : () => setDragged(r.id)}
                        onDragEnd={readOnly ? undefined : () => setDragged(null)}
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={readOnly ? undefined : () => reorder(c, r.id)}
                        className={dragged === r.id ? "dragging" : ""}
                      >
                        <td className="draghandle" title={readOnly ? t("Read-only") : t("Drag to reorder")}>
                          ⋮⋮ {r.position}
                        </td>
                        <td>
                          <input
                            type="checkbox"
                            checked={r.enabled}
                            disabled={readOnly}
                            onChange={(e) =>
                              commit({ ...r, enabled: e.target.checked })
                            }
                          />
                        </td>
                        <td>
                          <em>{r.action}</em>
                        </td>
                        <td>{address(r.source)}</td>
                        <td>{address(r.destination)}</td>
                        <td>{r.protocol}</td>
                        <td>
                          {(r.dest_ports || []).map(formatPort).join(",") ||
                            "any"}
                        </td>
                        {table === "nat" && (
                          <td>
                            {r.to_address
                              ? r.to_address +
                                (r.to_port ? ":" + r.to_port : "")
                              : r.action === "MASQUERADE"
                                ? "interface address"
                                : "—"}
                          </td>
                        )}
                        <td>{(r.states || []).join(", ") || "any"}</td>
                        <td>{r.packets || 0}</td>
                        <td>{formatBytes(r.bytes || 0)}</td>
                        <td>{r.comment || "—"}</td>
                        <td className="rowactions">
                          <button disabled={readOnly} onClick={() => setEditing(r)}>
                            <Edit3 />
                          </button>
                          <button disabled={readOnly} onClick={() => remove(r.id)}>
                            <Trash2 />
                          </button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            ) : (
              <div className="empty">{t("No editable rules in this chain.")}</div>
            )}
          </div>
        ))}
        {editing && (
          <RuleModal
            rule={editing}
            chains={chains}
            custom={custom}
            ipsets={ipsets}
            aliases={aliases}
            close={() => setEditing(null)}
            commit={commit}
          />
        )}
      </section>
      <aside className="righttools">
        <div className="card">
          <h3>{t("Table tools")}</h3>
          <p>{t("Manage policies, custom chains, and new rules.")}</p>
          <button
            className="toolbutton"
            onClick={async () => {
              if (confirm("Reset packet and byte counters?")) {
                await api("/firewall/counters/reset", { method: "POST" });
                location.reload();
              }
            }}
          >
            <RefreshCw /> Reset counters
          </button>
        </div>
        <div className="card">
          <h3>
            {table === "filter" ? t("Default Policies") : t("NAT Policies")}
          </h3>
          <p>{t("Chain policy lines are included when applying the draft.")}</p>
          {builtins.map((c) => (
            <label className="policy" key={c}>
              {c}
              <select
                value={draft?.policies[table + "/" + c] || "ACCEPT"}
                onChange={(e) => policy(c, e.target.value)}
                disabled={safeMode && builtins.includes(c)}
              >
                <option value="ACCEPT">{t("ACCEPT")}</option>
                {table === "filter" && <option value="DROP">{t("DROP")}</option>}
              </select>
            </label>
          ))}
        </div>
        <div className="card">
          <h3>{t("Custom chains")}</h3>
          <p>
            Custom chains are declared with policy '-' and can hold structured
            rules.
          </p>
          <form className="chainform" onSubmit={addChain}>
            <input
              value={newChain}
              onChange={(e) => setNewChain(e.target.value)}
            />
            <button className="darkbtn">
              <Plus /> Add chain
            </button>
          </form>
          {custom.length ? (
            custom.map((c) => (
              <div className="customchain" key={c}>
                <span>
                  {c}
                  <small>
                    {rules.filter((r) => r.chain === c).length} rules
                  </small>
                </span>
                <button onClick={() => renameChain(c)} title={t("Rename")}>
                  <Edit3 />
                </button>
                <button className="iconbtn" onClick={() => deleteChain(c)}>
                  <Trash2 />
                </button>
              </div>
            ))
          ) : (
            <p>{t("No custom chains.")}</p>
          )}
        </div>
      </aside>
    </div>
  );
}
function RuleModal({
  rule,
  chains,
  custom,
  ipsets,
  aliases,
  close,
  commit,
}: {
  rule: Rule;
  chains: string[];
  custom: string[];
  ipsets: IPSet[];
  aliases: Alias[];
  close: () => void;
  commit: (r: Rule) => void;
}) {
  const [value, setValue] = useState<Rule>({
      ...rule,
      source_ports: rule.source_ports || [],
      dest_ports: rule.dest_ports || [],
      states: rule.states || [],
    }),
    [source, setSource] = useState(rule.source.value),
    [destination, setDestination] = useState(rule.destination.value),
    [sport, setSport] = useState(portText(rule.source_ports)),
    [dport, setDport] = useState(portText(rule.dest_ports));
  function submit(e: React.FormEvent) {
    e.preventDefault();
    commit({
      ...value,
      source: makeAddr(value.source.type, source),
      destination: makeAddr(value.destination.type, destination),
      source_ports: parsePorts(sport),
      dest_ports: parsePorts(dport),
    });
  }
  return (
    <div className="modalback">
      <form className="modal card" onSubmit={submit}>
        <div className="modalhead">
          <h2>
            {rule.id.startsWith("filter-") || rule.id.startsWith("nat-")
              ? "Edit rule"
              : "Add rule"}
          </h2>
          <button type="button" onClick={close}>
            <X />
          </button>
        </div>
        <div className="formgrid">
          <label>
            {t("Chain")}
            <select
              value={value.chain}
              onChange={(e) => setValue({ ...value, chain: e.target.value })}
            >
              {chains.map((x) => (
                <option key={x}>{x}</option>
              ))}
            </select>
          </label>
          <label>
            {t("Action")}
            <select
              value={value.action}
              onChange={(e) => setValue({ ...value, action: e.target.value })}
            >
              {value.table === "nat" ? (
                <>
                  <option value="DNAT">{t("DNAT")}</option>
                  <option value="SNAT">{t("SNAT")}</option>
                  <option value="MASQUERADE">{t("MASQUERADE")}</option>
                </>
              ) : (
                <>
                  <option value="ACCEPT">{t("ACCEPT")}</option>
                  <option value="DROP">{t("DROP")}</option>
                  <option value="REJECT">{t("REJECT")}</option>
                </>
              )}
              {custom.map((x) => (
                <option key={x} value={x}>
                  JUMP → {x}
                </option>
              ))}
            </select>
          </label>
          <label>
            {t("Protocol")}
            <select
              value={value.protocol}
              onChange={(e) => setValue({ ...value, protocol: e.target.value })}
            >
              <option value="all">{t("Any")}</option>
              <option value="tcp">{t("TCP")}</option>
              <option value="udp">{t("UDP")}</option>
              <option value="icmp">{t("ICMP")}</option>
            </select>
          </label>
          <label>
            {t("Order")}
            <input
              type="number"
              min="1"
              value={value.position}
              onChange={(e) =>
                setValue({ ...value, position: Number(e.target.value) })
              }
            />
          </label>
          <Address
            label="Source"
            addr={value.source}
            text={source}
            sets={ipsets}
            aliases={aliases}
            change={(type, text) => {
              setValue({ ...value, source: { type, value: text } });
              setSource(text);
            }}
          />
          <Address
            label="Destination"
            addr={value.destination}
            text={destination}
            sets={ipsets}
            aliases={aliases}
            change={(type, text) => {
              setValue({ ...value, destination: { type, value: text } });
              setDestination(text);
            }}
          />
          <label>
            {t("Source port")}
            <input
              value={sport}
              onChange={(e) => setSport(e.target.value)}
              placeholder="Any or 1024-65535"
            />
          </label>
          <label>
            {t("Destination port")}
            <input
              value={dport}
              onChange={(e) => setDport(e.target.value)}
              placeholder="22 or 8000-8080"
            />
          </label>
          <label>
            {t("Input interface")}
            <input
              value={value.in_interface}
              onChange={(e) =>
                setValue({ ...value, in_interface: e.target.value })
              }
              placeholder="eth0"
            />
          </label>
          <label>
            {t("Output interface")}
            <input
              value={value.out_interface}
              onChange={(e) =>
                setValue({ ...value, out_interface: e.target.value })
              }
              placeholder="eth0"
            />
          </label>
          {value.table === "nat" &&
            (value.action === "DNAT" || value.action === "SNAT") && (
              <>
                <label>
                  {t("Translate to address")}
                  <input
                    value={value.to_address || ""}
                    onChange={(e) =>
                      setValue({ ...value, to_address: e.target.value })
                    }
                    placeholder="192.0.2.100"
                    required
                  />
                </label>
                <label>
                  {t("Translate to port")}
                  <input
                    type="number"
                    min="0"
                    max="65535"
                    value={value.to_port || ""}
                    onChange={(e) =>
                      setValue({ ...value, to_port: Number(e.target.value) })
                    }
                    placeholder={t("Keep original port")}
                  />
                </label>
              </>
            )}
        </div>
        <fieldset>
          <legend>{t("Connection state")}</legend>
          {["NEW", "ESTABLISHED", "RELATED", "INVALID"].map((s) => (
            <label key={s}>
              <input
                type="checkbox"
                checked={value.states.includes(s)}
                onChange={(e) =>
                  setValue({
                    ...value,
                    states: e.target.checked
                      ? [...value.states, s]
                      : value.states.filter((x) => x !== s),
                  })
                }
              />{" "}
              {s}
            </label>
          ))}
        </fieldset>
        <label>
          {t("Comment")}
          <input
            value={value.comment}
            onChange={(e) => setValue({ ...value, comment: e.target.value })}
            maxLength={256}
          />
        </label>
        <div className="modalactions">
          <button type="button" onClick={close}>
            {t("Cancel")}
          </button>
          <button className="primary">{t("Save to draft")}</button>
        </div>
      </form>
    </div>
  );
}
function Address({
  label,
  addr,
  text,
  sets,
  aliases,
  change,
}: {
  label: string;
  addr: Addr;
  text: string;
  sets: IPSet[];
  aliases: Alias[];
  change: (t: Addr["type"], v: string) => void;
}) {
  return (
    <label>
      {label}
      <select
        value={addr.type}
        onChange={(e) => change(e.target.value as Addr["type"], "")}
      >
        <option value="any">{t("Any")}</option>
        <option value="cidr">IP / CIDR</option>
        <option value="ipset">{t("IP Sets")}</option>
        <option value="alias">{t("Aliases")}</option>
      </select>
      {addr.type === "cidr" && (
        <input
          value={text}
          onChange={(e) => change("cidr", e.target.value)}
          placeholder="192.0.2.10/32"
        />
      )}
      {addr.type === "ipset" && (
        <select
          value={text}
          onChange={(e) => change("ipset", e.target.value)}
          required
        >
          <option value="">{t("Select IP Set")}</option>
          {sets.map((s) => (
            <option key={s.name}>{s.name}</option>
          ))}
        </select>
      )}
      {addr.type === "alias" && (
        <select
          value={text}
          onChange={(e) => change("alias", e.target.value)}
          required
        >
          <option value="">{t("Select Alias")}</option>
          {aliases.map((a) => (
            <option key={a.id} value={a.name}>
              {a.name} — {a.address}
            </option>
          ))}
        </select>
      )}
    </label>
  );
}
function makeAddr(type: Addr["type"], value: string): Addr {
  return type === "any" ? { type, value: "" } : { type, value };
}
function parsePorts(value: string): PortRange[] {
  if (!value.trim()) return [];
  return value.split(",").map((x) => {
    const p = x.trim().split("-").map(Number);
    return { from: p[0], to: p[1] || p[0] };
  });
}
function portText(ports?: PortRange[]) {
  return (ports || []).map(formatPort).join(",");
}
function formatPort(p: PortRange) {
  return p.from === p.to ? String(p.from) : `${p.from}-${p.to}`;
}
function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  if (value < 1048576) return `${(value / 1024).toFixed(1)} KB`;
  return `${(value / 1048576).toFixed(1)} MB`;
}
function address(a: Addr) {
  return !a || a.type === "any"
    ? "Any"
    : a.type === "ipset"
      ? `[IPSET ${a.value}]`
      : a.type === "alias"
        ? `[ALIAS ${a.value}]`
        : a.value;
}

function Raw({ draft }: { draft: Draft | null }) {
  return (
    <section>
      <div className="section-title">
        <div>
          <h2>{t("Raw / Read-only")}</h2>
          <p>{t("Unsupported rules are preserved during apply.")}</p>
        </div>
      </div>
      <div className="rawgrid">
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>{t("TABLE")}</th>
                <th>{t("CHAIN")}</th>
                <th>{t("LINE")}</th>
                <th>{t("REASON")}</th>
              </tr>
            </thead>
            <tbody>
              {(draft?.unsupported || []).map((r, i) => (
                <tr key={i}>
                  <td>{r.table}</td>
                  <td>{r.chain}</td>
                  <td>
                    <code>{r.line}</code>
                  </td>
                  <td>{r.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <pre>
          {draft?.raw || "Load the live firewall to view iptables-save output."}
        </pre>
      </div>
    </section>
  );
}
function Diagnostics({ sys, draft }: { sys: any; draft: Draft | null }) {
  return (
    <section>
      <h2>{t("iptables command diagnostics")}</h2>
      {(sys?.Commands || []).map((c: any) => (
        <div className="card diag" key={c.Name}>
          <b>$ {c.Name} --version</b>
          <pre>{c.Version || c.Path || t("Command is not available")}</pre>
        </div>
      ))}
      <div className="card diag">
        <b>$ iptables-save</b>
        <pre>{draft?.raw || t("No snapshot loaded")}</pre>
      </div>
    </section>
  );
}
function Backups({ refreshDraft }: { refreshDraft: () => Promise<void> }) {
  const [items, setItems] = useState<any[]>([]),
    [error, setError] = useState(""),
    [viewing, setViewing] = useState<any | null>(null);
  const load = () =>
    api("/backups")
      .then((v) => setItems(v || []))
      .catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);
  async function restore(id: string) {
    if (
      !confirm(`Restore backup ${id}? Current firewall rules will be replaced.`)
    )
      return;
    try {
      await api(`/backups/${encodeURIComponent(id)}/restore`, {
        method: "POST",
      });
      await refreshDraft();
      await load();
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function remove(id: string) {
    if (!confirm(`Delete backup ${id}?`)) return;
    try {
      await api(`/backups/${encodeURIComponent(id)}`, { method: "DELETE" });
      await load();
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function view(id: string) {
    try {
      setViewing(await api(`/backups/${encodeURIComponent(id)}`));
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function download(id: string) {
    const r = await fetch(`/api/v1/backups/${encodeURIComponent(id)}/download`);
    if (!r.ok) return setError("Download failed");
    const blob = await r.blob();
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `iptables-${id}.rules`;
    a.click();
    URL.revokeObjectURL(a.href);
  }
  return (
    <section>
      <h2>{t("Backups")}</h2>
      <p>{t("Snapshots created automatically before every Apply.")}</p>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>{t("ID")}</th>
              <th>{t("CREATED")}</th>
              <th>{t("USER")}</th>
              <th>{t("STATUS")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((b) => (
              <tr key={b.id}>
                <td>
                  <code>{b.id}</code>
                </td>
                <td>{new Date(b.created_at).toLocaleString()}</td>
                <td>{b.username || "—"}</td>
                <td>{b.status}</td>
                <td className="rowactions">
                  <button onClick={() => view(b.id)}>{t("View")}</button>
                  <button onClick={() => download(b.id)}>
                    {t("Download")}
                  </button>
                  <button onClick={() => restore(b.id)}>{t("Restore")}</button>
                  <button className="iconbtn" onClick={() => remove(b.id)}>
                    <Trash2 />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {viewing && (
        <div className="modalback" onClick={() => setViewing(null)}>
          <div className="modal card wide" onClick={(e) => e.stopPropagation()}>
            <div className="modalhead">
              <h2>{t("Backup")} {viewing.id}</h2>
              <button type="button" onClick={() => setViewing(null)}>
                <X />
              </button>
            </div>
            <pre className="backupview">{viewing.content}</pre>
          </div>
        </div>
      )}
    </section>
  );
}
function AuditLog() {
  const [items, setItems] = useState<any[]>([]),
    [error, setError] = useState(""),
    [expanded, setExpanded] = useState<number | null>(null);
  useEffect(() => {
    api("/audit")
      .then((v) => setItems(v || []))
      .catch((e) => setError(e.message));
  }, []);
  return (
    <section>
      <h2>{t("Audit Log")}</h2>
      <p>{t("Recent security and firewall operations.")}</p>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>{t("TIME")}</th>
              <th>{t("USER")}</th>
              <th>{t("IP")}</th>
              <th>{t("ACTION")}</th>
              <th>{t("OBJECT")}</th>
              <th>{t("RESULT")}</th>
              <th>{t("DETAILS")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <>
                <tr key={a.id}>
                  <td>{new Date(a.created_at).toLocaleString()}</td>
                  <td>{a.Username || a.username}</td>
                  <td>{a.IP || a.ip}</td>
                  <td>{a.Action || a.action}</td>
                  <td>{a.Object || a.object}</td>
                  <td>{a.Result || a.result}</td>
                  <td>
                    {a.details || "—"}
                    {(a.details || a.before || a.after) && (
                      <button
                        className="link"
                        onClick={() =>
                          setExpanded(expanded === a.id ? null : a.id)
                        }
                      >
                        {expanded === a.id ? t("hide") : a.before || a.after ? t("diff") : t("details")}
                      </button>
                    )}
                  </td>
                </tr>
                {expanded === a.id && (a.details || a.before || a.after) && (
                  <tr>
                    <td colSpan={7}>
                      <div className="audit-diff">
                        {a.details && (
                          <>
                            <b>{t("DETAILS")}</b>
                            <pre>{a.details}</pre>
                          </>
                        )}
                        {a.before && (
                          <>
                            <b>{t("Before")}</b>
                            <pre>{a.before}</pre>
                          </>
                        )}
                        {a.after && (
                          <>
                            <b>{t("After")}</b>
                            <pre>{a.after}</pre>
                          </>
                        )}
                      </div>
                    </td>
                  </tr>
                )}
              </>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
function LoginAttempts() {
  const [items, setItems] = useState<any[]>([]),
    [locks, setLocks] = useState<any[]>([]),
    [error, setError] = useState("");
  useEffect(() => {
    api("/auth/attempts")
      .then((v) => setItems(v || []))
      .catch((e) => setError(e.message));
    api("/auth/locks")
      .then((v) => setLocks(v || []))
      .catch(() => {});
  }, []);
  return (
    <section>
      <h2>{t("Login Attempts")}</h2>
      <p>{t("Authentication events and active rate-limit locks.")}</p>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <h3>{t("Active locks")}</h3>
        {locks.length ? (
          <table>
            <thead>
              <tr>
                <th>{t("KEY")}</th>
                <th>{t("UNTIL")}</th>
              </tr>
            </thead>
            <tbody>
              {locks.map((l: any, i: number) => (
                <tr key={i}>
                  <td>{l.key}</td>
                  <td>{new Date(l.until).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>{t("No active locks")}</p>
        )}
      </div>
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>{t("TIME")}</th>
              <th>{t("IP")}</th>
              <th>{t("USER")}</th>
              <th>{t("Success")}</th>
              <th>{t("Locked")}</th>
              <th>{t("Message")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((a) => (
              <tr key={a.id}>
                <td>{new Date(a.created_at).toLocaleString()}</td>
                <td>{a.ip}</td>
                <td>{a.username}</td>
                <td>{a.success ? t("yes") : t("no")}</td>
                <td>{a.locked ? t("yes") : t("no")}</td>
                <td>{a.message}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
function Aliases({
  aliases,
  reload,
}: {
  aliases: Alias[];
  reload: () => void;
}) {
  const [name, setName] = useState(""),
    [address, setAddress] = useState(""),
    [error, setError] = useState(""),
    [editing, setEditing] = useState<Alias | null>(null);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api("/aliases", {
        method: "POST",
        body: JSON.stringify({ name, address }),
      });
      setName("");
      setAddress("");
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function update(e: React.FormEvent) {
    e.preventDefault();
    if (!editing) return;
    try {
      await api("/aliases/" + editing.id, {
        method: "PUT",
        body: JSON.stringify({ name: editing.name, address: editing.address }),
      });
      setEditing(null);
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function remove(alias: Alias) {
    if (
      !confirm(
        `Delete alias ${alias.name}? This is blocked while firewall rules reference it.`,
      )
    )
      return;
    try {
      await api("/aliases/" + alias.id, { method: "DELETE" });
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <section>
      <div className="section-title">
        <div>
          <h2>{t("Aliases")}</h2>
          <p>{t("Named IP addresses and networks available in firewall rules.")}</p>
        </div>
        <form className="inline" onSubmit={create}>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("office_gateway")}
            required
          />
          <input
            value={address}
            onChange={(e) => setAddress(e.target.value)}
            placeholder="192.0.2.10/32"
            required
          />
          <button className="darkbtn">
            <Plus /> {t("Add alias")}
          </button>
        </form>
      </div>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>{t("NAME")}</th>
              <th>{t("IP / CIDR")}</th>
              <th>{t("REFERENCES")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {aliases.map((a) => (
              <tr key={a.id}>
                <td>
                  <b>{a.name}</b>
                </td>
                <td>
                  <code>{a.address}</code>
                </td>
                <td>{(a as any).references || 0}</td>
                <td className="rowactions">
                  <button className="iconbtn" onClick={() => setEditing(a)}>
                    <Edit3 />
                  </button>
                  <button className="iconbtn" onClick={() => remove(a)}>
                    <Trash2 />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {editing && (
        <div className="modalback">
          <form className="modal card" onSubmit={update}>
            <div className="modalhead">
              <h2>Edit alias</h2>
              <button type="button" onClick={() => setEditing(null)}>
                <X />
              </button>
            </div>
            <label>
              Name
              <input
                value={editing.name}
                onChange={(e) =>
                  setEditing({ ...editing, name: e.target.value })
                }
                required
              />
            </label>
            <label>
              IP / CIDR
              <input
                value={editing.address}
                onChange={(e) =>
                  setEditing({ ...editing, address: e.target.value })
                }
                required
              />
            </label>
            <div className="modalactions">
              <button type="button" onClick={() => setEditing(null)}>
                {t("Cancel")}
              </button>
              <button className="primary">Save</button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}
function IPSets({ sets, reload }: { sets: IPSet[]; reload: () => void }) {
  const [name, setName] = useState(""),
    [kind, setKind] = useState("hash:net"),
    [commentSupport, setCommentSupport] = useState(true),
    [error, setError] = useState(""),
    [selected, setSelected] = useState(""),
    [member, setMember] = useState(""),
    [memberComment, setMemberComment] = useState(""),
    [bulk, setBulk] = useState("");
  const current = sets.find((s) => s.name === selected);
  const [family, setFamily] = useState("inet");
  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api("/ipsets", {
        method: "POST",
        body: JSON.stringify({
          name,
          type: kind,
          family,
          comment: commentSupport,
        }),
      });
      setName("");
      setCommentSupport(false);
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function addMember(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api(`/ipsets/${encodeURIComponent(selected)}/members`, {
        method: "POST",
        body: JSON.stringify({ member, comment: memberComment }),
      });
      setMember("");
      setMemberComment("");
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function removeMember(value: string) {
    try {
      await api(`/ipsets/${encodeURIComponent(selected)}/members`, {
        method: "DELETE",
        body: JSON.stringify({ member: value }),
      });
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function bulkOp(method: string) {
    const members = bulk
      .split("\n")
      .map((x) => x.trim())
      .filter(Boolean);
    if (!members.length) return;
    try {
      const r = await api(
        `/ipsets/${encodeURIComponent(selected)}/members/bulk`,
        { method, body: JSON.stringify({ members }) },
      );
      setBulk("");
      setError("");
      reload();
      alert(`${r.applied} member(s) applied`);
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function removeSet(set: IPSet) {
    if (set.references)
      return setError(
        `IPSet ${set.name} is used by ${set.references} firewall rule(s).`,
      );
    if (!confirm(`Delete IPSet ${set.name}?`)) return;
    try {
      await api("/ipsets/" + encodeURIComponent(set.name), {
        method: "DELETE",
      });
      if (selected === set.name) setSelected("");
      reload();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <section>
      <div className="section-title">
        <div>
          <h2>{t("IP Sets")}</h2>
          <p>{t("Manage hash:ip and hash:net collections.")}</p>
        </div>
        <form className="inline" onSubmit={create}>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("admin_ips")}
            required
          />
          <select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option>hash:ip</option>
            <option>hash:net</option>
          </select>
          <select value={family} onChange={(e) => setFamily(e.target.value)}>
            <option value="inet">IPv4</option>
            <option value="inet6">IPv6</option>
          </select>
          <label className="inlinecheck">
            <input
              type="checkbox"
              checked={commentSupport}
              onChange={(e) => setCommentSupport(e.target.checked)}
            />
            {t("Comments")}
          </label>
          <button className="darkbtn">
            <Plus /> {t("New set")}
          </button>
        </form>
      </div>
      {error && (
        <div className="error bar">
          {error}
          <button onClick={() => setError("")}>
            <X />
          </button>
        </div>
      )}
      <div className="ipsetgrid">
        <div className="card">
          <table>
            <thead>
              <tr>
                <th>{t("NAME")}</th>
                <th>{t("TYPE")}</th>
                <th>{t("FAMILY")}</th>
                <th>{t("MEMBERS")}</th>
                <th>{t("REFERENCES")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {sets.map((s) => (
                <tr
                  key={s.name}
                  className={selected === s.name ? "selectedrow" : ""}
                  onClick={() => setSelected(s.name)}
                >
                  <td>
                    <b>{s.name}</b>
                  </td>
                  <td>{s.type}</td>
                  <td>{s.family === "inet6" ? "IPv6" : "IPv4"}</td>
                  <td>{(s.members || []).length}</td>
                  <td>{s.references || 0}</td>
                  <td>
                    <button
                      className="iconbtn"
                      onClick={(e) => {
                        e.stopPropagation();
                        removeSet(s);
                      }}
                    >
                      <Trash2 />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <aside className="card">
          <h3>{current ? current.name : t("Members")}</h3>
          {current ? (
            <>
              <form className="inline" onSubmit={addMember}>
                <input
                  value={member}
                  onChange={(e) => setMember(e.target.value)}
                  placeholder={
                    current.family === "inet6"
                      ? current.type === "hash:net"
                        ? "2001:db8::/32"
                        : "2001:db8::1"
                      : current.type === "hash:net"
                        ? "192.0.2.0/24"
                        : "192.0.2.10"
                  }
                  required
                />
                {current.comment && (
                  <input
                    value={memberComment}
                    onChange={(e) => setMemberComment(e.target.value)}
                    placeholder={t("Comment (optional)")}
                  />
                )}
                <button className="darkbtn">
                  <Plus /> Add
                </button>
              </form>
              <table className="members-table">
                <thead>
                  <tr>
                    <th>{t("VALUE")}</th>
                    {current.comment && <th>{t("COMMENT")}</th>}
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {(current.members || []).map((m) => (
                    <tr key={m.value}>
                      <td>
                        <code>{m.value}</code>
                      </td>
                      {current.comment && <td>{m.comment || "—"}</td>}
                      <td>
                        <button onClick={() => removeMember(m.value)}>
                          <Trash2 />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              <details className="bulk">
                <summary>{t("Bulk import / remove")}</summary>
                <textarea
                  value={bulk}
                  onChange={(e) => setBulk(e.target.value)}
                  placeholder={
                    current.family === "inet6"
                      ? current.comment
                        ? '2001:db8::1 comment "Home admin"\n2001:db8::/32'
                        : "2001:db8::1\n2001:db8::/32"
                      : current.comment
                        ? 'One IP/CIDR per line, optional: 192.0.2.10 comment "Home admin"'
                        : "One IP or CIDR per line"
                  }
                  rows={5}
                />
                <div className="modalactions">
                  <button onClick={() => bulkOp("POST")}>{t("Add all")}</button>
                  <button onClick={() => bulkOp("DELETE")}>{t("Remove all")}</button>
                </div>
              </details>
            </>
          ) : (
            <p>Select an IPSet to manage its members.</p>
          )}
        </aside>
      </div>
    </section>
  );
}
function DiffModal({
  diff,
  close,
  apply,
}: {
  diff: any;
  close: () => void;
  apply: () => void;
}) {
  const entries = diff?.entries || [];
  return (
    <div className="modalback">
      <div className="modal card wide">
        <div className="modalhead">
          <h2>Pending changes ({diff?.changed || 0})</h2>
          <button type="button" onClick={close}>
            <X />
          </button>
        </div>
        {entries.length ? (
          <table>
            <thead>
              <tr>
                <th>CHANGE</th>
                <th>OBJECT</th>
                <th>DETAILS</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((e: any, i: number) => (
                <tr key={i}>
                  <td>
                    <b className={"diff-" + e.kind}>
                      {e.kind === "added"
                        ? "+"
                        : e.kind === "removed"
                          ? "−"
                          : "~"}{" "}
                      {e.kind}
                    </b>
                  </td>
                  <td>
                    <code>{e.object}</code>
                  </td>
                  <td>{e.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          <p>No structural changes detected.</p>
        )}
        <div className="modalactions">
          <button type="button" onClick={close}>
            {t("Cancel")}
          </button>
          <button className="primary" onClick={apply}>
            Apply and start rollback timer
          </button>
        </div>
      </div>
    </div>
  );
}
function Users({ me }: { me: Principal }) {
  const [items, setItems] = useState<any[]>([]),
    [error, setError] = useState(""),
    [username, setUsername] = useState(""),
    [password, setPassword] = useState(""),
    [role, setRole] = useState("viewer"),
    [editing, setEditing] = useState<any | null>(null);
  const load = () =>
    api("/users")
      .then((v) => setItems(v || []))
      .catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api("/users", {
        method: "POST",
        body: JSON.stringify({ username, password, role }),
      });
      setUsername("");
      setPassword("");
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function update(e: React.FormEvent) {
    e.preventDefault();
    if (!editing) return;
    try {
      await api("/users/" + editing.id, {
        method: "PUT",
        body: JSON.stringify({
          role: editing.role,
          password: editing.password || "",
        }),
      });
      setEditing(null);
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function remove(u: any) {
    if (!confirm(`Delete user ${u.username}?`)) return;
    try {
      await api("/users/" + u.id, { method: "DELETE" });
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <section>
      <div className="section-title">
        <div>
          <h2>Users</h2>
          <p>Manage local accounts and roles.</p>
        </div>
        <form className="inline" onSubmit={create}>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            placeholder={t("username")}
            required
          />
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            placeholder={t("password (min 10)")}
            required
          />
          <select value={role} onChange={(e) => setRole(e.target.value)}>
            <option value="viewer">{t("viewer")}</option>
            <option value="operator">{t("operator")}</option>
            <option value="admin">{t("admin")}</option>
          </select>
          <button className="darkbtn">
            <Plus /> Add user
          </button>
        </form>
      </div>
      {error && <div className="error">{error}</div>}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>USERNAME</th>
              <th>ROLE</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((u) => (
              <tr key={u.id}>
                <td>
                  <b>{u.username}</b>
                  {u.id === (me as any).id && <i> (you)</i>}
                </td>
                <td>{u.role}</td>
                <td className="rowactions">
                  <button
                    className="iconbtn"
                    onClick={() => setEditing({ ...u, password: "" })}
                  >
                    <Edit3 />
                  </button>
                  <button className="iconbtn" onClick={() => remove(u)}>
                    <Trash2 />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {editing && (
        <div className="modalback">
          <form className="modal card" onSubmit={update}>
            <div className="modalhead">
              <h2>{t("Edit user")} {editing.username}</h2>
              <button type="button" onClick={() => setEditing(null)}>
                <X />
              </button>
            </div>
            <label>
              {t("Role")}
              <select
                value={editing.role}
                onChange={(e) =>
                  setEditing({ ...editing, role: e.target.value })
                }
              >
                <option value="viewer">{t("viewer")}</option>
                <option value="operator">{t("operator")}</option>
                <option value="admin">{t("admin")}</option>
              </select>
            </label>
            <label>
              {t("New password (leave empty to keep)")}
              <input
                type="password"
                value={editing.password}
                onChange={(e) =>
                  setEditing({ ...editing, password: e.target.value })
                }
              />
            </label>
            <div className="modalactions">
              <button type="button" onClick={() => setEditing(null)}>
                {t("Cancel")}
              </button>
              <button className="primary">Save</button>
            </div>
          </form>
        </div>
      )}
    </section>
  );
}
function Tokens() {
  const [items, setItems] = useState<any[]>([]),
    [error, setError] = useState(""),
    [name, setName] = useState(""),
    [scopes, setScopes] = useState<string[]>(["firewall:read"]),
    [created, setCreated] = useState("");
  const allScopes = [
    "firewall:read",
    "firewall:write",
    "ipset:read",
    "ipset:write",
    "system:read",
    "admin",
  ];
  const load = () =>
    api("/tokens")
      .then((v) => setItems(v || []))
      .catch((e) => setError(e.message));
  useEffect(() => {
    load();
  }, []);
  async function create(e: React.FormEvent) {
    e.preventDefault();
    try {
      const r = await api("/tokens", {
        method: "POST",
        body: JSON.stringify({ name, scopes }),
      });
      setCreated(r.token);
      setName("");
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function remove(t: any) {
    if (!confirm(`Revoke token ${t.name}?`)) return;
    try {
      await api("/tokens/" + t.id, { method: "DELETE" });
      load();
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <section>
      <div className="section-title">
        <div>
          <h2>API Tokens</h2>
          <p>
            Bearer tokens for programmatic access. The token is shown only once.
          </p>
        </div>
        <form className="inline" onSubmit={create}>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={t("token name")}
            required
          />
          {allScopes.map((s) => (
            <label key={s} className="scope">
              <input
                type="checkbox"
                checked={scopes.includes(s)}
                onChange={(e) =>
                  setScopes(
                    e.target.checked
                      ? [...scopes, s]
                      : scopes.filter((x) => x !== s),
                  )
                }
              />{" "}
              {s}
            </label>
          ))}
          <button className="darkbtn">
            <Plus /> Create token
          </button>
        </form>
      </div>
      {error && <div className="error">{error}</div>}
      {created && (
        <div className="notice bar">
          <b>Token (shown once):</b> <code>{created}</code>
          <button
            onClick={() => {
              navigator.clipboard?.writeText(created);
            }}
          >
            Copy
          </button>
          <button onClick={() => setCreated("")}>
            <X />
          </button>
        </div>
      )}
      <div className="card">
        <table>
          <thead>
            <tr>
              <th>NAME</th>
              <th>SCOPES</th>
              <th>CREATED</th>
              <th>LAST USED</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {items.map((t) => (
              <tr key={t.id}>
                <td>
                  <b>{t.name}</b>
                </td>
                <td>
                  <code>{t.scopes}</code>
                </td>
                <td>
                  {t.created_at ? new Date(t.created_at).toLocaleString() : "—"}
                </td>
                <td>
                  {t.last_used
                    ? new Date(t.last_used).toLocaleString()
                    : "never"}
                </td>
                <td>
                  <button className="iconbtn" onClick={() => remove(t)}>
                    <Trash2 />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </section>
  );
}
function Settings({
  fontSize,
  setFontSize,
  ipsets,
  setGlobalSafeMode,
  me,
  sys,
  draft,
  refreshDraft,
}: {
  fontSize: "small" | "medium" | "large" | "x-large";
  setFontSize: (v: "small" | "medium" | "large" | "x-large") => void;
  ipsets: IPSet[];
  setGlobalSafeMode: (v: boolean) => void;
  me: Principal;
  sys: any;
  draft: Draft | null;
  refreshDraft: () => Promise<void>;
}) {
  const [safeMode, setSafeMode] = useState(false),
    [timeout, setTimeoutV] = useState(120),
    [retention, setRetention] = useState(50),
    [rateEnabled, setRateEnabled] = useState(true),
    [rateAuth, setRateAuth] = useState(10),
    [rateApi, setRateApi] = useState(200),
    [rateWhitelist, setRateWhitelist] = useState(""),
    [sessionTTL, setSessionTTL] = useState(720),
    [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [subTab, setSubTab] = useState("settings");
  useEffect(() => {
    api("/settings")
      .then((v) => {
        setSafeMode(!!v.safe_mode);
        setTimeoutV(Number(v.rollback_timeout) || 120);
        setRetention(Number(v.backup_retention) || 50);
        setRateEnabled(v.rate_limit_enabled !== false);
        setRateAuth(Number(v.rate_limit_auth) || 10);
        setRateApi(Number(v.rate_limit_api) || 200);
        setRateWhitelist(v.rate_limit_whitelist_ipset || "");
        setSessionTTL(Number(v.session_ttl_minutes) || 720);
      })
      .catch((e) => setError(e.message));
  }, []);
  async function save(e: React.FormEvent) {
    e.preventDefault();
    try {
      await api("/settings", {
        method: "PUT",
        body: JSON.stringify({
          safe_mode: safeMode,
          rollback_timeout: timeout,
          backup_retention: retention,
          rate_limit_enabled: rateEnabled,
          rate_limit_auth: rateAuth,
          rate_limit_api: rateApi,
          rate_limit_whitelist_ipset: rateWhitelist,
          session_ttl_minutes: sessionTTL,
        }),
      });
      setGlobalSafeMode(safeMode);
      setNotice("Settings saved");
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  const subTabs = [
    { key: "settings", label: t("Settings") },
    { key: "users", label: t("Users") },
    { key: "tokens", label: t("API Tokens") },
    { key: "backups", label: t("Backups") },
    { key: "diagnostics", label: t("Diagnostics") },
    { key: "audit", label: t("Audit") },
    { key: "login", label: t("Login Attempts") },
  ];
  return (
    <section>
      <h2>{t("Settings")}</h2>
      <nav className="subnav">
        {subTabs.map((x) => (
          <button
            key={x.key}
            className={subTab === x.key ? "active" : ""}
            onClick={() => setSubTab(x.key)}
          >
            {x.label}
          </button>
        ))}
      </nav>
      {subTab !== "settings" && (
        <div className="subcontent">
          {subTab === "users" && <Users me={me} />}
          {subTab === "tokens" && <Tokens />}
          {subTab === "backups" && <Backups refreshDraft={refreshDraft} />}
          {subTab === "diagnostics" && <Diagnostics sys={sys} draft={draft} />}
          {subTab === "audit" && <AuditLog />}
          {subTab === "login" && <LoginAttempts />}
        </div>
      )}
      {subTab === "settings" && (
        <>
          {error && <div className="error">{error}</div>}
          {notice && <div className="notice bar">{notice}</div>}
          <form className="card settingsform" onSubmit={save}>
        <label className="check">
          <input
            type="checkbox"
            checked={safeMode}
            onChange={(e) => setSafeMode(e.target.checked)}
          />{" "}
          {t("Safe Mode")} — {t("only FWUI_* chains and jumps to them can be modified; built-in policies and external rules are read-only")}
        </label>
        <label>
          {t("Rollback timeout (seconds)")}
          <input
            type="number"
            min="10"
            max="3600"
            value={timeout}
            onChange={(e) => setTimeoutV(Number(e.target.value))}
          />
        </label>
        <label>
          {t("Backup retention (max snapshots, 0 = unlimited)")}
          <input
            type="number"
            min="0"
            max="1000"
            value={retention}
            onChange={(e) => setRetention(Number(e.target.value))}
          />
        </label>
        <div className="card" style={{ padding: 12, marginTop: 6 }}>
          <h3 style={{ marginTop: 0 }}>{t("API rate limiting")}</h3>
          <label className="check">
            <input
              type="checkbox"
              checked={rateEnabled}
              onChange={(e) => setRateEnabled(e.target.checked)}
            />{" "}
            {t("Enable per-IP rate limiting for API requests")}
          </label>
          <label>
            {t("Auth requests per minute (login / setup)")}
            <input
              type="number"
              min="1"
              max="10000"
              value={rateAuth}
              onChange={(e) => setRateAuth(Number(e.target.value))}
              disabled={!rateEnabled}
            />
          </label>
          <label>
            {t("API requests per minute")}
            <input
              type="number"
              min="1"
              max="10000"
              value={rateApi}
              onChange={(e) => setRateApi(Number(e.target.value))}
              disabled={!rateEnabled}
            />
          </label>
          <label>
            {t("Whitelist IPSet (optional)")}
            <select
              value={rateWhitelist}
              onChange={(e) => setRateWhitelist(e.target.value)}
              disabled={!rateEnabled}
            >
              <option value="">— none —</option>
              {ipsets.map((s) => (
                <option key={s.name} value={s.name}>
                  {s.name} ({s.family === "inet6" ? "IPv6" : "IPv4"})
                </option>
              ))}
            </select>
          </label>
        </div>
        <label>
          {t("Session lifetime (minutes)")}
          <input
            type="number"
            min="1"
            max="525600"
            value={sessionTTL}
            onChange={(e) => setSessionTTL(Number(e.target.value))}
          />
        </label>
        <label>
          {t("Font size")}
          <select
            value={fontSize}
            onChange={(e) => {
              const v = e.target.value as any;
              setFontSize(v);
              localStorage.setItem("fwui_font_size", v);
            }}
          >
            <option value="small">Small</option>
            <option value="medium">Medium</option>
            <option value="large">Large</option>
            <option value="x-large">Extra large</option>
          </select>
        </label>
        <button className="primary">{t("Save settings")}</button>
      </form>
      </>
      )}
    </section>
  );
}
function IPv6({
  draft6,
  setDraft6,
  baseline6,
  setBaseline6,
  rollback6,
  setRollback6,
  setDiff6,
  ipsets,
  aliases,
  setError,
  setNotice,
  safeMode,
}: any) {
  const pending = draft6 ? Number(JSON.stringify(draft6) !== baseline6) : 0;
  const rules = draft6?.rules || [];
  async function refresh() {
    try {
      const n = normalize(await api("/ip6/draft/refresh", { method: "POST" }));
      setDraft6(n);
      setBaseline6(JSON.stringify(n));
      setError("");
      setNotice("Live IPv6 firewall loaded");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function save(next: Draft) {
    const hydrated = {
      ...next,
      aliases: Object.fromEntries(
        (aliases as Alias[]).map((a) => [a.name, a.address]),
      ),
    };
    setDraft6(hydrated);
    try {
      await api("/ip6/draft", {
        method: "PUT",
        body: JSON.stringify(hydrated),
      });
      setError("");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  async function action(path: string) {
    try {
      const result = await api(path, { method: "POST" });
      setError("");
      if (path.endsWith("/apply")) {
        setRollback6({ active: true, deadline: result.rollback_deadline });
        setBaseline6(JSON.stringify(draft6));
        setNotice("IPv6 applied. Confirm before the timer expires.");
      }
      if (path.endsWith("/confirm")) {
        setRollback6({ active: false, deadline: "" });
        setNotice("IPv6 changes confirmed");
      }
      if (path.endsWith("/rollback")) {
        setRollback6({ active: false, deadline: "" });
        await refresh();
        setNotice("Previous IPv6 configuration restored");
      }
      if (path.endsWith("/validate"))
        setNotice("IPv6 draft validation successful");
    } catch (e) {
      setError((e as Error).message);
    }
  }
  return (
    <section>
      <div className="actions v6bar">
        <button onClick={refresh}>
          <RefreshCw /> Refresh IPv6
        </button>
        <button onClick={() => action("/ip6/draft/validate")}>
          <CheckCircle2 /> Validate
        </button>
        <button
          className="apply"
          disabled={!draft6 || !pending}
          onClick={() =>
            api("/ip6/draft/diff")
              .then(setDiff6)
              .catch((e) => setError(e.message))
          }
        >
          <Save /> Apply IPv6
        </button>
        <button
          disabled={!pending}
          onClick={async () => {
            const n = normalize(
              await api("/ip6/draft/discard", { method: "POST" }),
            );
            setDraft6(n);
            setBaseline6(JSON.stringify(n));
            setNotice("IPv6 draft discarded");
          }}
        >
          <X /> Discard
        </button>
        <button
          disabled={!rollback6.active}
          onClick={() => action("/ip6/firewall/rollback")}
        >
          <Undo2 /> Rollback
        </button>
        {rollback6.active && (
          <button
            className="primary"
            onClick={() => action("/ip6/firewall/confirm")}
          >
            Confirm changes
          </button>
        )}
      </div>
      {!draft6 ? (
        <div className="notice bar">
          IPv6 ruleset not loaded — check ip6tables availability and press
          Refresh IPv6.
        </div>
      ) : (
        <>
          <Rules
            title="IPv6 Filter Rules"
            table="filter"
            rules={rules.filter((r: Rule) => r.table === "filter")}
            draft={draft6}
            ipsets={ipsets}
            aliases={aliases}
            save={save}
            safeMode={safeMode}
          />
          <Rules
            title="IPv6 NAT"
            table="nat"
            rules={rules.filter((r: Rule) => r.table === "nat")}
            draft={draft6}
            ipsets={ipsets}
            aliases={aliases}
            save={save}
            safeMode={safeMode}
          />
        </>
      )}
    </section>
  );
}

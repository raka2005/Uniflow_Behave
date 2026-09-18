import { useEffect, useMemo, useState } from "react";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  PolarGrid,
  PolarRadiusAxis,
  Radar,
  RadarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import "./App.css";
const DEMO_DATA = {
  summary: {
    captured_packets: 248,
    detected_flows: 36,
    detected_threats: 5,
    average_risk: 72
  },

  threats: [
    {
      id: 1,
      source: "192.168.1.15",
      destination: "45.33.32.156",
      protocol: "TCP",
      threat_type: "Suspicious Port Activity",
      risk_score: 86,
      severity: "High"
    },
    {
      id: 2,
      source: "192.168.1.21",
      destination: "185.199.108.153",
      protocol: "HTTP",
      threat_type: "Unusual Outbound Traffic",
      risk_score: 68,
      severity: "Medium"
    },
    {
      id: 3,
      source: "192.168.1.18",
      destination: "8.8.8.8",
      protocol: "DNS",
      threat_type: "Repeated DNS Requests",
      risk_score: 54,
      severity: "Medium"
    }
  ],

  flows: [
    {
      source: "192.168.1.15",
      destination: "45.33.32.156",
      protocol: "TCP",
      packets: 84,
      risk_score: 86
    },
    {
      source: "192.168.1.21",
      destination: "185.199.108.153",
      protocol: "HTTP",
      packets: 61,
      risk_score: 68
    },
    {
      source: "192.168.1.18",
      destination: "8.8.8.8",
      protocol: "DNS",
      packets: 103,
      risk_score: 54
    }
  ]
};

// ============================================================
// API CONFIGURATION
// ============================================================

const API_BASE = "https://uniflow-behave.onrender.com";
const LOCAL_API_BASE = "http://127.0.0.1:5000";

// ============================================================
// COLORS
// ============================================================

const COLORS = {
  blue: "#20aef3",
  green: "#13c58b",
  yellow: "#f5b51b",
  pink: "#f34f79",
  orange: "#f58a32",
};


// ============================================================
// DEMO SCENARIOS
// ============================================================

const scenarios = [
  {
    name: "Normal Traffic",
    icon: "〽",
    status: "NORMAL",
    description:
      "Typical business-hour unidirectional flow with expected protocol distribution and volume.",
    pattern:
      "Steady traffic, diverse destinations and normal protocol mix.",
  },
  {
    name: "DDoS Attack",
    icon: "ϟ",
    status: "HIGH-RISK",
    description:
      "Abnormally high traffic volume from multiple sources targeting one destination.",
    pattern:
      "Sudden traffic spike, repeated connections and abnormal packet volume.",
  },
  {
    name: "Port Scanning",
    icon: "◎",
    status: "ESCALATING",
    description:
      "A source communicates with many destination ports in a short period.",
    pattern:
      "Multiple destination ports contacted with low packet count per connection.",
  },
  {
    name: "Botnet / C2 Beaconing",
    icon: "♧",
    status: "ESCALATING",
    description:
      "Periodic communication patterns may indicate command-and-control activity.",
    pattern:
      "Repeated connections at regular intervals with similar packet sizes.",
  },
  {
    name: "DNS Tunnelling",
    icon: "◎",
    status: "HIGH-RISK",
    description:
      "DNS traffic contains unusual volume, entropy or suspicious query patterns.",
    pattern:
      "High DNS request frequency and unusual domain or query characteristics.",
  },
  {
    name: "Data Exfiltration",
    icon: "↗",
    status: "HIGH-RISK",
    description:
      "Large or unusual outbound data transfer may indicate data exfiltration.",
    pattern:
      "Unusual outbound volume, rare destinations and abnormal transfer timing.",
  },
];


// ============================================================
// DEMO TRAFFIC DATA
// ============================================================

const trafficData = [
  { time: "19:32", total: 1500, normal: 1400, suspicious: 45, high: 20 },
  { time: "19:34", total: 1200, normal: 1100, suspicious: 55, high: 18 },
  { time: "19:36", total: 1450, normal: 1300, suspicious: 60, high: 25 },
  { time: "19:38", total: 900, normal: 800, suspicious: 42, high: 15 },
  { time: "19:40", total: 700, normal: 620, suspicious: 35, high: 12 },
  { time: "19:42", total: 850, normal: 750, suspicious: 48, high: 17 },
  { time: "19:44", total: 1100, normal: 980, suspicious: 52, high: 20 },
  { time: "19:46", total: 950, normal: 850, suspicious: 45, high: 18 },
  { time: "19:48", total: 1200, normal: 1080, suspicious: 65, high: 25 },
  { time: "19:50", total: 1600, normal: 1450, suspicious: 75, high: 32 },
  { time: "19:52", total: 1000, normal: 900, suspicious: 52, high: 20 },
  { time: "19:54", total: 1300, normal: 1150, suspicious: 60, high: 24 },
];


// ============================================================
// RADAR DATA
// ============================================================

const radarData = [
  { subject: "Flow", value: 85 },
  { subject: "TCP", value: 75 },
  { subject: "Protocol", value: 45 },
  { subject: "Unique", value: 90 },
  { subject: "Inter-Arrival", value: 30 },
  { subject: "Average", value: 25 },
];


// ============================================================
// MAIN APP
// ============================================================

function App() {
  const [activePage, setActivePage] = useState("Overview");

  const [summary, setSummary] = useState({});
  const [threats, setThreats] = useState([]);
  const [flows, setFlows] = useState([]);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [selectedScenario, setSelectedScenario] = useState(0);
  const [isPaused, setIsPaused] = useState(false);
  const [windowProgress, setWindowProgress] = useState(1);

  // Real live-analysis state
  const [liveData, setLiveData] = useState(null);
  const [liveLoading, setLiveLoading] = useState(false);
  const [liveError, setLiveError] = useState("");
  const [analysisMode, setAnalysisMode] = useState("demo");

  // ==========================================================
  // LOAD DASHBOARD DATA FROM CSV API
  // ==========================================================

  async function loadDashboard() {
    try {
      setLoading(true);
      setError("");

      const [
        summaryResponse,
        threatsResponse,
        flowsResponse,
      ] = await Promise.all([
        fetch(`${API_BASE}/api/summary`),
        fetch(`${API_BASE}/api/threats`),
        fetch(`${API_BASE}/api/flows`),
      ]);

      if (
        !summaryResponse.ok ||
        !threatsResponse.ok ||
        !flowsResponse.ok
      ) {
        throw new Error("Dashboard API request failed");
      }

      const summaryData = await summaryResponse.json();
      const threatsData = await threatsResponse.json();
      const flowsData = await flowsResponse.json();

      setSummary(summaryData || {});

      setThreats(
        Array.isArray(threatsData)
          ? threatsData
          : threatsData.threats ||
              threatsData.data ||
              []
      );

      setFlows(
        Array.isArray(flowsData)
          ? flowsData
          : flowsData.flows ||
              flowsData.data ||
              []
      );
    } catch (err) {
      console.error(err);

      setError(
        "Cannot connect to Flask API. Make sure your Flask backend is running on port 5000."
      );
    } finally {
      setLoading(false);
    }
  }


  // ==========================================================
  // LOAD REAL LIVE SCAPY ANALYSIS
  // ==========================================================

  async function loadLiveAnalysis() {
    try {
      setLiveLoading(true);
      setLiveError("");

      const response = await fetch(
      `${LOCAL_API_BASE}/api/live-analysis`
      );

      if (!response.ok) {
        throw new Error("Live analysis API request failed");
      }

      const data = await response.json();

      if (data.status === "error") {
        throw new Error(
          data.message || "Live analysis failed"
        );
      }

      setLiveData(data);
    } catch (err) {
      console.error(err);

      setLiveError(
        "Cannot load live analysis. Make sure Flask and Npcap are running."
      );
    } finally {
      setLiveLoading(false);
    }
  }
function loadDemoAnalysis() {
  setLiveError("");
  setLiveData({
    status: "success",
    window_seconds: 5,
    total_packets: DEMO_DATA.summary.captured_packets,
    total_flows: DEMO_DATA.summary.detected_flows,
    total_threats: DEMO_DATA.summary.detected_threats,
    average_risk_score: DEMO_DATA.summary.average_risk,
    overall_risk: "High",
    normal_flows:
      DEMO_DATA.summary.detected_flows -
      DEMO_DATA.summary.detected_threats,
    suspicious_flows: 2,
    high_risk_flows: 3,
    threats: DEMO_DATA.threats,
    flows: DEMO_DATA.flows,
  });
}
  // ==========================================================
  // INITIAL DASHBOARD LOAD
  // ==========================================================

  useEffect(() => {
    loadDashboard();
  }, []);


  // ==========================================================
  // LOAD LIVE ANALYSIS WHEN PAGE IS OPENED
  // ==========================================================

  useEffect(() => {
  if (activePage === "Live Analysis") {
    if (analysisMode === "demo") {
      loadDemoAnalysis();
    } else {
      loadLiveAnalysis();
    }
  }
}, [activePage, analysisMode]);

  // ==========================================================
  // DEMO WINDOW TIMER
  // ==========================================================

  useEffect(() => {
    if (isPaused) {
      return;
    }

    const timer = setInterval(() => {
      setWindowProgress((previous) => {
        if (previous >= 5) {
          return 1;
        }

        return previous + 1;
      });
    }, 1000);

    return () => clearInterval(timer);
  }, [isPaused]);


  // ==========================================================
  // DATA HELPER FUNCTIONS
  // ==========================================================

  function getThreatName(threat) {
    return (
      threat.threat_class ||
      threat.threat ||
      threat.category ||
      threat.threat_type ||
      threat.type ||
      "Unknown"
    );
  }

  function getSourceIP(item) {
    return (
      item.src_ip ||
      item.source_ip ||
      item.src ||
      "-"
    );
  }

  function getDestinationIP(item) {
    return (
      item.dst_ip ||
      item.destination_ip ||
      item.dst ||
      "-"
    );
  }

  function getRiskScore(threat) {
    return (
      threat.risk_score ??
      threat.score ??
      threat.risk ??
      0
    );
  }

  function getSeverity(threat) {
    return threat.severity || "Unknown";
  }


  // ==========================================================
  // SUMMARY VALUES
  // ==========================================================

  const totalFlows =
    summary.total_flows ??
    flows.length ??
    0;

  const totalThreats =
    summary.total_threats ??
    threats.length ??
    0;

  const highThreats =
    summary.high_threats ??
    threats.filter((threat) =>
      String(getSeverity(threat))
        .toLowerCase()
        .includes("high")
    ).length;

  const mediumThreats =
    summary.medium_threats ??
    threats.filter((threat) =>
      ["medium", "suspicious"].includes(
        String(getSeverity(threat)).toLowerCase()
      )
    ).length;

  const lowThreats =
    summary.low_threats ??
    threats.filter((threat) =>
      String(getSeverity(threat))
        .toLowerCase()
        .includes("low")
    ).length;

  const averageRisk =
    summary.average_risk_score ?? 0;


  // ==========================================================
  // THREAT CATEGORY DATA
  // ==========================================================

  const categoryData = useMemo(() => {
    const counts = {};

    threats.forEach((threat) => {
      const category = getThreatName(threat);

      counts[category] =
        (counts[category] || 0) + 1;
    });

    return Object.entries(counts).map(
      ([name, count]) => ({
        name,
        count,
      })
    );
  }, [threats]);


  // ==========================================================
  // OVERVIEW PAGE
  // ==========================================================

  function renderOverview() {
    return (
      <>
        <PageTitle
          title="Security Operations Centre"
          subtitle="Real-time passive traffic monitoring and risk analysis"
          right={
            <div className="date-display">
              Flows Today: <strong>{totalFlows.toLocaleString()}</strong>
            </div>
          }
        />

        <div className="notice">
          ◉ UniFlow-BEHAVE performs passive analysis of
          unidirectional IP traffic metadata only. No active
          scanning, blocking, packet injection, or payload
          decryption is performed.
        </div>

        <section className="stats-grid">
          <StatCard
            title="Total Traffic"
            value={totalFlows.toLocaleString()}
            subtitle="flows detected"
            icon="〽"
            color="blue"
          />

          <StatCard
            title="Normal"
            value={Math.max(
              totalFlows - totalThreats,
              0
            ).toLocaleString()}
            subtitle="normal flows"
            icon="◉"
            color="green"
          />

          <StatCard
            title="Suspicious"
            value={mediumThreats}
            subtitle="requires attention"
            icon="△"
            color="yellow"
          />

          <StatCard
            title="High-Risk"
            value={highThreats}
            subtitle="immediate review"
            icon="⚠"
            color="pink"
          />

          <StatCard
            title="Active Alerts"
            value={totalThreats}
            subtitle="detected threats"
            icon="⚠"
            color="orange"
          />
        </section>

        <section className="content-grid overview-grid">
          <Panel
            title="Traffic Activity"
            subtitle="Flow classification over time"
          >
            <div className="chart-legend">
              <Legend
                color={COLORS.blue}
                text="Total"
              />

              <Legend
                color={COLORS.green}
                text="Normal"
              />

              <Legend
                color={COLORS.yellow}
                text="Suspicious"
              />

              <Legend
                color={COLORS.pink}
                text="High-Risk"
              />
            </div>

            <ResponsiveContainer
              width="100%"
              height={300}
            >
              <BarChart data={trafficData}>
                <CartesianGrid
                  stroke="#263044"
                  strokeDasharray="3 3"
                />

                <XAxis
                  dataKey="time"
                  stroke="#75829a"
                />

                <YAxis stroke="#75829a" />

                <Tooltip
                  contentStyle={{
                    background: "#10182a",
                    border: "1px solid #263044",
                    color: "#ffffff",
                  }}
                />

                <Bar
  dataKey="total"
  fill={COLORS.blue}
  radius={[5, 5, 0, 0]}
/>

<Bar
  dataKey="normal"
  fill={COLORS.green}
  radius={[5, 5, 0, 0]}
/>

<Bar
  dataKey="suspicious"
  fill={COLORS.yellow}
  radius={[5, 5, 0, 0]}
/>

<Bar
  dataKey="high"
  fill={COLORS.pink}
  radius={[5, 5, 0, 0]}
/>
              </BarChart>
            </ResponsiveContainer>
          </Panel>

          <Panel
            title="Traffic State Distribution"
            subtitle="Current flow classification"
          >
            <ResponsiveContainer
              width="100%"
              height={270}
            >
              <PieChart>
                <Pie
                  data={[
                    {
                      name: "Normal",
                      value: Math.max(
                        totalFlows - totalThreats,
                        1
                      ),
                    },
                    {
                      name: "Suspicious",
                      value: Math.max(
                        mediumThreats,
                        1
                      ),
                    },
                    {
                      name: "High-Risk",
                      value: Math.max(
                        highThreats,
                        1
                      ),
                    },
                  ]}
                  dataKey="value"
                  nameKey="name"
                  innerRadius={70}
                  outerRadius={105}
                  paddingAngle={3}
                >
                  <Cell fill={COLORS.green} />
                  <Cell fill={COLORS.yellow} />
                  <Cell fill={COLORS.pink} />
                </Pie>

                <Tooltip
                  contentStyle={{
                    background: "#10182a",
                    border: "1px solid #263044",
                  }}
                />
              </PieChart>
            </ResponsiveContainer>

            <div className="distribution-list">
              <Legend
                color={COLORS.green}
                text="Normal"
              />

              <Legend
                color={COLORS.yellow}
                text="Suspicious"
              />

              <Legend
                color={COLORS.pink}
                text="High-Risk"
              />
            </div>
          </Panel>
        </section>

        <section className="content-grid">
          <Panel
            title="Risk Score Breakdown"
            subtitle="Composite risk from different detection models"
          >
            <div className="risk-bars">
              <RiskBar
                label="RuleScore"
                value={62}
                color={COLORS.blue}
              />

              <RiskBar
                label="MLScore"
                value={71}
                color="#16c7df"
              />

              <RiskBar
                label="DriftScore"
                value={55}
                color={COLORS.yellow}
              />

              <RiskBar
                label="TemporalScore"
                value={42}
                color="#f36d91"
              />
            </div>
          </Panel>

          <ThreatTable threats={threats.slice(0, 10)} />
        </section>

        <Panel
  title="Threat Detection"
  subtitle="Recently detected threats from passive traffic analysis"
>
  {threats.length === 0 ? (
    <p className="muted">
      No threats detected yet.
    </p>
  ) : (
    <div className="table-wrapper">
      <table>
        <thead>
          <tr>
            <th>Threat</th>
            <th>Source IP</th>
            <th>Destination IP</th>
            <th>Protocol</th>
            <th>Packets</th>
            <th>Risk Score</th>
            <th>Severity</th>
          </tr>
        </thead>

        <tbody>
          {threats.map((threat, index) => (
            <tr key={index}>
              <td>{getThreatLabel(threat)}</td>
              <td>{getSourceLabel(threat)}</td>
              <td>{getDestinationLabel(threat)}</td>
              <td>{threat.protocol || "-"}</td>
              <td>
                {threat.packets ??
                  threat.packet_count ??
                  "-"}
              </td>
              <td>
                {threat.risk_score ??
                  threat.score ??
                  threat.risk ??
                  "-"}
              </td>
              <td>
                <span className="severity-badge">
                  {threat.severity || "Unknown"}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )}
</Panel>
      </>
    );
  }

// ============================================================
// REAL LIVE ANALYSIS PAGE
// ============================================================

function renderLiveAnalysis() {
  const liveFlowList = Array.isArray(liveData?.flows)
    ? liveData.flows
    : [];

  const liveThreatList = Array.isArray(liveData?.threats)
    ? liveData.threats
    : [];

  const totalPackets =
    liveData?.total_packets ??
    liveData?.packets ??
    0;

  const liveTotalFlows =
    liveData?.total_flows ??
    liveFlowList.length;

  const liveTotalThreats =
    liveData?.total_threats ??
    liveThreatList.length;

  const liveAverageRisk =
    liveData?.average_risk_score ??
    liveData?.risk_score ??
    0;

  const liveOverallRisk =
    liveData?.overall_risk ??
    liveData?.risk_level ??
    "Unknown";

  const normalFlows =
    liveData?.normal_flows ??
    liveFlowList.filter(
      (flow) =>
        String(flow.status || "").toLowerCase() ===
        "normal"
    ).length;

  const suspiciousFlows =
    liveData?.suspicious_flows ??
    liveFlowList.filter(
      (flow) =>
        String(flow.status || "").toLowerCase() ===
        "suspicious"
    ).length;

  const highRiskFlows =
    liveData?.high_risk_flows ??
    liveFlowList.filter(
      (flow) =>
        String(flow.status || "")
          .toLowerCase()
          .includes("high")
    ).length;

  return (
    <>
      <PageTitle
  title="Live Analysis"
  subtitle="Real-time passive network traffic analysis using Scapy"
  right={
    <div className="header-actions">
      <button
        className={
          analysisMode === "demo"
            ? "refresh-button active-mode"
            : "refresh-button"
        }
        onClick={() => setAnalysisMode("demo")}
      >
        Demo Mode
      </button>

      <button
        className={
          analysisMode === "live"
            ? "refresh-button active-mode"
            : "refresh-button"
        }
        onClick={() => setAnalysisMode("live")}
      >
        Live Mode
      </button>

      {analysisMode === "live" && (
        <button
          className="refresh-button"
          onClick={loadLiveAnalysis}
          disabled={liveLoading}
        >
          {liveLoading
            ? "Analyzing..."
            : "↻ Run Analysis"}
        </button>
      )}
    </div>
  }
/>

      <div className="notice">
  ◉{" "}
  {analysisMode === "demo"
    ? "Demo Mode displays sample network traffic for presentation and testing."
    : "Live Mode captures real network metadata for 5 seconds using local Flask and Scapy."}
  No packet blocking, injection, active scanning, or payload decryption is performed.
</div>

      {liveError && (
        <div className="error">
          {liveError}
        </div>
      )}

      {liveLoading && (
        <div className="message">
          Capturing and analyzing live network traffic
          for 5 seconds...
        </div>
      )}

      <section className="stats-grid four">
        <StatCard
          title="Captured Packets"
          value={totalPackets.toLocaleString()}
          subtitle="packets in current window"
          icon="〽"
          color="blue"
        />

        <StatCard
          title="Detected Flows"
          value={liveTotalFlows.toLocaleString()}
          subtitle="network flows"
          icon="◉"
          color="green"
        />

        <StatCard
          title="Detected Threats"
          value={liveTotalThreats.toLocaleString()}
          subtitle="threats in current window"
          icon="⚠"
          color="orange"
        />

        <StatCard
          title="Average Risk"
          value={`${liveAverageRisk}/100`}
          subtitle={`Overall risk: ${liveOverallRisk}`}
          icon="◔"
          color={
            String(liveOverallRisk).toLowerCase() === "high"
              ? "pink"
              : String(liveOverallRisk).toLowerCase() ===
                "medium"
              ? "yellow"
              : "green"
          }
        />
      </section>

      <section className="content-grid">
        <Panel
          title="Live Analysis Summary"
          subtitle="Results returned directly from Flask and Scapy"
        >
          <div className="risk-bars">
            <RiskBar
              label="Normal Flows"
              value={
                liveTotalFlows > 0
                  ? (normalFlows / liveTotalFlows) * 100
                  : 0
              }
              color={COLORS.green}
            />

            <RiskBar
              label="Suspicious Flows"
              value={
                liveTotalFlows > 0
                  ? (suspiciousFlows / liveTotalFlows) * 100
                  : 0
              }
              color={COLORS.yellow}
            />

            <RiskBar
              label="High-Risk Flows"
              value={
                liveTotalFlows > 0
                  ? (highRiskFlows / liveTotalFlows) * 100
                  : 0
              }
              color={COLORS.pink}
            />

            <RiskBar
              label="Average Risk Score"
              value={liveAverageRisk}
              color={COLORS.blue}
            />
          </div>
        </Panel>

        <Panel
          title="Analysis Information"
          subtitle="Current capture window"
        >
          <div className="inner-box">
            <p>
              <strong>Capture Duration:</strong>{" "}
              {liveData?.window_seconds ?? 5} seconds
            </p>

            <p>
              <strong>Captured Packets:</strong>{" "}
              {totalPackets}
            </p>

            <p>
              <strong>Normal Flows:</strong>{" "}
              {normalFlows}
            </p>

            <p>
              <strong>Suspicious Flows:</strong>{" "}
              {suspiciousFlows}
            </p>

            <p>
              <strong>High-Risk Flows:</strong>{" "}
              {highRiskFlows}
            </p>

            <p>
              <strong>Overall Risk:</strong>{" "}
              {liveOverallRisk}
            </p>
          </div>
        </Panel>
      </section>

      <Panel
        title="Detected Threats"
        subtitle="Threats returned by live Scapy analysis"
      >
        {liveThreatList.length === 0 ? (
          <p className="muted">
            No threats detected during this capture window.
          </p>
        ) : (
          <ThreatTable
            threats={liveThreatList}
          />
        )}
      </Panel>

      <Panel
        title="Detected Network Flows"
        subtitle="Network flows captured during the current window"
      >
        {liveFlowList.length === 0 ? (
          <p className="muted">
            No network flows returned.
          </p>
        ) : (
          <div className="table-wrapper">
            <table>
              <thead>
                <tr>
                  <th>Source IP</th>
                  <th>Destination IP</th>
                  <th>Source Port</th>
                  <th>Destination Port</th>
                  <th>Protocol</th>
                  <th>Packets</th>
                  <th>Total Bytes</th>
                  <th>Status</th>
                </tr>
              </thead>

              <tbody>
                {liveFlowList.map((flow, index) => (
                  <tr key={index}>
                    <td>
                      {flow.source_ip ||
                        flow.src_ip ||
                        "-"}
                    </td>

                    <td>
                      {flow.destination_ip ||
                        flow.dst_ip ||
                        "-"}
                    </td>

                    <td>
                      {flow.source_port ??
                        flow.src_port ??
                        "-"}
                    </td>

                    <td>
                      {flow.destination_port ??
                        flow.dst_port ??
                        "-"}
                    </td>

                    <td>
                      {flow.protocol || "-"}
                    </td>

                    <td>
                      {flow.packet_count ??
                        flow.packets ??
                        "-"}
                    </td>

                    <td>
                      {flow.total_bytes ?? "-"}
                    </td>

                    <td>
                      <span
                        className={`severity-badge ${
                          String(flow.status || "")
                            .toLowerCase()
                            .includes("suspicious")
                            ? "suspicious"
                            : String(flow.status || "")
                                .toLowerCase()
                                .includes("high")
                            ? "high"
                            : "normal"
                        }`}
                      >
                        {flow.status || "Unknown"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}

  // ==========================================================
  // BEHAVIOUR ANALYSIS PAGE
  // ==========================================================

  function renderBehaviourAnalysis() {
    return (
      <>
        <PageTitle
          title="Behaviour Analysis"
          subtitle="Compare current behaviour against the historical baseline"
        />

        <section className="stats-grid three">
          <StatCard
            title="ChangeScore"
            value="78"
            subtitle="Magnitude of behavioural change"
            icon="〽"
            color="pink"
          />

          <StatCard
            title="DeviationScore"
            value="84"
            subtitle="Statistical distance from baseline"
            icon="⌘"
            color="yellow"
          />

          <StatCard
            title="DriftScore"
            value="62"
            subtitle="Sustained distribution shift"
            icon="〽"
            color="pink"
          />
        </section>

        <section className="content-grid behaviour-grid">
          <Panel
            title="Behaviour Fingerprint Radar"
            subtitle="Current behaviour profile"
          >
            <ResponsiveContainer
              width="100%"
              height={330}
            >
              <RadarChart data={radarData}>
                <PolarGrid stroke="#334155" />

                <PolarAngleAxis
                  dataKey="subject"
                  stroke="#9aa8bf"
                />

                <PolarRadiusAxis
                  stroke="#64748b"
                />

                <Radar
                  dataKey="value"
                  stroke={COLORS.blue}
                  fill={COLORS.blue}
                  fillOpacity={0.2}
                />
              </RadarChart>
            </ResponsiveContainer>
          </Panel>

          <Panel
            title="Current Behaviour vs Historical Baseline"
            subtitle="Per-metric comparison"
          >
            <BaselineBar
              label="Flow Rate (flows/sec)"
              baseline="1,180"
              current="4,280"
              percentage="263%"
              color={COLORS.pink}
              direction="up"
            />

            <BaselineBar
              label="Avg Packet Size (bytes)"
              baseline="680"
              current="142"
              percentage="79%"
              color={COLORS.green}
              direction="down"
            />

            <BaselineBar
              label="Inter-Arrival Time (ms)"
              baseline="85"
              current="12"
              percentage="86%"
              color={COLORS.green}
              direction="down"
            />

            <BaselineBar
              label="Unique Destinations"
              baseline="240"
              current="1,840"
              percentage="667%"
              color={COLORS.pink}
              direction="up"
            />
          </Panel>
        </section>

        <Panel
          title="State Progression Model"
          subtitle="How UniFlow-BEHAVE transitions between monitoring states"
        >
          <div className="state-grid">
            <StateBox
              title="NORMAL"
              range="Risk Range: 0–54"
              color="green"
              description="All scores below threshold. Behaviour matches baseline within tolerance."
            />

            <StateBox
              title="SUSPICIOUS"
              range="Risk Range: 55–69"
              color="yellow"
              description="One or more scores exceed the threshold. Drift or rule match detected."
            />

            <StateBox
              title="ESCALATING"
              range="Risk Range: 70–84"
              color="orange"
              description="Multiple models agree on anomaly. Behavioural fingerprint diverges from baseline."
            />

            <StateBox
              title="HIGH-RISK"
              range="Risk Range: 85–100"
              color="pink"
              description="Strong consensus across Rule, ML, Drift and Temporal models."
            />
          </div>
        </Panel>

        <Panel
          title="Composite Risk Score Components"
          subtitle="Weighted fusion of four scoring models"
        >
          <div className="component-grid">
            <RiskBar
              label="RuleScore — Weight 30%"
              value={62}
              color={COLORS.blue}
            />

            <RiskBar
              label="MLScore — Weight 35%"
              value={71}
              color="#16c7df"
            />

            <RiskBar
              label="DriftScore — Weight 20%"
              value={55}
              color={COLORS.yellow}
            />

            <RiskBar
              label="TemporalScore — Weight 15%"
              value={42}
              color="#f36d91"
            />
          </div>
        </Panel>
      </>
    );
  }


  // ==========================================================
  // PIPELINE PAGE
  // ==========================================================

  function renderPipeline() {
    const stages = [
      [
        "〽",
        "Traffic",
        "Unidirectional IP flow collection",
      ],
      [
        "☷",
        "Features",
        "Statistical and temporal features per 5-second window",
      ],
      [
        "◎",
        "Behaviour Fingerprint",
        "Compact behavioural representation of flow patterns",
      ],
      [
        "▤",
        "Baseline",
        "Rolling 30-day behavioural baseline per host or segment",
      ],
      [
        "⌁",
        "Drift",
        "KL-divergence and KS-test for distribution shift",
      ],
      [
        "♢",
        "Rules + RF",
        "Hybrid deterministic rules and ML classifier ensemble",
      ],
      [
        "◔",
        "Risk Score",
        "Weighted fusion of Rule, ML, Drift and Temporal scores",
      ],
      [
        "♧",
        "Alert",
        "State-mapped alert with full evidence trail",
      ],
    ];

    return (
      <>
        <PageTitle
          title="Detection Pipeline"
          subtitle="End-to-end flow from passive traffic collection to explainable alert generation"
        />

        <Panel title="Detection Pipeline">
          <div className="pipeline">
            {stages.map(
              ([icon, name], index) => (
                <div
                  className="pipeline-stage"
                  key={name}
                >
                  <div className="pipeline-icon">
                    {icon}
                  </div>

                  <strong>{name}</strong>

                  {index !== stages.length - 1 && (
                    <span className="pipeline-arrow">
                      ›
                    </span>
                  )}
                </div>
              )
            )}
          </div>
        </Panel>

        <div className="stage-card-grid">
          {stages.map(
            ([icon, name, description], index) => (
              <div
                className="stage-card"
                key={name}
              >
                <div className="stage-card-icon">
                  {icon}
                </div>

                <small>
                  Stage {index + 1}
                </small>

                <h3>{name}</h3>

                <p>{description}</p>
              </div>
            )
          )}
        </div>

        <section className="content-grid">
          <Panel title="Passive Collection Only">
            <p className="muted">
              UniFlow-BEHAVE operates exclusively on
              unidirectional IP flow metadata. The system
              does not send probes, inject packets, modify
              traffic or intercept payloads.
            </p>

            <ul className="indicator-list">
              <li>No active port scanning</li>
              <li>No packet injection</li>
              <li>No payload decryption</li>
              <li>No blocking or quarantine</li>
            </ul>
          </Panel>

          <Panel title="Read-Only Analysis">
            <p className="muted">
              The detection pipeline processes pre-collected
              flow data in a read-only manner. Behavioural
              fingerprints and baselines are built from
              historical metadata.
            </p>

            <ul className="indicator-list">
              <li>Flow metadata only</li>
              <li>Behavioural fingerprinting</li>
              <li>30-day rolling baseline</li>
              <li>Explainable scoring with evidence trail</li>
            </ul>
          </Panel>
        </section>

        <Panel title="Composite Risk Score Fusion">
          <div className="formula">
            Final Risk Score = 0.30 × Rule + 0.35 × ML
            + 0.20 × Drift + 0.15 × Temporal
          </div>
        </Panel>
      </>
    );
  }


  // ==========================================================
  // MAIN LAYOUT
  // ==========================================================

  return (
    <div className="app-layout">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon">
            ⬡
          </div>

          <div>
            <h2>UNIFLOW-BEHAVE</h2>
            <p>Passive AI Detection</p>
          </div>
        </div>

        <nav className="navigation">
          {[
            ["Overview", "▥"],
            ["Live Analysis", "◉"],
            ["Behaviour Analysis", "⌁"],
            ["Detection Pipeline", "⬡"],
          ].map(([name, icon]) => (
            <button
              key={name}
              className={
                activePage === name
                  ? "nav-active"
                  : ""
              }
              onClick={() => setActivePage(name)}
            >
              <span>{icon}</span>
              {name}
            </button>
          ))}
        </nav>

        <div className="sidebar-status">
          <strong>● PASSIVE MODE</strong>

          <p>
            <span>Uptime</span>
            <span>Live</span>
          </p>

          <p>
            <span>Flows/sec</span>
            <span>
              {summary.total_flows ?? 0}
            </span>
          </p>

          <p>
            <span>Sensors</span>
            <span>1 active</span>
          </p>
        </div>

        <div className="readonly-label">
          🔒 READ-ONLY · NO ACTIVE PROBING
        </div>
      </aside>

      <main className="main-content">
        <header className="top-header">
          <div>
            <h2>UniFlow Security Platform</h2>
            <p>
              Passive AI-Based Cyber-Threat Detection
            </p>
          </div>

          <div className="header-actions">
            <span className="monitor-badge">
              ◉ PASSIVE MONITORING · READ-ONLY
            </span>

            <button
              className="refresh-button"
              onClick={loadDashboard}
            >
              ↻ Refresh
            </button>
          </div>
        </header>

        {loading && (
          <div className="message">
            Loading dashboard data...
          </div>
        )}

        {error && (
          <div className="error">
            {error}
          </div>
        )}

       {!loading && (
  <div className="page-content">
    {activePage === "Overview" && renderOverview()}
    {activePage === "Live Analysis" && renderLiveAnalysis()}
    {activePage === "Behaviour Analysis" && renderBehaviourAnalysis()}
    {activePage === "Detection Pipeline" && renderPipeline()}
  </div>
)}

{loading && activePage === "Live Analysis" && (
  <div className="page-content">
    {renderLiveAnalysis()}
  </div>
)}
      </main>
    </div>
  );
}


// ============================================================
// PAGE TITLE COMPONENT
// ============================================================

function PageTitle({
  title,
  subtitle,
  right,
}) {
  return (
    <div className="page-heading">
      <div>
        <h1>{title}</h1>
        <p>{subtitle}</p>
      </div>

      {right}
    </div>
  );
}


// ============================================================
// STAT CARD COMPONENT
// ============================================================

function StatCard({
  title,
  value,
  subtitle,
  icon,
  color,
  progress,
  gauge,
}) {
  return (
    <div className="stat-card">
      <div className={`stat-icon ${color}`}>
        {icon}
      </div>

      <p>{title}</p>

      <h2>{value}</h2>

      <small>{subtitle}</small>

      {progress !== undefined && (
        <div className="mini-progress">
          <div
            style={{
              width: `${progress}%`,
            }}
          ></div>
        </div>
      )}

      {gauge && (
        <div className="mini-gauge">
          <div className="gauge-needle"></div>
        </div>
      )}
    </div>
  );
}


// ============================================================
// PANEL COMPONENT
// ============================================================

function Panel({
  title,
  subtitle,
  children,
}) {
  return (
    <section className="panel">
      <div className="panel-heading">
        <div>
          <h2>{title}</h2>

          {subtitle && (
            <p>{subtitle}</p>
          )}
        </div>
      </div>

      {children}
    </section>
  );
}


// ============================================================
// LEGEND COMPONENT
// ============================================================

function Legend({
  color,
  text,
}) {
  return (
    <span className="legend">
      <i
        style={{
          background: color,
        }}
      ></i>

      {text}
    </span>
  );
}


// ============================================================
// RISK BAR COMPONENT
// ============================================================

function RiskBar({
  label,
  value,
  color,
}) {
  const safeValue = Math.min(
    Math.max(Number(value) || 0, 0),
    100
  );

  return (
    <div className="risk-bar-wrapper">
      <div className="risk-bar-heading">
        <span>{label}</span>

        <strong>
          {Math.round(safeValue)}
        </strong>
      </div>

      <div className="risk-bar">
        <div
          style={{
            width: `${safeValue}%`,
            background: color,
          }}
        ></div>
      </div>
    </div>
  );
}


// ============================================================
// BASELINE BAR COMPONENT
// ============================================================

function BaselineBar({
  label,
  baseline,
  current,
  percentage,
  color,
  direction,
}) {
  return (
    <div className="baseline-wrapper">
      <div className="baseline-heading">
        <strong>{label}</strong>

        <span
          className={
            direction === "up"
              ? "change-up"
              : "change-down"
          }
        >
          {direction === "up" ? "↑" : "↓"}{" "}
          {percentage}
        </span>
      </div>

      <div className="baseline-track">
        <div className="baseline-old">
          Baseline: {baseline}
        </div>

        <div
          className="baseline-current"
          style={{
            background: color,
          }}
        >
          Current: {current}
        </div>
      </div>
    </div>
  );
}


// ============================================================
// STATE BOX COMPONENT
// ============================================================

function StateBox({
  title,
  range,
  color,
  description,
}) {
  return (
    <div className={`state-box ${color}`}>
      <h3>● {title}</h3>

      <small>{range}</small>

      <p>{description}</p>
    </div>
  );
}


// ============================================================
// THREAT TABLE COMPONENT
// ============================================================

function ThreatTable({
  threats,
}) {
  return (
    <Panel
      title="Detected Threats"
      subtitle="Threats identified from passive traffic analysis"
    >
      {threats.length === 0 ? (
        <p className="muted">
          No threats found.
        </p>
      ) : (
        <div className="table-wrapper">
          <table>
            <thead>
              <tr>
                <th>Threat</th>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Packets</th>
                <th>Risk Score</th>
                <th>Severity</th>
              </tr>
            </thead>

            <tbody>
              {threats.map(
                (threat, index) => (
                  <tr key={index}>
                    <td>
                      {getThreatLabel(threat)}
                    </td>

                    <td>
                      {getSourceLabel(threat)}
                    </td>

                    <td>
                      {getDestinationLabel(threat)}
                    </td>

                    <td>
                      {threat.protocol || "-"}
                    </td>

                    <td>
                      {threat.packets ??
                        threat.packet_count ??
                        "-"}
                    </td>

                    <td>
                      {threat.risk_score ??
                        threat.score ??
                        threat.risk ??
                        "-"}
                    </td>

                    <td>
                      <span className="severity-badge">
                        {threat.severity ||
                          "Unknown"}
                      </span>
                    </td>
                  </tr>
                )
              )}
            </tbody>
          </table>
        </div>
      )}
    </Panel>
  );
}


// ============================================================
// THREAT TABLE HELPER FUNCTIONS
// ============================================================

function getThreatLabel(threat) {
  return (
    threat.threat_class ||
    threat.threat ||
    threat.category ||
    threat.threat_type ||
    threat.type ||
    "Unknown"
  );
}

function getSourceLabel(threat) {
  return (
    threat.src_ip ||
    threat.source_ip ||
    threat.src ||
    "-"
  );
}

function getDestinationLabel(threat) {
  return (
    threat.dst_ip ||
    threat.destination_ip ||
    threat.dst ||
    "-"
  );
}


export default App;
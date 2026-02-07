import { useState, useEffect } from 'react'
import { Terminal, Shield, Play, Loader2, AlertTriangle, CheckCircle, FileJson, Globe, FileCode, List, Sun, Moon, Download, Trash2 } from 'lucide-react'
import RuleBuilder from './components/RuleBuilder'

const API_BASE = "http://localhost:8083/api"

function App() {
    const [theme, setTheme] = useState('dark')
    const [scanId, setScanId] = useState(null)
    const [view, setView] = useState('config') // config, running, results, rules
    const [status, setStatus] = useState(null)
    const [results, setResults] = useState([])
    const [history, setHistory] = useState([])
    const [rules, setRules] = useState([])
    const [isCreatingRule, setIsCreatingRule] = useState(false)

    // Config State
    const [inputType, setInputType] = useState('openapi')
    const [targetUrl, setTargetUrl] = useState('')
    const [curlCmd, setCurlCmd] = useState('')
    const [fileContent, setFileContent] = useState('')

    // Advanced State
    const [graphql, setGraphql] = useState(false)
    const [aiProvider, setAiProvider] = useState('')
    const [aiKey, setAiKey] = useState('')



    // UI State
    const [useBuilder, setUseBuilder] = useState(false)
    const [isSubmitting, setIsSubmitting] = useState(false)
    const [error, setError] = useState(null)

    // Theme Effect
    useEffect(() => {
        console.log("Theme changing to:", theme) // Debug log
        if (theme === 'dark') {
            document.documentElement.classList.add('dark')
        } else {
            document.documentElement.classList.remove('dark')
        }
    }, [theme])

    // Load history on mount
    useEffect(() => {
        fetchHistory()
        fetchRules()
    }, [])

    const fetchHistory = async () => {
        try {
            const res = await fetch(`${API_BASE}/scans`)
            if (!res.ok) throw new Error("Failed to fetch history")
            const data = await res.json()
            if (Array.isArray(data)) {
                setHistory(data)
            } else {
                setHistory([])
            }
        } catch (e) {
            console.error("Fetch history error:", e)
            setHistory([])
        }
    }

    const fetchRules = async () => {
        try {
            const res = await fetch(`${API_BASE}/rules`)
            if (!res.ok) throw new Error("Failed to fetch rules")
            const data = await res.json()
            setRules(Array.isArray(data) ? data : [])
        } catch (e) {
            console.error("Fetch rules error:", e)
        }
    }

    const saveRule = async (ruleData) => {
        try {
            const res = await fetch(`${API_BASE}/rules`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(ruleData)
            })
            if (!res.ok) throw new Error("Failed to save rule")
            setIsCreatingRule(false)
            fetchRules()
        } catch (e) {
            setError("Failed to save rule: " + e.message)
        }
    }

    const deleteRule = async (ruleId) => {
        if (!confirm("Delete this rule?")) return
        try {
            const res = await fetch(`${API_BASE}/rules/${ruleId}`, { method: 'DELETE' })
            if (!res.ok) throw new Error("Failed to delete rule")
            fetchRules()
        } catch (e) {
            setError("Failed to delete rule: " + e.message)
        }
    }

    const startScan = async () => {
        setIsSubmitting(true)
        setError(null)
        try {
            const payload = {
                input_type: inputType,
                target_url: inputType === 'openapi' ? targetUrl : undefined,
                curl_command: inputType === 'curl' ? curlCmd : undefined,
                file_content: (inputType !== 'openapi' && inputType !== 'curl') ? fileContent : undefined,
                auth_type: 'none',
                graphql: graphql,
                ai_provider: aiProvider || undefined,
                ai_key: aiKey || undefined
            }

            const res = await fetch(`${API_BASE}/scan`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            })
            const data = await res.json()
            setScanId(data.scan_id)
            setView('running')
        } catch (e) {
            setError("Failed to start scan: " + e.message)
            // Stay on config view to show error
        } finally {
            setIsSubmitting(false)
        }
    }

    const loadScan = async (id) => {
        setScanId(id)
        setError(null)
        setView('running')
    }

    const downloadReport = () => {
        window.open(`${API_BASE}/scan/${scanId}/report`, '_blank')
    }

    const deleteScan = async (e, id) => {
        e.stopPropagation()
        if (!confirm("Are you sure you want to delete this scan?")) return

        try {
            const res = await fetch(`${API_BASE}/scan/${id}`, { method: 'DELETE' })
            if (!res.ok) throw new Error("Failed to delete")

            // Refresh history
            fetchHistory()

            // If deleting current scan, go back to config
            if (scanId === id) {
                setScanId(null)
                setView('config')
                setResults([])
            }
        } catch (e) {
            console.error("Delete error:", e)
            setError("Failed to delete scan")
        }
    }

    // Polling Effect
    useEffect(() => {
        let interval
        if (view === 'running' && scanId) {
            interval = setInterval(async () => {
                try {
                    const res = await fetch(`${API_BASE}/scan/${scanId}`)
                    const data = await res.json()
                    setStatus(data)

                    if (data.state === 'completed' || data.state === 'failed') {
                        if (data.state === 'completed') {
                            const res2 = await fetch(`${API_BASE}/scan/${scanId}/results`)
                            const data2 = await res2.json()
                            setResults(Array.isArray(data2) ? data2 : [])
                        } else if (data.state === 'failed') {
                            setError(data.message || "Scan failed due to an unknown error.")
                        }
                        setView('results')
                        clearInterval(interval)
                    }
                } catch (e) { console.error(e) }
            }, 1000)
        }
        return () => clearInterval(interval)
    }, [view, scanId])

    return (
        <div className="min-h-screen bg-gray-100 dark:bg-gray-900 p-8 text-gray-800 dark:text-gray-300 transition-colors duration-200">
            <header className="max-w-5xl mx-auto flex items-center justify-between mb-12 border-b border-gray-200 dark:border-cyber-gray pb-6">
                <div className="flex items-center gap-3 cursor-pointer" onClick={() => setView('config')}>
                    <Shield className="w-10 h-10 text-cyber-green" />
                    <h1 className="text-3xl font-bold tracking-tight text-gray-900 dark:text-white">APScan <span className="text-cyber-green text-sm align-top">PRO</span> <span className="text-xs text-gray-500 ml-2">v0.1.0</span></h1>
                </div>
                <div className="flex items-center gap-6">
                    <button onClick={() => { setView('rules'); setIsCreatingRule(false); }} className={`text-sm font-bold hover:text-cyber-green ${view === 'rules' ? 'text-cyber-green' : 'text-gray-500'}`}>
                        Rules Engine
                    </button>
                    <button
                        onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
                        className="text-gray-500 hover:text-cyber-green transition-colors"
                        title="Toggle Theme"
                    >
                        {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
                    </button>
                    <div className="text-sm font-mono text-gray-500 flex gap-4">
                        {view !== 'config' && <button onClick={() => setView('config')} className="hover:text-cyber-green">← Back to Configuration</button>}
                    </div>
                </div>
            </header>

            <main className="max-w-5xl mx-auto">
                {/* Global Error Banner */}
                {error && (
                    <div className="mb-8 p-4 bg-red-900/50 border border-red-500 rounded text-red-200 flex items-start gap-3">
                        <AlertTriangle className="w-6 h-6 flex-shrink-0" />
                        <div>
                            <h3 className="font-bold">System Error</h3>
                            <p>{error}</p>
                        </div>
                        <button onClick={() => setError(null)} className="ml-auto text-red-300 hover:text-white">✕</button>
                    </div>
                )}

                {view === 'rules' && (
                    <div>
                        <div className="flex justify-between items-center mb-6">
                            <h2 className="text-2xl font-bold text-gray-900 dark:text-white flex items-center gap-2">
                                <FileCode className="w-6 h-6 text-cyber-green" /> Custom Rules Strategy
                            </h2>
                            {!isCreatingRule && (
                                <button
                                    onClick={() => setIsCreatingRule(true)}
                                    className="btn-primary flex items-center gap-2"
                                >
                                    <List className="w-4 h-4" /> Create New Rule
                                </button>
                            )}
                        </div>

                        {isCreatingRule ? (
                            <RuleBuilder onSave={saveRule} onCancel={() => setIsCreatingRule(false)} />
                        ) : (
                            <div className="grid grid-cols-1 gap-4">
                                {rules.map(rule => (
                                    <div key={rule.id} className="bg-white dark:bg-black p-4 rounded border border-gray-200 dark:border-cyber-gray hover:border-cyber-green flex justify-between items-start">
                                        <div>
                                            <h3 className="font-bold text-gray-900 dark:text-white mb-1 flex items-center gap-2">
                                                {rule.name}
                                                <span className={`text-[10px] px-2 py-0.5 rounded border ${rule.type === 'YAML' ? 'border-purple-500 text-purple-500' : 'border-blue-500 text-blue-500'}`}>
                                                    {rule.type}
                                                </span>
                                            </h3>
                                            <p className="text-sm text-gray-500">{rule.description}</p>
                                            <span className="text-xs font-mono text-gray-600 dark:text-gray-400 mt-2 block">ID: {rule.id}</span>
                                        </div>
                                        {rule.type === 'YAML' && (
                                            <button onClick={() => deleteRule(rule.id)} className="text-red-500 hover:text-red-300 p-2">
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        )}
                                    </div>
                                ))}
                                {rules.length === 0 && <p className="text-gray-500 italic">No custom rules defined.</p>}
                            </div>
                        )}
                    </div>
                )}

                {view === 'config' && (
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                        <div className="lg:col-span-2">
                            <div className="card">
                                <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6 flex items-center gap-2">
                                    <Terminal className="w-5 h-5 text-cyber-green" /> Configure Scan Target
                                </h2>

                                <div className="flex gap-4 mb-6 border-b border-cyber-gray pb-1">
                                    {['openapi', 'curl', 'har', 'postman', 'list', 'workflow'].map(t => (
                                        <button
                                            key={t}
                                            onClick={() => setInputType(t)}
                                            className={`pb-2 px-1 capitalize transition-colors ${inputType === t ? 'text-cyber-green border-b-2 border-cyber-green font-bold' : 'text-gray-500 hover:text-white'}`}
                                        >
                                            {t}
                                        </button>
                                    ))}
                                </div>

                                <div className="space-y-6">
                                    {inputType === 'openapi' && (
                                        <div>
                                            <label className="block text-sm font-medium mb-2">OpenAPI Spec URL</label>
                                            <input
                                                className="input-field"
                                                placeholder="http://domain.com/openapi.json"
                                                value={targetUrl}
                                                onChange={(e) => setTargetUrl(e.target.value)}
                                            />
                                        </div>
                                    )}

                                    {inputType === 'curl' && (
                                        <div>
                                            <label className="block text-sm font-medium mb-2">cURL Command</label>
                                            <textarea
                                                className="input-field h-32 font-mono text-sm"
                                                placeholder="curl -X POST http://..."
                                                value={curlCmd}
                                                onChange={(e) => setCurlCmd(e.target.value)}
                                            />
                                        </div>
                                    )}

                                    {['har', 'list', 'postman', 'workflow'].includes(inputType) && (
                                        <div>
                                            <div className="flex items-center justify-between mb-2">
                                                <label className="block text-sm font-medium">
                                                    {inputType === 'workflow' ? 'Workflow Definition' : 'Paste File Content (Simulated Upload)'}
                                                </label>
                                                {inputType === 'workflow' && (
                                                    <button
                                                        onClick={() => setUseBuilder(!useBuilder)}
                                                        className="text-xs text-cyber-green hover:underline flex items-center gap-1"
                                                    >
                                                        {useBuilder ? <><FileCode className="w-3 h-3" /> Switch to Code View</> : <><List className="w-3 h-3" /> Open Visual Builder</>}
                                                    </button>
                                                )}
                                            </div>

                                            {inputType === 'workflow' && useBuilder ? (
                                                <div className="h-96">
                                                    <WorkflowBuilder
                                                        initialYaml={fileContent}
                                                        onChange={(newYaml) => setFileContent(newYaml)}
                                                    />
                                                </div>
                                            ) : (
                                                <textarea
                                                    className="input-field h-64 font-mono text-sm"
                                                    placeholder={inputType === 'workflow' ? 'name: My Flow\nsteps:\n  - ...' : `Paste contents of your .${inputType === 'list' ? 'txt' : 'json'} file here...`}
                                                    value={fileContent}
                                                    onChange={(e) => setFileContent(e.target.value)}
                                                />
                                            )}
                                        </div>
                                    )}

                                    {/* Advanced Options */}
                                    <div className="border-t border-cyber-gray pt-6 mt-6">
                                        <h3 className="text-sm font-bold text-cyber-green uppercase mb-4">Advanced Configuration</h3>

                                        <div className="flex items-center gap-4 mb-4">
                                            <label className="flex items-center gap-2 cursor-pointer">
                                                <input
                                                    type="checkbox"
                                                    checked={graphql}
                                                    onChange={(e) => setGraphql(e.target.checked)}
                                                    className="w-4 h-4 rounded border-gray-600 bg-gray-700 text-cyber-green focus:ring-cyber-green"
                                                />
                                                <span className="text-gray-700 dark:text-white text-sm">Enable GraphQL Introspection</span>
                                            </label>
                                        </div>

                                        <div className="grid grid-cols-2 gap-4">
                                            <div>
                                                <label className="block text-sm font-medium mb-2">AI Triage Provider</label>
                                                <select
                                                    value={aiProvider}
                                                    onChange={(e) => setAiProvider(e.target.value)}
                                                    className="input-field"
                                                >
                                                    <option value="">None (Disabled)</option>
                                                    <option value="gemini">Google Gemini</option>
                                                    <option value="openai">OpenAI (GPT-4)</option>
                                                    <option value="local">Local LLM / Ollama</option>
                                                    <option value="mock">Mock Provider (Test)</option>
                                                </select>
                                            </div>
                                            {aiProvider && (
                                                <div>
                                                    <label className="block text-sm font-medium mb-2">API Key</label>
                                                    <input
                                                        type="password"
                                                        className="input-field"
                                                        placeholder="sk-..."
                                                        value={aiKey}
                                                        onChange={(e) => setAiKey(e.target.value)}
                                                    />
                                                </div>
                                            )}
                                        </div>
                                    </div>

                                    <button
                                        onClick={startScan}
                                        disabled={isSubmitting}
                                        className="btn-primary w-full flex items-center justify-center gap-2 mt-6"
                                    >
                                        {isSubmitting ? <Loader2 className="animate-spin" /> : <Play className="w-5 h-5" />}
                                        Initiate Scan Sequence
                                    </button>
                                </div>
                            </div>
                        </div>

                        <div className="hidden lg:block">
                            <div className="card h-full">
                                <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                                    <FileJson className="w-5 h-5 text-gray-400" /> Recent Scans
                                </h2>
                                <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2">
                                    {Array.isArray(history) && history.map(scan => (
                                        <div
                                            key={scan.id}
                                            onClick={() => loadScan(scan.id)}
                                            className="p-3 rounded border border-gray-200 dark:border-cyber-gray hover:border-cyber-green bg-white dark:bg-black cursor-pointer transition-all relative group"
                                        >
                                            <div className="flex justify-between items-start mb-1">
                                                <span className={`text-xs font-bold uppercase ${scan.state === 'completed' ? 'text-green-500' : 'text-yellow-500'}`}>{scan.state}</span>
                                                <span className="text-xs text-gray-500 font-mono">{scan.id ? scan.id.slice(0, 6) : '???'}</span>
                                            </div>
                                            <div className="text-sm text-gray-600 dark:text-gray-300">
                                                {scan.findings_count || 0} findings
                                            </div>
                                            <button
                                                onClick={(e) => deleteScan(e, scan.id)}
                                                className="absolute top-2 right-2 p-1 text-gray-500 hover:text-red-500 opacity-0 group-hover:opacity-100 transition-opacity"
                                                title="Delete Scan"
                                            >
                                                <Trash2 className="w-4 h-4" />
                                            </button>
                                        </div>
                                    ))}
                                    {(!Array.isArray(history) || history.length === 0) && <div className="text-gray-500 text-sm italic">No history yet.</div>}
                                </div>
                            </div>
                        </div>
                    </div>
                )}

                {view === 'running' && (
                    <div className="card max-w-xl mx-auto text-center py-16">
                        <Loader2 className="w-16 h-16 text-cyber-green animate-spin mx-auto mb-6" />
                        <h2 className="text-2xl font-bold text-gray-900 dark:text-white mb-2">Scanning in Progress...</h2>
                        <p className="text-gray-500 mb-8 font-mono">{status ? status.message : "Initializing assets..."}</p>

                        <div className="flex justify-center gap-8 text-sm">
                            <div className="bg-white dark:bg-black p-4 rounded border border-gray-200 dark:border-cyber-gray min-w-[120px]">
                                <div className="font-bold text-2xl text-gray-900 dark:text-white mb-1">{status?.endpoints_count || 0}</div>
                                <div className="text-gray-500">Endpoints</div>
                            </div>
                            <div className="bg-white dark:bg-black p-4 rounded border border-gray-200 dark:border-cyber-gray min-w-[120px]">
                                <div className="font-bold text-2xl text-cyber-green mb-1">{status ? 'Active' : '-'}</div>
                                <div className="text-gray-500">Status</div>
                            </div>
                        </div>
                    </div>
                )}

                {view === 'results' && (
                    <div className="space-y-6">
                        <div className="flex items-center justify-between">
                            <h2 className="text-2xl font-bold text-gray-900 dark:text-white">Scan Results</h2>
                            <div className="flex gap-4">
                                <button onClick={downloadReport} className="text-sm flex items-center gap-2 text-cyber-green hover:underline">
                                    <Download className="w-4 h-4" /> Download Report
                                </button>
                                <button onClick={() => { setView('config'); fetchHistory(); setError(null); }} className="text-sm text-cyber-green hover:underline">New Scan</button>
                            </div>
                        </div>

                        {/* Summary Cards */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                            <div className="card border-l-4 border-red-500">
                                <div className="text-3xl font-bold text-gray-900 dark:text-white">{results.filter(r => r.severity === 'HIGH' || r.severity === 'CRITICAL').length}</div>
                                <div className="text-gray-400">Critical / High</div>
                            </div>
                            <div className="card border-l-4 border-yellow-500">
                                <div className="text-3xl font-bold text-gray-900 dark:text-white">{results.filter(r => r.severity === 'MEDIUM').length}</div>
                                <div className="text-gray-400">Medium</div>
                            </div>
                            <div className="card border-l-4 border-blue-500">
                                <div className="text-3xl font-bold text-gray-900 dark:text-white">{results.filter(r => r.severity === 'LOW').length}</div>
                                <div className="text-gray-400">Low / Info</div>
                            </div>
                        </div>

                        {/* Findings List */}
                        <div className="card">
                            <h3 className="text-lg font-bold text-gray-900 dark:text-white mb-4">Vulnerability Feed</h3>
                            {results.length === 0 ? (
                                <div className="p-8 text-center text-gray-500 flex flex-col items-center">
                                    <CheckCircle className="w-12 h-12 text-green-500 mb-4" />
                                    <p>No vulnerabilities found. System secure.</p>
                                </div>
                            ) : (
                                <div className="space-y-4">
                                    {results.map((r, idx) => (
                                        <div key={idx} className="bg-white dark:bg-black border border-gray-200 dark:border-cyber-gray p-4 rounded hover:border-cyber-green transition-colors cursor-pointer group shadow-sm">
                                            <div className="flex items-center justify-between mb-2">
                                                <div className="flex items-center gap-3">
                                                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${r.severity === 'HIGH' ? 'bg-red-900 text-red-200' :
                                                        r.severity === 'MEDIUM' ? 'bg-yellow-900 text-yellow-200' : 'bg-blue-900 text-blue-200'
                                                        }`}>
                                                        {r.severity}
                                                    </span>
                                                    <h4 className="font-bold text-gray-900 dark:text-white group-hover:text-cyber-green">{r.name}</h4>
                                                </div>
                                                <span className="font-mono text-xs text-gray-500">{r.rule_id}</span>
                                            </div>
                                            <p className="text-sm text-gray-400 mb-2">{r.description}</p>
                                            <div className="text-xs font-mono bg-gray-100 dark:bg-cyber-dark p-2 rounded flex gap-2 mb-2">
                                                <span className="text-purple-400">{r.method}</span>
                                                <span className="text-gray-300">{r.endpoint}</span>
                                            </div>

                                            {/* Details Section */}
                                            <div className="mt-4 border-t border-gray-800 pt-2 text-xs">
                                                <div className="mb-2">
                                                    <span className="font-bold text-gray-500 block mb-1">REMEDIATION:</span>
                                                    <p className="text-gray-600 dark:text-gray-300">{r.recommendation || "No recommendation provided."}</p>
                                                </div>

                                                {r.reproduce_curl && (
                                                    <div className="mt-2">
                                                        <span className="font-bold text-gray-500 block mb-1">REPRODUCE (cURL):</span>
                                                        <code className="block bg-gray-900 p-2 rounded text-green-400 font-mono overflow-x-auto whitespace-pre-wrap">
                                                            {r.reproduce_curl}
                                                        </code>
                                                    </div>
                                                )}
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    </div>
                )}
            </main>
        </div>
    )
}

export default App

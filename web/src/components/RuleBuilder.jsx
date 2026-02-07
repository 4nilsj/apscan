import { useState } from 'react';
import { Plus, Trash, Check, AlertTriangle } from 'lucide-react';

export default function RuleBuilder({ onSave, onCancel }) {
    const [rule, setRule] = useState({
        name: 'My Custom Rule',
        description: 'Detects specific patterns in responses.',
        severity: 'MEDIUM',
        request: {
            path: '/api/.*',
            method: 'GET'
        },
        match: {
            status: 200,
            body: '',
            body_regex: '',
            headers: {}
        }
    });

    const [headerKey, setHeaderKey] = useState('');
    const [headerValue, setHeaderValue] = useState('');

    const addHeader = () => {
        if (!headerKey) return;
        setRule(prev => ({
            ...prev,
            match: {
                ...prev.match,
                headers: { ...prev.match.headers, [headerKey]: headerValue }
            }
        }));
        setHeaderKey('');
        setHeaderValue('');
    };

    const removeHeader = (key) => {
        setRule(prev => {
            const newHeaders = { ...prev.match.headers };
            delete newHeaders[key];
            return {
                ...prev,
                match: { ...prev.match, headers: newHeaders }
            };
        });
    };

    const handleSave = () => {
        // Basic Validation
        if (!rule.name) {
            alert("Rule name is required.");
            return;
        }
        onSave(rule);
    };

    return (
        <div className="bg-white dark:bg-gray-800 border border-gray-200 dark:border-gray-700 rounded-lg p-6 shadow-sm">
            <h2 className="text-xl font-bold text-gray-900 dark:text-white mb-6">Create Custom Rule</h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                <div>
                    <label className="block text-sm font-medium mb-1">Rule Name</label>
                    <input
                        className="input-field w-full"
                        value={rule.name}
                        onChange={e => setRule({ ...rule, name: e.target.value })}
                        placeholder="e.g. Detect API Key Leaks"
                    />
                </div>
                <div>
                    <label className="block text-sm font-medium mb-1">Severity</label>
                    <select
                        className="input-field w-full"
                        value={rule.severity}
                        onChange={e => setRule({ ...rule, severity: e.target.value })}
                    >
                        <option value="CRITICAL">Critical</option>
                        <option value="HIGH">High</option>
                        <option value="MEDIUM">Medium</option>
                        <option value="LOW">Low</option>
                        <option value="INFO">Info</option>
                    </select>
                </div>
            </div>

            <div className="mb-6">
                <label className="block text-sm font-medium mb-1">Description</label>
                <textarea
                    className="input-field w-full h-20"
                    value={rule.description}
                    onChange={e => setRule({ ...rule, description: e.target.value })}
                    placeholder="Describe what this rule detects..."
                />
            </div>

            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 mb-6">
                <h3 className="font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                    <span className="bg-blue-100 text-blue-800 text-xs px-2 py-0.5 rounded-full">Target</span>
                    Where to run?
                </h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div>
                        <label className="block text-xs text-gray-500 mb-1">Method</label>
                        <select
                            className="input-field w-full text-sm"
                            value={rule.request.method}
                            onChange={e => setRule({ ...rule, request: { ...rule.request, method: e.target.value } })}
                        >
                            <option value="GET">GET</option>
                            <option value="POST">POST</option>
                            <option value="PUT">PUT</option>
                            <option value="DELETE">DELETE</option>
                            <option value="PATCH">PATCH</option>
                            <option value="HEAD">HEAD</option>
                            <option value="OPTIONS">OPTIONS</option>
                        </select>
                    </div>
                    <div className="md:col-span-2">
                        <label className="block text-xs text-gray-500 mb-1">Path Pattern (Regex)</label>
                        <input
                            className="input-field w-full text-sm font-mono text-blue-600 dark:text-blue-400"
                            value={rule.request.path}
                            onChange={e => setRule({ ...rule, request: { ...rule.request, path: e.target.value } })}
                            placeholder="/api/.*"
                        />
                    </div>
                </div>
            </div>

            <div className="border-t border-gray-200 dark:border-gray-700 pt-6 mb-6">
                <h3 className="font-bold text-gray-900 dark:text-white mb-4 flex items-center gap-2">
                    <span className="bg-purple-100 text-purple-800 text-xs px-2 py-0.5 rounded-full">Logic</span>
                    Match Conditions (AND)
                </h3>

                <div className="space-y-4">
                    <div className="flex items-center gap-4">
                        <div className="w-1/3">
                            <label className="block text-xs text-gray-500 mb-1">Status Code</label>
                            <input
                                type="number"
                                className="input-field w-full text-sm"
                                value={rule.match.status || ''}
                                onChange={e => setRule({ ...rule, match: { ...rule.match, status: parseInt(e.target.value) || '' } })}
                                placeholder="200"
                            />
                        </div>
                        <div className="flex-1">
                            <label className="block text-xs text-gray-500 mb-1">Body Contains (Text)</label>
                            <input
                                className="input-field w-full text-sm"
                                value={rule.match.body || ''}
                                onChange={e => setRule({ ...rule, match: { ...rule.match, body: e.target.value } })}
                                placeholder="error"
                            />
                        </div>
                    </div>

                    <div>
                        <label className="block text-xs text-gray-500 mb-1">Body Regex (Advanced)</label>
                        <input
                            className="input-field w-full text-sm font-mono text-purple-600 dark:text-purple-400"
                            value={rule.match.body_regex || ''}
                            onChange={e => setRule({ ...rule, match: { ...rule.match, body_regex: e.target.value } })}
                            placeholder="(?i)password = ['\"]...['\"]"
                        />
                    </div>

                    <div className="bg-gray-50 dark:bg-gray-900/50 p-4 rounded border border-gray-200 dark:border-gray-700">
                        <label className="block text-xs text-gray-500 mb-2">Response Headers</label>

                        {Object.entries(rule.match.headers || {}).map(([key, val]) => (
                            <div key={key} className="flex items-center gap-2 mb-2 text-sm">
                                <span className="font-mono bg-gray-200 dark:bg-gray-700 px-2 py-0.5 rounded">{key}</span>
                                <span className="text-gray-400">=</span>
                                <span className="font-mono text-green-600 dark:text-green-400 truncate max-w-xs">{val || '*'}</span>
                                <button onClick={() => removeHeader(key)} className="text-red-500 hover:text-red-700 ml-auto"><Trash className="w-4 h-4" /></button>
                            </div>
                        ))}

                        <div className="flex gap-2 mt-2">
                            <input
                                className="input-field text-sm flex-1"
                                placeholder="Header Name (e.g. X-Content-Type-Options)"
                                value={headerKey}
                                onChange={e => setHeaderKey(e.target.value)}
                            />
                            <input
                                className="input-field text-sm flex-1"
                                placeholder="Value (Optional)"
                                value={headerValue}
                                onChange={e => setHeaderValue(e.target.value)}
                            />
                            <button onClick={addHeader} className="btn-secondary py-1 px-3"><Plus className="w-4 h-4" /></button>
                        </div>
                    </div>
                </div>
            </div>

            <div className="flex justify-end gap-3 mt-8">
                <button
                    onClick={onCancel}
                    className="px-4 py-2 text-gray-600 hover:text-gray-900 dark:text-gray-400 dark:hover:text-white transition-colors"
                >
                    Cancel
                </button>
                <button
                    onClick={handleSave}
                    className="btn-primary flex items-center gap-2"
                >
                    <Check className="w-4 h-4" /> Save Rule
                </button>
            </div>
        </div>
    );
}

import { useState, useEffect } from 'react';
import yaml from 'js-yaml';
import { Plus, Trash, ArrowDown, Code, Settings, List } from 'lucide-react';

export default function WorkflowBuilder({ initialYaml, onChange }) {
    const [workflow, setWorkflow] = useState({
        name: 'My Custom Workflow',
        steps: []
    });
    const [activeTab, setActiveTab] = useState('visual'); // visual | yaml
    const [yamlError, setYamlError] = useState(null);

    // Initialize from prop
    useEffect(() => {
        if (initialYaml) {
            try {
                const parsed = yaml.load(initialYaml);
                if (parsed && typeof parsed === 'object') {
                    setWorkflow(prev => ({ ...prev, ...parsed }));
                }
            } catch (e) {
                console.error("Failed to parse initial YAML", e);
            }
        }
    }, []); // Only on mount

    // Sync to parent whenever workflow changes
    useEffect(() => {
        try {
            const yamlStr = yaml.dump(workflow);
            onChange(yamlStr);
            setYamlError(null);
        } catch (e) {
            console.error("YAML Dump Error", e);
        }
    }, [workflow, onChange]);

    const addStep = (type) => {
        const newStep = {
            id: `step_${workflow.steps.length + 1}`,
            name: `New ${type} Step`,
            action: type,
            params: {},
            extract: []
        };

        if (type === 'http_request') {
            newStep.method = 'GET';
            newStep.url = 'http://example.com';
        }

        setWorkflow(prev => ({
            ...prev,
            steps: [...prev.steps, newStep]
        }));
    };

    const removeStep = (index) => {
        setWorkflow(prev => ({
            ...prev,
            steps: prev.steps.filter((_, i) => i !== index)
        }));
    };

    const updateStep = (index, field, value) => {
        setWorkflow(prev => {
            const newSteps = [...prev.steps];
            newSteps[index] = { ...newSteps[index], [field]: value };
            return { ...prev, steps: newSteps };
        });
    };

    const addExtraction = (stepIndex) => {
        setWorkflow(prev => {
            const newSteps = [...prev.steps];
            const step = newSteps[stepIndex];
            const newExtract = [...(step.extract || []), { source: 'body', key: '', variable: '' }];
            newSteps[stepIndex] = { ...step, extract: newExtract };
            return { ...prev, steps: newSteps };
        });
    };

    const updateExtraction = (stepIndex, extIndex, field, value) => {
        setWorkflow(prev => {
            const newSteps = [...prev.steps];
            const step = newSteps[stepIndex];
            const newExtract = [...(step.extract || [])];
            newExtract[extIndex] = { ...newExtract[extIndex], [field]: value };
            newSteps[stepIndex] = { ...step, extract: newExtract };
            return { ...prev, steps: newSteps };
        });
    }

    const removeExtraction = (stepIndex, extIndex) => {
        setWorkflow(prev => {
            const newSteps = [...prev.steps];
            const step = newSteps[stepIndex];
            newSteps[stepIndex] = { ...step, extract: step.extract.filter((_, i) => i !== extIndex) };
            return { ...prev, steps: newSteps };
        });
    }

    return (
        <div className="bg-gray-900 border border-cyber-gray rounded-lg overflow-hidden flex flex-col h-full">
            {/* Toolbar */}
            <div className="bg-black p-3 border-b border-cyber-gray flex justify-between items-center">
                <div className="flex gap-2">
                    <button
                        onClick={() => setActiveTab('visual')}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm ${activeTab === 'visual' ? 'bg-cyber-green text-black font-bold' : 'text-gray-400 hover:text-white'}`}
                    >
                        <List className="w-4 h-4" /> Visual Builder
                    </button>
                    {/* Add Code View toggle later if needed, mostly App handles raw input, but mixed mode is useful */}
                </div>
                <div className="flex items-center gap-2">
                    <input
                        className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-sm text-white focus:border-cyber-green outline-none"
                        value={workflow.name}
                        onChange={(e) => setWorkflow({ ...workflow, name: e.target.value })}
                        placeholder="Workflow Name"
                    />
                </div>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
                {activeTab === 'visual' && (
                    <>
                        {workflow.steps.length === 0 && (
                            <div className="text-center py-12 text-gray-500 border-2 border-dashed border-gray-800 rounded-lg">
                                <p className="mb-4">No steps defined yet.</p>
                                <button onClick={() => addStep('http_request')} className="btn-secondary text-xs">Add First Step</button>
                            </div>
                        )}

                        {workflow.steps.map((step, idx) => (
                            <div key={idx} className="bg-black border border-cyber-gray rounded-lg p-4 relative group hover:border-gray-500 transition-colors">
                                <div className="absolute top-2 right-2 opacity-0 group-hover:opacity-100 transition-opacity">
                                    <button onClick={() => removeStep(idx)} className="text-red-500 hover:text-red-400 p-1"><Trash className="w-4 h-4" /></button>
                                </div>

                                <div className="flex items-center gap-3 mb-4">
                                    <div className="bg-gray-800 text-gray-400 w-6 h-6 rounded-full flex items-center justify-center text-xs font-mono">{idx + 1}</div>
                                    <h3 className="text-white font-bold text-sm tracking-wide">{step.name || 'Unnamed Step'}</h3>
                                    <span className="text-xs bg-gray-800 px-2 py-0.5 rounded text-gray-400 uppercase">{step.action || 'http_request'}</span>
                                </div>

                                {/* Common Fields */}
                                <div className="grid grid-cols-2 gap-4 mb-4">
                                    <div>
                                        <label className="text-xs text-gray-500 block mb-1">Step Name</label>
                                        <input
                                            className="input-field py-1 text-sm"
                                            value={step.name || ''}
                                            onChange={(e) => updateStep(idx, 'name', e.target.value)}
                                        />
                                    </div>
                                    {step.action === 'http_request' && (
                                        <div>
                                            <label className="text-xs text-gray-500 block mb-1">Method</label>
                                            <select
                                                className="input-field py-1 text-sm"
                                                value={step.method || 'GET'}
                                                onChange={(e) => updateStep(idx, 'method', e.target.value)}
                                            >
                                                {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => <option key={m}>{m}</option>)}
                                            </select>
                                        </div>
                                    )}
                                </div>

                                {step.action === 'http_request' && (
                                    <>
                                        <div className="mb-4">
                                            <label className="text-xs text-gray-500 block mb-1">URL (Supports {'${var}'})</label>
                                            <input
                                                className="input-field py-1 text-sm font-mono text-green-400"
                                                value={step.path || ''}
                                                onChange={(e) => updateStep(idx, 'path', e.target.value)}
                                                placeholder="/api/login"
                                            />
                                        </div>

                                        {['POST', 'PUT', 'PATCH'].includes(step.method) && (
                                            <div className="mb-4">
                                                <label className="text-xs text-gray-500 block mb-1">JSON Body</label>
                                                <textarea
                                                    className="input-field py-1 text-xs font-mono h-20"
                                                    value={typeof step.body === 'object' ? JSON.stringify(step.body, null, 2) : step.body || ''}
                                                    onChange={(e) => {
                                                        try {
                                                            // If valid JSON, parse it, otherwise keep string
                                                            // For UX, simple string is easier unless we want structured editor
                                                            // Here we just store as is or try to parse if valid
                                                            // Actually, let's just treat as string/object freely or use YAML?
                                                            // For now string is safer for input
                                                            updateStep(idx, 'body', e.target.value)
                                                        } catch (e) { }
                                                    }}
                                                    placeholder='{ "username": "..." }'
                                                />
                                            </div>
                                        )}

                                        {/* Extractions */}
                                        <div className="bg-gray-900 rounded p-3 border border-gray-800">
                                            <div className="flex justify-between items-center mb-2">
                                                <span className="text-xs font-bold text-gray-400">Variable Extraction</span>
                                                <button onClick={() => addExtraction(idx)} className="text-xs text-cyber-green hover:underline flex items-center gap-1"><Plus className="w-3 h-3" /> Add</button>
                                            </div>
                                            {(step.extract || []).map((ext, eIdx) => (
                                                <div key={eIdx} className="grid grid-cols-7 gap-2 items-center mb-2">
                                                    <select
                                                        className="input-field py-0.5 text-xs col-span-2"
                                                        value={ext.source || 'body'}
                                                        onChange={(e) => updateExtraction(idx, eIdx, 'source', e.target.value)}
                                                    >
                                                        <option value="body">Body (JSON)</option>
                                                        <option value="header">Header</option>
                                                    </select>
                                                    <input
                                                        className="input-field py-0.5 text-xs col-span-2"
                                                        placeholder="Key (e.g. token)"
                                                        value={ext.key || ''}
                                                        onChange={(e) => updateExtraction(idx, eIdx, 'key', e.target.value)}
                                                    />
                                                    <span className="text-center text-gray-600">→</span>
                                                    <input
                                                        className="input-field py-0.5 text-xs col-span-2 text-yellow-400"
                                                        placeholder="Var Name"
                                                        value={ext.variable || ''}
                                                        onChange={(e) => updateExtraction(idx, eIdx, 'variable', e.target.value)}
                                                    />
                                                    <button onClick={() => removeExtraction(idx, eIdx)} className="text-red-500 hover:text-red-300 ml-auto"><Trash className="w-3 h-3" /></button>
                                                </div>
                                            ))}
                                            {(step.extract || []).length === 0 && <div className="text-xs text-gray-600 italic">No variables extracted.</div>}
                                        </div>
                                    </>
                                )}
                            </div>
                        ))}

                        <div className="flex justify-center pt-4 pb-12">
                            <button
                                onClick={() => addStep('http_request')}
                                className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-full border border-gray-600 transition-all text-sm"
                            >
                                <Plus className="w-4 h-4" /> Add Next Step
                            </button>
                        </div>
                    </>
                )}
            </div>
        </div>
    );
}

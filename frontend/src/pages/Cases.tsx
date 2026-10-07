import { useState } from 'react'

export default function Cases() {
  const [title, setTitle] = useState('')
  const [description, setDescription] = useState('')
  const [created, setCreated] = useState(null as any)
  const [file, setFile] = useState<File | null>(null)
  const [caseId, setCaseId] = useState('')
  const [analysis, setAnalysis] = useState<any>(null)

  const createCase = async (e: React.FormEvent) => {
    e.preventDefault()
    const res = await fetch('/api/v1/cases/', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title, description }),
    })
    const data = await res.json()
    setCreated(data)
    setCaseId(data.id)
  }

  const upload = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!file || !caseId) return alert('Select a file and case ID')
    const fd = new FormData()
    fd.append('file', file)
    fd.append('case_id', caseId)
    const res = await fetch('/api/v1/evidence/upload', { method: 'POST', body: fd })
    const data = await res.json()
    setAnalysis(data)
  }

  return (
    <div className="cases-page">
      <section>
        <h2>Create New Case</h2>
        <form onSubmit={createCase}>
          <label>
            Title
            <input value={title} onChange={(e) => setTitle(e.target.value)} />
          </label>
          <label>
            Description
            <input value={description} onChange={(e) => setDescription(e.target.value)} />
          </label>
          <button type="submit">Create Case</button>
        </form>
        {created && (
          <div className="created">
            <strong>Created:</strong> {created.title} (ID: {created.id})
          </div>
        )}
      </section>

      <section>
        <h2>Import Evidence</h2>
        <form onSubmit={upload}>
          <label>
            Case ID
            <input value={caseId} onChange={(e) => setCaseId(e.target.value)} />
          </label>
          <label>
            File
            <input type="file" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
          </label>
          <button type="submit">Upload & Analyze</button>
        </form>

        {analysis && (
          <div className="analysis-result">
            <h3>Analysis</h3>
            <pre>{JSON.stringify(analysis, null, 2)}</pre>
          </div>
        )}
      </section>
    </div>
  )
}

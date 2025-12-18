import { useState, useEffect } from 'react'
import './AgentsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || (window.location.hostname === 'localhost' ? 'http://localhost:8000' : '/api')

function AgentsPage() {
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)
  const [total, setTotal] = useState(0)
  const [searchQuery, setSearchQuery] = useState('')

  useEffect(() => {
    fetchAgents()
  }, [page, searchQuery])

  const fetchAgents = async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
      })
      if (searchQuery) {
        params.append('q', searchQuery)
      }

      const response = await fetch(`${API_BASE}/agents?${params}`)
      if (!response.ok) {
        throw new Error('Failed to fetch agents')
      }
      const data = await response.json()
      setAgents(data.items || [])
      setTotal(data.total || 0)
      setError(null)
    } catch (err) {
      setError(err.message)
      setAgents([])
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A'
    return new Date(dateString).toLocaleString()
  }

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div className="agents-page">
      <div className="page-header">
        <h2>Agents</h2>
        <p className="page-subtitle">
          Monitor and track all registered AI agents
        </p>
      </div>

      <div className="search-bar">
        <input
          type="text"
          placeholder="Search agents by ID..."
          value={searchQuery}
          onChange={(e) => {
            setSearchQuery(e.target.value)
            setPage(1)
          }}
          className="search-input"
        />
      </div>

      {error && <div className="error-message">Error: {error}</div>}

      {loading ? (
        <div className="loading">Loading agents...</div>
      ) : agents.length === 0 ? (
        <div className="empty-state">
          <p>No agents found</p>
        </div>
      ) : (
        <>
          <div className="agents-grid">
            {agents.map((agent) => (
              <div key={agent.agent_id} className="agent-card">
                <div className="agent-card-header">
                  <h3 className="agent-id">{agent.agent_id}</h3>
                  <span className="status-badge status-new">Active</span>
                </div>
                <div className="agent-card-body">
                  <div className="info-row">
                    <span className="info-label">Created:</span>
                    <span className="info-value">
                      {formatDate(agent.created_time)}
                    </span>
                  </div>
                  <div className="info-row">
                    <span className="info-label">Last Updated:</span>
                    <span className="info-value">
                      {formatDate(agent.updated_time)}
                    </span>
                  </div>
                  {agent.last_action_type && (
                    <div className="info-row">
                      <span className="info-label">Last Action:</span>
                      <span className="info-value action-type">
                        {agent.last_action_type}
                      </span>
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          {totalPages > 1 && (
            <div className="pagination">
              <button
                onClick={() => setPage((p) => Math.max(1, p - 1))}
                disabled={page === 1}
                className="pagination-btn"
              >
                Previous
              </button>
              <span className="pagination-info">
                Page {page} of {totalPages} ({total} total)
              </span>
              <button
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
                disabled={page === totalPages}
                className="pagination-btn"
              >
                Next
              </button>
            </div>
          )}
        </>
      )}
    </div>
  )
}

export default AgentsPage


import { useState, useEffect } from 'react'
import './ActionsPage.css'

const API_BASE = import.meta.env.VITE_API_URL || (window.location.hostname === 'localhost' ? 'http://localhost:8000' : '/api')

function ActionsPage() {
  const [actions, setActions] = useState([])
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [page, setPage] = useState(1)
  const [pageSize] = useState(20)
  const [total, setTotal] = useState(0)

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedAgent, setSelectedAgent] = useState('')
  const [selectedStatus, setSelectedStatus] = useState('')
  const [selectedActionType, setSelectedActionType] = useState('')

  useEffect(() => {
    fetchAgents()
  }, [])

  useEffect(() => {
    fetchActions()
  }, [page, searchQuery, selectedAgent, selectedStatus, selectedActionType])

  const fetchAgents = async () => {
    try {
      const response = await fetch(`${API_BASE}/agents?page_size=100`)
      if (response.ok) {
        const data = await response.json()
        setAgents(data.items || [])
      }
    } catch (err) {
      console.error('Failed to fetch agents:', err)
    }
  }

  const fetchActions = async () => {
    try {
      setLoading(true)
      const params = new URLSearchParams({
        page: page.toString(),
        page_size: pageSize.toString(),
      })
      if (searchQuery) params.append('q', searchQuery)
      if (selectedAgent) params.append('agent_id', selectedAgent)
      if (selectedStatus) params.append('status', selectedStatus)
      if (selectedActionType) params.append('action_type', selectedActionType)

      const response = await fetch(`${API_BASE}/actions?${params}`)
      if (!response.ok) {
        throw new Error('Failed to fetch actions')
      }
      const data = await response.json()
      setActions(data.items || [])
      setTotal(data.total || 0)
      setError(null)
    } catch (err) {
      setError(err.message)
      setActions([])
    } finally {
      setLoading(false)
    }
  }

  const formatDate = (dateString) => {
    if (!dateString) return 'N/A'
    return new Date(dateString).toLocaleString()
  }

  const formatActionDetails = (details) => {
    if (!details) return 'N/A'
    const parts = []
    if (details.command) parts.push(`Command: ${details.command}`)
    if (details.file_path) parts.push(`File: ${details.file_path}`)
    if (details.url) parts.push(`URL: ${details.url}`)
    if (details.method) parts.push(`Method: ${details.method}`)
    return parts.length > 0 ? parts.join(' | ') : 'No details'
  }

  const totalPages = Math.ceil(total / pageSize)

  const resetFilters = () => {
    setSearchQuery('')
    setSelectedAgent('')
    setSelectedStatus('')
    setSelectedActionType('')
    setPage(1)
  }

  return (
    <div className="actions-page">
      <div className="page-header">
        <h2>Actions</h2>
        <p className="page-subtitle">
          Monitor all agent actions and filter by various attributes
        </p>
      </div>

      <div className="filters-section">
        <div className="filters-grid">
          <div className="filter-group">
            <label className="filter-label">Search</label>
            <input
              type="text"
              placeholder="Search actions..."
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value)
                setPage(1)
              }}
              className="filter-input"
            />
          </div>

          <div className="filter-group">
            <label className="filter-label">Agent</label>
            <select
              value={selectedAgent}
              onChange={(e) => {
                setSelectedAgent(e.target.value)
                setPage(1)
              }}
              className="filter-select"
            >
              <option value="">All Agents</option>
              {agents.map((agent) => (
                <option key={agent.agent_id} value={agent.agent_id}>
                  {agent.agent_id}
                </option>
              ))}
            </select>
          </div>

          <div className="filter-group">
            <label className="filter-label">Status</label>
            <select
              value={selectedStatus}
              onChange={(e) => {
                setSelectedStatus(e.target.value)
                setPage(1)
              }}
              className="filter-select"
            >
              <option value="">All Statuses</option>
              <option value="NEW">NEW</option>
            </select>
          </div>

          <div className="filter-group">
            <label className="filter-label">Action Type</label>
            <select
              value={selectedActionType}
              onChange={(e) => {
                setSelectedActionType(e.target.value)
                setPage(1)
              }}
              className="filter-select"
            >
              <option value="">All Types</option>
              <option value="command_execution">Command Execution</option>
              <option value="file_operation">File Operation</option>
              <option value="api_call">API Call</option>
              <option value="other">Other</option>
            </select>
          </div>
        </div>

        {(searchQuery || selectedAgent || selectedStatus || selectedActionType) && (
          <button onClick={resetFilters} className="reset-filters-btn">
            Reset Filters
          </button>
        )}
      </div>

      {error && <div className="error-message">Error: {error}</div>}

      {loading ? (
        <div className="loading">Loading actions...</div>
      ) : actions.length === 0 ? (
        <div className="empty-state">
          <p>No actions found</p>
        </div>
      ) : (
        <>
          <div className="actions-table-container">
            <table className="actions-table">
              <thead>
                <tr>
                  <th>ID</th>
                  <th>Agent ID</th>
                  <th>Process ID</th>
                  <th>Host Address</th>
                  <th>Action Type</th>
                  <th>Details</th>
                  <th>Status</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((action) => (
                  <tr key={action.id}>
                    <td className="action-id">{action.id}</td>
                    <td className="agent-id-cell">
                      <code>{action.agent_id}</code>
                    </td>
                    <td className="process-id">
                      {action.process_id ? (
                        <code>{action.process_id}</code>
                      ) : (
                        <span className="text-muted">N/A</span>
                      )}
                    </td>
                    <td className="host-address">
                      {action.host_address ? (
                        <code>{action.host_address}</code>
                      ) : (
                        <span className="text-muted">N/A</span>
                      )}
                    </td>
                    <td>
                      <span className="action-type-badge">
                        {action.action_type}
                      </span>
                    </td>
                    <td className="action-details">
                      {formatActionDetails(action.action_details)}
                    </td>
                    <td>
                      <span className="status-badge status-new">
                        {action.status}
                      </span>
                    </td>
                    <td className="timestamp">
                      {formatDate(action.timestamp)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
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

export default ActionsPage


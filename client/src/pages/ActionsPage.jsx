import React, { useState, useEffect } from 'react'
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
  
  // Expanded rows
  const [expandedRows, setExpandedRows] = useState(new Set())

  useEffect(() => {
    fetchAgents()
  }, [])

  useEffect(() => {
    fetchActions()
    
    // Auto-refresh every 3 seconds to show evaluation updates
    const interval = setInterval(() => {
      fetchActions()
    }, 3000)
    
    return () => clearInterval(interval)
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

  const toggleRow = (actionId) => {
    setExpandedRows((prev) => {
      const newSet = new Set(prev)
      if (newSet.has(actionId)) {
        newSet.delete(actionId)
      } else {
        newSet.add(actionId)
      }
      return newSet
    })
  }

  const getRiskBadgeClass = (risk) => {
    if (!risk) return 'risk-badge risk-unknown'
    const riskUpper = risk.toUpperCase()
    if (riskUpper === 'CRITICAL') return 'risk-badge risk-critical'
    if (riskUpper === 'HIGH') return 'risk-badge risk-high'
    if (riskUpper === 'MEDIUM') return 'risk-badge risk-medium'
    if (riskUpper === 'LOW') return 'risk-badge risk-low'
    return 'risk-badge risk-unknown'
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
              <option value="UNDER_EVALUATION">UNDER_EVALUATION</option>
              <option value="EVALUATED">EVALUATED</option>
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
                  <th style={{ width: '30px' }}></th>
                  <th>ID</th>
                  <th>Agent ID</th>
                  <th>Action Type</th>
                  <th>Status</th>
                  <th>Risk</th>
                  <th>Intent</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                {actions.map((action) => {
                  const isExpanded = expandedRows.has(action.id)
                  return (
                    <React.Fragment key={action.id}>
                      <tr
                        className={isExpanded ? 'row-expanded' : ''}
                        onClick={() => toggleRow(action.id)}
                        style={{ cursor: 'pointer' }}
                      >
                        <td className="expand-icon">
                          {isExpanded ? '▼' : '▶'}
                        </td>
                        <td className="action-id">{action.id}</td>
                        <td className="agent-id-cell">
                          <code>{action.agent_id}</code>
                        </td>
                        <td>
                          <span className="action-type-badge">
                            {action.action_type}
                          </span>
                        </td>
                        <td>
                          <span className={`status-badge status-${action.status.toLowerCase().replace('_', '-')}`}>
                            {action.status}
                          </span>
                        </td>
                        <td>
                          {action.risk ? (
                            <span className={getRiskBadgeClass(action.risk)}>
                              {action.risk}
                            </span>
                          ) : (
                            <span className="text-muted">-</span>
                          )}
                        </td>
                        <td className="intent-cell">
                          {action.intent ? (
                            <span className="intent-text">{action.intent}</span>
                          ) : (
                            <span className="text-muted">-</span>
                          )}
                        </td>
                        <td className="timestamp">
                          {formatDate(action.timestamp)}
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr className="expanded-row-details">
                          <td colSpan="8">
                            <div className="expanded-content">
                              <div className="detail-section">
                                <h4>Action Details</h4>
                                <div className="detail-grid">
                                  <div className="detail-item">
                                    <span className="detail-label">Process ID:</span>
                                    <span className="detail-value">
                                      {action.process_id || 'N/A'}
                                    </span>
                                  </div>
                                  <div className="detail-item">
                                    <span className="detail-label">Host Address:</span>
                                    <span className="detail-value">
                                      {action.host_address || 'N/A'}
                                    </span>
                                  </div>
                                  <div className="detail-item">
                                    <span className="detail-label">Details:</span>
                                    <span className="detail-value">
                                      {formatActionDetails(action.action_details)}
                                    </span>
                                  </div>
                                </div>
                              </div>
                              {action.status === 'EVALUATED' && (
                                <div className="detail-section">
                                  <h4>Evaluation Results</h4>
                                  <div className="detail-grid">
                                    <div className="detail-item">
                                      <span className="detail-label">Evaluation By:</span>
                                      <span className="detail-value">
                                        {action.evaluation_by || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Intent:</span>
                                      <span className="detail-value">
                                        {action.intent || 'N/A'}
                                      </span>
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Risk:</span>
                                      <span className="detail-value">
                                        {action.risk ? (
                                          <span className={getRiskBadgeClass(action.risk)}>
                                            {action.risk}
                                          </span>
                                        ) : (
                                          'N/A'
                                        )}
                                      </span>
                                    </div>
                                    <div className="detail-item">
                                      <span className="detail-label">Time Taken:</span>
                                      <span className="detail-value">
                                        {action.evaluation_time_taken
                                          ? `${action.evaluation_time_taken}s`
                                          : 'N/A'}
                                      </span>
                                    </div>
                                    <div className="detail-item full-width">
                                      <span className="detail-label">Description:</span>
                                      <div className="detail-value description-text">
                                        {action.evaluation_description || 'N/A'}
                                      </div>
                                    </div>
                                    {action.evaluation_timestamp && (
                                      <div className="detail-item">
                                        <span className="detail-label">Evaluated At:</span>
                                        <span className="detail-value">
                                          {formatDate(action.evaluation_timestamp)}
                                        </span>
                                      </div>
                                    )}
                                  </div>
                                </div>
                              )}
                              {action.status === 'UNDER_EVALUATION' && (
                                <div className="detail-section">
                                  <div className="evaluating-indicator">
                                    <span className="spinner">⏳</span>
                                    <span>Evaluation in progress...</span>
                                  </div>
                                </div>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  )
                })}
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


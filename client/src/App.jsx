import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Header from './components/Header'
import Navigation from './components/Navigation'
import AgentsPage from './pages/AgentsPage'
import ActionsPage from './pages/ActionsPage'
import './styles/App.css'

function App() {
  return (
    <Router>
      <div className="app">
        <Header />
        <div className="app-content">
          <Navigation />
          <main className="main-content">
            <Routes>
              <Route path="/" element={<AgentsPage />} />
              <Route path="/agents" element={<AgentsPage />} />
              <Route path="/actions" element={<ActionsPage />} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  )
}

export default App


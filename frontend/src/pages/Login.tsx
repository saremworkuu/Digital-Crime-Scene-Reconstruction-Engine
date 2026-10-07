import { Link, useNavigate } from 'react-router-dom'

export default function Login() {
  const navigate = useNavigate()

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    localStorage.setItem('dcsre_auth', 'true')
    navigate('/dashboard')
  }

  return (
    <div className="auth-page">
      <div className="auth-panel">
        <div className="auth-visual">
          <div className="auth-badge">DCSRE</div>
          <h1>Digital Crime Scene Reconstruction Engine</h1>
          <p>
            Untangle complex investigations, correlate digital artifacts, and reconstruct the complete attack narrative with confidence.
          </p>

          <div className="auth-metrics">
            <div>
              <strong>1,486</strong>
              <span>Evidence items</span>
            </div>
            <div>
              <strong>91%</strong>
              <span>Attack path confidence</span>
            </div>
            <div>
              <strong>28</strong>
              <span>Open cases</span>
            </div>
          </div>
        </div>

        <div className="auth-form-card">
          <div className="auth-header">
            <span className="eyebrow">Secure access</span>
            <h2>Analyst sign in</h2>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <label>
              <span>Email address</span>
              <input type="email" placeholder="analyst@forensic.local" />
            </label>

            <label>
              <span>Password</span>
              <input type="password" placeholder="••••••••" />
            </label>

            <div className="auth-options">
              <label className="check-row">
                <input type="checkbox" defaultChecked />
                Keep me signed in
              </label>
              <a href="#">Forgot password?</a>
            </div>

            <button type="submit" className="primary-btn">Access workspace</button>
          </form>

          <p className="switch-copy">
            Need an account? <Link to="/register">Register here</Link>
          </p>
        </div>
      </div>
    </div>
  )
}

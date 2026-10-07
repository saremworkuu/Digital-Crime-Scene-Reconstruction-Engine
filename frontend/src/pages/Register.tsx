import { Link, useNavigate } from 'react-router-dom'

export default function Register() {
  const navigate = useNavigate()

  const handleSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    localStorage.setItem('dcsre_auth', 'true')
    navigate('/dashboard')
  }

  return (
    <div className="auth-page">
      <div className="auth-panel auth-panel-compact">
        <div className="auth-visual">
          <div className="auth-badge">DCSRE</div>
          <h1>Build your forensic response team.</h1>
          <p>
            Create an account to manage investigations, track evidence, and reconstruct events with structured forensic intelligence.
          </p>

          <div className="auth-metrics">
            <div>
              <strong>24/7</strong>
              <span>Investigation workflow</span>
            </div>
            <div>
              <strong>Secure</strong>
              <span>Protected evidence access</span>
            </div>
            <div>
              <strong>Audit</strong>
              <span>Traceable analyst actions</span>
            </div>
          </div>
        </div>

        <div className="auth-form-card">
          <div className="auth-header">
            <span className="eyebrow">Create account</span>
            <h2>Register</h2>
          </div>

          <form className="auth-form" onSubmit={handleSubmit}>
            <label>
              <span>Full name</span>
              <input type="text" placeholder="Jane Investigator" />
            </label>

            <label>
              <span>Email address</span>
              <input type="email" placeholder="jane@forensic.local" />
            </label>

            <label>
              <span>Password</span>
              <input type="password" placeholder="Create a strong password" />
            </label>

            <label>
              <span>Organization</span>
              <input type="text" placeholder="Cyber Defense Unit" />
            </label>

            <button type="submit" className="primary-btn">Create account</button>
          </form>

          <p className="switch-copy">
            Already have an account? <Link to="/login">Sign in</Link>
          </p>
        </div>
      </div>
    </div>
  )
}

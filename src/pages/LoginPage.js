export const LoginPage = () => {
  return `
    <div class="auth-page fade-in">
      <div class="auth-wrapper">
        <div class="auth-image login-image">
          <img src="/src/assets/logo.svg" alt="COGNI AI Logo" style="width: 100%; max-width: 450px; height: auto; filter: drop-shadow(0 10px 15px rgba(0,0,0,0.05));" />
        </div>
        
        <div class="auth-content">
          <div class="auth-header">
            <h1>Login</h1>
            <p>Enter your credentials to continue</p>
          </div>

          <form id="loginForm" onsubmit="window.app.handleLogin(event)">
            <div class="form-group" style="margin-bottom: 1.5rem;">
              <label>Select Your Role</label>
              <select id="roleSelect" name="role" required>
                <option value="student">Student</option>
                <option value="faculty">Faculty</option>
                <option value="admin">Forum Coordinator (Admin)</option>
              </select>
            </div>
            
            <div class="form-group" style="margin-bottom: 1.5rem;">
              <label>Institutional ID / Email</label>
              <input type="email" name="email" placeholder="e.g. jscoe@college.edu" required>
            </div>

            <div class="form-group" style="margin-bottom: 2rem;">
              <label>Password</label>
              <input type="password" name="password" placeholder="••••••••" required>
            </div>

            <button type="submit" class="btn btn-primary auth-btn">Secure Login</button>
          </form>

          <div class="auth-footer">
            <p>New to the platform? <a href="#" onclick="window.app.navigate('signup')">Create an account</a></p>
            <p style="margin-top: 1rem; font-size: 0.8rem; color: var(--text-muted);">
              Institutional Access Only. Need help? 
              <a href="#" style="font-weight: normal; opacity: 0.8;">Contact Support</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  `;
};

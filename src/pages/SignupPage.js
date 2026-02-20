export const SignupPage = () => {
  return `
    <div class="auth-page fade-in">
      <div class="auth-wrapper">
        <div class="auth-image signup-image">
          <img src="/logo.svg" alt="COGNI AI Logo" style="width: 100%; max-width: 450px; height: auto; filter: drop-shadow(0 10px 15px rgba(0,0,0,0.05));" />
        </div>
        
        <div class="auth-content">
          <div class="auth-header">
            <h1>Create Account</h1>
            <p>Select your role to get started</p>
          </div>

          <div class="role-selector">
            <button class="role-tab active" onclick="window.app.switchSignupRole('student')">Student</button>
            <button class="role-tab" onclick="window.app.switchSignupRole('faculty')">Faculty</button>
            <button class="role-tab" onclick="window.app.switchSignupRole('admin')">Admin</button>
          </div>

          <!-- Student Signup Form -->
          <form id="studentSignupForm" class="signup-form active" onsubmit="window.app.handleSignup(event, 'student')">
            <div class="form-grid">
              <div class="form-group">
                <label>Full Name</label>
                <input type="text" name="name" placeholder="John Doe" required>
              </div>
              <div class="form-group">
                <label>Year</label>
                <select name="year" required>
                  <option value="">Select Year</option>
                  <option value="FE">First Year (FE)</option>
                  <option value="SE">Second Year (SE)</option>
                  <option value="TE">Third Year (TE)</option>
                  <option value="BE">Fourth Year (BE)</option>
                </select>
              </div>
              <div class="form-group">
                <label>Department</label>
                <select name="dept" required>
                  <option value="">Select Department</option>
                  <option value="Computer">Computer</option>
                  <option value="IT">IT</option>
                  <option value="ENTC">ENTC</option>
                  <option value="Mechanical">Mechanical</option>
                  <option value="Electrical">Electrical</option>
                  <option value="FE">FE (First Year)</option>
                  <option value="MCA">MCA</option>
                  <option value="MBA">MBA</option>
                  <option value="AI & DS">AI & DS</option>
                </select>
              </div>
              <div class="form-group">
                <label>Roll No</label>
                <input type="text" name="rollno" placeholder="21CO042" required>
              </div>
              <div class="form-group">
                <label>Institutional Email</label>
                <input type="email" name="email" placeholder="john.doe@college.edu" required>
              </div>
              <div class="form-group">
                <label>Mobile Number</label>
                <input type="tel" name="number" placeholder="+91 9876543210" required>
              </div>
              <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required>
              </div>
              <div class="form-group">
                <label>Retype Password</label>
                <input type="password" name="retype" placeholder="••••••••" required>
              </div>
            </div>
            <button type="submit" class="btn btn-primary auth-btn">Create Student Account</button>
          </form>

          <!-- Faculty Signup Form -->
          <form id="facultySignupForm" class="signup-form" onsubmit="window.app.handleSignup(event, 'faculty')" style="display: none;">
            <div class="form-grid">
              <div class="form-group">
                <label>Full Name</label>
                <input type="text" name="name" placeholder="Dr. Jane Smith" required>
              </div>
              <div class="form-group">
                <label>Department</label>
                <select name="dept" required>
                  <option value="">Select Department</option>
                  <option value="Computer">Computer</option>
                  <option value="IT">IT</option>
                  <option value="ENTC">ENTC</option>
                  <option value="Mechanical">Mechanical</option>
                  <option value="Electrical">Electrical</option>
                  <option value="FE">FE (First Year)</option>
                  <option value="MCA">MCA</option>
                  <option value="MBA">MBA</option>
                  <option value="AI & DS">AI & DS</option>
                </select>
              </div>
              <div class="form-group">
                <label>College Email ID</label>
                <input type="email" name="email" placeholder="jane.smith@faculty.college.edu" required>
              </div>
              <div class="form-group">
                <label>Mobile Number</label>
                <input type="tel" name="number" placeholder="+91 9876543210" required>
              </div>
              <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required>
              </div>
            </div>
            <button type="submit" class="btn btn-primary auth-btn">Create Faculty Account</button>
          </form>

          <!-- Admin Signup Form -->
          <form id="adminSignupForm" class="signup-form" onsubmit="window.app.handleSignup(event, 'admin')" style="display: none;">
            <div class="form-grid">
              <div class="form-group">
                <label>Admin Name</label>
                <input type="text" name="name" placeholder="System Administrator" required>
              </div>
              <div class="form-group">
                <label>Admin Email Address</label>
                <input type="email" name="email" placeholder="admin@college.edu" required>
              </div>
              <div class="form-group">
                <label>Mobile Number</label>
                <input type="tel" name="number" placeholder="+91 9876543210" required>
              </div>
              <div class="form-group">
                <label>Password</label>
                <input type="password" name="password" placeholder="••••••••" required>
              </div>
            </div>
            <button type="submit" class="btn btn-primary auth-btn">Create Admin Account</button>
          </form>

          <div class="auth-footer">
            <p>Already have an account? <a href="#" onclick="window.app.navigate('login')">Login instead</a></p>
          </div>
        </div>
      </div>
    </div>
  `;
};

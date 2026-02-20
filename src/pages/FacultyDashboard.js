export const FacultyDashboard = (user, events = [], registrations = []) => {
  const initials = user.name.split(' ').map(n => n[0]).join('');
  const registrationCount = registrations.length;

  const eventCards = events.length > 0 ? events.map(event => {
    const isClosed = new Date() > new Date(event.registrationDeadline);
    const imageUrl = event.image || 'https://images.unsplash.com/photo-1591115765373-5207764f72e7?q=80&w=1000&auto=format&fit=crop';
    const isRegistered = registrations.some(reg => reg.event && reg.event._id === event._id);

    return `
      <div class="student-event-card" onclick="window.app.navigate('event/${event._id}')">
        <div class="card-image-wrapper">
          <img src="${imageUrl}" alt="${event.title}">
          <div class="status-badge ${isClosed ? 'closed' : 'open'}">${isClosed ? 'Expired' : 'Live'}</div>
          ${isRegistered ? '<div class="registered-badge">✓ Registered</div>' : ''}
          <div class="category-tag">${event.type}</div>
        </div>
        
        <div class="card-content">
          <h4>${event.title}</h4>
          <div class="card-meta">
            <span>🏛️ ${event.department === 'ALL' ? 'Open for All' : event.department}</span>
            <span>📅 ${new Date(event.registrationDeadline).toLocaleDateString()}</span>
            <span style="font-weight: 800; color: ${event.isPaid ? '#E11D48' : '#059669'};">
               ${event.isPaid ? `₹${event.price}` : 'FREE'}
            </span>
          </div>
          <p>${event.description}</p>
          
          <div class="card-footer">
            <button class="action-btn ${isClosed ? 'secondary' : 'primary'}">
                ${isClosed ? 'View Details' : (isRegistered ? 'Manage Registration' : 'Register Now')}
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('') : `<div style="grid-column: 1/-1; padding: 4rem; text-align: center; color: var(--text-muted);">No active faculty events found.</div>`;

  const registrationList = registrations.length > 0 ? registrations.map(reg => {
    return `
      <div class="activity-item" style="flex-direction: column; align-items: flex-start; gap: 0.5rem; padding: 1.2rem;">
        <div style="display: flex; justify-content: space-between; width: 100%; align-items: center;">
           <div style="font-weight: 800; color: #1E293B;">${reg.event ? reg.event.title : 'Deleted Event'}</div>
           <div class="activity-status ${reg.isConfirmed ? 'status-active' : 'status-pending'}" style="margin: 0;">
              ${reg.isConfirmed ? 'Confirmed' : 'Pending'}
           </div>
        </div>
        
        <div style="font-size: 0.8rem; color: #94A3B8;">Registered on ${new Date(reg.registeredAt).toLocaleDateString()}</div>
      </div>
    `;
  }).join('') : '<p style="text-align: center; color: var(--text-muted); padding: 1rem;">No enrollments yet.</p>';

  return `
    <div class="student-dashboard" style="background: #F8FAFC; min-height: 100vh; position: relative;">
      <!-- Using same gradient background as student for consistency -->
      <div style="position: absolute; top: 0; left: 0; width: 100%; height: 400px; background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); clip-path: polygon(0 0, 100% 0, 100% 80%, 0 100%); z-index: 0;"></div>

      <nav class="student-nav" style="position: relative; z-index: 10; padding: 1.5rem 5%; display: flex; justify-content: space-between; align-items: center; color: white;">
        <div class="logo" style="font-size: 1.5rem; font-weight: 800; display: flex; align-items: center; gap: 0.8rem; color: white;">
          <div style="width: 32px; height: 32px; background: white; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: var(--accent);">🎓</div>
          COGNI AI <span style="font-weight: 400; font-size: 1rem; opacity: 0.8; margin-left: 0.5rem;">| Faculty Portal</span>
        </div>
        <div style="display: flex; gap: 1.5rem; align-items: center;">
          <div class="profile-pill" onclick="window.app.showEditProfileModal()">
             <div class="avatar-small" style="color: var(--accent);">${initials}</div>
             <span class="user-name-white">${user.name}</span>
          </div>
          <button class="logout-btn-minimal" onclick="window.app.logout()">Logout</button>
        </div>
      </nav>

      <div class="container" style="position: relative; z-index: 10; padding-bottom: 5rem;">
        <header class="student-hero">
           <div class="hero-text">
              <div class="greeting-tag">FACULTY DASHBOARD</div>
              <h1>Empower. Lead. Mentor.</h1>
              <p>Your hub for academic events, workshops, and institutional programs.</p>
           </div>
           <div class="hero-stats-grid">
              <div class="stat-card">
                 <div class="stat-icon" style="color: var(--accent); background: #EEF2FF;">📅</div>
                 <div class="stat-value">${events.length}</div>
                 <div class="stat-label">Available Events</div>
              </div>
              <div class="stat-card">
                 <div class="stat-icon" style="color: var(--primary); background: #EFF6FF;">📝</div>
                 <div class="stat-value">${registrationCount}</div>
                 <div class="stat-label">My Registrations</div>
              </div>
              <div class="stat-card" style="opacity: 0.7; cursor: not-allowed;" title="Coming Soon">
                 <div class="stat-icon">📊</div>
                 <div class="stat-value">-</div>
                 <div class="stat-label">Publications</div>
              </div>
           </div>
        </header>

        <div style="display: grid; grid-template-columns: 1fr 350px; gap: 3rem; margin-top: 4rem;">
          <section>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
               <h2 style="font-size: 1.8rem; color: #1E293B;">Event Gallery</h2>
               <!-- Filter functionality can be added later if needed -->
            </div>
            <div class="student-events-grid">
               ${eventCards}
            </div>
          </section>

          <aside style="display: flex; flex-direction: column; gap: 2rem;">
            <!-- Profile Summary / Quick Actions -->
            <div class="glass-section" style="text-align: center;">
                <div style="width: 80px; height: 80px; background: var(--accent); color: white; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 2rem; font-weight: 800; margin: 0 auto 1.5rem;">${initials}</div>
                <h3 style="margin-bottom: 0.25rem;">${user.name}</h3>
                <p style="font-size: 0.875rem; color: var(--text-muted); margin-bottom: 1.5rem;">${user.role.toUpperCase()} | ${user.dept || 'Department'}</p>
                <button class="btn btn-outline" style="width: 100%; font-size: 0.9rem;" onclick="window.app.showEditProfileModal()">Edit Profile</button>
            </div>

            <!-- Enrollment List -->
            <div class="glass-section">
               <h3 class="section-title-small">My Enrollments</h3>
               <div class="activity-feed">
                  ${registrationList}
               </div>
            </div>
          </aside>
        </div>
      </div>

       <!-- Edit Profile Modal -->
      <div id="editProfileModal" class="modal-overlay">
        <div class="modal-content">
          <button class="modal-close" onclick="window.app.closeEditProfileModal()">&times;</button>
          <div class="modal-header">
             <h2>Edit Profile</h2>
          </div>
          <div class="modal-body">
            <form onsubmit="window.app.handleEditProfile(event)" style="display: flex; flex-direction: column; gap: 1.5rem;">
              <div class="form-group">
                <label>Full Name</label>
                <input type="text" name="name" value="${user.name}" required>
              </div>
              
              <div class="form-group">
                  <label>Department</label>
                  <select name="dept" required>
                  <option value="${user.dept}" selected>${user.dept || 'Select Department'}</option>
                  <option value="Computer">Computer</option>
                  <option value="IT">IT</option>
                  <option value="ENTC">ENTC</option>
                  <option value="Mechanical">Mechanical</option>
                  <option value="Electrical">Electrical</option>
                  <option value="AI & DS">AI & DS</option>
                  </select>
              </div>

              <div class="form-group">
                <label>Phone Number</label>
                <input type="tel" name="number" value="${user.number || ''}" placeholder="Contact Number">
              </div>

              <button type="submit" class="btn btn-primary" style="width: 100%; padding: 1rem; font-size: 1rem;">Save Changes</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  `;
};

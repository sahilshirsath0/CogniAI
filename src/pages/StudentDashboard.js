export const StudentDashboard = (user, events = [], registrations = [], filters = {}, invitations = []) => {
  const initials = user.name.split(' ').map(n => n[0]).join('');
  const registrationCount = registrations.length;

  const currentPoints = user.aiPoints || 0;
  const learningProgress = Math.min((currentPoints / 100) * 100, 100);
  const skillScore = currentPoints;

  const eventCards = events.length > 0 ? events.map(event => {
    const isClosed = new Date() > new Date(event.registrationDeadline);
    const imageUrl = event.image || 'https://images.unsplash.com/photo-1620712943543-bcc4688e7485?q=80&w=1000&auto=format&fit=crop';
    const isRegistered = registrations.some(reg => reg.event && reg.event._id === event._id);

    return `
      <div class="student-event-card" onclick="window.app.navigate('event/${event._id}')">
        <div class="card-image-wrapper">
          <img src="${imageUrl}" alt="${event.title}">
          <div class="status-badge ${isClosed ? 'closed' : 'open'}">${isClosed ? 'Expired' : 'Live'}</div>
          ${isRegistered ? '<div class="registered-badge">✓ Enrolled</div>' : ''}
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
                ${isClosed ? 'View Details' : (isRegistered ? 'Manage Entry' : 'Get Started')}
            </button>
          </div>
        </div>
      </div>
    `;
  }).join('') : `<div style="grid-column: 1/-1; padding: 4rem; text-align: center;">Scanning...</div>`;

  const invitationItems = invitations.length > 0 ? invitations.map(inv => `
    <div style="background: white; padding: 1rem; border-radius: 12px; border: 1px solid #BFDBFE; margin-bottom: 0.8rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
       <div style="font-size: 0.8rem; color: #1E40AF; font-weight: 800; margin-bottom: 0.3rem;">TEAM REQUEST</div>
       <div style="font-weight: 700; color: #1E293B; margin-bottom: 0.2rem;">${inv.teamName}</div>
       <div style="font-size: 0.85rem; color: #64748B; margin-bottom: 0.8rem;">Invite from ${inv.fromUser?.name} for ${inv.event?.title}</div>
       <div style="display: flex; gap: 0.5rem;">
          <button class="btn btn-primary" style="flex: 1; padding: 0.5rem; font-size: 0.8rem;" onclick="window.app.navigate('event/${inv.event?._id}?invId=${inv._id}')">Accept & Join</button>
          <button class="btn btn-outline" style="flex: 1; padding: 0.5rem; font-size: 0.8rem;" onclick="window.app.respondToInvitation('${inv._id}', 'rejected')">Decline</button>
       </div>
    </div>
  `).join('') : '<p style="color: #64748B; font-size: 0.9rem; text-align: center; padding: 1rem;">No pending formation requests</p>';

  const registrationList = registrations.length > 0 ? registrations.map(reg => {
    const isLeader = reg.teamLeader === user.id;
    const isTeam = reg.registrationType === 'Team';
    const awaitingLeader = isTeam && !reg.isConfirmed;

    return `
      <div class="activity-item" style="flex-direction: column; align-items: flex-start; gap: 0.5rem; padding: 1.2rem;">
        <div style="display: flex; justify-content: space-between; width: 100%; align-items: center;">
           <div style="font-weight: 800; color: #1E293B;">${reg.event ? reg.event.title : 'Deleted Event'}</div>
           <div class="activity-status ${reg.isConfirmed ? 'status-active' : 'status-pending'}" style="margin: 0;">
              ${reg.isConfirmed ? 'Confirmed' : 'Awaiting'}
           </div>
        </div>
        
        ${isTeam ? `
          <div style="background: #F8FAFC; width: 100%; padding: 0.8rem; border-radius: 8px; border: 1px solid var(--border); margin-top: 0.5rem;">
             <div style="font-size: 0.75rem; color: #64748B; font-weight: 700; text-transform: uppercase;">Team ${reg.teamName}</div>
             <div style="display: flex; gap: 0.3rem; margin-top: 0.4rem;">
                ${reg.teamMembers?.length || 0} members joined
             </div>
             ${isLeader && !reg.isConfirmed ? `
               <button class="btn btn-primary" style="width: 100%; margin-top: 0.8rem; padding: 0.5rem; font-size: 0.8rem;" onclick="window.app.confirmTeam('${reg._id}')">Confirm Team Completion</button>
             ` : ''}
          </div>
        ` : ''}
        
        <div style="font-size: 0.8rem; color: #94A3B8;">Registered on ${new Date(reg.registeredAt).toLocaleDateString()}</div>
      </div>
    `;
  }).join('') : '<p style="text-align: center; color: var(--text-muted); padding: 1rem;">No enrollments</p>';

  return `
    <div class="student-dashboard" style="background: #F8FAFC; min-height: 100vh; position: relative;">
      <div style="position: absolute; top: 0; left: 0; width: 100%; height: 400px; background: linear-gradient(135deg, #2563EB 0%, #4F46E5 100%); clip-path: polygon(0 0, 100% 0, 100% 80%, 0 100%); z-index: 0;"></div>

      <nav class="student-nav" style="position: relative; z-index: 10; padding: 1.5rem 5%; display: flex; justify-content: space-between; align-items: center; color: white;">
        <div class="logo" style="font-size: 1.5rem; font-weight: 800; display: flex; align-items: center; gap: 0.8rem;">
          <div style="width: 32px; height: 32px; background: white; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: var(--primary);">🤖</div>
          COGNI AI
        </div>
        <div style="display: flex; gap: 1.5rem; align-items: center;">
          <div class="profile-pill" onclick="window.app.showEditProfileModal()">
             <div class="avatar-small">${initials}</div>
             <span class="user-name-white">${user.name}</span>
          </div>
          <button class="logout-btn-minimal" onclick="window.app.logout()">Logout</button>
        </div>
      </nav>

      <div class="container" style="position: relative; z-index: 10; padding-bottom: 5rem;">
        <header class="student-hero">
           <div class="hero-text">
              <div class="greeting-tag">STUDENT DASHBOARD</div>
              <h1>Innovate. Build. Learn.</h1>
              <p>The centralized hub for all your academic events and team collaborations.</p>
           </div>
           <div class="hero-stats-grid">
              <div class="stat-card">
                 <div class="stat-icon">🏆</div>
                 <div class="stat-value">${skillScore}</div>
                 <div class="stat-label">AI Points</div>
                 <div class="stat-progress-bar"><div style="width: ${learningProgress}%"></div></div>
              </div>
              <div class="stat-card">
                 <div class="stat-icon">⚡</div>
                 <div class="stat-value">${registrationCount}</div>
                 <div class="stat-label">Registrations</div>
              </div>
           </div>
        </header>

        <div style="display: grid; grid-template-columns: 1fr 380px; gap: 3rem; margin-top: 4rem;">
          <section>
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 2rem;">
               <h2 style="font-size: 1.8rem; color: #1E293B;">Discovery Feed</h2>
              <select class="sort-select-premium" onchange="window.app.handleUnifiedFilter(this.value)">
                  <option value="all">Sort: All Events</option>
                  <optgroup label="Payment">
                     <option value="free" ${filters.isPaid === false ? 'selected' : ''}>Free</option>
                     <option value="paid" ${filters.isPaid === true ? 'selected' : ''}>Paid</option>
                  </optgroup>
                  <optgroup label="Departments">
                     <option value="dept:Computer" ${filters.department === 'Computer' ? 'selected' : ''}>Computer</option>
                     <option value="dept:IT" ${filters.department === 'IT' ? 'selected' : ''}>IT</option>
                     <option value="dept:ENTC" ${filters.department === 'ENTC' ? 'selected' : ''}>ENTC</option>
                     <option value="dept:Electrical" ${filters.department === 'Electrical' ? 'selected' : ''}>Electrical</option>
                     <option value="dept:Mechanical" ${filters.department === 'Mechanical' ? 'selected' : ''}>Mechanical</option>
                     <option value="dept:AI & DS" ${filters.department === 'AI & DS' ? 'selected' : ''}>AI & DS</option>
                     <option value="dept:FE" ${filters.department === 'FE' ? 'selected' : ''}>FE</option>
                     <option value="dept:MCA" ${filters.department === 'MCA' ? 'selected' : ''}>MCA</option>
                     <option value="dept:MBA" ${filters.department === 'MBA' ? 'selected' : ''}>MBA</option>
                  </optgroup>
               </select>
            </div>
            <div id="student-events-grid" class="student-events-grid">
               ${eventCards}
            </div>
          </section>

          <aside style="display: flex; flex-direction: column; gap: 2rem;">
            <!-- Formation Hub -->
            <div class="glass-section" style="background: #EFF6FF; border-color: #BFDBFE;">
               <h3 class="section-title-small" style="color: #1E40AF;">Team Formation Hub</h3>
               <p style="font-size: 0.85rem; color: #1E40AF; margin-bottom: 1.5rem;">Accept team invites from fellow students here.</p>
               ${invitationItems}
            </div>

            <!-- Enrollment List -->
            <div class="glass-section">
               <h3 class="section-title-small">My Registration Log</h3>
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
            <h2>Update Profile</h2>
          </div>
          <div class="modal-body">
            <form onsubmit="window.app.handleEditProfile(event)" id="editProfileForm">
               <div class="form-group"><label>Name</label><input type="text" name="name" value="${user.name}" required></div>
               <div class="form-group"><label>Year</label><select name="year"><option value="FE">FE</option><option value="SE">SE</option><option value="TE">TE</option><option value="BE">BE</option></select></div>
               <div class="form-group"><label>RollNo</label><input type="text" name="rollno" value="${user.rollno || ''}"></div>
               <button type="submit" class="btn btn-primary" style="width:100%">Save Changes</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  `;
};
